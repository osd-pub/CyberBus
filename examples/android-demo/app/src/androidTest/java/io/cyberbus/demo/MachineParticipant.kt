package io.cyberbus.demo

import android.app.Instrumentation
import android.system.Os
import android.util.AtomicFile
import android.util.Base64
import cyberbus.easytier.v1.Sdk.SdkResult
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Private test-only transport for the actual foreground sample, never a second SDK. */
internal class MachineParticipant(private val test: Instrumentation, private val session: DemoSession) {
    private val directory = File(test.targetContext.noBackupFilesDir, "multiclient")
    private val journal = File(directory, "events.ndjson")
    private var journalBytes = 0L
    private var failure: String? = null
    private lateinit var completions: CompletionJournal
    private val seen = mutableSetOf<String>()
    var closed = false; private set

    init {
        check(directory.isDirectory || directory.mkdir())
        Os.chmod(directory.path, 448)
        directory.listFiles()?.forEach { check(it.delete()) }
        journal.writeBytes(byteArrayOf()); Os.chmod(journal.path, 384)
        completions = CompletionJournal(directory)
        val application = test.targetContext.applicationInfo
        val extracted = File(application.nativeLibraryDir, "libcyberbus_ffi.so")
        val nativeHash = if (extracted.isFile) hash(extracted) else {
            // AGP can load uncompressed JNI directly from the installed APK.
            java.util.zip.ZipFile(application.sourceDir).use { apk ->
                val entry = android.os.Build.SUPPORTED_ABIS.firstNotNullOfOrNull { abi ->
                    apk.getEntry("lib/$abi/libcyberbus_ffi.so")
                }
                checkNotNull(entry) { "Installed APK has no supported JNI library" }
                apk.getInputStream(entry).use { hash(it) }
            }
        }
        val apkHash = hash(File(application.sourceDir))
        test.runOnMainSync {
            check(session.authenticated && session.foregroundReady && session.canStart)
            val local = session.deviceList.single { it.isLocal }
            session.observeCompletions { completions.append(it) }
            session.observeTestEvents { bytes ->
                try {
                    val row = (JSONObject().put("event_base64", encode(bytes)).toString() + "\n").toByteArray()
                    if (journalBytes + row.size > 32L * 1024 * 1024) throw IOException("Journal full")
                    journal.appendBytes(row)
                    journalBytes += row.size
                } catch (_: Exception) { failure = "event_journal_failed" }
            }
            write("ready.json", JSONObject().put("ready", true).put("protocol", "cyberbus-test-client/1")
                .put("externalAuth", true).put("preconfigured", true).put("autoCompleteData", true)
                .put("completionDiagnostics", true)
                .put("nativeLibrarySha256", nativeHash).put("apkSha256", apkHash)
                .put("deviceId", encode(local.deviceId.toByteArray())))
        }
    }

    fun pump() {
        var failed: String? = null
        test.runOnMainSync { failed = failure }
        check(failed == null) { "Machine event transport failed" }
        val file = File(directory, "request.json")
        if (!file.exists()) return
        check(file.length() in 1..2L * 1024 * 1024)
        val request = JSONObject(file.readText())
        check(file.delete())
        val id = request.getString("request_id")
        check(id.matches(Regex("[a-zA-Z0-9_-]{1,80}")) && seen.add(id) && seen.size <= 4096)
        val done = CountDownLatch(1)
        var result: ByteArray? = null
        var error: String? = null
        when (request.getString("op")) {
            "execute" -> {
                val command = Base64.decode(request.getString("command_base64"), Base64.NO_WRAP)
                test.runOnMainSync { session.executeTestCommand(command) { bytes, rejected ->
                    result = bytes; error = rejected; done.countDown()
                } }
            }
            "on_resume" -> {
                test.runOnMainSync { session.resume() }
                val deadline = android.os.SystemClock.elapsedRealtime() + 15_000
                var resumed = false
                while (!resumed && android.os.SystemClock.elapsedRealtime() < deadline) {
                    test.runOnMainSync { resumed = session.foregroundReady }
                    if (!resumed) android.os.SystemClock.sleep(50)
                }
                write("reply.json", JSONObject().put("request_id", id).put("resumed", resumed))
                return
            }
            "shutdown" -> test.runOnMainSync { session.close {
                result = session.testCloseResult
                if (result == null || session.status != "SDK 已关闭") error = "sdk_cleanup_unconfirmed"
                closed = true; done.countDown()
            } }
            else -> { error = "operation_not_allowed"; done.countDown() }
        }
        check(done.await(30, TimeUnit.SECONDS))
        val reply = JSONObject().put("request_id", id)
        if (error != null) reply.put("error", error) else {
            val bytes = checkNotNull(result)
            check(SdkResult.parseFrom(bytes).bodyCase != SdkResult.BodyCase.BODY_NOT_SET)
            reply.put("result_base64", encode(bytes))
        }
        write("reply.json", reply)
        if (closed) {
            test.runOnMainSync { session.observeTestEvents(null); session.observeCompletions(null) }
            write("completions-closed.json", completions.finish())
            write("closed.json", JSONObject().put("eventsClosed", true))
        }
    }
    fun detach() {
        test.runOnMainSync { session.observeTestEvents(null); session.observeCompletions(null) }
        write("completions-closed.json", completions.finish())
        File(directory, "ready.json").delete()
    }
    private fun write(name: String, value: JSONObject) {
        val file = AtomicFile(File(directory, name))
        val stream = file.startWrite()
        try {
            Os.fchmod(stream.fd, 384)
            stream.write(value.toString().toByteArray()); stream.fd.sync(); file.finishWrite(stream)
        } catch (error: Exception) { file.failWrite(stream); throw error }
    }
    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hash(file: File): String = file.inputStream().use { hash(it) }
    private fun hash(input: java.io.InputStream): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(65536)
        while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
