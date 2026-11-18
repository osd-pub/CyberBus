package io.cyberbus.demo

import android.system.Os
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

/** One bounded private journal shared by the App main thread and its existing native worker. */
internal class CompletionJournal(directory: File) {
    private val file = File(directory, "completions.ndjson")
    private var rows = 0
    private var bytes = 0
    private var dropped = false
    private var writeFailed = false
    private var closed = false

    init { file.writeBytes(byteArrayOf()); Os.chmod(file.path, 384) }

    @Synchronized fun append(value: CompletionDiagnostic) {
        if (closed || dropped || writeFailed) { dropped = true; return }
        try {
            check(value.peerDeviceId.size() == 32 && value.messageId.size() == 16)
            val row = JSONObject().put("sequence", rows + 1).put("kind", value.kind.name)
                .put("peerDeviceId", encode(value.peerDeviceId.toByteArray()))
                .put("messageId", encode(value.messageId.toByteArray()))
            value.commandId?.let { check(it.size() == 16); row.put("commandId", encode(it.toByteArray())) }
            value.foregroundReady?.let { row.put("foregroundReady", it) }
            value.completion?.let { row.put("completion", it.name) }
            value.result?.let { row.put("result", it.name) }
            value.errorCode?.let { row.put("errorCode", it.name) }
            value.correlated?.let { row.put("correlated", it) }
            value.localFailure?.let { row.put("localFailure", it.name) }
            val encoded = (row.toString() + "\n").toByteArray(Charsets.UTF_8)
            if (rows >= 512 || encoded.size > 2048 || bytes + encoded.size > 512 * 1024) {
                dropped = true; return
            }
            FileOutputStream(file, true).use { it.write(encoded) }
            rows++; bytes += encoded.size
        } catch (_: Exception) { writeFailed = true }
    }

    @Synchronized fun finish(): JSONObject {
        closed = true
        try { FileOutputStream(file, true).use { it.fd.sync() } }
        catch (_: Exception) { writeFailed = true }
        return JSONObject().put("rows", rows).put("bytes", bytes).put("dropped", dropped)
            .put("writeFailed", writeFailed).put("closed", closed)
    }

    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
}
