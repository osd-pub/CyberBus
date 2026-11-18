package io.cyberbus.demo

import android.content.Context
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileLock
import java.security.MessageDigest

/** DEVELOPMENT ONLY: plaintext, checksummed app-private records, not Keystore protection.
 * A durable per-record marker precedes the first state commit. Only the instance that
 * established that marker in a freshly created directory may return absent repeatedly
 * during the initial JNI CreateNew transaction. Reopening missing state fails closed.
 */
class ProtectedStore private constructor(private val directory: File, private val markerDirectory: File,
    private val disposable: Boolean) : Closeable {
    constructor(context: Context) : this(File(context.noBackupFilesDir, "cyberbus-development-store-v1"),
        File(context.noBackupFilesDir, "cyberbus-development-markers-v1"), false)
    private val freshDirectory: Boolean
    private val ownerPath = markerDirectory.canonicalPath
    private val owner: RandomAccessFile
    private val ownerLock: FileLock
    private val creating = mutableSetOf<String>()
    private val deletedTestRecords = mutableSetOf<String>()
    private var closed = false
    private var failed = false
    var migratedLegacy = false; private set

    init {
        val freshRecordDirectory = directory.mkdir()
        val freshMarkerDirectory = markerDirectory.mkdir()
        freshDirectory = freshRecordDirectory && freshMarkerDirectory
        if (!directory.isDirectory || !markerDirectory.isDirectory) throw IOException("Development store unavailable")
        Os.chmod(directory.path, 448)
        Os.chmod(markerDirectory.path, 448)
        syncDirectory(directory.parentFile!!)
        syncDirectory(markerDirectory.parentFile!!)
        // Do not even open a second descriptor in this process: closing it can release
        // process-scoped POSIX locks belonging to the first channel on some runtimes.
        synchronized(owners) { if (!owners.add(ownerPath)) throw IOException("Development store already owned") }
        owner = try { RandomAccessFile(File(markerDirectory, ".owner-lock"), "rw") }
        catch (error: Exception) { synchronized(owners) { owners.remove(ownerPath) }; throw error }
        try {
            Os.fchmod(owner.fd, 384)
            ownerLock = owner.channel.tryLock() ?: throw IOException("Development store already owned")
            owner.fd.sync()
            syncDirectory(markerDirectory)
        } catch (_: Exception) {
            try { owner.close() } finally { synchronized(owners) { owners.remove(ownerPath) } }
            throw IOException("Development store ownership unavailable")
        }
    }
    private fun name(key: String): String {
        require(key.isNotEmpty() && key.length <= 4096) { "Invalid local record key" }
        if (!disposable && key != "cyberbus-v1") throw IOException("Unexpected SDK record")
        return digest(key.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    private fun checkOwner() {
        if (closed || failed || !ownerLock.isValid) throw IOException("Development store closed or failed")
    }
    private fun exists(file: AtomicFile) = file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()
    private fun read(file: AtomicFile, limit: Int): ByteArray = file.openRead().use { stream ->
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (out.size() <= limit) {
            val count = stream.read(buffer, 0, minOf(buffer.size, limit + 1 - out.size()))
            if (count < 0) break
            out.write(buffer, 0, count)
        }
        if (out.size() > limit) throw IOException("Local record too large")
        out.toByteArray()
    }
    private fun replace(file: AtomicFile, bytes: ByteArray) {
        val stream = file.startWrite()
        try {
            Os.fchmod(stream.fd, 384)
            stream.write(bytes); stream.fd.sync()
            file.finishWrite(stream)
            syncDirectory(file.baseFile.parentFile!!)
            // AtomicFile logs some rename/sync failures instead of throwing: verify commit.
            if (!read(file, bytes.size).contentEquals(bytes)) throw IOException("Local commit unconfirmed")
        } catch (error: Exception) { file.failWrite(stream); throw error }
    }
    private fun envelope(value: ByteArray): ByteArray = ByteBuffer.allocate(HEADER_BYTES + value.size)
        .put(MAGIC).putInt(value.size).put(digest(value)).put(value).array()
    private fun decode(bytes: ByteArray): ByteArray {
        if (bytes.size < HEADER_BYTES || !bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC))
            throw IOException("Local record format invalid")
        val input = ByteBuffer.wrap(bytes)
        input.position(MAGIC.size)
        val size = input.int
        if (size !in 1..MAX_RECORD_BYTES || bytes.size != HEADER_BYTES + size) throw IOException("Local record size invalid")
        val expected = ByteArray(32).also { input.get(it) }
        val value = ByteArray(size).also { input.get(it) }
        if (!MessageDigest.isEqual(expected, digest(value))) throw IOException("Local record checksum invalid")
        return value
    }
    @Synchronized
    fun load(key: String): ByteArray? {
        checkOwner()
        val name = name(key)
        val record = AtomicFile(File(directory, name))
        val marker = AtomicFile(File(markerDirectory, "$name.created"))
        if (!exists(marker)) {
            // Existing directories without either record or marker are not trusted new installs.
            if (!exists(record) && !freshDirectory && name !in deletedTestRecords)
                throw IOException("Previously provisioned state missing")
            val legacy = if (exists(record)) read(record, MAX_RECORD_BYTES + HEADER_BYTES) else null
            if (legacy != null && legacy.isEmpty()) throw IOException("Legacy state invalid")
            try { replace(marker, MARKER) } catch (error: Exception) { failed = true; throw error }
            if (legacy != null) {
                // Explicit one-time migration. If interrupted after marking, raw legacy state
                // fails closed next time instead of silently falling back to CreateNew.
                val value = if (legacy.copyOfRange(0, minOf(legacy.size, MAGIC.size)).contentEquals(MAGIC)) decode(legacy) else legacy
                if (value.size > MAX_RECORD_BYTES) throw IOException("Legacy state too large")
                replace(record, envelope(value)); migratedLegacy = true
                return value
            }
            creating.add(name)
            return null
        }
        if (!read(marker, MARKER.size).contentEquals(MARKER)) throw IOException("Local creation marker invalid")
        if (!exists(record)) {
            if (name in creating) return null // same locked, not-yet-committed first transaction
            throw IOException("Previously committed state missing")
        }
        return decode(read(record, MAX_RECORD_BYTES + HEADER_BYTES))
    }
    @Synchronized
    fun save(key: String, value: ByteArray): Boolean {
        require(value.isNotEmpty() && value.size <= MAX_RECORD_BYTES) { "Invalid local record size" }
        return try {
            load(key) // Establish durable marker or verify existing state before replacement.
            val name = name(key)
            replace(AtomicFile(File(directory, name)), envelope(value))
            creating.remove(name); deletedTestRecords.remove(name)
            true
        } catch (_: Exception) { failed = true; false }
    }
    @Synchronized
    fun delete(key: String): Boolean {
        // Rust owns identity/security state; production callers cannot erase its first-use proof.
        if (!disposable) return false
        return try {
            checkOwner()
            val name = name(key)
            AtomicFile(File(directory, name)).delete()
            AtomicFile(File(markerDirectory, "$name.created")).delete()
            syncDirectory(directory)
            syncDirectory(markerDirectory)
            creating.remove(name); deletedTestRecords.add(name)
            !File(directory, name).exists() && !File(markerDirectory, "$name.created").exists()
        } catch (_: Exception) { false }
    }
    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        try { ownerLock.release() } finally {
            try { owner.close() } finally { synchronized(owners) { owners.remove(ownerPath) } }
        }
    }
    companion object {
        private const val MAX_RECORD_BYTES = 4 * 1024 * 1024
        private val owners = mutableSetOf<String>()
        private val MAGIC = "CBDS1\n".toByteArray(Charsets.US_ASCII)
        private val MARKER = "cyberbus-development-record-created-v1\n".toByteArray(Charsets.US_ASCII)
        private val HEADER_BYTES = MAGIC.size + 4 + 32
        private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun syncDirectory(directory: File) {
            val descriptor = Os.open(directory.path, OsConstants.O_RDONLY, 0)
            try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
        }
        /** Separate disposable namespace: tests never remove real SDK records or markers. */
        internal fun forTest(context: Context, scope: String): ProtectedStore {
            require(scope.matches(Regex("[a-zA-Z0-9-]{1,80}")))
            val parent = File(context.noBackupFilesDir, "cyberbus-development-store-tests")
            if (!parent.isDirectory && !parent.mkdir()) throw IOException("Test store unavailable")
            return ProtectedStore(File(parent, scope), File(parent, "$scope-markers"), true)
        }
    }
}
