package io.cyberbus.demo

/** JNI is the only owner of auth, transport, identity, and secure storage. */
object NativeBridge {
    // No static initializer: an APK without core can still explain the missing dependency.
    fun load() = System.loadLibrary("cyberbus_ffi")

    @JvmStatic external fun nativeCreate(configJson: String, store: ProtectedStore): Long
    @JvmStatic external fun nativeExecute(handle: Long, command: ByteArray): ByteArray
    @JvmStatic external fun nativePoll(handle: Long, timeoutMs: Int): ByteArray?
    /** true only after Client::on_resume() succeeds; false leaves the UI gate closed. */
    @JvmStatic external fun nativeOnResume(handle: Long): Boolean
    @JvmStatic external fun nativeClose(handle: Long)
}
