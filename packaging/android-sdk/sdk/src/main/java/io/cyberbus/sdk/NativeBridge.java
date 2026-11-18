package io.cyberbus.sdk;

/** Stable public JNI namespace. All business logic lives in the Rust SDK. */
public final class NativeBridge {
    private NativeBridge() {}
    public static void load() { System.loadLibrary("cyberbus_ffi"); }
    public static native long nativeCreate(String configJson, SecureStore store);
    public static native byte[] nativeExecute(long handle, byte[] command);
    /** null is timeout; terminal EOF and invalid handles throw IllegalStateException. */
    public static native byte[] nativePoll(long handle, int timeoutMs);
    public static native boolean nativeOnResume(long handle);
    public static native void nativeClose(long handle);
}
