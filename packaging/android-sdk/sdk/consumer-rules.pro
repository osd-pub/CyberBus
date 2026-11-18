# JNI looks up opaque store callbacks by name, including consumer implementations.
-keep class io.cyberbus.sdk.NativeBridge { *; }
-keep class * implements io.cyberbus.sdk.SecureStore { public *; }
-keep interface io.cyberbus.sdk.SecureStore { *; }
