# CyberBus native bindings

Thin C and Android JNI adapters for the committed Rust `cyberbus::Client`.
The adapter owns handles, a shared Tokio runtime, binary copies and storage
callbacks. Authentication, leases, discovery, block policy, transport and ACKs
remain in the shared Client. No fallback identity, grant, network or success
implementation exists here.

## Android build

From the repository root, with JDK 17, SDK 35, NDK 27.2.12479018, Rust stable and
its `aarch64-linux-android` target installed:

```sh
./scripts/build-android.sh
CYBERBUS_INSTALL=1 ./scripts/build-android.sh --offline
```

The default command builds the actual JNI SDK, requires public deployment
configuration, and packages the library in the APK. `CYBERBUS_SHELL_ONLY=1` is
an explicitly labeled UI development exception. To build only native output:

```sh
crates/cyberbus-ffi/scripts/build-android-native.sh --offline
```

Native output defaults to this crate's ignored `target/android-jni/`; the root
sample build selects root `target/android-jni/`. Override `CARGO_TARGET_DIR` for
a shared compilation cache and `CYBERBUS_JNI_DIR` for packaging output. Host
`PROTOC` is needed by EasyTier code generation; scripts discover locally cached
vendored macOS ARM protoc when no compiler is on PATH. Java lite generation is
separate and uses protoc 4.26.1 (`CYBERBUS_PROTOC` can select a cached binary).

## JNI

Library: `cyberbus_ffi`; class: `io.cyberbus.demo.NativeBridge` (`@JvmStatic`).

```kotlin
nativeCreate(configJson: String, store: ProtectedStore): Long
nativeExecute(handle: Long, command: ByteArray): ByteArray
nativePoll(handle: Long, timeoutMs: Int): ByteArray?
nativeOnResume(handle: Long): Boolean
nativeClose(handle: Long)
```

Create retains the store GlobalRef. It synchronously calls `load(String):ByteArray?`
and `save(String,ByteArray):Boolean` using the fixed whole-record key
`cyberbus-v1`. Native callback threads attach to the JVM. Temporary Java
record arrays are cleared after copying/saving; the Activity never receives
record contents. This ABI name `ProtectedStore` denotes the user-authorized
**development plaintext app-private atomic-file store**, not Keystore protection.
OAuth grants remain memory-only. No MemoryStore fallback is supplied.

Execute and Poll use unframed binary `SdkCommand`, `SdkResult`, `SdkEvent`.
Arrays are copied, and returned arrays belong to Java. Poll null means timeout;
EOF/errors throw sanitized exceptions. Resume calls actual `Client::on_resume`
and returns false on failure, keeping the sample's business gate closed. Calls
are blocking and belong on a worker; never run network calls on the UI thread.

## C ownership and lifecycle

The stable v1 interface is `include/cyberbus.h`. `CyberbusResponse.status`
distinguishes native failure, timeout and EOF. On native errors its owned buffer
contains a sanitized `ProtocolError`; successful Execute returns `SdkResult`,
which can itself contain a typed SDK rejection. Always inspect both layers.
Create returns a nonzero handle. Input spans are borrowed only for the call.
Every nonempty returned buffer must be freed exactly once with
`cyberbus_buffer_free`; never use the host allocator or mutate its pointer/length.
Unknown pointers and immediate double frees are rejected. Using a freed buffer
is invalid even if a later allocation reuses that address.

`cyberbus_create` requires synchronous whole-blob callbacks. A valid callback
store transfers ownership even on creation failure; `destroy` runs when released.
Callbacks may run on different threads, are serialized by their native store
owner, and must not unwind or reenter the same Client. `load` returns 0/present,
1/absent, or an error. Rust copies present bytes before `release`. `replace`
returns 0 only after a durable atomic replacement. The SDK owns the blob format.
`cyberbus_create_development` explicitly selects the auth crate's private
plaintext file store instead and opens an already installed record only. Its C
signature is unchanged. Trusted first installation uses the additive
`cyberbus_create_development_new` with the same arguments; trusted legacy upgrade
uses `cyberbus_create_development_migrate`. The latter requires a valid complete
vault with no marker and preserves its identity. Missing vault/marker, corruption,
read errors and failed replacements fail closed; never fall back from open to new
or authorize migration merely because a marker is missing. Both the vault and its
`.auth-install` marker must survive restart. Public config is validated before
provisioning. ABI version remains 1; callback-store behavior is unchanged.
Development mode does not provide production installation-loss recovery.

One event consumer is allowed per handle; overlapping Poll returns conflict.
Start consuming events before subscriptions/commands. Poll is bounded to 30s;
0 performs an immediate read. Execute `SdkClose` first to observe typed cleanup,
then drain terminal events through Poll until EOF, then call native Close.
Explicit SDK close keeps the handle alive for that drain. Native Close removes
it, performs actual SDK cleanup if needed, and releases owned state after
in-flight calls complete. Stale handles return an error. Close is not cloud
logout; request `AuthLogout` explicitly when needed. C/JNI panics are isolated
at entry points, and diagnostic strings do not expose callbacks, grants or blobs.

## Apple and verification

```sh
./scripts/build-apple.sh
CYBERBUS_APPLE_TARGET=aarch64-apple-ios ./scripts/build-apple.sh --release
cargo +stable test -p cyberbus-ffi --test abi -- --test-threads=1
crates/cyberbus-ffi/scripts/c-smoke.sh deploy/test-client.json
```

Apple output includes the static library/header and the dylib where available.
iOS requires the matching Rust target and Xcode SDK; an XCFramework/Swift sample
is not generated. See `VERIFICATION.md` for observed builds, device evidence and
remaining end-to-end acceptance.
