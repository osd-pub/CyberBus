The SDK static archives are ordinary ar archives containing native object
members (not just Rust rlibs). SOURCES.tar.gz contains the exact working source
snapshot, Cargo.lock and resolved registry dependency sources. MANIFEST.json
identifies the base revision, source hashes, target, profile and tools. Extract
the source archive, enter source/, and set CARGO_HOME to an isolated directory.

    mkdir -p .cargo
    cp ../registry-config.toml .cargo/config.toml
    cargo build --locked --offline -p cyberbus-ffi --target <manifest target>

Use the original Rust version, the target standard library and platform SDK
recorded in MANIFEST.json (those compilers/OS SDKs are not included). EasyTier's
build needs host protoc: use the target archive's vendored host protoc binary
under registry/ or install the recorded protoc version, and export PROTOC.
For Android, use NDK 27.2/API26 and scripts/package-android-sdk.sh; for Apple,
scripts/build-apple.sh; for desktop, scripts/package-desktop-sdk.py. Cross-built
Linux requires the recorded zig version and cargo-zigbuild. This source archive
contains dependencies for its recorded target, not every Rust target.

Modify vendor/easytier/ or crates/cyberbus-transport/, rebuild the static archive,
then link the supplied C sample source against your replacement archive. On
macOS, add -framework Security -framework SystemConfiguration -framework
CoreFoundation -lresolv -liconv; on Linux use -lpthread -ldl -lm; on Windows use
MSVC and the native libraries reported by cargo rustc -- --print=native-static-libs.
The SDK includes the C sample's source so it can be rebuilt/relinked. For a
downstream closed-source application, preserve and supply its .o/.obj files
(before final LTO), link scripts and required resources to let users relink
against a modified SDK. Alternatively provide its corresponding source.

Swift: replace the .a in the matching XCFramework slice and rebuild the Swift
package/application. Android: replace jni/<ABI>/libcyberbus_ffi.so in the AAR,
keep the public JNI symbols, rebuild the APK and sign with a user-controlled
key. Supply product-specific installation instructions when necessary. The
SDK does not contain private signing keys and does not implement Keystore.

Development-file store mode is explicitly plaintext; it is not a platform
protected store. Store errors, corrupt records and missing installed records
must fail closed. Custom stores implement the exact cyberbus.h/SecureStore
callback ownership contract. OAuth grants are not persisted.
