#!/usr/bin/env bash
set -euo pipefail
FFI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_ROOT="$(cd "$FFI_DIR/../.." && pwd)"
SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK_DIR="${ANDROID_NDK_HOME:-$SDK_DIR/ndk/27.2.12479018}"
TOOLCHAIN_DIR="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/bin"
if [[ "$(uname -s)" != Darwin ]]; then TOOLCHAIN_DIR="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin"; fi
[[ -x "$TOOLCHAIN_DIR/aarch64-linux-android26-clang" ]] || { echo 'NDK 27.2 with API 26 clang required' >&2; exit 1; }
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN_DIR/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
export AR_aarch64_linux_android="$TOOLCHAIN_DIR/llvm-ar"
export CXX_aarch64_linux_android="$TOOLCHAIN_DIR/aarch64-linux-android26-clang++"
export CFLAGS_aarch64_linux_android="${CFLAGS_aarch64_linux_android:-} -D__ANDROID_API__=26"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$FFI_DIR/target}"
MANIFEST="${CYBERBUS_FFI_MANIFEST:-$FFI_DIR/Cargo.toml}"
TOOLCHAIN="${CYBERBUS_RUST_TOOLCHAIN:-stable}"
# EasyTier's code generator needs a HOST protoc even while cross compiling.
if [[ -z "${PROTOC:-}" ]] && ! command -v protoc >/dev/null; then
  for candidate in "$HOME"/.cargo/registry/src/*/protoc-bin-vendored-macos-aarch_64-*/bin/protoc; do
    if [[ -x "$candidate" ]]; then export PROTOC="$candidate"; break; fi
  done
fi
cargo "+$TOOLCHAIN" build --manifest-path "$MANIFEST" --target aarch64-linux-android -j "${CYBERBUS_BUILD_JOBS:-4}" "$@"
PROFILE_DIR=debug
for option in "$@"; do if [[ "$option" == --release ]]; then PROFILE_DIR=release; fi; done
OUTPUT_DIR="${CYBERBUS_JNI_DIR:-$FFI_DIR/target/android-jni}/arm64-v8a"
mkdir -p "$OUTPUT_DIR"
cp "$CARGO_TARGET_DIR/aarch64-linux-android/$PROFILE_DIR/libcyberbus_ffi.so" "$OUTPUT_DIR/"
"$TOOLCHAIN_DIR/llvm-readelf" -h "$OUTPUT_DIR/libcyberbus_ffi.so" | head -18
"$TOOLCHAIN_DIR/llvm-readelf" -d "$OUTPUT_DIR/libcyberbus_ffi.so" | rg NEEDED || true
echo "JNI directory: $(dirname "$OUTPUT_DIR")"
echo "Package with CYBERBUS_JNI_DIR=$(dirname "$OUTPUT_DIR") scripts/build-android.sh"
