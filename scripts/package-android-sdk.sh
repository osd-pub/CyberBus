#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$TASK_ROOT/target}"
export CYBERBUS_RUST_TOOLCHAIN="${CYBERBUS_RUST_TOOLCHAIN:-1.97.1}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"
export CYBERBUS_JNI_DIR="${CYBERBUS_JNI_DIR:-$CARGO_TARGET_DIR/packages-002/android-jni}"
export JAVA_HOME="${JAVA_HOME:-/opt/zerobrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home}"
GRADLE_COMMAND="${GRADLE_BIN:-}"
if [[ -z "$GRADLE_COMMAND" ]]; then
  for candidate in "$HOME"/.gradle/wrapper/dists/gradle-8.14.3-bin/*/gradle-8.14.3/bin/gradle; do
    if [[ -x "$candidate" ]]; then GRADLE_COMMAND="$candidate"; break; fi
  done
fi
[[ -x "$GRADLE_COMMAND" && -x "$JAVA_HOME/bin/java" ]] || { echo 'Gradle 8.14.3 and JDK17 required' >&2; exit 1; }
"$GRADLE_COMMAND" --version | rg -q 'Gradle 8.14.3'
PROFILE=release
OPTIONS=(--release --locked)
if [[ "${CYBERBUS_NATIVE_DEBUG:-0}" == 1 ]]; then PROFILE=debug; OPTIONS=(--locked); fi
if [[ "${CYBERBUS_REUSE_NATIVE:-0}" != 1 ]]; then
  "$TASK_ROOT/crates/cyberbus-ffi/scripts/build-android-native.sh" "${OPTIONS[@]}"
fi
NDK_HOST=darwin-x86_64
if [[ "$(uname -s)" != Darwin ]]; then NDK_HOST=linux-x86_64; fi
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/llvm-nm" -D --defined-only "$CYBERBUS_JNI_DIR/arm64-v8a/libcyberbus_ffi.so" > "$CARGO_TARGET_DIR/packages-002-jni-symbols.txt"
for method in Create Execute Poll OnResume Close; do
  rg -q "Java_io_cyberbus_sdk_NativeBridge_native$method$" "$CARGO_TARGET_DIR/packages-002-jni-symbols.txt"
done
GRADLE_OPTIONS=(-p "$TASK_ROOT/packaging/android-sdk" --console=plain "-PcyberbusJniDir=$CYBERBUS_JNI_DIR")
if [[ -n "${CYBERBUS_PROTOC:-}" ]]; then GRADLE_OPTIONS+=("-PcyberbusProtoc=$CYBERBUS_PROTOC"); fi
"$GRADLE_COMMAND" "${GRADLE_OPTIONS[@]}" :sdk:assembleRelease :sdk:publish "$@"
REPOSITORY="$TASK_ROOT/packaging/android-sdk/sdk/build/repository/io/cyberbus/cyberbus-sdk/0.1.0"
mkdir -p "$REPOSITORY/third-party"
# Keep exact runtime binary, upstream source and license in the standalone bundle.
python3 "$TASK_ROOT/packaging/maven-material.py" "$REPOSITORY/third-party"
PACKAGE_DIR="${CYBERBUS_PACKAGE_DIR:-$CARGO_TARGET_DIR/packages-002/android-arm64}"
python3 "$TASK_ROOT/packaging/package.py" android --target aarch64-linux-android --profile "$PROFILE" --native-dir "$REPOSITORY" --output "$PACKAGE_DIR"
# Publish directly included corresponding native sources alongside the Java
# sources classifier; Maven users can retrieve it without an upstream checkout.
cp "$PACKAGE_DIR/SOURCES.tar.gz" "$REPOSITORY/cyberbus-sdk-0.1.0-native-sources.tar.gz"
cp "$PACKAGE_DIR/SBOM.cdx.json" "$REPOSITORY/cyberbus-sdk-0.1.0-sbom.json"
echo "Maven repository: $TASK_ROOT/packaging/android-sdk/sdk/build/repository"
