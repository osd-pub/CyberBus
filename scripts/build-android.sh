#!/usr/bin/env bash
set -euo pipefail

# Default: build the actual Rust JNI SDK, then package the Android sample.
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$TASK_ROOT/examples/android-demo"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"
if [[ -z "${JAVA_HOME:-}" ]]; then
  for candidate in /opt/zerobrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home; do
    if [[ -x "$candidate/bin/java" ]]; then export JAVA_HOME="$candidate"; break; fi
  done
fi
if [[ -z "${JAVA_HOME:-}" ]] && command -v /usr/libexec/java_home >/dev/null; then
  export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
fi
[[ -x "${JAVA_HOME:-}/bin/java" ]] || { echo 'JDK 17 required: set JAVA_HOME' >&2; exit 1; }
[[ -d "$ANDROID_HOME/platforms/android-35" ]] || { echo 'Android SDK 35 required: set ANDROID_HOME' >&2; exit 1; }

GRADLE_COMMAND="${GRADLE_BIN:-}"
if [[ -z "$GRADLE_COMMAND" ]]; then
  for candidate in "$HOME"/.gradle/wrapper/dists/gradle-8.14.3-bin/*/gradle-8.14.3/bin/gradle "$HOME"/.gradle/wrapper/dists/gradle-8.14.2-bin/*/gradle-8.14.2/bin/gradle; do
    if [[ -x "$candidate" ]]; then GRADLE_COMMAND="$candidate"; break; fi
  done
fi
if [[ -z "$GRADLE_COMMAND" ]]; then GRADLE_COMMAND="$(command -v gradle || true)"; fi
[[ -n "$GRADLE_COMMAND" ]] || { echo 'Gradle 8.14.x required: set GRADLE_BIN' >&2; exit 1; }

PROTO_DIR="${CYBERBUS_PROTO_DIR:-$TASK_ROOT/proto}"
[[ -f "$PROTO_DIR/cyberbus/easytier/v1/sdk.proto" ]] || { echo 'Schema required: set CYBERBUS_PROTO_DIR' >&2; exit 1; }

CONFIG_FILE="${CYBERBUS_CONFIG:-$TASK_ROOT/deploy/test-client.json}"
JNI_DIR="${CYBERBUS_JNI_DIR:-$TASK_ROOT/target/android-jni}"
OPTIONS=(-p "$DEMO_DIR" --console=plain "-PcyberbusProtoDir=$PROTO_DIR" "-PcyberbusConfig=$CONFIG_FILE" "-PcyberbusJniDir=$JNI_DIR")
if [[ -n "${CYBERBUS_PROTOC:-}" ]]; then OPTIONS+=("-PcyberbusProtoc=$CYBERBUS_PROTOC"); fi
if [[ "${CYBERBUS_SHELL_ONLY:-0}" != 1 ]]; then
  [[ -f "$CONFIG_FILE" ]] || { echo 'Public deployment config required: set CYBERBUS_CONFIG' >&2; exit 1; }
  if [[ "${CYBERBUS_SKIP_NATIVE_BUILD:-0}" != 1 ]]; then
    NATIVE_SCRIPT="$TASK_ROOT/crates/cyberbus-ffi/scripts/build-android-native.sh"
    [[ -x "$NATIVE_SCRIPT" ]] || { echo 'Actual FFI build script required; merge the native SDK implementation first' >&2; exit 1; }
    NATIVE_OPTIONS=()
    if [[ "${CYBERBUS_NATIVE_RELEASE:-0}" == 1 ]]; then NATIVE_OPTIONS+=(--release); fi
    for option in "$@"; do if [[ "$option" == --offline ]]; then NATIVE_OPTIONS+=(--offline); fi; done
    CYBERBUS_JNI_DIR="$JNI_DIR" "$NATIVE_SCRIPT" "${NATIVE_OPTIONS[@]}"
  fi
  [[ -f "$JNI_DIR/arm64-v8a/libcyberbus_ffi.so" ]] || { echo 'Actual Android JNI library required; native build did not produce it' >&2; exit 1; }
  OPTIONS+=(-PrequireNative=true)
else
  echo 'EXPLICIT SHELL-ONLY BUILD: native SDK/config may be absent; this is not an integrated SDK APK.' >&2
fi
if [[ ! -f "$CONFIG_FILE" ]]; then echo 'Public config absent: APK will display CONFIGURATION_ERROR.' >&2; fi
if [[ ! -f "$JNI_DIR/arm64-v8a/libcyberbus_ffi.so" ]]; then echo 'Native library absent: APK will display UNAVAILABLE.' >&2; fi
"$GRADLE_COMMAND" "${OPTIONS[@]}" :app:assembleDebug "$@"
APK="$DEMO_DIR/app/build/outputs/apk/debug/app-debug.apk"
echo "APK: $APK"
if [[ "${CYBERBUS_INSTALL:-0}" == 1 ]]; then
  ADB_ARGS=()
  if [[ -n "${ANDROID_SERIAL:-}" ]]; then ADB_ARGS=(-s "$ANDROID_SERIAL"); fi
  "$ANDROID_HOME/platform-tools/adb" "${ADB_ARGS[@]}" install -r "$APK"
  "$ANDROID_HOME/platform-tools/adb" "${ADB_ARGS[@]}" shell am start -n io.cyberbus.demo/.MainActivity
fi
