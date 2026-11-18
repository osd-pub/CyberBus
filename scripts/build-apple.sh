#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FFI_DIR="$TASK_ROOT/crates/cyberbus-ffi"
TARGET_TRIPLE="${CYBERBUS_APPLE_TARGET:-aarch64-apple-darwin}"
TOOLCHAIN="${CYBERBUS_RUST_TOOLCHAIN:-1.97.1}"
MANIFEST="${CYBERBUS_FFI_MANIFEST:-$FFI_DIR/Cargo.toml}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$TASK_ROOT/target}"
case "$TARGET_TRIPLE" in
  aarch64-apple-darwin|x86_64-apple-darwin) export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}" ;;
  aarch64-apple-ios|aarch64-apple-ios-sim|x86_64-apple-ios) export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}" ;;
  *) echo 'Unsupported Apple target triple' >&2; exit 1 ;;
esac
if [[ -z "${PROTOC:-}" ]] && ! command -v protoc >/dev/null; then
  for candidate in "$HOME"/.cargo/registry/src/*/protoc-bin-vendored-macos-aarch_64-*/bin/protoc; do
    if [[ -x "$candidate" ]]; then export PROTOC="$candidate"; break; fi
  done
fi
cargo "+$TOOLCHAIN" build --locked --manifest-path "$MANIFEST" --target "$TARGET_TRIPLE" -j "${CYBERBUS_BUILD_JOBS:-4}" "$@"
PROFILE_DIR=debug
for option in "$@"; do if [[ "$option" == --release ]]; then PROFILE_DIR=release; fi; done
OUTPUT_DIR="${CYBERBUS_PACKAGE_DIR:-$CARGO_TARGET_DIR/packages-002/apple-$TARGET_TRIPLE}"
python3 "$TASK_ROOT/packaging/package.py" apple --target "$TARGET_TRIPLE" --profile "$PROFILE_DIR" \
  --native-dir "$CARGO_TARGET_DIR/$TARGET_TRIPLE/$PROFILE_DIR" --output "$OUTPUT_DIR"
echo "Apple Swift package/XCFramework: $OUTPUT_DIR"
