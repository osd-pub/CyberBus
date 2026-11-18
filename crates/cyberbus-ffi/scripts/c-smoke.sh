#!/usr/bin/env bash
set -euo pipefail
FFI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_ROOT="$(cd "$FFI_DIR/../.." && pwd)"
CONFIG_FILE="${1:?Usage: c-smoke.sh /path/to/public/test-client.json}"
MANIFEST="${CYBERBUS_FFI_MANIFEST:-$FFI_DIR/Cargo.toml}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$FFI_DIR/target}"
if [[ -z "${PROTOC:-}" ]] && ! command -v protoc >/dev/null; then
  for candidate in "$HOME"/.cargo/registry/src/*/protoc-bin-vendored-macos-aarch_64-*/bin/protoc; do
    if [[ -x "$candidate" ]]; then export PROTOC="$candidate"; break; fi
  done
fi
cargo "+${CYBERBUS_RUST_TOOLCHAIN:-stable}" build --manifest-path "$MANIFEST" -j "${CYBERBUS_BUILD_JOBS:-4}"
mkdir -p "$FFI_DIR/target/smoke"
cc -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -I "$TASK_ROOT/include" \
  "$FFI_DIR/tests/c_smoke.c" -L "$CARGO_TARGET_DIR/debug" -lcyberbus_ffi \
  -Wl,-rpath,"$CARGO_TARGET_DIR/debug" -o "$FFI_DIR/target/smoke/c-smoke"
"$FFI_DIR/target/smoke/c-smoke" "$CONFIG_FILE"
