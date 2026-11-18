#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
if ! command -v protoc >/dev/null 2>&1 && [[ -z "${PROTOC:-}" ]]; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform=macos-aarch_64 ;;
    Darwin-x86_64) platform=macos-x86_64 ;;
    Linux-x86_64) platform=linux-x86_64 ;;
    Linux-aarch64) platform=linux-aarch_64 ;;
    *) platform=unknown ;;
  esac
  for candidate in "$HOME"/.cargo/registry/src/*/protoc-bin-vendored-"$platform"-*/bin/protoc; do
    if [[ -x "$candidate" ]]; then export PROTOC="$candidate"; break; fi
  done
fi
cargo +stable build --locked -p cyberbus-test-client
exec python3 tests/multiclient/runner.py --binary "$CARGO_TARGET_DIR/debug/cyberbus-test-client" "$@"
