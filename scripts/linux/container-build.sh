#!/usr/bin/env bash
set -euo pipefail
umask 077
rustc --version
cargo --version
cc --version | head -1
pkg-config --modversion openssl
cargo fetch --locked
if ! command -v protoc >/dev/null 2>&1; then
  for candidate in /cargo/registry/src/*/protoc-bin-vendored-linux-x86_64-*/bin/protoc; do
    if [[ -x "$candidate" ]]; then export PROTOC="$candidate"; break; fi
  done
fi
"${PROTOC:-protoc}" --version
# Optional package names enable the independently owned JSONL client without root edits.
exec nice -n 19 cargo build --locked -j 1 -p cyberbus -p cyberbus-ffi -p cyberbus-cli "$@"
