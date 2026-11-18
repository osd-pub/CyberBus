#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# EasyTier's build needs protoc too; reuse the protocol crate's downloaded compiler when the
# host has no system protoc. No Rust dependency or application configuration is changed.
if [[ -z "${PROTOC:-}" ]] && ! command -v protoc >/dev/null 2>&1; then
  cargo +stable fetch --locked --manifest-path "$ROOT/Cargo.toml" >/dev/null
  for candidate in "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/protoc-bin-vendored-*/bin/protoc; do
    if [[ -x "$candidate" ]] && "$candidate" --version >/dev/null 2>&1; then
      export PROTOC="$candidate"
      break
    fi
  done
fi
exec cargo +stable run --locked --manifest-path "$ROOT/Cargo.toml" -p cyberbus-cli -- "$@"
