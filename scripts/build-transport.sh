#!/usr/bin/env bash
# Build independently of the root workspace; restore the manifest on exit.
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
crate_dir="$repo_dir/crates/cyberbus-transport"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_dir/target}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
mode="${1:-test}"
if [[ $# -gt 0 ]]; then shift; fi
if ! command -v protoc >/dev/null && [[ -z "${PROTOC:-}" ]]; then
  for p in "$HOME"/.cargo/registry/src/*/protoc-bin-vendored-macos-aarch_64-*/bin/protoc; do
    if [[ -x "$p" ]]; then export PROTOC="$p"; break; fi
  done
fi
if [[ -z "${PROTOC:-}" ]] && ! command -v protoc >/dev/null; then
  echo 'Set PROTOC to a host protoc executable (Protobuf >= 3.15).' >&2; exit 1
fi
# Root workspace may be under construction by another agent. Only this owned manifest is touched.
lock_dir="$crate_dir/.build-transport.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
  echo "Another standalone transport build owns $lock_dir; wait for it to finish (remove only if its owner exited)." >&2
  exit 1
fi
manifest_backup="$(mktemp)"
cp "$crate_dir/Cargo.toml" "$manifest_backup"
trap 'cp "$manifest_backup" "$crate_dir/Cargo.toml"; rm -f "$manifest_backup"; rmdir "$lock_dir"' EXIT
if ! grep -q '^\[workspace\]' "$crate_dir/Cargo.toml"; then
  printf '\n[workspace]\n' >> "$crate_dir/Cargo.toml"
fi
case "$mode" in
  test) cargo test --locked --manifest-path "$crate_dir/Cargo.toml" "$@" ;;
  check) cargo check --locked --manifest-path "$crate_dir/Cargo.toml" "$@" ;;
  build) cargo build --locked --manifest-path "$crate_dir/Cargo.toml" "$@" ;;
  android)
    ndk_dir="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-$HOME/Library/Android/sdk/ndk/27.2.12479018}}"
    ndk_host="${NDK_HOST_TAG:-darwin-x86_64}"
    ndk_bin="$ndk_dir/toolchains/llvm/prebuilt/$ndk_host/bin"
    export CC_aarch64_linux_android="$ndk_bin/aarch64-linux-android28-clang"
    export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
    [[ -x "$CC_aarch64_linux_android" ]] || { echo "NDK compiler missing: $CC_aarch64_linux_android" >&2; exit 1; }
    cargo build --locked --manifest-path "$crate_dir/Cargo.toml" --target aarch64-linux-android "$@" ;;
  *) echo 'Usage: build-transport.sh {test|check|build|android} [cargo options]' >&2; exit 2 ;;
esac
