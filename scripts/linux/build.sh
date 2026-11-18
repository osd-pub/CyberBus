#!/usr/bin/env bash
# Run on a Linux host in an isolated source checkout. Does not manage service containers.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${CYBERBUS_LINUX_WORK:-$(dirname "$ROOT")/build}"
IMAGE="${CYBERBUS_LINUX_IMAGE:-rust:1.97.1-bookworm}"
[[ "$(uname -s)" == Linux ]] || { echo 'Linux host required' >&2; exit 2; }
mkdir -p "$WORK" "$WORK/cargo" "$WORK/target" "$WORK/reports"
python3 "$ROOT/scripts/linux/preflight.py" > "$WORK/reports/preflight.json"
available="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["memory"]["MemAvailable_KiB"])' "$WORK/reports/preflight.json")"
(( available >= 700000 )) || { echo 'Less than 700 MB available; retry when idle' >&2; exit 3; }
# Defaults: one Cargo job, 0.75 CPU, 900 MiB RAM + up to 600 MiB swap.
# Docker is invoked through sudo only at the CLI; compilation runs as the caller without capabilities.
sudo -n docker image inspect "$IMAGE" > "$WORK/reports/image-private.json"
sudo -n docker run --rm --name "cyberbus-linux-build-$(id -u)" \
  --cpus="${CYBERBUS_BUILD_CPUS:-0.75}" --memory="${CYBERBUS_BUILD_MEMORY:-900m}" \
  --memory-swap="${CYBERBUS_BUILD_MEMORY_SWAP:-1500m}" --pids-limit=256 \
  --cap-drop=ALL --security-opt=no-new-privileges --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
  -e RUSTUP_TOOLCHAIN="${CYBERBUS_RUST_TOOLCHAIN:-1.97.1}" \
  -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 \
  -v "$ROOT:/src:ro" -v "$WORK/cargo:/cargo" -v "$WORK/target:/target" \
  -w /src "$IMAGE" bash /src/scripts/linux/container-build.sh "$@" \
  > "$WORK/reports/build-private.log" 2>&1 || {
    echo "Build failed; inspect $WORK/reports/build-private.log privately" >&2; exit 1;
  }
python3 - "$WORK" "$ROOT" "$IMAGE" <<'PY'
import hashlib, json, os, pathlib, sys
work = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
artifacts = []
for name in ('cyberbus-cli', 'libcyberbus.rlib', 'libcyberbus_ffi.so',
             'libcyberbus_ffi.a', 'libcyberbus_ffi.rlib', 'cyberbus-test-client'):
    path = work / 'target/debug' / name
    if path.is_file():
        digest = hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
        artifacts.append({'name': name, 'bytes': path.stat().st_size, 'sha256': digest})
report = {'schema': 1, 'artifacts': artifacts, 'image': sys.argv[3],
          'rust_toolchain': os.environ.get('CYBERBUS_RUST_TOOLCHAIN', '1.97.1'),
          'source_revision': os.environ.get('CYBERBUS_SOURCE_REVISION',
              (root / 'source-revision.txt').read_text().strip()
              if (root / 'source-revision.txt').is_file() else 'unrecorded'),
          'scripts_revision': (root / 'scripts-revision.txt').read_text().strip()
              if (root / 'scripts-revision.txt').is_file() else 'unrecorded',
          'cargo_lock_sha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()}
(work / 'reports/artifacts.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
PY
