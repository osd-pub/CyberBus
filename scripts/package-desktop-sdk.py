#!/usr/bin/env python3
"""Build and package a native Windows/Linux/macOS SDK. Missing tools fail hard."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--target', required=True)
p.add_argument('--debug', action='store_true')
p.add_argument('--zig', action='store_true', help='Use installed cargo-zigbuild for a Linux cross build')
a = p.parse_args()
env = os.environ.copy()
env.setdefault('RUSTUP_TOOLCHAIN', env.get('CYBERBUS_RUST_TOOLCHAIN', '1.97.1'))
if a.zig: env['CYBERBUS_PACKAGE_CC'] = 'zig cc (cargo-zigbuild)'
env.setdefault('CARGO_TARGET_DIR', str(ROOT / 'target'))
if not env.get('PROTOC'):
    candidates = list((Path.home() / '.cargo/registry/src').glob('*/protoc-bin-vendored-*/bin/protoc'))
    # Select a HOST binary, never a target executable.
    import platform
    host = ('macos-aarch_64' if platform.machine() == 'arm64' else 'macos-x86_64') if sys.platform == 'darwin' else ('win32' if sys.platform == 'win32' else 'linux-x86_64')
    for candidate in candidates:
        if host in candidate.as_posix(): env['PROTOC'] = str(candidate); break
profile = 'debug' if a.debug else 'release'
cmd = ['cargo', 'zigbuild' if a.zig else 'build', '--locked', '--target', a.target, '-p', 'cyberbus-ffi', '-p', 'cyberbus-cli', '-j', env.get('CYBERBUS_BUILD_JOBS','2')]
if not a.debug: cmd.append('--release')
subprocess.run(cmd, cwd=ROOT, env=env, check=True)
out = Path(env.get('CYBERBUS_PACKAGE_DIR', str(Path(env['CARGO_TARGET_DIR']) / 'packages-002' / a.target)))
subprocess.run([sys.executable, str(ROOT / 'packaging/package.py'), 'desktop', '--target', a.target, '--profile', profile,
    '--native-dir', str(Path(env['CARGO_TARGET_DIR']) / a.target / profile), '--output', str(out)], cwd=ROOT, env=env, check=True)
