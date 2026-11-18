#!/usr/bin/env python3
"""Select the pinned Cargo.lock vendored HOST protoc after cargo fetch."""
from pathlib import Path
import os
import platform
import subprocess
host = ('macos-aarch_64' if platform.machine() == 'arm64' else 'macos-x86_64') if platform.system() == 'Darwin' else ('win32' if os.name == 'nt' else 'linux-x86_64')
suffix = 'protoc.exe' if os.name == 'nt' else 'protoc'
path = next((Path.home() / '.cargo/registry/src').glob('*/protoc-bin-vendored-' + host + '-*/bin/' + suffix))
subprocess.run([str(path), '--version'], check=True)
with open(os.environ['GITHUB_ENV'], 'a') as f: f.write('PROTOC=' + str(path) + '\n')
