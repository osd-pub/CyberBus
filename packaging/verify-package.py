#!/usr/bin/env python3
"""Verify sealed package hashes and run the portable C consumer on its host."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
p = argparse.ArgumentParser(); p.add_argument('package', type=Path); p.add_argument('--config', type=Path); a = p.parse_args()
root = a.package.resolve(); manifest = json.loads((root / 'MANIFEST.json').read_text())
for name, expected in manifest['files'].items():
    path = root / name; h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): h.update(block)
    if h.hexdigest() != expected: raise RuntimeError('Hash mismatch: ' + name)
print('PASS manifest hashes:', len(manifest['files']), 'files')
if a.config:
    with tempfile.TemporaryDirectory(prefix='cyberbus-package-consumer-') as temp:
        directory = Path(temp); exe = directory / ('smoke.exe' if os.name == 'nt' else 'smoke')
        if os.name == 'nt':
            command = ['cl', '/nologo', '/W4', '/I' + str(root / 'include'), '/I' + str(root), str(root / 'sample.c'),
                       '/Fe:' + str(exe), '/Fo:' + str(directory / 'smoke.obj'), '/link', '/LIBPATH:' + str(root), 'cyberbus_ffi.dll.lib']
        else:
            command = ['cc', '-Wall', '-Wextra', '-Werror', '-I' + str(root / 'include'), str(root / 'sample.c'), str(root / 'libcyberbus_ffi.a')]
            if 'apple' in manifest['target']:
                command += ['-framework','Security','-framework','CoreFoundation','-framework','SystemConfiguration','-liconv','-lresolv']
            else: command += ['-lpthread','-ldl','-lm']
            command += ['-o',str(exe)]
        subprocess.run(command, check=True, cwd=directory)
        env = os.environ.copy(); env['PATH'] = str(root) + os.pathsep + env.get('PATH', '')
        subprocess.run([str(exe), str(a.config.resolve()), str(directory / 'state')], env=env, check=True)
