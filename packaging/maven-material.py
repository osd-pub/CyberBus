#!/usr/bin/env python3
"""Preserve protobuf runtime/source/POM (which includes its BSD notice)."""
import hashlib
from pathlib import Path
import shutil
import sys
import urllib.request
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
cache = Path.home() / '.gradle/caches/modules-2/files-2.1/com.google.protobuf/protobuf-javalite/4.26.1'
for suffix in ['.jar', '-sources.jar', '.pom']:
    name = 'protobuf-javalite-4.26.1' + suffix
    cached = list(cache.glob('*/' + name))
    dest = out / name
    if cached: shutil.copy2(cached[0], dest)
    elif not dest.exists():
        urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/com/google/protobuf/protobuf-javalite/4.26.1/' + name, dest)
    if dest.stat().st_size == 0: raise RuntimeError('Empty protobuf material')
# License is included in the runtime jar and sources; retain a standalone copy.
import zipfile
with zipfile.ZipFile(out / 'protobuf-javalite-4.26.1.jar') as jar:
    candidates = [n for n in jar.namelist() if 'LICENSE' in n.upper() and not n.endswith('/')]
    if candidates:
        (out / 'protobuf-LICENSE.txt').write_bytes(jar.read(candidates[0]))
    else:
        urllib.request.urlretrieve('https://raw.githubusercontent.com/protocolbuffers/protobuf/v26.1/LICENSE', out / 'protobuf-LICENSE.txt')
(out / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in sorted(out.iterdir()) if p.name != 'SHA256SUMS'))
