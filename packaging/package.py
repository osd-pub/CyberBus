#!/usr/bin/env python3
"""Assemble real native outputs with exact sources, license notices and hashes."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = os.environ.get('CYBERBUS_VERSION', '0.1.0')
if VERSION.startswith('v'):
    VERSION = VERSION[1:]

def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, cwd=ROOT, **kwargs)

def text(args):
    return run(args, stdout=subprocess.PIPE).stdout.decode().strip()

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()

def add_bytes(tar, name, data):
    info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))

def sources(output, target, include_cli=False):
    """Include all resolved registry source (incl build deps), not just notices."""
    output.mkdir(parents=True, exist_ok=True)
    metadata = json.loads(text(['cargo', 'metadata', '--locked', '--offline', '--format-version=1', '--filter-platform', target]))
    graph = {n['id']: n for n in metadata['resolve']['nodes']}
    # filter-platform removes edges, not necessarily orphan package nodes.
    # Walk only the shipped FFI/desktop CLI normal+build dependency closure.
    nodes = set()
    shipped = ['cyberbus-ffi', 'cyberbus-cli'] if include_cli else ['cyberbus-ffi']
    pending = [p['id'] for p in metadata['packages'] if p['name'] in shipped and p['source'] is None]
    while pending:
        node = pending.pop()
        if node in nodes: continue
        nodes.add(node)
        pending.extend(d['pkg'] for d in graph[node]['deps'] if any(k['kind'] != 'dev' for k in d['dep_kinds']))
    packages = [p for p in metadata['packages'] if p['id'] in nodes]
    checksums = {}
    for block in (ROOT / 'Cargo.lock').read_text().split('[[package]]')[1:]:
        values = dict(re.findall(r'^(name|version|checksum) = "([^"]+)"', block, re.M))
        if 'checksum' in values: checksums[(values['name'], values['version'])] = values['checksum']
    cache = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')) / 'packages-002'
    cache.mkdir(parents=True, exist_ok=True)
    vendor = cache / 'cargo-vendor'
    vendor_config = cache / 'vendor-config.toml'
    stamp = cache / 'vendor-lock.sha256'
    lock_hash = digest(ROOT / 'Cargo.lock')
    if not stamp.exists() or stamp.read_text().strip() != lock_hash or not vendor_config.exists():
        # Cargo normalizes Git path dependencies and emits the authoritative
        # replacement configuration. Include optional and other-target sources
        # because offline resolution needs their metadata too.
        config = text(['cargo', 'vendor', '--locked', '--versioned-dirs', '--respect-source-config', vendor])
        vendor_config.write_text(config + '\n')
        stamp.write_text(lock_hash + '\n')
    notices = output / 'LICENSES'
    if notices.exists(): shutil.rmtree(notices)
    notices.mkdir()
    shutil.copytree(ROOT / 'packaging/licenses', notices, dirs_exist_ok=True)
    entries = []
    for package in sorted(packages, key=lambda p: (p['name'], p['version'])):
        entry = {k: package.get(k) for k in ['name', 'version', 'source', 'license', 'repository']}
        entry['checksum'] = checksums.get((package['name'], package['version']))
        if package.get('license_file'):
            path = Path(package['license_file'])
            if not path.is_absolute(): path = Path(package['manifest_path']).parent / path
            dest = notices / (package['name'] + '-' + package['version']) / 'SOURCE-LICENSE'
            dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, dest)
            entry['license_file'] = dest.relative_to(output).as_posix()
            entry['license_file_sha256'] = digest(dest)
        if package['source']:
            source = vendor / (package['name'] + '-' + package['version'])
            if not source.is_dir(): raise RuntimeError('Missing vendored dependency: ' + str(source))
            for path in source.rglob('*'):
                if path.is_file() and re.search(r'(?i)(licen[cs]e|copying|copyright|notice)', path.name):
                    dest = notices / source.name / path.relative_to(source)
                    dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, dest)
        entries.append(entry)
    with tarfile.open(output / 'SOURCES.tar.gz', 'w:gz', compresslevel=3) as tar:
        files = run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], stdout=subprocess.PIPE).stdout.split(b'\0')
        permitted = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.github', 'crates', 'include', 'proto', 'vendor', 'packaging', 'scripts', 'examples'}
        for name in sorted(set(os.fsdecode(x) for x in files if x)):
            path = ROOT / name
            if Path(name).parts[0] in permitted and path.is_file(): tar.add(path, 'source/' + name, recursive=False)
        tar.add(vendor, 'registry')
        config = re.sub(r'^directory = .*$', 'directory = "../registry"', vendor_config.read_text(), flags=re.M)
        add_bytes(tar, 'registry-config.toml', config.encode())
    (output / 'DEPENDENCIES.json').write_text(json.dumps(entries, indent=2) + '\n')
    components = []
    for entry in entries:
        component = {'type': 'library', 'name': entry['name'], 'version': entry['version'],
                     'purl': 'pkg:cargo/' + entry['name'] + '@' + entry['version'],
                     'licenses': [{'expression': re.sub(r'\s*/\s*', ' OR ', entry['license']) if entry['license'] else 'NOASSERTION'}]}
        component['bom-ref'] = component['purl']
        if entry.get('license_file') and not entry['license']:
            component['licenses'] = [{'license': {'name': 'License text: ' + entry['license_file']}}]
        if entry['checksum']: component['hashes'] = [{'alg': 'SHA-256', 'content': entry['checksum']}]
        components.append(component)
    (output / 'SBOM.cdx.json').write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'metadata': {'properties': [{'name': 'cyberbus:target', 'value': target}, {'name': 'cyberbus:scope', 'value': ', '.join(shipped) + ' normal/build dependency closure; includes host build tools'}]},
        'components': components,
        'dependencies': [{'ref': 'pkg:cargo/' + p['name'] + '@' + p['version'],
            'dependsOn': sorted('pkg:cargo/' + next(x['name'] + '@' + x['version'] for x in packages if x['id'] == d['pkg'])
                for d in graph[p['id']]['deps'] if d['pkg'] in nodes and any(k['kind'] != 'dev' for k in d['dep_kinds']))}
            for p in packages]}, indent=2) + '\n')
    for name in ['NOTICE.md', 'RELINK.md', 'README.md']:
        shutil.copy2(ROOT / 'packaging' / name, output / name)
    shutil.copytree(ROOT / 'include', output / 'include', dirs_exist_ok=True)
    shutil.copytree(ROOT / 'proto', output / 'proto', dirs_exist_ok=True)
    return metadata

def finalize(output, target, profile, kind, tools=None):
    manifest = {
        'name': 'CyberBus SDK', 'version': VERSION, 'kind': kind,
        'base_revision': text(['git', 'rev-parse', 'HEAD']),
        'working_tree_status': text(['git', 'status', '--porcelain']),
        'source_snapshot_sha256': digest(output / 'SOURCES.tar.gz'),
        'target': target, 'profile': profile, 'abi_version': 1,
        'minimum_os': ('Android API26' if 'android' in target else 'iOS13' if 'ios' in target else 'macOS11' if 'apple' in target else 'Windows10 x64 (not validated locally)' if 'windows' in target else 'See linked GLIBC versions / build-host ABI; not a musl package'),
        'cargo_lock_sha256': digest(ROOT / 'Cargo.lock'),
        'rustc': text(['rustc', '-Vv']), 'cargo': text(['cargo', '-V']),
        'build_host': platform.platform(), 'tools': tools or {},
        'runtime_validation': 'See the public validation status in docs/UNRESOLVED.md; assembly alone is not runtime validation.',
        'files': {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob('*')) if p.is_file() and '.build' not in p.relative_to(output).parts and p.name not in ['MANIFEST.json', 'SHA256SUMS']}
    }
    (output / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'SHA256SUMS').write_text(''.join(digest(p) + '  ' + p.relative_to(output).as_posix() + '\n' for p in sorted(output.rglob('*')) if p.is_file() and '.build' not in p.relative_to(output).parts and p.name != 'SHA256SUMS'))

def apple(output, native, target):
    shutil.copytree(ROOT / 'packaging/apple', output, dirs_exist_ok=True)
    identifiers = {
        'aarch64-apple-darwin': ('macos-arm64', 'macos', 'arm64', None),
        'x86_64-apple-darwin': ('macos-x86_64', 'macos', 'x86_64', None),
        'aarch64-apple-ios': ('ios-arm64', 'ios', 'arm64', None),
        'aarch64-apple-ios-sim': ('ios-arm64-simulator', 'ios', 'arm64', 'simulator'),
        'x86_64-apple-ios': ('ios-x86_64-simulator', 'ios', 'x86_64', 'simulator')
    }
    identifier, system, arch, variant = identifiers[target]
    framework = output / 'CyberBus.xcframework'; framework.mkdir(exist_ok=True)
    info_path = framework / 'Info.plist'
    info = plistlib.loads(info_path.read_bytes()) if info_path.exists() else {
        'CFBundlePackageType': 'XFWK', 'XCFrameworkFormatVersion': '1.0', 'AvailableLibraries': []}
    dest = framework / identifier; headers = dest / 'Headers'; headers.mkdir(parents=True, exist_ok=True)
    shutil.copy2(native / 'libcyberbus_ffi.a', dest)
    shutil.copy2(ROOT / 'include/cyberbus.h', headers)
    (headers / 'module.modulemap').write_text('module CCyberBus {\n header "cyberbus.h"\n export *\n}\n')
    lib = {'LibraryIdentifier': identifier, 'LibraryPath': 'libcyberbus_ffi.a', 'HeadersPath': 'Headers',
           'SupportedArchitectures': [arch], 'SupportedPlatform': system}
    if variant: lib['SupportedPlatformVariant'] = variant
    info['AvailableLibraries'] = [x for x in info['AvailableLibraries'] if x['LibraryIdentifier'] != identifier] + [lib]
    info_path.write_bytes(plistlib.dumps(info))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=['apple', 'desktop', 'android'])
    parser.add_argument('--target', required=True)
    parser.add_argument('--profile', choices=['debug', 'release'], default='release')
    parser.add_argument('--native-dir', type=Path, required=True, help='Actual build outputs; build first, never placeholder files')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); output = args.output.resolve(); native = args.native_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    tools = {}
    if args.kind == 'apple':
        apple(output, native, args.target)
        shutil.copy2(ROOT / 'packaging/smoke/swift.swift', output / 'sample.swift')
        tools['swift'] = text(['swift', '--version'])
        tools['sdk'] = text(['xcrun', '--show-sdk-path'])
        tools['clang'] = text(['clang', '--version'])
    elif args.kind == 'desktop':
        if 'windows' in args.target: names = ['cyberbus_ffi.dll', 'cyberbus_ffi.lib', 'cyberbus_ffi.dll.lib', 'cyberbus-cli.exe']
        elif 'linux' in args.target: names = ['libcyberbus_ffi.so', 'libcyberbus_ffi.a', 'cyberbus-cli']
        else: names = ['libcyberbus_ffi.dylib', 'libcyberbus_ffi.a', 'cyberbus-cli']
        for name in names: shutil.copy2(native / name, output / name)
        shutil.copy2(ROOT / 'packaging/smoke/desktop.c', output / 'sample.c')
        if 'windows' in args.target: shutil.copy2(ROOT / 'packaging/windows-store.h', output)
        tools['compiler'] = os.environ.get('CYBERBUS_PACKAGE_CC', os.environ.get('CC', 'cl' if 'windows' in args.target else 'cc'))
        if os.environ.get('PROTOC'): tools['protoc'] = text([os.environ['PROTOC'], '--version'])
        for tool in ['zig', 'cargo-zigbuild']:
            if shutil.which(tool): tools[tool] = text([tool, 'version' if tool == 'zig' else '--version'])
    else:
        for name in [f'cyberbus-sdk-{VERSION}.aar', f'cyberbus-sdk-{VERSION}.pom',
                     f'cyberbus-sdk-{VERSION}-sources.jar']:
            shutil.copy2(native / name, output / name)
        # Maven repository includes pinned runtime, sources and license material.
        shutil.copytree(native / 'third-party', output / 'third-party', dirs_exist_ok=True)
        java = run([str(Path(os.environ['JAVA_HOME']) / 'bin/java'), '-version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().strip()
        tools = {'gradle': '8.14.3', 'agp': '8.9.1', 'jdk': java, 'ndk': '27.2.12479018', 'minSdk': 26,
                 'protobuf': '4.26.1', 'schema-includes': 'protobuf-java 3.25.5', 'protoc-java': '26.1'}
    sources(output, args.target, include_cli=args.kind == 'desktop')
    if args.kind == 'android':
        runtime = output / 'third-party/protobuf-javalite-4.26.1.jar'
        entry = {'name': 'protobuf-javalite', 'version': '4.26.1', 'source': 'Maven Central',
                 'license': 'BSD-3-Clause', 'checksum': digest(runtime)}
        path = output / 'DEPENDENCIES.json'; entries = json.loads(path.read_text()); entries.append(entry)
        path.write_text(json.dumps(entries, indent=2) + '\n')
        path = output / 'SBOM.cdx.json'; sbom = json.loads(path.read_text())
        sbom['components'].append({'type': 'library', 'name': entry['name'], 'version': entry['version'],
            'purl': 'pkg:maven/com.google.protobuf/protobuf-javalite@4.26.1', 'licenses': [{'expression': 'BSD-3-Clause'}],
            'hashes': [{'alg': 'SHA-256', 'content': entry['checksum']}]})
        path.write_text(json.dumps(sbom, indent=2) + '\n')
    finalize(output, args.target, args.profile, args.kind, tools)
    print(output)

if __name__ == '__main__': main()
