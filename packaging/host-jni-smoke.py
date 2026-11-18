#!/usr/bin/env python3
"""Run the production JNI module on a host JVM; not an Android device test."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import zipfile
ROOT = Path(__file__).resolve().parents[1]
target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')).resolve()
out = target / 'packages-002/host-jni-check'; out.mkdir(parents=True, exist_ok=True)
source = ROOT / 'crates/cyberbus-ffi'
shutil.copytree(source / 'src', out / 'src', dirs_exist_ok=True)
lib = out / 'src/lib.rs'
lib.write_text(lib.read_text().replace('#[cfg(target_os = "android")]\n', ''))
manifest = (source / 'Cargo.toml').read_text().replace('name = "cyberbus_ffi"', 'name = "cyberbus_ffi_jni_test"')
for name in ['cyberbus', 'cyberbus-auth']:
    manifest = manifest.replace('path = "../' + name + '"', 'path = "' + (ROOT / 'crates' / name).as_posix() + '"')
manifest = manifest.replace('[target.\'cfg(target_os = "android")\'.dependencies]\n', '')
(out / 'Cargo.toml').write_text(manifest + '\n[workspace]\n[profile.dev]\ndebug = 0\n')
shutil.copy2(ROOT / 'Cargo.lock', out / 'Cargo.lock')
env = os.environ.copy(); env['CARGO_TARGET_DIR'] = str(target)
if not env.get('PROTOC'):
    import platform
    host = ('macos-aarch_64' if platform.machine() == 'arm64' else 'macos-x86_64') if sys.platform == 'darwin' else 'linux-x86_64'
    env['PROTOC'] = str(next((Path.home() / '.cargo/registry/src').glob('*/protoc-bin-vendored-' + host + '-*/bin/protoc')))
# The isolated harness removes only the Android module cfg and enables the same
# jni dependency on the host; release Cargo.lock itself is never changed.
subprocess.run(['cargo', 'build', '--offline', '--manifest-path', str(out / 'Cargo.toml'), '-j', '2'], cwd=ROOT, env=env, check=True)
extension = '.dylib' if sys.platform == 'darwin' else '.so'
shutil.copy2(target / ('debug/libcyberbus_ffi_jni_test' + extension), out / ('libcyberbus_ffi' + extension))
aar = ROOT / 'packaging/android-sdk/sdk/build/outputs/aar/sdk-release.aar'
with zipfile.ZipFile(aar) as archive:
    (out / 'classes.jar').write_bytes(archive.read('classes.jar'))
    assert [p for p in archive.namelist() if p.endswith('.so')] == ['jni/arm64-v8a/libcyberbus_ffi.so']
with zipfile.ZipFile(out / 'classes.jar') as jar:
    for name in ['io/cyberbus/sdk/CyberBus.class', 'cyberbus/easytier/v1/Sdk$SdkCommand.class',
                 'cyberbus/example/v1/EchoOuterClass$EchoRequest.class', 'com/google/protobuf/DescriptorProtos.class']:
        assert name in jar.namelist(), name
runtime = next((Path.home() / '.gradle/caches/modules-2/files-2.1/com.google.protobuf/protobuf-javalite/4.26.1').glob('*/*.jar'))
cp = str(out / 'classes.jar') + os.pathsep + str(runtime)
jdk = Path(env['JAVA_HOME']) / 'bin'
subprocess.run([str(jdk / 'javac'), '-cp', cp, '-d', str(out), str(ROOT / 'packaging/smoke/BoundarySmoke.java')], check=True)
subprocess.run([str(jdk / 'java'), '-Xcheck:jni', '-Djava.library.path=' + str(out), '-cp', str(out) + os.pathsep + cp,
    'BoundarySmoke', str(ROOT / 'deploy/test-client.json')], check=True)
