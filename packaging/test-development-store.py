#!/usr/bin/env python3
"""Test production AAR Java store ownership without rebuilding Rust/JNI/AAR."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
           or Path.home() / 'Library/Android/sdk')
android = sorted((sdk / 'platforms').glob('*/android.jar'))[-1]
java_home = os.environ.get('JAVA_HOME')
javac = str(Path(java_home) / 'bin/javac') if java_home else shutil.which('javac')
java = str(Path(java_home) / 'bin/java') if java_home else shutil.which('java')
source = root / 'packaging/android-sdk/sdk/src/main/java/io/cyberbus/sdk'
with tempfile.TemporaryDirectory(prefix='cyberbus-aar-owner-') as temp:
    subprocess.run([javac, '-cp', str(android), '-d', temp,
                    str(source / 'SecureStore.java'), str(source / 'DevelopmentFileStore.java'),
                    str(root / 'packaging/smoke/DevelopmentStoreSmoke.java')], check=True)
    subprocess.run([java, '-cp', temp + os.pathsep + str(android),
                    'DevelopmentStoreSmoke'], check=True, timeout=60)
