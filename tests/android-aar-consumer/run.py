#!/usr/bin/env python3
"""Build an offline Java consumer; run sealed public AAR on the exclusively owned ADB."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SEALED = REPO / 'target/artifacts/final-70f5f99/android/cyberbus-sdk-70f5f99.aar'
# The original sealed artifact is in the repository root, outside this worktree.
if not SEALED.exists():
    SEALED = REPO.parents[1] / 'target/artifacts/final-70f5f99/android/cyberbus-sdk-70f5f99.aar'
AAR_HASH = 'b00e0d4861765815b999075f901c42372dac1c3d8453561f64d6324c61d5291d'
RUNTIME_HASH = 'ae83d2b063988c4565462845269472ddc817117506b6e467a2c3222c96636829'
JNI_HASH = 'b433cd1830a0cd26c138d2a381142949bdaa382c48ec961957c56cef86df47a6'
APP = 'io.cyberbus.aarconsumer'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def library(path):
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if n.endswith('/libcyberbus_ffi.so')]
        assert len(names) == 1, 'Exactly one packaged CyberBus JNI library required'
        return names[0], hashlib.sha256(archive.read(names[0])).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--aar', type=Path, default=SEALED)
    parser.add_argument('--result', type=Path, default=HERE / 'build/result.json')
    args = parser.parse_args()
    sdk = Path(os.environ.get('ANDROID_HOME', str(Path.home() / 'Library/Android/sdk')))
    adb = [str(sdk / 'platform-tools/adb'), '-s', args.serial]
    build = HERE / 'build'; build.mkdir(exist_ok=True)
    report = dict(status='FAIL', suite='sealed-public-aar-android-art-jni',
                  sdkRevision='70f5f991b9d590fafba9346b33c503bed9f4b21c',
                  startedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  applicationId=APP, nativeRebuilt=False, sourceWorktree=str(REPO),
                  limitations=['No auth/network, complete API, RPC, scale or stability acceptance',
                               'This is Android ART/JNI evidence; no host JNI harness was run'])
    stage = 'sealed-inputs'
    attempted_device_run = False
    try:
        assert digest(args.aar) == AAR_HASH
        aar_entry, aar_jni = library(args.aar); assert aar_jni == JNI_HASH
        runtimes = list((Path.home() / '.gradle/caches/modules-2/files-2.1/com.google.protobuf/protobuf-javalite/4.26.1').glob('*/protobuf-javalite-4.26.1.jar'))
        assert len(runtimes) == 1 and digest(runtimes[0]) == RUNTIME_HASH
        gradles = list((Path.home() / '.gradle/wrapper/dists/gradle-8.14.3-bin').glob('*/gradle-8.14.3/bin/gradle'))
        assert len(gradles) == 1
        config = REPO / 'deploy/test-client.json'
        report['inputs'] = dict(aar=str(args.aar.resolve()), aarSha256=AAR_HASH,
                                aarJniEntry=aar_entry, aarJniSha256=aar_jni,
                                runtime=str(runtimes[0]), runtimeSha256=RUNTIME_HASH,
                                publicConfigSha256=digest(config))
        report['consumerBaseCommit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
        report['consumerSourceSha256'] = {str(p.relative_to(HERE)): digest(p) for p in sorted(HERE.rglob('*'))
            if p.is_file() and not any(part in ('build', '.gradle', 'results', '__pycache__') for part in p.relative_to(HERE).parts)}
        stage = 'offline-gradle-build'
        env = os.environ.copy()
        env['ANDROID_HOME'] = str(sdk)
        env['JAVA_HOME'] = env.get('JAVA_HOME', '/opt/zerobrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home')
        command = [str(gradles[0]), '-p', str(HERE), '--offline', '--console=plain',
                   '-PconsumerAar=' + str(args.aar.resolve()), '-PconsumerRuntime=' + str(runtimes[0]),
                   '-PconsumerConfig=' + str(config), ':app:assembleDebug', ':app:lintDebug']
        with (build / 'gradle.log').open('w') as log:
            subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        report['build'] = dict(status='PASS', gradle='8.14.3', agp='8.9.1', java='17', compileSdk=35,
                               minSdk=26, tasks=['assembleDebug', 'lintDebug'], offline=True)
        apk = HERE / 'app/build/outputs/apk/debug/app-debug.apk'
        _, apk_jni = library(apk); assert apk_jni == aar_jni
        stage = 'device-install'
        subprocess.run(adb + ['install', '-t', '-r', str(apk)], capture_output=True, check=True, timeout=90)
        attempted_device_run = True
        subprocess.run(adb + ['shell', 'input', 'keyevent', '224'], capture_output=True, check=True, timeout=10)
        stage = 'public-art-instrumentation'
        result = subprocess.run(adb + ['shell', 'am', 'instrument', '-w', APP + '/.SmokeInstrumentation'],
                                capture_output=True, text=True, check=True, timeout=100)
        (build / 'instrumentation.txt').write_text(result.stdout + result.stderr)
        rows = [line.removeprefix('INSTRUMENTATION_RESULT: report=') for line in result.stdout.splitlines()
                if line.startswith('INSTRUMENTATION_RESULT: report=')]
        assert len(rows) == 1, 'Instrumentation did not return exactly one report'
        report['instrumentation'] = json.loads(rows[0])
        assert 'INSTRUMENTATION_CODE: -1' in result.stdout.splitlines(), 'Non-success instrumentation finish'
        app = report['instrumentation']
        assert app['status'] == 'PASS' and len(app['cases']) == 13 and all(c['status'] == 'PASS' for c in app['cases'])
        assert app['sdkCloseEofCount'] == 2 and app['eventCount'] >= 3 and app['authOrNetworkRequested'] is False
        assert app['mainPid'] > 0 and app['lockProbePid'] > 0 and app['mainPid'] != app['lockProbePid']
        assert app['malformedProtobufErrorCode'] == 'PROTOCOL_ERROR'
        stage = 'installed-apk-jni-verification'
        remote = subprocess.check_output(adb + ['shell', 'pm', 'path', APP], text=True, timeout=10).strip()
        assert remote.startswith('package:') and '\n' not in remote
        installed = build / 'installed.apk'
        with installed.open('wb') as output:
            subprocess.run(adb + ['exec-out', 'cat', remote.removeprefix('package:')], stdout=output, stderr=subprocess.PIPE, check=True, timeout=60)
        entry, installed_jni = library(installed)
        assert digest(installed) == digest(apk) and installed_jni == aar_jni
        report['installedArtifact'] = dict(apkSha256=digest(apk), installedApkSha256=digest(installed),
                                         jniEntry=entry, jniSha256=installed_jni, matchesOriginalAarBytes=True)
        report['device'] = {key: subprocess.check_output(adb + ['shell', 'getprop', prop], text=True, timeout=10).strip()
                            for key, prop in [('model', 'ro.product.model'), ('release', 'ro.build.version.release'),
                                              ('api', 'ro.build.version.sdk'), ('abi', 'ro.product.cpu.abi')]}
        report['status'] = 'PASS'
    except Exception as error:
        report.update(failureStage=stage, failureClass=type(error).__name__)
    finally:
        if attempted_device_run:
            try:
                subprocess.run(adb + ['shell', 'am', 'force-stop', APP], capture_output=True, check=True, timeout=10)
                report['consumerProcessCleanup'] = 'PASS'
            except Exception as error:
                report.update(status='FAIL', failureStage='consumer-force-stop', failureClass=type(error).__name__)
        report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_text(json.dumps(report, indent=2) + '\n')
    print(report['status'] + ' public AAR ART/JNI smoke; result=' + str(args.result))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
