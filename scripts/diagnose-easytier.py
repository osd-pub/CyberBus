#!/usr/bin/env python3
"""Run public EasyTier fixtures in both connection directions; retain stage logs.

Build/deploy easytier_probe first. This never authenticates or changes radios.
The remote timeout bounds the owned peer even if its adb/ssh channel disconnects.
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time
import uuid


def records(path):
    result = []
    for line in path.read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and 'stage' in row:
            result.append(row)
    return result


def wait(process):
    try:
        return process.wait(timeout=170)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        return 'HARNESS_TIMEOUT'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/examples/easytier_probe'))
    parser.add_argument('--peer', choices=('local', 'android', 'ssh'), default='local')
    parser.add_argument('--peer-binary')
    parser.add_argument('--ssh-host')
    parser.add_argument('--android-serial')
    parser.add_argument('--relay', required=True)
    parser.add_argument('--mode', choices=('raw', 'noise'), default='raw')
    parser.add_argument('--handshake-ms', type=int, default=10000)
    parser.add_argument('--rounds', type=int, default=3, choices=range(1, 21))
    parser.add_argument('--topology', choices=('relay', 'p2p', 'fallback'), default='relay')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = str(args.binary.resolve(strict=True))
    if args.peer != 'local' and not args.peer_binary:
        parser.error('--peer-binary required for android/ssh')
    if args.peer == 'ssh' and not args.ssh_host:
        parser.error('--ssh-host required for ssh peer')
    args.output.mkdir(parents=True, exist_ok=False)
    run = 'probe-' + uuid.uuid4().hex
    report = {'schema': 1, 'run': run, 'peer': args.peer, 'relay': args.relay,
              'mode': args.mode, 'handshake_ms': args.handshake_ms,
              'rounds': args.rounds, 'topology': args.topology,
              'host_binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              'pairs': []}
    for host_role in ('listen', 'connect'):
        peer_role = 'connect' if host_role == 'listen' else 'listen'
        # Separate network per pair; no stale routes/session can satisfy a new run.
        common = [args.relay, run + '-' + host_role, args.mode,
                  str(args.handshake_ms), str(args.rounds), args.topology]
        host = [binary, host_role, *common]
        peer = [args.peer_binary or binary, peer_role, *common]
        if args.peer == 'android':
            prefix = ['adb'] + (['-s', args.android_serial] if args.android_serial else [])
            peer = prefix + ['shell', shlex.join(['toybox', 'timeout', '-s', 'KILL', '150', *peer])]
        elif args.peer == 'ssh':
            peer = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host,
                    shlex.join(['timeout', '-s', 'KILL', '150', *peer])]
        paths = [args.output / (host_role + '-' + name + '.log') for name in ('host', 'peer')]
        began = time.monotonic()
        processes = []
        try:
            with paths[0].open('w') as a, paths[1].open('w') as b:
                processes.append(subprocess.Popen(host, stdout=a, stderr=subprocess.STDOUT))
                processes.append(subprocess.Popen(peer, stdout=b, stderr=subprocess.STDOUT))
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    exits = list(pool.map(wait, processes))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        stages = [records(path) for path in paths]
        complete = [any(r['stage'] == 'complete' and r['detail'].get('result') == 'PASS'
                        for r in rows) for rows in stages]
        pair = {'host_role': host_role, 'exit_codes': exits,
                'result': 'PASS' if exits == [0, 0] and all(complete) else 'FAIL',
                'elapsed_s': round(time.monotonic() - began, 3),
                'logs': [p.name for p in paths], 'stages': stages}
        report['pairs'].append(pair)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({k: v for k, v in pair.items() if k != 'stages'}), flush=True)
    return 0 if all(p['result'] == 'PASS' for p in report['pairs']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
