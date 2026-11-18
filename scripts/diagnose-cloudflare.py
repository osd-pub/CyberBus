#!/usr/bin/env python3
"""Own a loopback EasyTier WS relay and an anonymous Cloudflare test tunnel.

Delegate raw/Noise transport checks to diagnose-easytier.py. Both relay and tunnel
are stopped in finally. No existing Cloudflare configuration/account is read.
"""
import argparse
import json
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time


def read_until(process, path, pattern, seconds):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + seconds
    pending = b''
    with path.open('wb') as output:
        while time.monotonic() < deadline:
            for key, _ in selector.select(timeout=1):
                chunk = key.fileobj.read1(65536)
                if not chunk:
                    raise RuntimeError('process exited before readiness: ' + str(path))
                output.write(chunk)
                output.flush()
                pending += chunk
                match = re.search(pattern, pending.decode(errors='replace'))
                if match:
                    selector.close()
                    return match.group(1)
            if process.poll() is not None:
                raise RuntimeError('process exited before readiness: ' + str(path))
    selector.close()
    raise TimeoutError('readiness deadline: ' + str(path))


def stop(process):
    if process is None:
        return None
    if process.poll() is None:
        if process.stdin:
            process.stdin.close()
        else:
            process.terminate()
        try:
            return process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
    return process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--relay-binary', type=Path, default=Path('target/debug/examples/ws_relay'))
    parser.add_argument('--binary', type=Path, default=Path('target/debug/examples/easytier_probe'))
    parser.add_argument('--managed', action='store_true', help='use the SDK-owned official connector and loopback relay')
    parser.add_argument('--topology', choices=('relay', 'fallback'), default='relay')
    parser.add_argument('--backend', choices=('official',), default='official')
    parser.add_argument('--tunnel-binary', default='cloudflared')
    parser.add_argument('--protocol', choices=('quic', 'http2'), default='http2')
    parser.add_argument('--peer', choices=('local', 'android', 'ssh'), default='local')
    parser.add_argument('--peer-binary')
    parser.add_argument('--ssh-host')
    parser.add_argument('--android-serial')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.peer == 'ssh' and not args.ssh_host:
        parser.error('--ssh-host required for ssh peer')
    args.output.mkdir(parents=True, exist_ok=False)
    relay = tunnel = None
    receipt = {'backend': args.backend, 'peer': args.peer, 'runs': []}
    try:
        if args.managed:
            relay = subprocess.Popen([str(args.relay_binary.resolve(strict=True)), args.tunnel_binary, args.protocol],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            endpoint = read_until(relay, args.output/'relay-start.log', r'READY (wss://\S+)', 70)
            receipt['endpoint'] = endpoint
            receipt['managed'] = True
        else:
            relay = subprocess.Popen([str(args.relay_binary.resolve(strict=True))],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            endpoint = read_until(relay, args.output/'relay-start.log', r'READY (ws://\S+)', 25)
            port = endpoint.rsplit(':', 1)[1].rstrip('/')
            command = [args.tunnel_binary, 'tunnel', '--config', '/dev/null', '--no-autoupdate',
                       '--protocol', args.protocol, '--url', 'http://127.0.0.1:' + port]
            log = (args.output/'tunnel.log').open('wb')
            try:
                tunnel = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            finally:
                log.close()
            deadline = time.monotonic() + 65
            url = None
            while time.monotonic() < deadline and tunnel.poll() is None:
                text = (args.output/'tunnel.log').read_text(errors='replace')
                found = re.search(r'(https://[a-z0-9-]+\.trycloudflare\.com)', text)
                if found and 'Registered tunnel connection' in text:
                    url = found.group(1)
                    break
                time.sleep(0.2)
            if url is None:
                raise RuntimeError('tunnel did not register within 65s; see tunnel.log')
            receipt['endpoint'] = 'wss://' + url.removeprefix('https://') + ':443/'
        print(json.dumps({'registered': True, 'backend': args.backend, 'managed': args.managed}), flush=True)
        for mode in ('raw', 'noise'):
            command = [sys.executable, str(Path(__file__).with_name('diagnose-easytier.py')),
                       '--binary', str(args.binary), '--peer', args.peer,
                       '--relay', receipt['endpoint'], '--mode', mode,
                       '--rounds', str(args.rounds), '--topology', args.topology, '--output', str(args.output/mode)]
            for name in ('peer_binary', 'ssh_host', 'android_serial'):
                value = getattr(args, name)
                if value:
                    command += ['--'+name.replace('_', '-'), value]
            result = subprocess.run(command, timeout=350)
            receipt['runs'].append({'mode': mode, 'exit': result.returncode})
    except Exception as exc:
        receipt['error'] = str(exc)
    finally:
        receipt['tunnel_exit'] = stop(tunnel)
        receipt['relay_exit'] = stop(relay)
        receipt['owned_processes_exited'] = all(p is None or p.poll() is not None for p in (relay, tunnel))
        (args.output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt), flush=True)
    return 0 if len(receipt['runs']) == 2 and all(r['exit'] == 0 for r in receipt['runs']) and not receipt.get('error') and receipt['relay_exit'] == 0 and receipt['owned_processes_exited'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
