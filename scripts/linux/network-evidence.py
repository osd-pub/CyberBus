#!/usr/bin/env python3
"""Read-only topology evidence. Socket existence does not prove message routing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def capture(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, help='Observe only this owned client process')
    args = parser.parse_args()
    routes = capture(['ip', '-j', 'route', 'show', 'table', 'all'])
    links = capture(['ip', '-j', 'link', 'show'])
    report = {'schema': 1, 'observed_unix': int(time.time()),
              'route_sha256': hashlib.sha256(routes.encode()).hexdigest() if routes else None,
              'resolv_sha256': hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest(),
              'interface_names': [item['ifname'] for item in json.loads(links)] if links else [],
              'relay_listening_11010': False, 'relay_socket_established': False,
              'message_path': 'not_observable_from_socket_presence',
              'client_uses_tun': None, 'client_rss_kib': None, 'client_fd_count': None}
    sockets = capture(['ss', '-H', '-tn'])
    listeners = capture(['ss', '-H', '-ltn'])
    if listeners is not None:
        report['relay_listening_11010'] = any(':11010 ' in line for line in listeners.splitlines())
    if sockets is not None:
        report['relay_socket_established'] = any(
            line.startswith('ESTAB ') and ':11010 ' in line for line in sockets.splitlines())
    if args.pid:
        proc = Path('/proc') / str(args.pid)
        if proc.stat().st_uid != os.getuid():
            parser.error('PID must belong to current user')
        targets = []
        for fd in (proc / 'fd').iterdir():
            try:
                targets.append(os.readlink(fd))
            except FileNotFoundError:
                pass
        report['client_uses_tun'] = any(target == '/dev/net/tun' for target in targets)
        report['client_fd_count'] = len(targets)
        for line in (proc / 'status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                report['client_rss_kib'] = int(line.split()[1])
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
