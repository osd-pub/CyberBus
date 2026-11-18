#!/usr/bin/env python3
"""Read-only Linux inventory; never reads credentials or process arguments."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def capture(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    return result.stdout.strip() if result.returncode == 0 else None


def inventory(root):
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
            memory[key + '_KiB'] = int(value.split()[0])
    disk = shutil.disk_usage(root)
    tools = {name: shutil.which(name) for name in
             ('cargo', 'rustc', 'docker', 'podman', 'cc', 'cmake', 'make',
              'pkg-config', 'protoc', 'git', 'python3', 'curl')}
    containers = capture(['sudo', '-n', 'docker', 'ps', '--format',
                          '{{.Names}} {{.Image}} {{.Status}}']) if tools['docker'] else None
    return {'schema': 1, 'os': platform.platform(), 'arch': platform.machine(),
            'cpu_count': os.cpu_count(), 'memory': memory,
            'disk': {'total_bytes': disk.total, 'free_bytes': disk.free},
            'tools': tools, 'containers': containers.splitlines() if containers else [],
            'unprivileged_uid': os.getuid()}


if __name__ == '__main__':
    print(json.dumps(inventory(Path.cwd()), indent=2))
