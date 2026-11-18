#!/usr/bin/env python3
"""Two real CLIs: public config RPC, live declaration changes and remote terminals."""
import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('cli_sample_controller', ROOT / 'tests/cli-sample/run.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
require = controller.require
Q = r'"(?:[^"\\]|\\.)*"'
PROFILE = re.compile(r'PUBLIC_PROFILE revision=(\d+) name=(' + Q + r') application_version=(' + Q +
                     r') semantic_version=(' + Q + r') config_sha256=([a-f0-9]{64})')
REPLY = re.compile(r'RPC_CONFIG call_id=([a-f0-9]{32}) peer=([a-f0-9]{64}) '
                   r'request_id=([a-f0-9]{32}) revision=(\d+) name=(' + Q +
                   r') application_version=(' + Q + r') semantic_version=(' + Q +
                   r') config_sha256=([a-f0-9]{64})')


def declared(lines):
    rows = [PROFILE.fullmatch(s) for s in lines if s.startswith('PUBLIC_PROFILE ')]
    require(rows and all(rows), 'missing or malformed accepted public declaration')
    m = rows[-1]
    return dict(revision=int(m[1]), name=json.loads(m[2]), applicationVersion=json.loads(m[3]),
                semanticVersion=json.loads(m[4]), configSha256=m[5])


def check_reply(lines, expected, remote_lines, local_id, remote_id):
    rows = [REPLY.fullmatch(s) for s in lines if s.startswith('RPC_CONFIG ')]
    require(len(rows) == 1 and rows[0], 'missing unique config reply')
    m = rows[0]
    require(m[2] == remote_id, 'reply peer mismatch')
    actual = dict(revision=int(m[4]), name=json.loads(m[5]), applicationVersion=json.loads(m[6]),
                  semanticVersion=json.loads(m[7]), configSha256=m[8])
    require(actual == expected, 'reply differs from actual callee public declaration')
    accepted = f'RPC_REQUEST_ACCEPTED mode=config call_id={m[1]} peer={remote_id}'
    terminal = f'RPC_CONFIG_END call_id={m[1]} peer={remote_id} items=1 error='
    require([s for s in lines if s.startswith('RPC_REQUEST_ACCEPTED ')] == [accepted],
            'request acceptance correlation mismatch')
    require([s for s in lines if s.startswith('RPC_CONFIG_END ')] == [terminal],
            'missing unique successful remote terminal')
    require(lines.index(terminal) > next(i for i, s in enumerate(lines) if s.startswith('RPC_CONFIG ')),
            'terminal precedes config reply')
    request = f'RPC_REQUEST_RECEIVED role=callee call_id={m[1]} peer={local_id}'
    require([s for s in remote_lines if s.startswith('RPC_REQUEST_RECEIVED ') and
             f'call_id={m[1]} ' in s] == [request], 'owned callee did not receive this request')
    sdk_end = f'RPC_EVENT source=sdk_event kind=response_end role=caller call_id={m[1]} peer={remote_id} code=OK'
    require([s for s in lines if s.startswith('RPC_EVENT ') and f'call_id={m[1]} ' in s] == [sdk_end],
            'missing correlated successful SDK response end')
    return dict(**actual, callId=m[1], peer=remote_id, requestId=m[3],
                remoteHandlerObserved=True, responseItems=1, sdkResponseEnd='OK')


async def run(args):
    os.umask(0o077)
    args.private_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    clients, owned = [], []
    report = dict(status='FAIL', suite='cli-public-config-003',
                  startedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  provenance=dict(sourceRevision=args.revision, cliBinarySha256=controller.sha(args.binary),
                                  relayBinarySha256=controller.sha(args.relay_binary),
                                  controllerSha256=controller.sha(Path(__file__)),
                                  sharedControllerSha256=controller.sha(ROOT / 'tests/cli-sample/run.py')),
                  cases=[], cleanup=[], limitations=['Owned loopback relay; no scale/platform acceptance'])

    async def case(name, action):
        facts = {}
        start = time.monotonic()
        try:
            await action(facts)
            report['cases'].append(dict(id=name, status='PASS', facts=facts,
                                        durationSeconds=round(time.monotonic() - start, 3)))
        except Exception as error:
            row = dict(id=name, status='FAIL', errorType=type(error).__name__, facts=facts)
            if isinstance(error, AssertionError):
                row['assertion'] = str(error)
            report['cases'].append(row)
            raise
        print(name, 'PASS', flush=True)

    try:
        descriptor = args.descriptor.read_bytes()
        require(descriptor in args.binary.read_bytes(), 'descriptor not embedded in tested CLI')
        report['provenance'].update(descriptorSha256=hashlib.sha256(descriptor).hexdigest(),
                                    descriptorBytes=len(descriptor))
        relay = await controller.spawn(args.relay_binary, '--relay')
        owned.append(('relay', relay))
        relay_stderr = asyncio.create_task(relay.stderr.read())
        ready = json.loads(await asyncio.wait_for(relay.stdout.readline(), 20))
        endpoint = ready.get('relayEndpoint', '')
        uri = urlsplit(endpoint)
        require(ready.get('ready') is True and uri.scheme == 'tcp' and uri.hostname == '127.0.0.1'
                and uri.port, 'relay not owned loopback')
        config = json.loads(args.config.read_text())
        config.update(bootstrap_peers=[endpoint], enable_p2p=False, persist_grant=False)
        configpath = args.private_dir / 'public-config.json'
        configpath.write_text(json.dumps(config))
        for name in ['a', 'b']:
            directory = args.private_dir / name
            directory.mkdir(mode=0o700)
            authfile = directory / 'authorization'
            process = await controller.spawn(args.binary, '--config', configpath,
                '--store', directory / 'state.json', '--create-store', '--name', 'CLI-config-003-' + name,
                '--no-browser', '--authorization-file', authfile)
            cli = controller.CLI(name, process)
            clients.append(cli)
            await cli.wait(lambda: any(s.startswith('READY ') for s in cli.lines), 15)
            await case('login-' + name, lambda facts: controller.login(cli, authfile, owned, facts))
        for cli in clients:
            await cli.command('start')
        for cli in clients:
            await cli.command('wait-devices 2', 45)
        identities, views = {}, []
        for cli in clients:
            marker = await cli.command('devices')
            await cli.wait(lambda: sum(s.startswith('DEVICE ') for s in cli.lines[marker:]) >= 2)
            rows = [re.fullmatch(r'DEVICE ([a-f0-9]{64}) local=(true|false) online=(true|false) name=.*', s)
                    for s in cli.lines[marker:] if s.startswith('DEVICE ')]
            require(len(rows) == 2 and all(rows) and all(m[3] == 'true' for m in rows),
                    'not exactly two online installations')
            local = [m[1] for m in rows if m[2] == 'true']
            require(len(local) == 1, 'self cardinality')
            identities[cli.name] = local[0]
            views.append({m[1] for m in rows})
        require(len(set(identities.values())) == 2 and all(v == set(identities.values()) for v in views),
                'unexpected identity or external installation')
        report['isolation'] = dict(distinctOnlineInstallations=2, serialCallbackOnlyLogin=True,
                                   bootstrap='owned-loopback-relay-only', tokenImport=False)

        async def query(facts, cli, remote, changed):
            before = declared(remote.lines)
            if changed:
                await remote.command('name CLI-config-003-' + remote.name + '-updated')
            expected = declared(remote.lines)
            if changed:
                require(expected['revision'] > before['revision'] and expected['name'] != before['name'],
                        'SDK did not accept a new public declaration')
            require(expected['name'] != declared(cli.lines)['name'], 'pair needs distinct public names')
            remote_marker = len(remote.lines)
            target = '@peer' if changed else identities[remote.name]
            marker = await cli.command('config ' + target)
            facts.update(check_reply(cli.lines[marker:], expected, remote.lines[remote_marker:],
                                     identities[cli.name], identities[remote.name]))
            facts.update(changedDeclaration=changed, beforeRevision=before['revision'], targetMode=target if target == '@peer' else 'device-id')

        for cli, remote in [(clients[0], clients[1]), (clients[1], clients[0])]:
            await case(cli.name + '-config', lambda facts: query(facts, cli, remote, False))
            await case(cli.name + '-config-after-change', lambda facts: query(facts, cli, remote, True))
    except Exception as error:
        report['failure'] = dict(errorType=type(error).__name__)
        if isinstance(error, AssertionError):
            report['failure']['assertion'] = str(error)
    finally:
        for cli in reversed(clients):
            try:
                result = await cli.close()
            except Exception as error:
                result = await controller.stop(cli.p)
                result['cleanupException'] = type(error).__name__
            report['cleanup'].append(dict(name='cli-' + cli.name, **result))
        for name, process in reversed(owned):
            report['cleanup'].append(dict(name=name, **await controller.stop(process)))
        if 'relay_stderr' in locals():
            await relay_stderr
            remaining = await relay.stdout.read()
            report['relayClosedObserved'] = any(json.loads(line).get('relayClosed') is True
                for line in remaining.splitlines() if line.startswith(b'{'))
        shutil.rmtree(args.private_dir)
        report['privateArtifactsRemoved'] = not args.private_dir.exists()
        report['summary'] = dict(passed=sum(c['status'] == 'PASS' for c in report['cases']),
                                 failed=sum(c['status'] == 'FAIL' for c in report['cases']), expectedCases=6)
        success = len(report['cases']) == 6 and report['summary']['failed'] == 0 and 'failure' not in report
        success &= report.get('relayClosedObserved') is True and report['privateArtifactsRemoved']
        success &= all(r['exitCode'] == 0 and not r['forced'] and not r.get('cleanupException')
                       for r in report['cleanup'])
        report['status'] = 'PASS' if success else 'FAIL'
        report['exitCode'] = 0 if success else 1
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('RESULT', report['status'], 'report', args.report, flush=True)
    return report['exitCode']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ['binary', 'relay-binary', 'descriptor', 'private-dir', 'report']:
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--config', type=Path, default=ROOT / 'deploy/test-client.json')
    raise SystemExit(asyncio.run(run(parser.parse_args())))
