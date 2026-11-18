#!/usr/bin/env python3
"""Opt-in N5 public-query quota controller. Never builds a native artifact."""
import argparse
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import types

SDK = '3ae5fc732922914b5225f3dc5811724a95a3302d'
RUNNER = '1fef9178cd8e08763c29dd5c969c70d55d3a1949a1bc2667ed0fbfae77b8125d'
MACHINE = 'aa7e8d4aa10986b7953cfbd79a6e1c08c033f6a294b1821adb4df228132090f1'
CACHE_AGE = 31  # Natural expiry of the documented <=30-second authenticated cache.
QUERY_BUDGET = 30  # Existing SDK deadline, not a controller extension.
QUERY_EVENTS = ('devicesQuery', 'refreshDevices', 'deviceDescriptor', 'blockedDevices', 'descriptor')


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def load_base(path):
    source = path.read_bytes()
    require(hashlib.sha256(source).hexdigest() == RUNNER, 'requires reviewed cursor/settle runner bytes')
    base = types.ModuleType('query_capacity_base')
    base.__file__ = str(path.resolve())
    exec(compile(source, str(path), 'exec'), base.__dict__)
    require(callable(getattr(base.Client, 'mark', None)) and
            callable(getattr(base.Client, 'events_since', None)), 'absolute history API required')
    return base


class Ledger:
    """Six registered handles counted through EOF, independent of history trimming."""
    def __init__(self, error_codes=(), clock=time.monotonic):
        self.counts, self.first = {}, {}
        self.details, self.observed = {}, {}
        self.error_codes, self.clock, self.origin = error_codes, clock, None

    def register(self, qid, role, peer=None):
        require(qid not in self.counts, 'controller reused a query ID')
        if self.origin is None:
            self.origin = self.clock()
        self.counts[qid] = 0
        self.details[qid] = dict(queryId=qid, role=role)
        if peer is not None:
            self.details[qid]['peer'] = peer

    def mark(self, qid, step):
        self.details[qid][step + 'Seconds'] = round(self.clock() - self.origin, 6)

    def wait_failed(self, qid, error):
        self.mark(qid, 'controllerWaitFailed')
        self.details[qid]['controllerWaitOutcome'] = (
            'TIMEOUT' if isinstance(error, AssertionError) and
            str(error) == 'expected correlated event timed out' else
            'CANCELLED' if isinstance(error, asyncio.CancelledError) else 'FAILED')

    def observe(self, event):
        for kind in QUERY_EVENTS:
            body = event.get(kind, {})
            qid = body.get('queryId')
            if qid in self.counts:
                self.counts[qid] += 1
                self.first.setdefault(qid, (kind, body))
                self.observed.setdefault(qid, round(self.clock() - self.origin, 6))

    def absent(self, ids):
        require(all(self.counts[qid] == 0 for qid in ids), 'unexpected early or rejected-ID query terminal')

    def single(self, qid, kind):
        require(self.counts[qid] == 1 and self.first[qid][0] == kind,
                'query must have exactly one terminal of the correct type')
        return self.first[qid][1]

    def snapshot(self):
        """Safe observation only: never serialize profiles, SDK messages or auth data."""
        rows = []
        for qid, details in self.details.items():
            row = dict(details, terminalCount=self.counts[qid])
            if qid in self.first:
                kind, body = self.first[qid]
                terminal = dict(kind=kind, observedSeconds=self.observed[qid])
                error = body.get('error')
                if isinstance(error, dict):
                    code = error.get('code')
                    terminal['sdkErrorCode'] = code if isinstance(code, str) and code in self.error_codes else 'UNRECOGNIZED'
                if (kind == 'deviceDescriptor' and 'profile' in body and not isinstance(error, dict)
                        and type(body.get('fromCache', False)) is bool):
                    terminal['fromCache'] = body.get('fromCache', False)
                row['firstTerminal'] = terminal
            rows.append(row)
        return rows


def check_profile(body, peer, expected, resumed_at):
    require(body.get('peerDeviceId') == peer, 'profile terminal names the wrong peer')
    require(body.get('fromCache', False) is False, 'stalled query returned cached profile')
    require(body.get('profile') == expected and not body.get('error') and 'unchanged' not in body,
            'fresh authenticated profile differs from remote public profile')
    try:
        authenticated = datetime.fromisoformat(body['authenticatedAt'].replace('Z', '+00:00'))
        require(authenticated.tzinfo is not None and authenticated.timestamp() >= int(resumed_at),
                'profile authentication predates this peer resume')
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        raise AssertionError('profile lacks a valid fresh authenticated timestamp') from None


async def stopped(pid):
    process = await asyncio.create_subprocess_exec('ps', '-o', 'state=', '-p', str(pid),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 2)
        return process.returncode == 0 and output.strip().startswith(b'T')
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


@asynccontextmanager
async def pause_owned(peers):
    """Resume every self-created child even if pause, query or owner is cancelled."""
    paused = []
    try:
        for peer in peers:
            require(peer.process.returncode is None, 'owned peer already exited')
            os.kill(peer.process.pid, signal.SIGSTOP)
            paused.append(peer)
        deadline = time.monotonic() + 2
        for peer in peers:
            while not await stopped(peer.process.pid):
                require(time.monotonic() < deadline, 'owned peer did not enter stopped state')
                await asyncio.sleep(0.02)

        def resume(peer):
            require(peer in paused, 'peer already resumed')
            os.kill(peer.process.pid, signal.SIGCONT)
            paused.remove(peer)
        yield resume
    finally:
        failures = 0
        for peer in paused:
            try:
                os.kill(peer.process.pid, signal.SIGCONT)
            except OSError:
                failures += 1
        require(not failures, 'failed to resume every paused peer')


async def resume_then_settle(base, pairs, resume_query, finish_query):
    """Complete all SIGCONT actions before starting any remaining-query wait."""
    resumed = [(peer, qid, resume_query(peer, qid)) for peer, qid in pairs]
    return await base.settle_all((dict(peer=peer.name, queryId=qid), finish_query(peer, qid, at))
                                 for peer, qid, at in resumed)


async def saturation(base, clients, profiles, pause=pause_owned, age=asyncio.sleep,
                     clock=time.monotonic, wall=time.time):
    observer, *peers = clients
    require(len(peers) == 4 and len({c.identity for c in clients}) == 5,
            'five independent SDK identities required')
    ledger = observer.query_ledger
    ids = [base.ident() for _ in peers]
    rejected, recovery = base.ident(), base.ident()
    for peer, qid in zip(peers, ids):
        ledger.register(qid, 'originalProfile', peer.name)
    ledger.register(rejected, 'rejectedGetDevices')
    ledger.register(recovery, 'recoveryGetDevices')  # Register before any SdkResult.
    marker = observer.mark()
    deadlines = {}
    facts = dict(accepted=[], terminalPeers=[], cacheAgeSeconds=CACHE_AGE, sdkQueryBudgetSeconds=QUERY_BUDGET)
    base.CURRENT.get()['facts'] = facts

    def remaining(qid):
        budget = deadlines[qid] - clock()
        require(budget > 0, 'original profile query budget expired')
        return min(25, budget)  # Never reset a per-peer SDK deadline at resume.

    async with pause(peers) as resume:
        await observer.cmd('getAuthState')
        aged_from = clock()
        await age(CACHE_AGE)
        require(clock() - aged_from >= CACHE_AGE, 'cache did not naturally expire')
        for peer, qid in zip(peers, ids):
            deadlines[qid] = clock() + QUERY_BUDGET
            ledger.mark(qid, 'submitted')
            result = await observer.cmd('getDeviceDescriptor', dict(queryId=qid, peerDeviceId=peer.identity))
            require('ok' in result, 'profile query was not accepted')
            ledger.mark(qid, 'accepted')
            facts['accepted'].append(dict(queryId=qid, peer=peer.name))
            ledger.absent(ids)
            remaining(ids[0])
        ledger.mark(rejected, 'submitted')
        await observer.cmd('getDevices', dict(queryId=rejected), error='RESOURCE_EXHAUSTED')
        ledger.mark(rejected, 'rejected')
        ledger.absent(ids + [rejected])
        remaining(ids[0])
        facts.update(pendingAtRejection=4, fifthError='RESOURCE_EXHAUSTED', rejectedQueryId=rejected)
        def resume_query(peer, qid):
            remaining(qid)
            ledger.absent([qid, rejected])
            resumed_at = wall()
            resume(peer)
            ledger.mark(qid, 'resumed')
            return resumed_at

        async def finish_query(peer, qid, resumed_at):
            try:
                await observer.wait(lambda e, qid=qid: e.get('deviceDescriptor', {}).get('queryId') == qid,
                                    timeout=remaining(qid), since=marker)
            except BaseException as error:
                ledger.wait_failed(qid, error)
                raise
            remaining(qid)
            check_profile(ledger.single(qid, 'deviceDescriptor'), peer.identity, profiles[peer.identity], resumed_at)
            ledger.mark(qid, 'validated')
            facts['terminalPeers'].append(dict(queryId=qid, peer=peer.name, fromCache=False))
            ledger.absent([rejected])

        await finish_query(peers[0], ids[0], resume_query(peers[0], ids[0]))
        ledger.absent(ids[1:] + [rejected])
        mark = observer.mark()
        ledger.mark(recovery, 'submitted')
        result = await observer.cmd('getDevices', dict(queryId=recovery))
        require('ok' in result, 'released global slot was not reusable')
        ledger.mark(recovery, 'accepted')
        await observer.wait(lambda e: e.get('devicesQuery', {}).get('queryId') == recovery,
                            timeout=remaining(ids[1]), since=mark)
        devices = ledger.single(recovery, 'devicesQuery').get('snapshot', {}).get('devices', [])
        require(len(devices) == 5 and {d.get('deviceId') for d in devices} == {c.identity for c in clients}
                and all(d.get('presence') == 'ONLINE' for d in devices),
                'slot recovery query lacks the five ONLINE real participants')
        require([d['deviceId'] for d in devices if d.get('isLocal')] == [observer.identity],
                'slot recovery query has the wrong self')
        ledger.absent(ids[1:] + [rejected])
        facts['slotReusedWithThreePending'] = True
        await resume_then_settle(base, zip(peers[1:], ids[1:]), resume_query, finish_query)
    return ids, rejected, recovery


def extend(base):
    original = base.Client

    class QueryClient(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.query_ledger = Ledger(error_codes=base.SDK_ERROR_CODES)

        def observe_event(self, event):
            super().observe_event(event)  # Preserve sequence/strict SDK validation gates.
            self.query_ledger.observe(event)

    base.Client = QueryClient


def check_final(suite, handles):
    require(handles is not None and len(suite.clients) == 5, 'saturation did not complete')
    ids, rejected, recovery = handles
    ledger = suite.clients[0].query_ledger
    for qid in ids:
        ledger.single(qid, 'deviceDescriptor')
    ledger.single(recovery, 'devicesQuery')
    ledger.absent([rejected])  # Includes late events during public shutdown and EOF.
    require(not suite.invalid_sdk, 'strict SDK validation failed')
    require(all(c.sdk_closed and c.process.returncode == 0 and not c.fatal for c in suite.clients),
            'not every SDK closed and exited cleanly')


async def run_plan(base, suite, stages):
    blocked, cancelled = None, None
    for cid, operation in stages:
        if blocked:
            async def skip():
                raise base.Skip('not executed: blocked by ' + blocked)
            await suite.case(cid, cid, skip)
        else:
            try:
                if not await suite.case(cid, cid, operation):
                    blocked = cid
            except asyncio.CancelledError as error:
                blocked, cancelled = cid, error
    if cancelled:
        raise cancelled


def record_final_ledger(suite):
    for row in suite.cases:
        if row['id'] == 'D07-FOUR-INFLIGHT' and suite.clients:
            row.setdefault('facts', {})['finalLedger'] = suite.clients[0].query_ledger.snapshot()


async def execute(base, args):
    os.umask(0o077)
    args.private_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    pinned = args.private_dir / 'cyberbus-test-client'
    shutil.copyfile(args.binary, pinned)
    pinned.chmod(0o700)
    require(sha256(pinned) == MACHINE, 'private machine differs from frozen 3ae5fc7 artifact')
    args.binary = pinned
    metadata = json.loads(subprocess.check_output([str(pinned), '--describe']))
    extend(base)
    suite = base.Suite(args, metadata)
    require(suite.provenance['sdkSourceCommit'] == SDK and not suite.provenance['sdkSourceDirty']
            and suite.provenance['binarySha256'] == MACHINE, 'frozen SDK changed during preflight')
    suite.provenance.update(controllerCommit=git(Path(__file__).parent, 'rev-parse', 'HEAD'),
        controllerDirty=bool(git(Path(__file__).parent, 'status', '--porcelain')),
        controllerSha256=sha256(__file__), runnerSha256=RUNNER)
    profiles, handles = {}, None

    async def prepare():
        for client in suite.clients:
            await suite.profile(client)
            profiles[client.identity] = (await client.query('getDeviceDescriptor', 'deviceDescriptor',
                                                           peerDeviceId=client.identity))['profile']

    async def online():
        await base.settle_all((dict(client=c.name), c.cmd('networkStart')) for c in suite.clients)
        await suite.converge()

    async def queries():
        nonlocal handles
        handles = await saturation(base, suite.clients, profiles)

    stages = [('QS-CREATE', suite.setup), ('QS-PROFILES', prepare)]
    stages += [('QS-LOGIN-' + str(i), lambda i=i: suite.login(suite.clients[i])) for i in range(5)]
    stages += [('QS-ONLINE', online), ('D07-FOUR-INFLIGHT', queries)]
    try:
        await run_plan(base, suite, stages)
    finally:
        # pause_owned's synchronous finally has resumed all children before cleanup.
        for client in suite.clients:
            if hasattr(client, 'process'):
                await suite.case('PROCESS-' + client.name, 'Public SDK close, receiver EOF and zero exit', client.terminate, 'close')
        if suite.relay:
            async def relay_close():
                suite.relay.stdin.close()
                try:
                    await asyncio.wait_for(suite.relay.wait(), 10)
                except asyncio.TimeoutError:
                    suite.relay.kill()
                    await suite.relay.wait()
                    raise AssertionError('owned relay cleanup exceeded budget') from None
                require(suite.relay.returncode == 0, 'owned relay exited nonzero')
            await suite.case('QS-RELAY-CLOSE', 'Owned relay cleanup', relay_close, 'close')
        # Preserve actual terminal observations even when saturation raised before
        # returning handles. This never upgrades a failed case or changes deadlines.
        record_final_ledger(suite)
        await suite.case('QS-FINAL', 'Query terminals checked through EOF', lambda: final_case(suite, handles))
        report = suite.report()
        report.update(format='cyberbus-query-capacity/1', fullG3Coverage=False,
                      scope='five-real-clients/four-pending-public-profile-queries')
        # Generic scale/API targets from Suite.report are outside this sidecar.
        report.pop('targets', None)
        report.pop('apiCoverage', None)
        report['scenarioPassed'] = all(row['status'] == 'PASS' for row in suite.cases)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['scenarioPassed'] else 1


async def final_case(suite, handles):
    check_final(suite, handles)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runner', 'sdk-source', 'binary', 'config', 'private-dir', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--login-driver', required=True)
    args = parser.parse_args()
    require(git(args.sdk_source, 'rev-parse', 'HEAD') == SDK and
            not git(args.sdk_source, 'status', '--porcelain'), 'requires clean frozen 3ae5fc7 SDK source')
    require(sha256(args.binary) == MACHINE, 'requires delivered immutable 3ae5fc7 Mac machine')
    require(not args.report.exists(), 'refuse to overwrite earlier evidence')
    base = load_base(args.runner.resolve())
    args.binary, args.private_dir = args.binary.resolve(), args.private_dir.resolve()
    args.n, args.suite, args.offline = 5, 'query-capacity', False
    args.local_relay, args.participants, args.store_mode = True, None, 'provision'
    args.converge_timeout = 180
    return asyncio.run(execute(base, args))


if __name__ == '__main__':
    raise SystemExit(main())
