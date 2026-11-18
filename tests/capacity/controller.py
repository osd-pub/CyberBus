#!/usr/bin/env python3
"""Reviewed live 256→257 sidecar. Imports a caller-pinned N-client runner."""
import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import types

FROZEN_SDK = '70f5f991b9d590fafba9346b33c503bed9f4b21c'
FROZEN_BINARY = '18113d4b132c3405ce6801e0de20549159130b4afa4a83d856bf9e437e91814b'
CURSOR_BASE_COMMIT = '329acc9a6101c5a56ae84b157af48e91f93021c1'
CURSOR_BASE_SHA = '3ed12f2f0af14de42d66a3038a1adffd786d41cd1d124d77aaebfd088eceb6d1'
LIMIT = 256
STAGES = ['CAPACITY-BASE-256', 'CAPACITY-257-CREATE', 'CAPACITY-257-SETUP',
          'CAPACITY-257-LOGIN', 'CAPACITY-257-START', 'CAPACITY-MEMBERSHIP',
          'CAPACITY-ADMITTED-DATA', 'CAPACITY-BUSINESS-GATES', 'CAPACITY-FINAL-VIEW']


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def device_bytes(identity):
    try:
        raw = base64.b64decode(identity, validate=True)
    except (ValueError, TypeError):
        raise AssertionError('device ID must be base64 bytes') from None
    require(len(raw) == 32, 'device ID must contain 32 bytes')
    return raw


def select_members(identities):
    require(len(identities) == LIMIT + 1, 'capacity requires 257 actual identities')
    ordered = sorted(identities, key=device_bytes)
    require(len({device_bytes(i) for i in ordered}) == LIMIT + 1,
            'installation identities must be distinct')
    return ordered[:LIMIT], ordered[LIMIT]


def check_view(owner, devices, members, excluded=None):
    ids = [d.get('deviceId') for d in devices]
    raw = [device_bytes(i) for i in ids]
    require(raw == sorted(raw) and len(set(raw)) == len(raw),
            'directory IDs must be unique and sorted by raw bytes')
    require(all(type(d.get('isLocal', False)) is bool for d in devices),
            'isLocal must be boolean')
    selves = [d for d in devices if d.get('isLocal') is True]
    require(len(selves) == 1 and selves[0]['deviceId'] == owner,
            'directory must contain exactly the correct self')
    if owner == excluded:
        require(ids == [owner] and selves[0].get('presence') == 'OFFLINE',
                'excluded directory must contain only OFFLINE self')
    else:
        require(ids == members, 'admitted directory differs from sorted selected membership')
        require(all(d.get('presence') == 'ONLINE' for d in devices),
                'every admitted directory entry must be ONLINE')


def check_network(identity, network, excluded):
    require(isinstance(network, dict) and network.get('running') is True,
            'capacity network must remain running')
    if identity == excluded:
        # Proto JSON omits false scalar values.
        require(network.get('reachable', False) is False and
                network.get('error', {}).get('code') == 'CAPACITY_EXCEEDED',
                'excluded network must report unreachable CAPACITY_EXCEEDED')
    else:
        require(network.get('reachable') is True and not network.get('error'),
                'admitted network must be reachable without error')


def passed_once(rows, cid):
    matches = [r for r in rows if r['id'] == cid]
    require(len(matches) == 1 and matches[0]['status'] == 'PASS',
            'required case must pass exactly once: ' + cid)
    return matches[0]


def check_base(rows, identities):
    require(len(identities) == LIMIT and len({device_bytes(i) for i in identities}) == LIMIT,
            'base cohort must contain 256 independent installations')
    require(not any(r.get('status') == 'FAIL' for r in rows), 'base harness has retained failures')
    directory = passed_once(rows, 'SCALE-DIRECTORY')
    require(directory.get('facts', {}).get('simultaneousClients') == LIMIT and
            directory['facts'].get('fullAuthenticatedDirectory') is True,
            'base full-directory evidence missing')
    for offset in range(1, LIMIT):
        row = passed_once(rows, 'SCALE-ROUND-' + str(offset))
        require(row.get('facts', {}).get('directedPairs') == LIMIT and
                row['facts'].get('offset') == offset, 'ordered-pair round evidence differs')
    rounds = [r for r in rows if r['id'].startswith('SCALE-ROUND-')]
    require(len(rounds) == LIMIT - 1, 'base must cover exactly 65,280 directed pairs')


def check_final(suite):
    require(len(suite.clients) == LIMIT + 1, 'not all 257 SDK clients were created')
    select_members([c.identity for c in suite.clients])
    for cid in STAGES:
        passed_once(suite.cases, cid)
    require(not suite.invalid_sdk, 'strict SDK output validation failed')
    require(not any(r['status'] == 'FAIL' for r in suite.cases), 'retained harness failure')
    for c in suite.clients:
        passed_once(suite.cases, 'CLOSE-' + c.name)
        passed_once(suite.cases, 'CLOSE-REJECT-' + c.name)
        passed_once(suite.cases, 'PROCESS-' + c.name)
        require(c.sdk_closed and c.process.returncode == 0 and not c.fatal,
                'all 257 SDK clients must close and exit zero')
        require(c.capacity_forbidden_callbacks == 0, 'excluded business callback observed')
    if suite.relay is not None:
        require(suite.relay.returncode == 0, 'owned relay did not exit zero')


def load_base(path, expected_sha):
    require(expected_sha == CURSOR_BASE_SHA, 'requires known cursor-safe 329acc9 base runner')
    source = path.read_bytes()
    require(hashlib.sha256(source).hexdigest() == expected_sha, 'base runner SHA-256 differs')
    module = types.ModuleType('capacity_base_' + expected_sha)
    module.__file__ = str(path.resolve())
    # Compile the exact bytes whose digest was verified; do not reread a mutable runner.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    require(callable(getattr(module.Client, 'mark', None)) and
            callable(getattr(module.Client, 'events_since', None)), 'base runner lacks absolute cursor API')
    return module


def extend(base, provenance):
    original_client, original_suite = base.Client, base.Suite

    class CapacityClient(original_client):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.capacity_network = None
            self.capacity_blocked_id = None
            self.capacity_forbidden_callbacks = 0

        def observe_event(self, event):
            super().observe_event(event)  # Preserve strict sequence and SDK observation gates.
            if 'network' in event:
                self.capacity_network = event['network']
            callback = event.get('dataReceived')
            rpc = event.get('rpc', {})
            if any(k in rpc for k in ('request', 'chunk', 'window')):
                callback = rpc
            if callback is not None and self.capacity_blocked_id is not None:
                if self.identity == self.capacity_blocked_id or callback.get('peerDeviceId') == self.capacity_blocked_id:
                    self.capacity_forbidden_callbacks += 1

    class CapacitySuite(original_suite):
        def __init__(self, args, metadata):
            super().__init__(args, metadata)
            # The base runner has now copied the binary into the private run.
            # Verify that copy too, before any participants can start.
            require(self.provenance['binarySha256'] == FROZEN_BINARY,
                    'private binary copy differs from frozen artifact')
            require(self.provenance['sdkSourceCommit'] == FROZEN_SDK and
                    not self.provenance['sdkSourceDirty'], 'SDK source changed during preflight')

        async def views(self):
            semaphore = asyncio.Semaphore(self.args.view_concurrency)

            async def query(c):
                async with semaphore:
                    require(not c.fatal and c.process.returncode is None,
                            'SDK process ended before capacity checks completed')
                    return await c.devices()
            results = await asyncio.wait_for(asyncio.gather(
                *(query(c) for c in self.clients), return_exceptions=True), self.args.view_timeout)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
            return results

        def validate_views(self, views, members, excluded=None):
            require(len(views) == len(self.clients), 'every live SDK must return a directory view')
            for c, view in zip(self.clients, views):
                check_view(c.identity, view, members, excluded)
                if excluded is not None:
                    check_network(c.identity, c.capacity_network, excluded)
            require(not self.invalid_sdk, 'SDK strict validation failed during capacity checks')

        async def exact_views(self, members, excluded=None):
            self.validate_views(await self.views(), members, excluded)

        def no_forbidden_callbacks(self):
            require(all(c.capacity_forbidden_callbacks == 0 for c in self.clients),
                    'business callback involving excluded installation observed')

        async def capacity_membership(self):
            self.capacity_members, self.capacity_excluded = select_members([c.identity for c in self.clients])
            deadline = time.monotonic() + self.args.capacity_timeout
            last = 'capacity views have not converged'
            while time.monotonic() < deadline:
                # Query/stream failures fail immediately; only valid but still
                # converging snapshots and capacity states enter the polling loop.
                views = await asyncio.wait_for(self.views(), max(0, deadline - time.monotonic()))
                try:
                    self.validate_views(views, self.capacity_members, self.capacity_excluded)
                    break
                except AssertionError as error:
                    # Only transient membership/state may converge. Process/codec faults
                    # are fatal; no case assertion or previously recorded FAIL is retried.
                    require(not self.invalid_sdk and all(not c.fatal and c.process.returncode is None
                            for c in self.clients), 'SDK stream/process fault during convergence')
                    last = str(error)
                await asyncio.sleep(min(1, max(0, deadline - time.monotonic())))
            else:
                raise AssertionError('capacity convergence deadline: ' + last)
            for c in self.clients:
                c.capacity_blocked_id = self.capacity_excluded
            # After first exact convergence any instability is a failure, not another attempt.
            until = time.monotonic() + self.args.capacity_stable_seconds
            while time.monotonic() < until:
                await asyncio.sleep(min(1, until - time.monotonic()))
                await self.exact_views(self.capacity_members, self.capacity_excluded)
                self.no_forbidden_callbacks()
            base.CURRENT.get()['facts'] = dict(selectedDeviceIds=self.capacity_members,
                excludedDeviceId=self.capacity_excluded, admittedClients=LIMIT,
                stableSeconds=self.args.capacity_stable_seconds, allAdmittedEntriesOnline=True,
                excludedSelfOnlyOffline=True, excludedNetworkError='CAPACITY_EXCEEDED')

        async def capacity_gates(self):
            excluded = next(c for c in self.clients if c.identity == self.capacity_excluded)
            admitted = [c for c in self.clients if c is not excluded]
            # Frozen SDK directory::ensure_peer / session::unavailable, not enum guesses:
            # excluded local Send => PERMISSION_DENIED; admitted Send to absent excluded
            # directory/session => DEVICE_UNREACHABLE. An accepted send is a failure.
            semaphore = asyncio.Semaphore(self.args.network_concurrency)
            failures = []
            facts = dict(attemptedOutbound=0, attemptedInbound=0,
                rejectedOutbound=0, rejectedInbound=0,
                outboundError='PERMISSION_DENIED', inboundError='DEVICE_UNREACHABLE',
                observationSeconds=self.args.gate_observation_seconds, failures=failures)
            base.CURRENT.get()['facts'] = facts  # Retain progress and failures even on timeout.

            async def probe(peer):
                async with semaphore:
                    for source, target, code in [(excluded, peer, 'PERMISSION_DENIED'),
                                                  (peer, excluded, 'DEVICE_UNREACHABLE')]:
                        direction = 'Outbound' if source is excluded else 'Inbound'
                        facts['attempted' + direction] += 1
                        try:
                            await source.cmd('send', dict(peerDeviceId=target.identity, message=dict(
                                messageId=base.ident(), requestedAck='PROCESSED', timeout='5s',
                                fragment=base.fragment('capacity-gate'))), error=code)
                            facts['rejected' + direction] += 1
                        except Exception as error:
                            failures.append(dict(source=source.name, target=target.name,
                                reason=str(error) if isinstance(error, AssertionError) else type(error).__name__))
                        self.no_forbidden_callbacks()
            results = await asyncio.wait_for(asyncio.gather(
                *(probe(peer) for peer in admitted), return_exceptions=True), self.args.gate_timeout)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
            require(not failures, 'capacity gate probes failed; all failures retained in case facts')
            await asyncio.sleep(self.args.gate_observation_seconds)
            self.no_forbidden_callbacks()
            base.CURRENT.get()['facts']['forbiddenCallbacks'] = 0

        async def large_cases(self):
            await super().large_cases()  # Same 256 installations, logins, directory and all rounds.
            extra = None

            async def base_gate():
                check_base(self.cases, [c.identity for c in self.clients])
                await self.exact_views(sorted([c.identity for c in self.clients], key=device_bytes))
                base.CURRENT.get()['facts'] = dict(independentInstallations=LIMIT, directedPairs=65280)

            async def create():
                nonlocal extra
                name = 'client-256'
                state = self.args.private_dir / name
                require(not state.exists(), '257th installation directory already exists')
                extra = CapacityClient(name, [str(self.args.binary), '--config', str(self.args.config),
                    '--state-dir', str(state), '--store-mode', 'provision'], self)
                self.clients.append(extra)  # Own cleanup even if start/identity/query fails.
                await extra.start()
                initial = await extra.devices()
                require(len(initial) == 1 and initial[0].get('isLocal') is True and
                        initial[0].get('presence') == 'OFFLINE', 'new installation self must start OFFLINE')
                extra.identity = initial[0]['deviceId']
                select_members([c.identity for c in self.clients])

            async def setup_extra():
                await self.profile(extra)
                await self.register(extra, 'UNARY')
                await self.register(extra, 'BIDI')
                await extra.cmd('subscribeData', dict(subscriptionId=extra.subscription, typeUrls=[base.REQUEST]))
                await extra.cmd('watchDevices', dict(watchId=extra.watch))

            async def start_extra():
                mark = extra.mark()
                await extra.cmd('networkStart')
                await extra.wait(lambda e: e.get('network', {}).get('running') is True, since=mark)
                require(any(m.get('event', {}).get('network', {}).get('running') is True
                            for m in extra.events_since(mark)), 'new network event missing from absolute range')

            async def admitted_data():
                admitted = [c for c in self.clients if c.identity in self.capacity_members]
                a = extra if extra in admitted else admitted[0]
                b = next(c for c in admitted if c is not a)
                await self.data(a, b)
                await self.data(b, a)
                self.no_forbidden_callbacks()

            async def final_view():
                await self.exact_views(self.capacity_members, self.capacity_excluded)
                self.no_forbidden_callbacks()

            actions = [base_gate, create, setup_extra, lambda: self.login(extra), start_extra,
                       self.capacity_membership, admitted_data, self.capacity_gates, final_view]
            blocked = False
            for cid, action in zip(STAGES, actions):
                if blocked:
                    async def skip():
                        raise base.Skip('capacity stage not run after earlier failure')
                    await self.case(cid, cid, skip)
                else:
                    blocked = not await self.case(cid, cid, action)

        def report(self):
            if not any(r['id'] == 'CAPACITY-ALL-257-CLEANUP' for r in self.cases):
                row = dict(id='CAPACITY-ALL-257-CLEANUP', title='All stages and all 257 clean SDK exits',
                           dimensions='close', commands=[], seconds=0)
                try:
                    check_final(self)
                    row.update(status='PASS', reason='all capacity stages and cleanup assertions satisfied')
                except AssertionError as error:
                    row.update(status='FAIL', reason=str(error))
                self.cases.append(row)
            report = super().report()
            report['capacity'] = dict(format='cyberbus-capacity/1', provenance=provenance,
                baseClients=LIMIT, requestedClients=LIMIT + 1, stages=STAGES,
                verdict=passed_status(self.cases, 'CAPACITY-ALL-257-CLEANUP'),
                selectedDeviceIds=getattr(self, 'capacity_members', []),
                excludedDeviceId=getattr(self, 'capacity_excluded', None),
                forbiddenCallbackCounts={c.name: c.capacity_forbidden_callbacks for c in self.clients
                                         if c.capacity_forbidden_callbacks},
                limitations=['Bounded stable-view and callback observation, not partition or re-admission proof',
                             'Inherited base harness limitations and all original cases remain in this report'])
            return report

    base.Client, base.Suite = CapacityClient, CapacitySuite
    return CapacityClient, CapacitySuite


def passed_status(rows, cid):
    return next(r['status'] for r in rows if r['id'] == cid)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-runner', type=Path, required=True)
    p.add_argument('--base-runner-sha256', required=True)
    p.add_argument('--controller-sha256', required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--sdk-source', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--private-dir', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--login-driver', required=True)
    p.add_argument('--local-relay', action='store_true')
    p.add_argument('--converge-timeout', type=float, default=300)
    p.add_argument('--network-concurrency', type=int, default=4)
    p.add_argument('--view-concurrency', type=int, default=4)
    p.add_argument('--view-timeout', type=float, default=60)
    p.add_argument('--gate-timeout', type=float, default=180)
    p.add_argument('--capacity-timeout', type=float, default=300)
    p.add_argument('--capacity-stable-seconds', type=float, default=15)
    p.add_argument('--gate-observation-seconds', type=float, default=2)
    return p


async def run(args):
    own = Path(__file__).resolve()
    require(sha256(own) == args.controller_sha256, 'controller SHA-256 differs')
    require(sha256(args.binary) == FROZEN_BINARY, 'binary differs from frozen 70f5f99 artifact')
    require(git(args.sdk_source, 'rev-parse', 'HEAD') == FROZEN_SDK, 'SDK source is not frozen 70f5f99')
    require(not git(args.sdk_source, 'status', '--porcelain'), 'frozen SDK source must be clean')
    require(not args.private_dir.exists(), 'capacity run requires a fresh private directory')
    base = load_base(args.base_runner.resolve(), args.base_runner_sha256)
    provenance = dict(sdkSourceCommit=FROZEN_SDK, binarySha256=FROZEN_BINARY,
        baseRunnerPath=str(args.base_runner.resolve()), baseRunnerSha256=args.base_runner_sha256,
        baseRunnerCommit=git(base.ROOT, 'rev-parse', 'HEAD'), cursorFixCommit=CURSOR_BASE_COMMIT,
        baseRunnerDirty=bool(git(base.ROOT, 'status', '--porcelain')),
        controllerPath=str(own), controllerSha256=sha256(own),
        controllerCommit=git(own.parent, 'rev-parse', 'HEAD'),
        controllerDirty=bool(git(own.parent, 'status', '--porcelain')))
    extend(base, provenance)
    # Fixed cohort, no capacity override, fixture mode, token import or participants override.
    args.n, args.suite, args.offline = LIMIT, 'scale', False
    args.participants, args.store_mode = None, 'provision'
    args.stability_seconds, args.restart_cycles = 1800, 100
    return await base.run(args)


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    values = [args.converge_timeout, args.capacity_timeout, args.capacity_stable_seconds,
              args.gate_observation_seconds, args.network_concurrency, args.view_concurrency,
              args.view_timeout, args.gate_timeout]
    if any(not 0 < v < float('inf') for v in values):
        p.error('timeouts, observation windows and concurrency must be finite and positive')
    try:
        return asyncio.run(run(args))
    except Exception as error:
        # External exceptions may contain OAuth requests. Detailed case failures live
        # in the base runner report; never print raw exception values here.
        print('capacity controller stopped: ' + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
