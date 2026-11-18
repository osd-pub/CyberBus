"""Python controller faults only; no real SDK, hosted auth, ps, pause or live claim."""
import asyncio
from contextlib import asynccontextmanager, redirect_stdout
from datetime import datetime, timezone
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import controller

ROOT = Path(__file__).resolve().parents[2]


class Scenario:
    def __init__(self, fault=None):
        self.base = controller.load_base(ROOT / 'tests/multiclient/runner.py')
        controller.extend(self.base)
        self.suite = SimpleNamespace(results=set(), observe=lambda event: None)
        self.clients = [self.base.Client('client-' + str(i), [], self.suite) for i in range(5)]
        for i, client in enumerate(self.clients):
            client.identity = 'identity-' + str(i)
            client.process = SimpleNamespace(pid=1000+i, returncode=0)
            client.sdk_closed = True
        self.profiles = {c.identity: dict(deviceName=c.name, configRevision='1') for c in self.clients}
        self.queries, self.resumed = {}, []
        self.profile_submissions = []
        self.fault, self.now, self.walltime = fault, 0, 1_000_000.5
        self.clients[0].query_ledger.clock = lambda:self.now
        self.entered = asyncio.Event()
        self.block = asyncio.Event()
        self.row = dict(commands=set())
        self.clients[0].request = self.request

    def emit(self, kind, body):
        client = self.clients[0]
        event = dict(eventSequence=str(client.sequence+1), **{kind:body})
        client.observe_event(event)  # Actual Client strict sequence + sidecar ledger hook.
        client.events.append(dict(event=event))

    async def request(self, op, command):
        require = controller.require
        require(op == 'execute', 'fixture only supports execute')
        kind = next(k for k in command if k != 'commandId')
        body = command[kind]
        result = dict(commandId=command['commandId'], ok={})
        if kind == 'getDeviceDescriptor':
            self.profile_submissions.append(body['queryId'])
            self.entered.set()
            if self.fault == 'cancel':
                await self.block.wait()
            if self.fault == 'reject-fourth' and len(self.queries) == 3:
                return dict(commandId=command['commandId'], error=dict(code='RESOURCE_EXHAUSTED'))
            self.queries[body['peerDeviceId']] = body['queryId']
            if self.fault == 'early':
                self.profile(body['peerDeviceId'])
            if self.fault == 'slow-admission':
                self.now += 31
        elif kind == 'getDevices':
            pending = set(self.queries) - set(self.resumed)
            if len(pending) == 4:
                self.rejected = body['queryId']
                if self.fault != 'accept-fifth':
                    return dict(commandId=command['commandId'], error=dict(code='RESOURCE_EXHAUSTED'))
            devices = [dict(deviceId=c.identity, presence='ONLINE', isLocal=i==0)
                       for i, c in enumerate(self.clients)]
            if self.fault == 'wrong-recovery-view':
                devices.pop()
            self.emit('devicesQuery', dict(queryId=body['queryId'], snapshot=dict(devices=devices)))
        return result

    def profile(self, peer):
        qid = self.queries[peer]
        body = dict(queryId=qid, peerDeviceId=peer, profile=self.profiles[peer],
                    authenticatedAt=datetime.fromtimestamp(self.walltime, timezone.utc).isoformat())
        if self.fault == 'cached':
            body['fromCache'] = True
        elif self.fault == 'wrong-peer':
            body['peerDeviceId'] = 'other-peer'
        elif self.fault == 'wrong-profile':
            body['profile'] = dict(deviceName='other-profile', configRevision='1')
        elif self.fault == 'stale-auth':
            body['authenticatedAt'] = '1970-01-01T00:00:00Z'
        elif self.fault == 'query-error':
            body.pop('profile')
            body['error'] = dict(code='DEADLINE_EXCEEDED')
        elif self.fault == 'wrong-qid':
            body['queryId'] = 'unrelated-query'
        elif self.fault == 'late-terminal':
            self.now += 31
        self.emit('deviceDescriptor', body)
        if self.fault == 'duplicate':
            self.emit('deviceDescriptor', body)

    @asynccontextmanager
    async def pause(self, peers):
        self.paused = list(peers)
        try:
            def resume(peer):
                self.resumed.append(peer.identity)
                self.paused.remove(peer)
                self.profile(peer.identity)
            yield resume
        finally:
            self.restored_on_exit = [c.identity for c in self.paused]
            self.paused.clear()

    async def age(self, seconds):
        if self.fault != 'short-age':
            self.now += seconds

    async def run(self):
        token = self.base.CURRENT.set(self.row)
        try:
            # Shorten ONLY fixture waits for an injected unmatched terminal.
            # The production function still supplies its original remaining budget.
            observer = self.clients[0]
            original_wait = observer.wait
            if self.fault == 'wrong-qid':
                async def fixture_wait(predicate, **kwargs):
                    return await original_wait(predicate, **dict(kwargs, timeout=0.01))
                observer.wait = fixture_wait
            self.handles = await controller.saturation(self.base, self.clients, self.profiles,
                pause=self.pause, age=self.age, clock=lambda:self.now, wall=lambda:self.walltime)
            return self.handles
        finally:
            self.base.CURRENT.reset(token)

    def final(self):
        suite = SimpleNamespace(clients=self.clients, invalid_sdk=[])
        controller.check_final(suite, self.handles)


class RetryScenario(Scenario):
    """Event-driven logical clock: each real-path profile needs 8s after resume.

    The same production correlation/profile/deadline checks consume these events.
    Responses and original SDK deadlines advance together, not once per waiter.
    """
    def __init__(self):
        super().__init__()
        self.sdk_deadlines, self.ready, self.waiters = {}, {}, []
        self.resume_times, self.reply_times = {}, {}
        self.pump = None
        self.clients[0].wait = self.wait

    async def request(self, op, command):
        result = await super().request(op, command)
        if 'getDeviceDescriptor' in command:
            peer = command['getDeviceDescriptor']['peerDeviceId']
            self.sdk_deadlines[peer] = self.now + controller.QUERY_BUDGET
        return result

    def match(self, predicate, since):
        for message in self.clients[0].events_since(since):
            event = message.get('event', {})
            if predicate(event):
                return event

    async def wait(self, predicate, timeout=25, since=None):
        match = self.match(predicate, since)
        if match is not None:
            return match
        future = asyncio.get_running_loop().create_future()
        self.waiters.append((self.now + timeout, predicate, since, future))
        if self.pump is None or self.pump.done():
            self.pump = asyncio.create_task(self.advance())
        return await future

    async def advance(self):
        while self.ready or any(not f.done() for _, _, _, f in self.waiters):
            dates = list(self.ready.values()) + [at for at, _, _, f in self.waiters if not f.done()]
            assert min(dates) >= self.now, 'fixture clock cannot move backwards'
            self.now = min(dates)
            self.walltime = 1_000_000.5 + self.now
            for peer, at in list(self.ready.items()):
                if at <= self.now:
                    del self.ready[peer]
                    self.reply_times[peer] = self.now
                    if self.resume_times[peer] + 8 <= self.sdk_deadlines[peer]:
                        self.profile(peer)
                    else:
                        self.emit('deviceDescriptor', dict(queryId=self.queries[peer], peerDeviceId=peer,
                            error=dict(code='DEADLINE_EXCEEDED')))
            for at, predicate, since, future in self.waiters:
                if future.done():
                    continue
                match = self.match(predicate, since)
                if match is not None:
                    future.set_result(match)
                elif at <= self.now:
                    future.set_exception(AssertionError('expected correlated event timed out'))
            await asyncio.sleep(0)  # Run ready waiters before advancing the clock again.

    @asynccontextmanager
    async def pause(self, peers):
        self.paused = list(peers)
        try:
            def resume(peer):
                self.resumed.append(peer.identity)
                self.paused.remove(peer)
                self.resume_times[peer.identity] = self.now
                self.ready[peer.identity] = min(self.now + 8, self.sdk_deadlines[peer.identity])
            yield resume
        finally:
            self.restored_on_exit = [c.identity for c in self.paused]
            self.paused.clear()

    async def run(self):
        try:
            return await super().run()
        finally:
            if self.pump is not None:
                await self.pump


class ControllerTests(unittest.IsolatedAsyncioTestCase):
    async def test_eight_second_retry_old_serial_exhausts_new_batch_keeps_original_budget(self):
        # Negative control: old per-peer SIGCONT -> wait -> next SIGCONT ordering,
        # using the SAME production finish_query and all its original assertions.
        async def old_serial(base, pairs, resume_query, finish_query):
            for peer, qid in pairs:
                await finish_query(peer, qid, resume_query(peer, qid))
        old = RetryScenario()
        with mock.patch.object(controller, 'resume_then_settle', new=old_serial):
            with self.assertRaisesRegex(AssertionError, 'original profile query budget expired'):
                await old.run()
        final_peer = old.clients[4].identity
        self.assertEqual(old.resume_times[final_peer] - controller.CACHE_AGE, 24)
        self.assertEqual(old.now - controller.CACHE_AGE, 30)
        self.assertEqual(len(old.row['facts']['terminalPeers']), 3)
        self.assertEqual(old.clients[0].query_ledger.first[old.queries[final_peer]][1]['error']['code'],
                         'DEADLINE_EXCEEDED')

        new = RetryScenario()
        await new.run()
        new.final()  # Original exactly-once, rejected-ID and EOF/exit assertions.
        self.assertTrue(new.row['facts']['slotReusedWithThreePending'])
        self.assertEqual(new.row['facts']['pendingAtRejection'], 4)
        self.assertEqual(len(new.profile_submissions), 4)  # No replacement query or resubmission.
        self.assertEqual(new.profile_submissions, [r['queryId'] for r in new.row['facts']['accepted']])
        self.assertEqual(len(new.row['facts']['terminalPeers']), 4)
        self.assertEqual(new.now - controller.CACHE_AGE, 16)
        self.assertEqual({new.resume_times[c.identity] - controller.CACHE_AGE for c in new.clients[2:]}, {8})
        self.assertTrue(all(new.reply_times[c.identity] < new.sdk_deadlines[c.identity] for c in new.clients[1:]))

    async def test_resumed_cohort_settles_all_errors_and_drains_owner_cancel(self):
        base = controller.load_base(ROOT / 'tests/multiclient/runner.py')
        peers = [SimpleNamespace(name='client-' + str(i)) for i in range(3)]
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                resumed, finished, active = [], [], set()
                entered = asyncio.Event()
                def resume(peer, qid):
                    resumed.append(peer.name)
                    return 0
                async def finish(peer, qid, at):
                    self.assertEqual(resumed, [p.name for p in peers])
                    active.add(peer.name)
                    if len(active) == 3:
                        entered.set()
                    try:
                        if cancelled:
                            await asyncio.Event().wait()
                        await asyncio.sleep(0)
                        if peer is not peers[2]:
                            raise base.UnexpectedSdkError('UNAVAILABLE')
                    finally:
                        active.remove(peer.name)
                        finished.append(peer.name)
                task = asyncio.create_task(controller.resume_then_settle(base,
                    [(p, 'qid-' + str(i)) for i, p in enumerate(peers)], resume, finish))
                if cancelled:
                    await entered.wait()
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                else:
                    with self.assertRaises(base.SettledFailure) as raised:
                        await task
                    self.assertEqual([f['peer'] for f in raised.exception.failures], [p.name for p in peers[:2]])
                    self.assertEqual([f['queryId'] for f in raised.exception.failures], ['qid-0', 'qid-1'])
                self.assertEqual(active, set())
                self.assertEqual(set(finished), {p.name for p in peers})

    async def test_success_four_pending_cross_command_rejection_and_slot_recovery(self):
        scenario = Scenario()
        ids, rejected, recovery = await scenario.run()
        scenario.final()
        self.assertEqual(scenario.row['facts']['pendingAtRejection'], 4)
        self.assertTrue(scenario.row['facts']['slotReusedWithThreePending'])
        self.assertEqual(scenario.resumed, [c.identity for c in scenario.clients[1:]])
        self.assertEqual(len(scenario.row['facts']['terminalPeers']), 4)
        self.assertEqual(len(set(ids + [rejected, recovery])), 6)

    async def test_admission_and_cache_barriers_fail_closed(self):
        for fault in ('short-age', 'early', 'reject-fourth', 'accept-fifth', 'slow-admission'):
            with self.subTest(fault=fault):
                scenario = Scenario(fault)
                with self.assertRaises(AssertionError):
                    await scenario.run()
                self.assertEqual(scenario.paused, [])

    async def test_each_original_query_needs_its_own_exact_fresh_profile(self):
        for fault in ('cached', 'wrong-peer', 'wrong-profile', 'stale-auth', 'query-error',
                      'wrong-qid', 'duplicate', 'late-terminal', 'wrong-recovery-view'):
            with self.subTest(fault=fault):
                scenario = Scenario(fault)
                with self.assertRaises(AssertionError):
                    await scenario.run()
                self.assertEqual(scenario.paused, [])

    async def test_late_rejected_id_event_or_duplicate_until_eof_fails(self):
        for fault in ('rejected', 'duplicate'):
            with self.subTest(fault=fault):
                scenario = Scenario()
                ids, rejected, _ = await scenario.run()
                if fault == 'rejected':
                    scenario.emit('blockedDevices', dict(queryId=rejected, snapshot={}))
                else:
                    scenario.profile(scenario.clients[1].identity)
                with self.assertRaises(AssertionError):
                    scenario.final()

    async def test_nonzero_exit_missing_close_or_invalid_sdk_fails(self):
        for fault in ('exit', 'close', 'fatal', 'codec'):
            with self.subTest(fault=fault):
                scenario = Scenario()
                await scenario.run()
                suite = SimpleNamespace(clients=scenario.clients, invalid_sdk=[])
                if fault == 'exit':
                    scenario.clients[2].process.returncode = 1
                elif fault == 'close':
                    scenario.clients[2].sdk_closed = False
                elif fault == 'fatal':
                    scenario.clients[2].fatal = 'fixture stream failure'
                else:
                    suite.invalid_sdk.append(dict(kind='event'))
                with self.assertRaises(AssertionError):
                    controller.check_final(suite, scenario.handles)

    async def test_cancel_pending_command_restores_every_peer(self):
        scenario = Scenario('cancel')
        task = asyncio.create_task(scenario.run())
        await scenario.entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(scenario.paused, [])
        self.assertEqual(len(scenario.restored_on_exit), 4)

    async def test_actual_pause_finally_resumes_all_on_cancel_or_partial_stop_failure(self):
        peers = [SimpleNamespace(process=SimpleNamespace(pid=1000+i, returncode=None)) for i in range(4)]
        for failure in ('cancel', 'partial'):
            with self.subTest(failure=failure):
                calls = []
                def kill(pid, sig):
                    if failure == 'partial' and pid == 1002 and sig == controller.signal.SIGSTOP:
                        raise ProcessLookupError()
                    calls.append((pid, sig))
                entered = asyncio.Event()
                async def operation():
                    async with controller.pause_owned(peers):
                        entered.set()
                        await asyncio.Event().wait()
                with mock.patch.object(controller.os, 'kill', side_effect=kill), \
                     mock.patch.object(controller, 'stopped', new=mock.AsyncMock(return_value=True)):
                    task = asyncio.create_task(operation())
                    if failure == 'cancel':
                        await entered.wait()
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        with self.assertRaises(ProcessLookupError):
                            await task
                stops = [pid for pid, sig in calls if sig == controller.signal.SIGSTOP]
                continues = [pid for pid, sig in calls if sig == controller.signal.SIGCONT]
                self.assertEqual(stops, continues)

    async def test_blocking_failure_or_cancel_enumerates_remaining_skips(self):
        base = controller.load_base(ROOT / 'tests/multiclient/runner.py')
        for cancellation in (False, True):
            with self.subTest(cancellation=cancellation):
                suite = base.Suite.__new__(base.Suite)
                suite.cases = []
                executed = []
                async def fail():
                    if cancellation:
                        raise asyncio.CancelledError()
                    raise AssertionError('fixture prerequisite failure')
                async def forbidden():
                    executed.append('unexpected dependent work')
                plan = [('QS-LOGIN-0', fail), ('QS-LOGIN-1', forbidden), ('QS-ONLINE', forbidden),
                        ('D07-FOUR-INFLIGHT', forbidden)]
                with redirect_stdout(io.StringIO()):
                    if cancellation:
                        with self.assertRaises(asyncio.CancelledError):
                            await controller.run_plan(base, suite, plan)
                    else:
                        await controller.run_plan(base, suite, plan)
                self.assertEqual([r['status'] for r in suite.cases], ['FAIL', 'SKIP', 'SKIP', 'SKIP'])
                self.assertTrue(all('QS-LOGIN-0' in r['reason'] for r in suite.cases[1:]))
                self.assertEqual(executed, [])

    async def test_failed_wait_retains_late_sdk_terminal_without_changing_failure(self):
        scenario = Scenario('wrong-qid')
        with self.assertRaisesRegex(AssertionError, 'expected correlated event timed out'):
            await scenario.run()
        ledger = scenario.clients[0].query_ledger
        original = next(row for row in ledger.snapshot() if row.get('peer') == 'client-1')
        self.assertEqual(original['terminalCount'], 0)
        self.assertEqual(original['controllerWaitOutcome'], 'TIMEOUT')
        self.assertIn('resumedSeconds', original)
        self.assertNotIn('validatedSeconds', original)
        scenario.now += 1
        scenario.emit('deviceDescriptor', dict(queryId=original['queryId'],
            error=dict(code='DEADLINE_EXCEEDED', message='private external text'),
            profile=dict(deviceName='private profile content')))
        failed = dict(id='D07-FOUR-INFLIGHT', status='FAIL', reason='expected correlated event timed out')
        suite = SimpleNamespace(clients=scenario.clients, cases=[failed])
        controller.record_final_ledger(suite)
        final = next(row for row in failed['facts']['finalLedger'] if row['queryId'] == original['queryId'])
        self.assertEqual(final['terminalCount'], 1)
        self.assertEqual(final['controllerWaitOutcome'], 'TIMEOUT')
        self.assertEqual(final['firstTerminal']['sdkErrorCode'], 'DEADLINE_EXCEEDED')
        self.assertNotIn('fromCache', final['firstTerminal'])
        self.assertGreater(final['firstTerminal']['observedSeconds'], final['controllerWaitFailedSeconds'])
        self.assertEqual(failed['status'], 'FAIL')
        self.assertNotIn('private', str(failed['facts']))

    async def test_safe_snapshot_keeps_success_counts_and_rejects_unknown_error_strings(self):
        scenario = Scenario()
        _, rejected, _ = await scenario.run()
        ledger = scenario.clients[0].query_ledger
        before = ledger.snapshot()
        profiles = [row for row in before if row['role'] == 'originalProfile']
        self.assertEqual(len(profiles), 4)
        self.assertTrue(all(row['terminalCount'] == 1 and 'validatedSeconds' in row for row in profiles))
        scenario.emit('blockedDevices', dict(queryId=rejected,
            error=dict(code='external secret value', message='external secret value')))
        final = next(row for row in ledger.snapshot() if row['queryId'] == rejected)
        self.assertEqual(final['firstTerminal']['sdkErrorCode'], 'UNRECOGNIZED')
        self.assertNotIn('secret', str(final))


if __name__ == '__main__':
    unittest.main()
