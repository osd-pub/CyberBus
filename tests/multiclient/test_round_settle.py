"""Python controller fixtures only: no live SDK, authentication or scale claim."""
import asyncio
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import runner


class FixtureClient:
    def __init__(self, index, suite):
        self.name = 'client-'+str(index)
        self.identity = self.name
        self.suite = suite

    async def cmd(self, command):
        runner.CURRENT.get()['commands'].add(command)
        if self.suite.start_hook:
            await self.suite.start_hook(self)

    async def devices(self):
        if self.suite.view_hook:
            return await self.suite.view_hook(self)
        return [dict(deviceId=c.identity, presence='ONLINE') for c in self.suite.clients]


class FixtureSuite(runner.Suite):
    def __init__(self, n=4):
        # Exercise the actual case/report/large_cases/converge code without invoking
        # Suite's native-binary provenance subprocesses or any real client process.
        self.args = SimpleNamespace(suite='scale', network_concurrency=n,
                                    converge_timeout=1, offline=False, local_relay=False)
        self.cases, self.results, self.events = [], set(), set()
        self.nested, self.invalid_sdk = {}, []
        self.probes, self.relay = [], None
        self.started, self.provenance = time.time(), {}
        self.metadata = dict(shapes=dict(SdkCommand=[], SdkResult=[], SdkEvent=[]), clientApi=[])
        self.clients = [FixtureClient(i, self) for i in range(n)]
        self.start_hook = self.view_hook = self.exchange_hook = None
        self.attempts, self.active = [], set()

    async def login(self, client):
        pass

    async def restore_authenticated(self, client):
        pass

    async def data(self, sender, receiver):
        pair = (sender.name, receiver.name)
        self.attempts.append(pair)
        self.active.add(pair)
        try:
            runner.CURRENT.get()['commands'].add('send')
            if self.exchange_hook:
                await self.exchange_hook(sender, receiver)
            # This write fails if a case finalized its command set before settling.
            runner.CURRENT.get()['commands'].add('completeData')
        finally:
            self.active.remove(pair)

    async def setup(self):
        pass

    async def poll_api(self):
        pass

    async def offline_cases(self):
        pass

    async def offline_contract_cases(self):
        pass

    async def cleanup_cases(self):
        assert not self.active, 'cleanup overlapped outstanding round tasks'


class RoundSettle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def rounds(self, suite):
        return [row for row in suite.cases if row['id'].startswith('SCALE-ROUND-')]

    async def fixture_run(self, suite):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root.joinpath('controller-test-program')
            binary.write_bytes(b'not an SDK; describe is mocked')
            suite.args.binary = binary
            suite.args.private_dir = root/'private'
            suite.args.report = root/'report.json'
            with mock.patch.object(runner, 'Suite', return_value=suite), \
                 mock.patch.object(runner.subprocess, 'check_output', return_value=b'{}'):
                code = await runner.run(suite.args)
            return code, json.loads(suite.args.report.read_text())

    def assert_prerequisite_blocked(self, suite, result, blocking_case):
        code, report = result
        self.assertEqual(code, 1)
        self.assertFalse(report['fullCoverage'])
        self.assertEqual(report['summary']['FAIL'], 1)
        self.assertEqual(next(r for r in suite.cases if r['id'] == blocking_case)['status'], 'FAIL')
        rows = self.rounds(suite)
        self.assertEqual([r['id'] for r in rows],
                         ['SCALE-ROUND-'+str(i) for i in range(1, len(suite.clients))])
        self.assertTrue(all(r['status'] == 'SKIP' and blocking_case in r['reason'] for r in rows))
        self.assertFalse(suite.attempts, 'business ran after a prerequisite failed')
        self.assertFalse(suite.active)

    async def test_login_failure_explicitly_skips_all_remaining_planned_cases(self):
        suite = FixtureSuite(4)
        attempted = []

        async def login(client):
            attempted.append(client.name)
            raise runner.UnexpectedSdkError('UNAUTHENTICATED')

        async def forbidden(client=None):
            self.fail('blocked restore/startup/directory executed')

        suite.login = login
        suite.restore_authenticated = forbidden
        suite.start_hook = suite.view_hook = forbidden
        result = await self.fixture_run(suite)
        self.assert_prerequisite_blocked(suite, result, 'AUTH-LIVE-client-0')
        self.assertEqual(attempted, ['client-0'])
        expected = ['AUTH-LIVE-client-'+str(i) for i in range(1, 4)]+[
            'AUTH-RESTORE-AUTHENTICATED', 'SCALE-DIRECTORY']
        rows = [r for r in suite.cases if r['id'] in expected]
        self.assertEqual([r['id'] for r in rows], expected)
        self.assertTrue(all(r['status'] == 'SKIP' and 'AUTH-LIVE-client-0' in r['reason'] for r in rows))

    async def test_fast_failure_waits_for_slow_success_before_case_and_skips(self):
        suite = FixtureSuite()
        all_started, failed, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def exchange(sender, receiver):
            if len(suite.active) == len(suite.clients):
                all_started.set()
            await all_started.wait()
            if sender is suite.clients[0]:
                failed.set()
                raise runner.UnexpectedSdkError('DEVICE_UNREACHABLE')
            await finish.wait()

        suite.exchange_hook = exchange
        task = asyncio.create_task(suite.large_cases())
        try:
            await asyncio.wait_for(failed.wait(), 1)
            self.assertFalse(task.done())
            self.assertEqual(len(self.rounds(suite)), 1)
            self.assertNotIn('status', self.rounds(suite)[0])
            self.assertIsInstance(self.rounds(suite)[0]['commands'], set)
            finish.set()
            await asyncio.wait_for(task, 1)
        finally:
            finish.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        rows = self.rounds(suite)
        self.assertEqual([r['status'] for r in rows], ['FAIL', 'SKIP', 'SKIP'])
        self.assertEqual(rows[0]['facts']['failures'], [dict(
            sender='client-0', receiver='client-1',
            errorClass='UnexpectedSdkError', errorCode='DEVICE_UNREACHABLE')])
        self.assertTrue(all('not executed after SCALE-ROUND-1' in r['reason'] for r in rows[1:]))
        self.assertEqual(rows[0]['commands'], ['completeData', 'send'])
        self.assertEqual(len(suite.attempts), 4)
        self.assertFalse(suite.active)
        self.assertFalse(suite.report()['fullCoverage'])

    async def test_every_failed_direction_retained_without_external_text(self):
        suite = FixtureSuite()
        secret = 'sentinel external diagnostic must stay private'

        async def exchange(sender, receiver):
            if sender is suite.clients[0]:
                raise runner.UnexpectedSdkError('DEVICE_UNREACHABLE')
            if sender is suite.clients[1]:
                raise ValueError(secret)
            if sender is suite.clients[2]:
                raise runner.UnexpectedSdkError(secret)

        suite.exchange_hook = exchange
        await suite.large_cases()
        failures = self.rounds(suite)[0]['facts']['failures']
        self.assertEqual([(f['sender'], f['receiver']) for f in failures], [
            ('client-0', 'client-1'), ('client-1', 'client-2'), ('client-2', 'client-3')])
        self.assertEqual([f['errorClass'] for f in failures],
                         ['UnexpectedSdkError', 'ValueError', 'UnexpectedSdkError'])
        self.assertNotIn('errorCode', failures[2])
        self.assertNotIn(secret, json.dumps(suite.report()))
        self.assertFalse(suite.active)

    async def test_owner_cancel_waits_for_all_task_finalizers(self):
        entered, finalizing, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        tasks, started, closing = [], set(), set()

        async def operation(index):
            tasks.append(asyncio.current_task())
            started.add(index)
            if len(started) == 3:
                entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                closing.add(index)
                if len(closing) == 3:
                    finalizing.set()
                await finish.wait()

        owner = asyncio.create_task(runner.settle_all(
            (dict(client=str(i)), operation(i)) for i in range(3)))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            owner.cancel()
            await asyncio.wait_for(finalizing.wait(), 1)
            self.assertFalse(owner.done(), 'owner returned before child cleanup completed')
            finish.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(owner, 1)
            self.assertEqual(len(tasks), 3)
            self.assertTrue(all(t.done() and t.cancelled() for t in tasks))
        finally:
            finish.set()
            owner.cancel()
            await asyncio.gather(owner, return_exceptions=True)

    async def test_independently_cancelled_pair_is_a_failure(self):
        async def cancelled():
            raise asyncio.CancelledError()

        with self.assertRaises(runner.SettledFailure) as raised:
            await runner.settle_all([(dict(sender='a', receiver='b'), cancelled())])
        self.assertEqual(raised.exception.failures,
                         [dict(sender='a', receiver='b', errorClass='CancelledError')])

    async def test_actual_case_cancellation_drains_before_finalizing_commands(self):
        suite = FixtureSuite(3)
        entered, finalizing, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        closing = set()

        async def exchange(sender, receiver):
            if len(suite.active) == 3:
                entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                closing.add(sender.name)
                if len(closing) == 3:
                    finalizing.set()
                await finish.wait()
                runner.CURRENT.get()['commands'].add('completeData')

        suite.exchange_hook = exchange
        owner = asyncio.create_task(suite.large_cases())
        try:
            await asyncio.wait_for(entered.wait(), 1)
            owner.cancel()
            await asyncio.wait_for(finalizing.wait(), 1)
            row = self.rounds(suite)[0]
            self.assertIsInstance(row['commands'], set)
            self.assertFalse(owner.done())
            finish.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(owner, 1)
            self.assertEqual(row['status'], 'FAIL')
            self.assertEqual(row['reason'], 'controller case cancelled')
            self.assertEqual(row['commands'], ['completeData', 'send'])
            self.assertFalse(suite.active)
            self.assertEqual(len(self.rounds(suite)), 1)
        finally:
            finish.set()
            owner.cancel()
            await asyncio.gather(owner, return_exceptions=True)

    async def test_startup_failure_settles_all_network_starts(self):
        suite = FixtureSuite(3)
        failed, finish = asyncio.Event(), asyncio.Event()
        completed = set()

        async def start(client):
            if client is suite.clients[0]:
                failed.set()
                raise runner.UnexpectedSdkError('NETWORK_NOT_READY')
            await finish.wait()
            runner.CURRENT.get()['commands'].add('networkStart')
            completed.add(client.name)

        suite.start_hook = start
        owner = asyncio.create_task(self.fixture_run(suite))
        try:
            await asyncio.wait_for(failed.wait(), 1)
            self.assertFalse(owner.done())
            finish.set()
            result = await asyncio.wait_for(owner, 1)
        finally:
            finish.set()
            owner.cancel()
            await asyncio.gather(owner, return_exceptions=True)
        row = next(r for r in suite.cases if r['id'] == 'SCALE-DIRECTORY')
        self.assertEqual(row['status'], 'FAIL')
        self.assertEqual(row['facts']['failures'][0]['client'], 'client-0')
        self.assertEqual(completed, {'client-1', 'client-2'})
        self.assert_prerequisite_blocked(suite, result, 'SCALE-DIRECTORY')

    async def test_converge_query_failure_settles_without_retry(self):
        suite = FixtureSuite(3)
        failed, finish = asyncio.Event(), asyncio.Event()
        calls, completed = [], set()

        async def view(client):
            calls.append(client.name)
            if client is suite.clients[0]:
                failed.set()
                raise RuntimeError('private external diagnostic')
            await finish.wait()
            completed.add(client.name)
            return []

        suite.view_hook = view
        owner = asyncio.create_task(self.fixture_run(suite))
        try:
            await asyncio.wait_for(failed.wait(), 1)
            self.assertFalse(owner.done())
            finish.set()
            result = await asyncio.wait_for(owner, 1)
        finally:
            finish.set()
            owner.cancel()
            await asyncio.gather(owner, return_exceptions=True)
        self.assertEqual(calls, ['client-0', 'client-1', 'client-2'])
        self.assertEqual(completed, {'client-1', 'client-2'})
        self.assert_prerequisite_blocked(suite, result, 'SCALE-DIRECTORY')
        row = next(r for r in suite.cases if r['id'] == 'SCALE-DIRECTORY')
        self.assertEqual(row['facts']['failures'], [dict(client='client-0', errorClass='RuntimeError')])

    async def test_success_executes_n_minus_one_rounds_and_all_directed_pairs(self):
        suite = FixtureSuite(5)
        await suite.large_cases()
        rows = self.rounds(suite)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r['status'] == 'PASS' for r in rows))
        self.assertEqual([r['facts'] for r in rows],
                         [dict(directedPairs=5, offset=i) for i in range(1, 5)])
        expected = {(a.name, b.name) for a in suite.clients for b in suite.clients if a is not b}
        self.assertEqual(set(suite.attempts), expected)
        self.assertEqual(len(suite.attempts), 20)
        self.assertFalse(suite.active)
        self.assertTrue(suite.report()['fullCoverage'])
        suite.cases.remove(rows[-1])
        self.assertFalse(suite.report()['fullCoverage'], 'partial success claimed full scale')

    async def test_actual_run_returns_nonzero_and_report_keeps_fail_and_skips(self):
        suite = FixtureSuite(4)

        async def exchange(sender, receiver):
            offset = (suite.clients.index(receiver)-suite.clients.index(sender)) % 4
            if offset == 2 and sender is suite.clients[0]:
                raise runner.UnexpectedSdkError('DEVICE_UNREACHABLE')

        suite.exchange_hook = exchange
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root.joinpath('controller-test-program')
            binary.write_bytes(b'not an SDK; describe is mocked')
            suite.args.binary = binary
            suite.args.private_dir = root/'private'
            suite.args.report = root/'report.json'
            with mock.patch.object(runner, 'Suite', return_value=suite), \
                 mock.patch.object(runner.subprocess, 'check_output', return_value=b'{}'):
                code = await runner.run(suite.args)
            report = json.loads(suite.args.report.read_text())
        self.assertEqual(code, 1)
        self.assertFalse(report['fullCoverage'])
        rows = self.rounds(suite)
        self.assertEqual([r['status'] for r in rows], ['PASS', 'FAIL', 'SKIP'])
        self.assertIn('SCALE-ROUND-2', rows[-1]['reason'])
        self.assertEqual(len(suite.attempts), 8)
        self.assertEqual(report['summary']['FAIL'], 1)

    async def test_actual_command_retains_only_allowlisted_sdk_error_code(self):
        client = runner.Client('fixture', [], SimpleNamespace(results=set()))

        async def request(operation, command):
            return dict(commandId=command['commandId'],
                        error=dict(code='DEVICE_UNREACHABLE', message='private external text'))

        client.request = request
        with self.assertRaises(runner.UnexpectedSdkError) as raised:
            await client.cmd('send')
        self.assertEqual(raised.exception.code, 'DEVICE_UNREACHABLE')
        self.assertEqual(str(raised.exception), 'unexpected SDK error DEVICE_UNREACHABLE')


if __name__ == '__main__':
    unittest.main()
