"""Controller rejection fixtures only. No live SDK capacity evidence."""
import asyncio
import base64
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
from types import MethodType, SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import controller as c


def identity(n):
    return base64.b64encode(n.to_bytes(32, 'big')).decode()


IDS = [identity(n) for n in range(257)]
MEMBERS, EXCLUDED = c.select_members(IDS)


def view(owner, members=MEMBERS):
    ids = [owner] if owner == EXCLUDED else members
    return [dict(deviceId=i, isLocal=i == owner,
                 presence='OFFLINE' if owner == EXCLUDED else 'ONLINE') for i in ids]


def base_rows():
    return [dict(id='SCALE-DIRECTORY', status='PASS',
                 facts=dict(simultaneousClients=256, fullAuthenticatedDirectory=True))] + [
        dict(id='SCALE-ROUND-' + str(i), status='PASS', facts=dict(offset=i, directedPairs=256))
        for i in range(1, 256)]


def final_fixture():
    clients = [SimpleNamespace(identity=i, name='client-' + str(n), sdk_closed=True,
        process=SimpleNamespace(returncode=0), fatal=None, capacity_forbidden_callbacks=0)
        for n, i in enumerate(IDS)]
    rows = [dict(id=i, status='PASS') for i in c.STAGES]
    rows += [dict(id=prefix + client.name, status='PASS') for client in clients
             for prefix in ('CLOSE-', 'CLOSE-REJECT-', 'PROCESS-')]
    return SimpleNamespace(clients=clients, cases=rows, invalid_sdk=[], relay=None)


class CapacityChecks(unittest.TestCase):
    def test_raw_byte_sort_and_either_installation_can_be_excluded(self):
        self.assertNotEqual(sorted(IDS), sorted(IDS, key=c.device_bytes))
        self.assertEqual(c.select_members(list(reversed(IDS))), (MEMBERS, EXCLUDED))
        # The additional installation may be selected or excluded; creation order is irrelevant.
        self.assertIn(IDS[0], c.select_members(IDS[1:] + IDS[:1])[0])
        self.assertEqual(c.select_members(IDS)[1], IDS[-1])
        for malformed in [IDS[:-1], IDS[:-1] + [IDS[0]], IDS[:-1] + ['bad']]:
            with self.assertRaises(AssertionError):
                c.select_members(malformed)

    def test_exact_members_presence_order_and_self_are_all_required(self):
        good = view(MEMBERS[0])
        c.check_view(MEMBERS[0], good, MEMBERS, EXCLUDED)
        variants = []
        wrong_member = copy.deepcopy(good)
        wrong_member[-1]['deviceId'] = EXCLUDED
        variants.append(wrong_member)
        for field, value in [('presence', 'OFFLINE'), ('presence', None), ('isLocal', True),
                             ('isLocal', 'true')]:
            bad = copy.deepcopy(good)
            bad[1][field] = value
            variants.append(bad)
        variants += [list(reversed(good)), good[:-1], good + [good[0]]]
        missing_self = copy.deepcopy(good)
        missing_self[0]['isLocal'] = False
        variants.append(missing_self)
        for bad in variants:
            with self.subTest(bad=variants.index(bad)), self.assertRaises(AssertionError):
                c.check_view(MEMBERS[0], bad, MEMBERS, EXCLUDED)

    def test_excluded_requires_self_only_offline_and_exact_network_capacity_state(self):
        c.check_view(EXCLUDED, view(EXCLUDED), MEMBERS, EXCLUDED)
        network = dict(running=True, error=dict(code='CAPACITY_EXCEEDED'))
        c.check_network(EXCLUDED, network, EXCLUDED)
        for bad in [[dict(deviceId=EXCLUDED, isLocal=True, presence='ONLINE')],
                    view(EXCLUDED) + [dict(deviceId=MEMBERS[0], presence='ONLINE')]]:
            with self.assertRaises(AssertionError):
                c.check_view(EXCLUDED, bad, MEMBERS, EXCLUDED)
        for bad in [None, dict(running=False, error=dict(code='CAPACITY_EXCEEDED')),
                    dict(running=True, reachable=True, error=dict(code='CAPACITY_EXCEEDED')),
                    dict(running=True, error=dict(code='PERMISSION_DENIED'))]:
            with self.assertRaises(AssertionError):
                c.check_network(EXCLUDED, bad, EXCLUDED)
        c.check_network(MEMBERS[0], dict(running=True, reachable=True), EXCLUDED)
        with self.assertRaises(AssertionError):
            c.check_network(MEMBERS[0], network, EXCLUDED)

    def test_257_cannot_begin_with_missing_failed_or_incorrect_base_rounds(self):
        c.check_base(base_rows(), IDS[:256])
        for fault in ['missing', 'fail', 'skip', 'duplicate', 'pairs', 'offset', 'directory', 'other_fail']:
            rows = base_rows()
            if fault == 'missing': rows.pop()
            if fault == 'fail': rows[1]['status'] = 'FAIL'
            if fault == 'skip': rows[1]['status'] = 'SKIP'
            if fault == 'duplicate': rows.append(copy.deepcopy(rows[1]))
            if fault == 'pairs': rows[1]['facts']['directedPairs'] = 255
            if fault == 'offset': rows[1]['facts']['offset'] = 2
            if fault == 'directory': rows[0]['facts']['fullAuthenticatedDirectory'] = False
            if fault == 'other_fail': rows.append(dict(id='AUTH-failure', status='FAIL'))
            with self.subTest(fault=fault), self.assertRaises(AssertionError):
                c.check_base(rows, IDS[:256])

    def test_final_requires_every_stage_all_257_zero_exits_and_no_hidden_failures(self):
        c.check_final(final_fixture())
        for fault in ['nonzero', 'early', 'not_closed', 'fatal', 'callback', 'invalid',
                      'missing_client', 'missing_case', 'skip', 'other_fail', 'relay']:
            suite = final_fixture()
            last = suite.clients[-1]
            if fault == 'nonzero': last.process.returncode = 3
            if fault == 'early': last.process.returncode = None
            if fault == 'not_closed': last.sdk_closed = False
            if fault == 'fatal': last.fatal = 'stream error'
            if fault == 'callback': last.capacity_forbidden_callbacks = 1
            if fault == 'invalid': suite.invalid_sdk.append({})
            if fault == 'missing_client': suite.clients.pop()
            if fault == 'missing_case': suite.cases.pop()
            if fault == 'skip': suite.cases[0]['status'] = 'SKIP'
            if fault == 'other_fail': suite.cases.append(dict(id='base-fault', status='FAIL'))
            if fault == 'relay': suite.relay = SimpleNamespace(returncode=1)
            with self.subTest(fault=fault), self.assertRaises(AssertionError):
                c.check_final(suite)

    def test_unknown_or_modified_base_runner_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runner.py'
            path.write_text('raise RuntimeError("must not execute")')
            with self.assertRaisesRegex(AssertionError, 'known cursor-safe'):
                c.load_base(path, c.sha256(path))
            with self.assertRaisesRegex(AssertionError, 'SHA-256 differs'):
                c.load_base(path, c.CURSOR_BASE_SHA)


class BaseIntegrationFixtures(unittest.IsolatedAsyncioTestCase):
    def base(self):
        path = os.environ.get('CAPACITY_BASE_RUNNER')
        self.assertIsNotNone(path, 'set CAPACITY_BASE_RUNNER to the reviewed cursor-safe runner.py')
        base = c.load_base(Path(path).resolve(), c.CURSOR_BASE_SHA)
        Client, Suite = c.extend(base, {})
        return base, Client, Suite

    async def test_observer_preserves_sequence_checks_and_cannot_lose_absence_evidence_to_trim(self):
        base, Client, Suite = self.base()
        suite = SimpleNamespace(observe=lambda event: None, invalid_sdk=[], results=set())
        client = Client('excluded', [], suite)
        client.identity = EXCLUDED
        client.capacity_blocked_id = EXCLUDED
        client.observe_event(dict(eventSequence='1', network=dict(running=True,
            error=dict(code='CAPACITY_EXCEEDED'))))
        client.observe_event(dict(eventSequence='2', dataReceived=dict(peerDeviceId=MEMBERS[0])))
        self.assertEqual(client.capacity_forbidden_callbacks, 1)
        client.events.clear()
        client.event_base = 9000
        self.assertEqual(client.mark(), 9000)
        self.assertEqual(client.events_since(client.mark()), [])
        with self.assertRaises(AssertionError): client.events_since(0)
        self.assertEqual(client.capacity_forbidden_callbacks, 1)
        with self.assertRaises(AssertionError): client.observe_event(dict(eventSequence='2'))

    async def test_base_failure_prevents_extra_installation_and_preserves_original_rows(self):
        base, Client, Suite = self.base()
        suite = Suite.__new__(Suite)
        suite.cases = base_rows()
        suite.cases[1]['status'] = 'FAIL'
        suite.clients = [SimpleNamespace(identity=i) for i in IDS[:256]]
        async def completed(_self): pass
        # Replace only the fixture's base action; the sidecar's gating/case machinery is real.
        original = Suite.__mro__[1].large_cases
        Suite.__mro__[1].large_cases = completed
        try:
            await suite.large_cases()
        finally:
            Suite.__mro__[1].large_cases = original
        self.assertEqual(suite.cases[1]['status'], 'FAIL')
        self.assertEqual(len(suite.clients), 256)
        self.assertEqual(c.passed_status(suite.cases, 'CAPACITY-BASE-256'), 'FAIL')
        self.assertTrue(all(c.passed_status(suite.cases, stage) == 'SKIP' for stage in c.STAGES[1:]))

    async def test_real_base_client_rejects_nonzero_process_even_after_successful_close(self):
        base, Client, Suite = self.base()
        wire = '''import json,sys
print(json.dumps({'ready':True}),flush=True)
for line in sys.stdin:
 r=json.loads(line)
 print(json.dumps({'id':r['id'],'ok':True,'result':{'sdkClosed':{'closed':True}}}),flush=True)
 break
sys.exit(7)
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'peer.py'
            path.write_text(wire)
            suite = SimpleNamespace(observe=lambda e: None, invalid_sdk=[], results=set())
            client = Client('exit-fixture', [sys.executable, str(path)], suite)
            await client.start()
            with self.assertRaises(AssertionError): await client.terminate()
            self.assertEqual(client.process.returncode, 7)

    async def test_gate_rejects_accepted_send_and_wrong_error_without_hiding_other_failures(self):
        for fault in ['valid', 'accepted', 'wrong_error', 'timeout']:
            base, Client, Suite = self.base()
            suite = Suite.__new__(Suite)
            suite.cases, suite.results, suite.invalid_sdk = [], set(), []
            suite.capacity_excluded = EXCLUDED
            suite.args = SimpleNamespace(network_concurrency=1 if fault == 'timeout' else 4,
                                         gate_timeout=0.02 if fault == 'timeout' else 5,
                                         gate_observation_seconds=0.001)
            suite.clients = [Client('client-' + str(n), [], suite) for n in range(257)]
            for client, ident in zip(suite.clients, IDS):
                client.identity = ident

                async def request(self, operation, **kwargs):
                    if fault == 'timeout' and self.identity == IDS[1]:
                        await asyncio.sleep(10)
                    command = kwargs['command']
                    error = 'PERMISSION_DENIED' if self.identity == EXCLUDED else 'DEVICE_UNREACHABLE'
                    result = dict(commandId=command['commandId'], error=dict(code=error))
                    if fault != 'valid' and self.identity in IDS[:2]:
                        if fault == 'accepted': result.pop('error')
                        else: result['error']['code'] = 'UNAUTHENTICATED'
                    return result
                client.request = MethodType(request, client)
            ok = await suite.case('CAPACITY-BUSINESS-GATES', 'fixture gates', suite.capacity_gates)
            self.assertEqual(ok, fault == 'valid')
            facts = suite.cases[-1]['facts']
            self.assertEqual(len(facts['failures']), 0 if fault == 'valid' else 1 if fault == 'timeout' else 2)
            self.assertEqual(facts['rejectedInbound'], 256 if fault == 'valid' else 0 if fault == 'timeout' else 254)

    async def test_query_failure_is_not_retried_as_capacity_convergence(self):
        base, Client, Suite = self.base()
        suite = Suite.__new__(Suite)
        suite.cases, suite.invalid_sdk = [], []
        suite.clients = [SimpleNamespace(identity=i) for i in IDS]
        suite.args = SimpleNamespace(capacity_timeout=1)
        queries = []
        async def rejected():
            queries.append(True)
            raise AssertionError('unexpected SDK error UNAUTHENTICATED')
        suite.views = rejected
        self.assertFalse(await suite.case('CAPACITY-MEMBERSHIP', 'query fault', suite.capacity_membership))
        self.assertEqual(len(queries), 1)

    async def test_successful_hook_reuses_original_objects_and_logs_in_only_one_new_client(self):
        base, Client, Suite = self.base()
        suite = Suite.__new__(Suite)
        suite.cases, suite.results = base_rows(), set()
        original_clients = [SimpleNamespace(identity=i) for i in IDS[:256]]
        suite.clients = list(original_clients)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        suite.args = SimpleNamespace(private_dir=Path(directory.name),
                                     binary=Path(directory.name) / 'machine',
                                     config=Path(directory.name) / 'config.json')
        calls = []

        async def completed(_): calls.append('base-scale-completed')
        async def start(client):
            client.event_base = 9000  # Force absolute cursors, never list offsets.
            calls.append('new-process')
        async def devices(client): return [dict(deviceId=EXCLUDED, isLocal=True, presence='OFFLINE')]
        async def cmd(client, name, value=None, error=None):
            if name == 'networkStart':
                event = dict(eventSequence='1', network=dict(running=True, reachable=True))
                client.observe_event(event)
                client.events.append(dict(event=event))
        async def prepare(client, *args): calls.append('prepare-' + client.name)
        async def login(client): calls.append('login-' + client.name)
        async def exact(members, excluded=None): calls.append(('view', len(members)))
        async def membership():
            suite.capacity_members, suite.capacity_excluded = c.select_members([x.identity for x in suite.clients])
        async def gates(): calls.append('gates')
        async def data(a, b): calls.append('admitted-data')
        suite.profile, suite.register, suite.login = prepare, prepare, login
        suite.exact_views, suite.capacity_membership, suite.capacity_gates = exact, membership, gates
        suite.data, suite.no_forbidden_callbacks = data, lambda: None
        suite.observe = lambda event: None
        old = Suite.__mro__[1].large_cases
        Suite.__mro__[1].large_cases = completed
        Client.start, Client.devices, Client.cmd = start, devices, cmd
        try:
            await suite.large_cases()
        finally:
            Suite.__mro__[1].large_cases = old
        self.assertEqual(len(suite.clients), 257)
        self.assertTrue(all(a is b for a, b in zip(original_clients, suite.clients[:256])))
        self.assertEqual(calls.count('new-process'), 1)
        self.assertEqual([x for x in calls if isinstance(x, str) and x.startswith('login-')], ['login-client-256'])
        self.assertEqual(calls[0], 'base-scale-completed')
        self.assertTrue(all(c.passed_status(suite.cases, stage) == 'PASS' for stage in c.STAGES))

    async def test_report_keeps_base_failure_and_final_capacity_verdict_fails(self):
        base, Client, Suite = self.base()
        suite = Suite.__new__(Suite)
        fixture = final_fixture()
        suite.__dict__.update(fixture.__dict__)
        suite.args = SimpleNamespace(offline=False, suite='scale', local_relay=False)
        suite.metadata = dict(shapes=dict(SdkCommand=[], SdkResult=[], SdkEvent=[]), clientApi=[])
        suite.started, suite.provenance = time.time(), {}
        suite.events, suite.nested = set(), dict(devices=set(), rpc=set())
        suite.cases.append(dict(id='original-base-failure', status='FAIL', reason='retained'))
        report = suite.report()
        self.assertEqual(report['capacity']['verdict'], 'FAIL')
        self.assertEqual(c.passed_status(report['cases'], 'original-base-failure'), 'FAIL')
        self.assertEqual(report['summary']['FAIL'], 2)


if __name__ == '__main__':
    unittest.main()
