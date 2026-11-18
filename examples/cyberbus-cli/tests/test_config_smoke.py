"""Reject false-positive public config evidence without running a CLI or OAuth."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('config_smoke', Path(__file__).with_name('config_smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.call, self.local, self.remote = '01' * 16, '02' * 32, '03' * 32
        self.expected = dict(revision=4, name='remote', applicationVersion='0.1.0',
                             semanticVersion='1.0.0', configSha256='04' * 32)
        self.lines = [
            f'RPC_REQUEST_ACCEPTED mode=config call_id={self.call} peer={self.remote}',
            f'RPC_CONFIG call_id={self.call} peer={self.remote} request_id={"05" * 16} '
            f'revision=4 name="remote" application_version="0.1.0" semantic_version="1.0.0" config_sha256={"04" * 32}',
            f'RPC_EVENT source=sdk_event kind=response_end role=caller call_id={self.call} peer={self.remote} code=OK',
            f'RPC_CONFIG_END call_id={self.call} peer={self.remote} items=1 error=',
            'OK config',
        ]
        self.remote_lines = [f'RPC_REQUEST_RECEIVED role=callee call_id={self.call} peer={self.local}']

    def check(self, lines=None, remote=None, expected=None):
        return smoke.check_reply(self.lines if lines is None else lines,
            self.expected if expected is None else expected,
            self.remote_lines if remote is None else remote, self.local, self.remote)

    def test_valid_correlated_configuration(self):
        self.assertTrue(self.check()['remoteHandlerObserved'])

    def test_reject_stale_revision_and_local_configuration(self):
        for changes in [dict(revision=5), dict(name='local'), dict(configSha256='06' * 32)]:
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                self.check(expected=dict(self.expected, **changes))

    def test_reject_missing_or_wrong_remote_and_terminal(self):
        variants = [[], [self.remote_lines[0].replace(self.local, self.remote)]]
        for remote in variants:
            with self.subTest(remote=remote), self.assertRaises(AssertionError):
                self.check(remote=remote)
        for index in range(4):
            lines = self.lines.copy()
            lines.pop(index)
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                self.check(lines=lines)
        for old, new in [('items=1', 'items=2'), ('code=OK', 'code=Internal'),
                         ('role=caller', 'role=callee'), (f'call_id={self.call}', 'call_id=' + '07' * 16)]:
            lines = [s.replace(old, new) for s in self.lines]
            with self.subTest(change=(old, new)), self.assertRaises(AssertionError):
                self.check(lines=lines)

    def test_reject_duplicate_reply_or_terminal(self):
        for index in [1, 3]:
            with self.subTest(duplicate=index), self.assertRaises(AssertionError):
                self.check(lines=self.lines + [self.lines[index]])


if __name__ == '__main__':
    unittest.main()
