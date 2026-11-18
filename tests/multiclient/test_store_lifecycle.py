"""Offline real machine-client store lifecycle; no hosted authorization or tokens."""
import asyncio
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from runner import Client, ROOT


class Observer:
    def __init__(self):
        self.invalid_sdk = []
        self.results = set()

    def observe(self, event):
        pass


@unittest.skipUnless(os.environ.get('CYBERBUS_TEST_CLIENT'),
                     'set CYBERBUS_TEST_CLIENT to the built, pinned real SDK machine client')
class StoreLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_provision_reopen_migrate_and_loss(self):
        binary = str(Path(os.environ['CYBERBUS_TEST_CLIENT']).resolve())
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'installation'
            config = ROOT / 'deploy/test-client.json'

            def argv(mode=None, selected=config):
                command = [binary, '--config', str(selected), '--state-dir', str(state)]
                return command + (['--store-mode', mode] if mode else [])

            async def rejected(mode=None, selected=config):
                # A real startup refusal must exit, not emit readiness or create an identity.
                environment = dict(os.environ)
                environment.pop('CYBERBUS_DEVELOPMENT_STORE_MODE', None)
                process = await asyncio.create_subprocess_exec(*argv(mode, selected),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, env=environment)
                stdout, _ = await asyncio.wait_for(process.communicate(), 10)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(stdout, b'')

            async def identity(mode):
                observer = Observer()
                client = Client('store-lifecycle', argv(mode), observer)
                try:
                    await client.start()
                    result = (await client.devices())[0]['deviceId']
                    await client.terminate()
                    self.assertEqual(observer.invalid_sdk, [])
                    return result
                finally:
                    if getattr(client, 'process', None) and client.process.returncode is None:
                        client.process.kill()
                        await client.process.wait()
                        await client.reader

            await rejected()  # Installed-only is the default even on a fresh directory.
            self.assertFalse(state.exists())
            invalid = Path(directory) / 'invalid.json'
            invalid.write_text('{}')
            await rejected('provision', invalid)
            self.assertFalse(state.exists())
            first = await identity('provision')
            vault = state / 'identity'
            marker = vault.with_suffix('.auth-install')
            self.assertTrue(vault.is_file() and marker.is_file())
            self.assertEqual(await identity('open'), first)
            await rejected('provision')

            # A legacy/missing-marker vault requires explicit host migration intent.
            before = hashlib.sha256(vault.read_bytes()).digest()
            marker.unlink()
            await rejected('open')
            await rejected('provision')
            self.assertEqual(hashlib.sha256(vault.read_bytes()).digest(), before)
            self.assertEqual(await identity('migrate'), first)
            self.assertEqual(await identity('open'), first)
            vault.unlink()
            for mode in [None, 'open', 'provision', 'migrate']:
                await rejected(mode)
                self.assertFalse(vault.exists())
                self.assertTrue(marker.is_file())


if __name__ == '__main__':
    unittest.main()
