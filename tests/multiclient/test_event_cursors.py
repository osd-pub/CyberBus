"""Controller-only JSONL regressions through Client.read; no live SDK evidence."""
import asyncio
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from runner import Client


PEER = '''import json,sys
sequence=0
print(json.dumps({"ready":True}),flush=True)
for line in sys.stdin:
 r=json.loads(line)
 if r["op"]=="shutdown":
  print(json.dumps({"id":r["id"],"ok":True,"result":{"sdkClosed":{"closed":True}}}),flush=True)
  break
 for event in ([{"filler":{}}]*r.get("count",0)+r.get("events",[])):
  sequence+=1
  print(json.dumps({"event":dict({"eventSequence":str(sequence)},**event),"sdkValid":r.get("sdkValid",True)}))
 if r["op"]=="poll_event":
  sequence+=1
  value={"event":{"eventSequence":str(r.get("sequence",sequence)),"filler":{}},"sdkValid":r.get("sdkValid",True)}
 else:
  value={}
 print(json.dumps({"id":r["id"],"ok":True,"result":value}),flush=True)
'''


class Observations:
    def __init__(self):
        self.invalid_sdk = []
        self.observed = []

    def observe(self, event):
        self.observed.append(event)


class EventCursors(unittest.IsolatedAsyncioTestCase):
    async def client(self):
        client = Client('cursor-fixture', [sys.executable, '-u', '-c', PEER], Observations())
        await client.start()

        async def cleanup():
            if client.fatal:
                client.process.stdin.close()
                await asyncio.wait_for(client.process.wait(), 3)
                await client.reader
            else:
                await client.terminate()
        self.addAsyncCleanup(cleanup)
        return client

    def waiter(self, client, predicate, marker):
        task = asyncio.create_task(client.wait(predicate, since=marker))

        async def cleanup():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.addAsyncCleanup(cleanup)
        return task

    async def barrier(self, client, seen, **kwargs):
        # The response drains Client.read; predicate Events prove waiters scanned
        # the batch before the producer advances. No scheduling sleeps required.
        await client.request('emit', **kwargs)
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in seen)), 3)

    async def test_auth_and_data_waiters_cross_trim_with_absolute_marks(self):
        client = await self.client()
        old_auth = {'auth': {'operationId': 'prior-auth', 'phase': 'AUTHENTICATED'}}
        old_data = {'dataStatus': {'messageId': 'prior-data', 'stage': 'PROCESSED'}}
        await client.request('emit', count=8188, events=[old_auth, old_data])
        marker = client.mark()
        self.assertEqual(marker, 8191)
        before = [asyncio.Event(), asyncio.Event()]
        after = [asyncio.Event(), asyncio.Event()]

        def predicate(kind, key, wanted, terminal, index):
            def matches(event):
                if event.get('barrier') == 'before':
                    before[index].set()
                if event.get('barrier') == 'after':
                    after[index].set()
                value = event.get(kind, {})
                return value.get(key) == wanted and value.get(terminal[0]) == terminal[1]
            return matches

        auth = self.waiter(client, predicate('auth', 'operationId', 'current-auth',
                                           ('phase', 'AUTHENTICATED'), 0), marker)
        data = self.waiter(client, predicate('dataStatus', 'messageId', 'current-data',
                                           ('stage', 'PROCESSED'), 1), marker)
        await self.barrier(client, before, events=[{'barrier': 'before'}])
        self.assertEqual(len(client.events), 8192)
        await self.barrier(client, after, count=16,
                           events=[old_auth, old_data, {'barrier': 'after'}])
        self.assertEqual(client.event_base, 4096)
        self.assertFalse(auth.done(), 'prior auth operation satisfied current waiter')
        self.assertFalse(data.done(), 'prior data message satisfied current waiter')
        # Pre-marker stale events still physically exist after trimming; the
        # absolute slice must exclude them rather than treating marker as an index.
        self.assertTrue(any(m.get('event', {}).get('auth') == old_auth['auth']
                            for m in client.events))
        self.assertFalse(any(int(m['event']['eventSequence']) <= 8190
                             for m in client.events_since(marker)))
        current_auth = {'auth': {'operationId': 'current-auth', 'phase': 'AUTHENTICATED'}}
        current_data = {'dataStatus': {'messageId': 'current-data', 'stage': 'PROCESSED'}}
        await client.request('emit', events=[
            {'auth': {'operationId': 'current-auth', 'phase': 'RESTORING'}},
            current_auth, current_data])
        self.assertEqual((await auth)['auth'], current_auth['auth'])
        self.assertEqual((await data)['dataStatus'], current_data['dataStatus'])
        phases = [m['event']['auth']['phase'] for m in client.events_since(marker)
                  if m.get('event', {}).get('auth', {}).get('operationId') == 'current-auth']
        self.assertEqual(phases, ['RESTORING', 'AUTHENTICATED'])
        self.assertEqual(client.mark(), client.sequence + 1)  # ready is not an SDK event
        self.assertGreater(client.mark(), 8192)
        self.assertLessEqual(len(client.events), 8192)
        self.assertEqual(len(client.suite.observed), client.sequence)
        self.assertEqual(client.suite.invalid_sdk, [])
        self.assertIsNone(client.fatal)
        self.assertEqual((await client.wait(lambda e: e.get('dataStatus') == current_data['dataStatus']))['dataStatus'],
                         current_data['dataStatus'])

    async def test_fresh_marker_excludes_matching_prior_terminal(self):
        client = await self.client()
        await client.request('emit', count=8192, events=[
            {'auth': {'operationId': 'prior', 'phase': 'AUTHENTICATED'}}])
        marker = client.mark()
        scanned = asyncio.Event()

        def terminal(event):
            if 'barrier' in event:
                scanned.set()
            return event.get('auth', {}).get('phase') == 'AUTHENTICATED'

        task = self.waiter(client, terminal, marker)
        await self.barrier(client, [scanned], events=[{'barrier': 'new-operation'}])
        self.assertFalse(task.done(), 'retained previous terminal bypassed fresh marker')
        await client.request('emit', events=[{'auth': {'operationId': 'new', 'phase': 'AUTHENTICATED'}}])
        self.assertEqual((await task)['auth']['operationId'], 'new')

    async def test_active_wait_advances_cursor_across_multiple_trims(self):
        client = await self.client()
        marker = client.mark()
        scanned = {i: asyncio.Event() for i in range(4)}

        def terminal(event):
            if event.get('barrier') in scanned:
                scanned[event['barrier']].set()
            return event.get('dataStatus', {}).get('messageId') == 'current'

        task = self.waiter(client, terminal, marker)
        for i in range(4):
            await self.barrier(client, [scanned[i]], count=4000, events=[{'barrier': i}])
        self.assertEqual(client.event_base, 8192)
        self.assertGreater(client.event_base, marker)
        self.assertFalse(task.done())
        await client.request('emit', events=[{'dataStatus': {'messageId': 'current', 'stage': 'PROCESSED'}}])
        self.assertEqual((await task)['dataStatus']['stage'], 'PROCESSED')

    async def test_evicted_explicit_cursor_fails_closed_default_uses_retained_history(self):
        client = await self.client()
        marker = client.mark()
        await client.request('emit', count=9000, events=[{'auth': {'phase': 'FAILED'}}])
        self.assertGreater(client.event_base, marker)
        with self.assertRaisesRegex(AssertionError, 'cursor expired'):
            client.events_since(marker)
        # Even a retained matching terminal cannot prove what happened in the
        # lost range. This must fail directly, not wait until the event timeout.
        with self.assertRaisesRegex(AssertionError, 'cursor expired'):
            await client.wait(lambda e: 'auth' in e, since=marker)
        self.assertEqual((await client.wait(lambda e: 'auth' in e))['auth']['phase'], 'FAILED')
        for invalid in [-1, client.mark() + 1]:
            with self.assertRaisesRegex(AssertionError, 'invalid event history cursor'):
                client.events_since(invalid)

    async def test_trim_preserves_invalid_gate_and_strict_receiver_poll_sequence(self):
        for source, delta in [('receiver', 0), ('poll', 0), ('poll', -1)]:
            with self.subTest(source=source, delta=delta):
                client = await self.client()
                await client.request('emit', count=8193)
                self.assertEqual(client.event_base, 4096)
                await client.request('emit', events=[{'auth': {'phase': 'FAILED'}}], sdkValid=False)
                self.assertEqual(len(client.suite.invalid_sdk), 1)
                self.assertEqual(client.suite.invalid_sdk[0]['kind'], 'event')
                mark = client.mark()
                with self.assertRaisesRegex(AssertionError, 'strict validation'):
                    await client.request('poll_event', sdkValid=False)
                self.assertEqual(len(client.suite.invalid_sdk), 2)
                self.assertEqual(client.mark(), mark, 'nested poll was appended to receiver history')
                self.assertEqual(len(client.suite.observed), client.sequence)
                sequence = client.sequence
                if source == 'receiver':
                    # Fixture eventSequence overrides its generated value.
                    request = client.request('emit', events=[{'eventSequence': str(sequence)}])
                else:
                    request = client.request('poll_event', sequence=sequence + delta)
                with self.assertRaisesRegex(AssertionError, 'client stream closed'):
                    await request
                self.assertEqual(client.sequence, sequence)
                self.assertEqual(len(client.suite.observed), sequence)
                self.assertEqual(client.fatal, 'invalid machine event stream')


if __name__ == '__main__':
    unittest.main()
