#!/usr/bin/env python3
"""Real SDK integration suite. Reports contain assertions, never raw protocol logs."""
import argparse
import asyncio
import base64
import contextvars
import hashlib
import itertools
import platform
import json
import os
import re
from pathlib import Path
import shlex
import signal
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
REQUEST = 'type.googleapis.com/cyberbus.example.v1.EchoRequest'
RESPONSE = 'type.googleapis.com/cyberbus.example.v1.EchoReply'
CURRENT = contextvars.ContextVar('case', default=None)


def b64(value):
    return base64.b64encode(value).decode()


def ident():
    return b64(uuid.uuid4().bytes)


def check(condition, reason):
    if not condition:
        raise AssertionError(reason)


def duration_nanoseconds(value):
    # Protobuf JSON Duration, parsed exactly so a one-nanosecond overrun fails.
    match = re.fullmatch(r'(-?)([0-9]+)(?:\.([0-9]{1,9}))?s', value) if isinstance(value, str) else None
    check(match is not None, 'RPC timeout must be a protobuf JSON duration')
    nanos = int(match[2]) * 1_000_000_000 + int((match[3] or '').ljust(9, '0'))
    return -nanos if match[1] else nanos


def check_rpc_request(received, submitted):
    check({k:v for k,v in received.items() if k!='timeout'} ==
          {k:v for k,v in submitted.items() if k!='timeout'}, 'RPC request metadata differs')
    check(0 < duration_nanoseconds(received.get('timeout')) <= duration_nanoseconds(submitted.get('timeout')),
          'RPC remaining timeout must be positive and no greater than submitted budget')


def fragment(text, response=False):
    raw = text.encode()
    # EchoRequest/EchoReply string field 1; all suite messages fit one-byte length.
    check(len(raw) < 128, 'test payload too long')
    payload = b'\x0a' + bytes([len(raw)]) + raw
    return dict(applicationTypeUrl=RESPONSE if response else REQUEST,
                encoding='PROTOBUF_MESSAGE', totalSize=len(payload), protobufBytes=b64(payload))


class Skip(Exception):
    pass


# Protocol ErrorCode names only; never retain an SDK error message or unknown value.
SDK_ERROR_CODES = frozenset('''ERROR_CODE_UNSPECIFIED INVALID_ARGUMENT UNAUTHENTICATED
PERMISSION_DENIED NOT_FOUND CONFLICT RESOURCE_EXHAUSTED DEADLINE_EXCEEDED CANCELLED
UNAVAILABLE UNSUPPORTED PROTOCOL_ERROR TYPE_MISMATCH METHOD_NOT_EXPOSED
MESSAGE_TOO_LARGE QUEUE_FULL CLOSED UNKNOWN_OUTCOME INVALID_CLAIMS LOGTO_CONFIGURATION
CAPACITY_EXCEEDED NO_ROUTE DEVICE_UNREACHABLE NETWORK_NOT_READY DUPLICATE_DEVICE_ID
STALE_REVISION INTERNAL'''.split())


class UnexpectedSdkError(AssertionError):
    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in SDK_ERROR_CODES else None
        super().__init__('unexpected SDK error '+(self.code or 'unrecognized code'))


class SettledFailure(AssertionError):
    def __init__(self, failures):
        self.failures = failures
        first = failures[0]
        super().__init__('parallel operations failed: '+str(len(failures))+
                         '; first '+first.get('errorCode', first['errorClass']))


async def settle_all(jobs):
    """Finish this cohort before reporting failure; cancel/drain it on owner exit."""
    jobs = list(jobs)
    tasks = []
    try:
        for _, operation in jobs:
            tasks.append(asyncio.create_task(operation))
        results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    failures = []
    for (labels, _), result in zip(jobs, results):
        if isinstance(result, BaseException):
            failure = dict(labels, errorClass=type(result).__name__)
            if isinstance(result, UnexpectedSdkError) and result.code:
                failure['errorCode'] = result.code
            failures.append(failure)
    if failures:
        raise SettledFailure(failures)
    return results


class Client:
    def __init__(self, name, argv, suite):
        self.name, self.argv, self.suite = name, argv, suite
        self.pending, self.events = {}, []
        self.condition = asyncio.Condition()
        self.sequence = 0
        self.counter = 0
        self.event_base = 0
        self.fatal = None
        self.sdk_closed = False
        self.identity = None
        self.watch = ident()
        self.subscription = ident()
        self.handlers = {}
        self.revision = 0

    async def start(self):
        self.process = await asyncio.create_subprocess_exec(*self.argv, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    limit=8*1024*1024, start_new_session=True)
        self.reader = asyncio.create_task(self.read())
        await self.wait(lambda e: e.get('ready'), raw=True)

    def observe_event(self, event):
        # Both receiver delivery and nested poll responses share one sequence domain.
        # Observe here once, before resolving a request; do not append poll responses
        # to the unsolicited event list or repair the SDK validity gate.
        seq = int(event['eventSequence'])
        check(seq > self.sequence, 'event sequence must strictly increase')
        self.sequence = seq
        self.suite.observe(event)

    async def read(self):
        try:
            while line := await self.process.stdout.readline():
                message = json.loads(line)
                nested=message.get('result')
                if message.get('sdkValid') is False or (isinstance(nested,dict) and nested.get('sdkValid') is False):
                    value=message.get('result',message.get('event',{}))
                    kind='result' if 'id' in message else 'event'
                    if isinstance(value,dict) and ('event' in value or 'result' in value):
                        kind='event' if 'event' in value else 'result'
                        value=value.get('event',value.get('result'))
                    self.suite.invalid_sdk.append(dict(client=self.name,kind=kind,
                        variants=sorted(set(value)-{'commandId','eventSequence','runtimeId'})))
                if 'id' in message:
                    if isinstance(nested, dict) and isinstance(nested.get('event'), dict):
                        self.observe_event(nested['event'])
                    future = self.pending.pop(str(message['id']), None)
                    if future and not future.done():
                        future.set_result(message)
                    continue
                if 'event' in message:
                    event = message['event']
                    self.observe_event(event)
                async with self.condition:
                    self.events.append(message)
                    # Keep process memory bounded during 256-client/30-minute suites.
                    if len(self.events)>8192:
                        del self.events[:4096]
                        self.event_base += 4096
                    self.condition.notify_all()
        except Exception:
            self.fatal = 'invalid machine event stream'
        finally:
            if self.fatal is None and self.process.returncode not in (None, 0):
                self.fatal = 'client process failed'
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(AssertionError('client stream closed'))
            async with self.condition:
                self.condition.notify_all()

    async def request(self, op, **kwargs):
        self.counter += 1
        rid = str(self.counter)
        future = asyncio.get_running_loop().create_future()
        self.pending[rid] = future
        self.process.stdin.write((json.dumps(dict(id=rid, op=op, **kwargs))+'\n').encode())
        await self.process.stdin.drain()
        result = await asyncio.wait_for(future, 50)
        check(result.get('ok'), 'machine request rejected')
        value=result.get('result')
        check(result.get('sdkValid') is not False and not (isinstance(value,dict) and value.get('sdkValid') is False),
              'SDK output failed strict validation')
        if (isinstance(value,dict) and 'error' not in value and
                value.get('sdkClosed',{}).get('closed') is True and
                'cleanupError' not in value.get('sdkClosed',{})):
            self.sdk_closed=True
        return value

    async def resume(self):
        result=await self.request('on_resume')
        check(isinstance(result,dict) and 'error' not in result,'SDK on_resume failed')
        return result

    async def cmd(self, name, value=None, error=None):
        case = CURRENT.get()
        if case:
            case['commands'].add(name)
        cid = ident()
        result = await self.request('execute', command=dict(commandId=cid, **{name: value or {}}))
        check(result.get('commandId') == cid, 'SDK command correlation mismatch')
        self.suite.results.update(set(result)-{'commandId'})
        code = result.get('error', {}).get('code')
        if error:
            allowed = [error] if isinstance(error, str) else error
            check(code in allowed, 'expected SDK error '+str(allowed)+'; observed '+str(code))
        else:
            if code:
                raise UnexpectedSdkError(code)
        return result

    def mark(self):
        """Absolute cursor after the last retained unsolicited message (not SDK sequence)."""
        return self.event_base + len(self.events)

    def events_since(self, since=None):
        """Snapshot a retained absolute range; never infer absence from evicted history."""
        if since is None:
            since = self.event_base
        check(isinstance(since, int) and 0 <= since <= self.mark(), 'invalid event history cursor')
        check(since >= self.event_base, 'event history cursor expired before retained range')
        return self.events[since - self.event_base:]

    async def wait(self, predicate, timeout=25, raw=False, since=None):
        async def find():
            cursor = since
            async with self.condition:
                while True:
                    for message in self.events_since(cursor):
                        value = message if raw else message.get('event', {})
                        if predicate(value):
                            return value
                    cursor = self.mark()
                    check(not self.fatal, self.fatal or 'client stream failure')
                    await self.condition.wait()
        try:
            return await asyncio.wait_for(find(), timeout)
        except asyncio.TimeoutError:
            raise AssertionError('expected correlated event timed out') from None

    async def query(self, command, event, **kwargs):
        qid = ident()
        await self.cmd(command, dict(queryId=qid, **kwargs))
        result = (await self.wait(lambda e: e.get(event, {}).get('queryId') == qid))[event]
        return result

    async def devices(self):
        return (await self.query('getDevices', 'devicesQuery'))['snapshot']['devices']

    async def terminate(self):
        shutdown_error=None
        if self.process.returncode is None:
            previously_closed=self.sdk_closed
            try:
                result=await asyncio.wait_for(self.request('shutdown'),8)
                if previously_closed and result.get('error',{}).get('code') in ['CLOSED','CANCELLED']:
                    # Idempotent-close contract is asserted separately; cleanup here
                    # still verifies a real terminal handle and an actual zero exit.
                    pass
                else:
                    closed=result.get('sdkClosed',{})
                    check('error' not in result and closed.get('closed') is True and 'cleanupError' not in closed,
                          'shutdown did not confirm successful SDK cleanup')
            except AssertionError as error:
                shutdown_error=str(error)
            except Exception:
                shutdown_error='shutdown command failed or timed out'
            try:
                await asyncio.wait_for(self.process.wait(),8)
            except asyncio.TimeoutError:
                os.killpg(self.process.pid,signal.SIGTERM)
                try:
                    await asyncio.wait_for(self.process.wait(),3)
                except asyncio.TimeoutError:
                    os.killpg(self.process.pid,signal.SIGKILL)
                    await self.process.wait()
        await self.reader
        check(shutdown_error is None,shutdown_error or 'shutdown failed')
        check(self.sdk_closed, 'process EOF without successful SDK cleanup confirmation')
        check(self.process.returncode == 0, 'client cleanup process exit was nonzero')
        check(not self.fatal, self.fatal or 'machine stream failure')


class Suite:
    def __init__(self, args, metadata):
        self.args, self.metadata = args, metadata
        self.cases, self.results, self.events = [], set(), set()
        self.nested = {'devices': set(), 'rpc': set()}
        self.clients = []
        self.descriptor = metadata['descriptorSet']
        self.digest = b64(hashlib.sha256(base64.b64decode(self.descriptor)).digest())
        self.started = time.time()
        self.relay = None
        self.invalid_sdk=[]
        self.probes = []
        sdk_source=getattr(self.args,'sdk_source',ROOT).resolve()
        self.provenance=dict(sdkSourceCommit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=sdk_source,text=True).strip(),
            sdkSourceDirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=sdk_source,text=True)),
            sdkCargoLockSha256=hashlib.sha256((sdk_source/'Cargo.lock').read_bytes()).hexdigest(),commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True)),
            cargoLockSha256=hashlib.sha256((ROOT/'Cargo.lock').read_bytes()).hexdigest(),
            binarySha256=hashlib.sha256(self.args.binary.read_bytes()).hexdigest(),
            os=platform.platform(),arch=platform.machine(),
            toolchain=subprocess.check_output(['rustc','+stable','--version'],text=True).strip())

    def observe(self, event):
        self.events.update(set(event)-{'eventSequence', 'runtimeId'})
        for name in self.nested:
            if name in event:
                candidates = (['snapshot','added','updated','offline','removed','reset'] if name == 'devices'
                              else ['request','chunk','end','cancel','window'])
                self.nested[name].update(set(event[name]) & set(candidates))

    async def case(self, cid, title, fn, dimensions='positive'):
        row = dict(id=cid, title=title, dimensions=dimensions, commands=set())
        self.cases.append(row)
        token = CURRENT.set(row)
        start = time.monotonic()
        try:
            await fn()
            row.update(status='PASS', reason='assertions satisfied')
        except asyncio.CancelledError:
            row.update(status='FAIL', reason='controller case cancelled')
            raise
        except Skip as e:
            row.update(status='SKIP', reason=str(e))
        except SettledFailure as e:
            row.update(status='FAIL', reason=str(e))
            row.setdefault('facts', {})['failures'] = e.failures
        except AssertionError as e:
            row.update(status='FAIL', reason=str(e))
        except Exception as e:
            # External exceptions may embed secret requests; report only the class.
            row.update(status='FAIL', reason='harness exception '+type(e).__name__)
        finally:
            CURRENT.reset(token)
            row['commands'] = sorted(row['commands'])
            row['seconds'] = round(time.monotonic()-start, 3)
            print(row['status'], cid, title, '-', row['reason'], flush=True)
        return row['status'] == 'PASS'

    def report(self):
        command_coverage = {}
        for name in self.metadata['shapes']['SdkCommand']:
            rows = [r for r in self.cases if name in r['commands']]
            command_coverage[name] = dict(cases=[r['id'] for r in rows],
                status=('FAIL' if any(r['status']=='FAIL' for r in rows) else
                        'PASS' if any(r['status']=='PASS' for r in rows) else 'SKIP'),
                dimensions=sorted({r['dimensions'] for r in rows if r['status']=='PASS'}))
        report = dict(format='cyberbus-multiclient/1', startedAt=self.started,
            provenance=self.provenance, durationSeconds=round(time.time()-self.started, 2), n=len(self.clients),
            mode='offline' if self.args.offline else 'hosted-real-sdk', suite=self.args.suite,
            localRelay=bool(self.args.local_relay),
            targets=dict(scaleLevels=[2,16,64,128,256], stabilitySeconds=1800, restartCycles=100),
            summary={s: sum(r['status']==s for r in self.cases) for s in ['PASS','FAIL','SKIP']},
            apiCoverage={name:dict(status=('FAIL' if any(c['id'] in ids and c['status']=='FAIL' for c in self.cases) else
                    'PASS' if any(c['id'] in ids and c['status']=='PASS' for c in self.cases) else 'NOT_RUN'),cases=ids)
                for name,ids in {'new':['N-000','API-003','AUTH-RESTORE-GRANT'],'execute':['N-000','AUTH-RESTORE-GRANT'],
                    'execute_bytes':['API-002'],'poll_event':['API-003'],
                    'take_event_receiver':['API-001','API-003'],'on_resume':['API-001']}.items()},
            cases=self.cases, commands=command_coverage,invalidSdkObjects=self.invalid_sdk,
            results={n: 'OBSERVED' if n in self.results else 'NOT_OBSERVED'
                     for n in self.metadata['shapes']['SdkResult']},
            events={n: 'OBSERVED' if n in self.events else 'NOT_OBSERVED'
                    for n in self.metadata['shapes']['SdkEvent']},
            eventVariants={n: sorted(v) for n,v in self.nested.items()},
            clientApi=self.metadata['clientApi'],
            limitations=['DevelopmentFileStore, opt-in durable OAuth grant' if self.args.suite=='restore' else 'DevelopmentFileStore, memory-only OAuth grants',
                'No Android control; external JSONL participants may be supplied',
                'No 256-node, 30-minute refresh, lease exhaustion, or persistence fault injection',
                'CLIENT_STREAMING and SERVER_STREAMING explicitly rejected by current SDK'])
        if self.args.suite == 'scale':
            rounds = [r for r in self.cases if r['id'].startswith('SCALE-ROUND-')]
            expected = ['SCALE-ROUND-'+str(i) for i in range(1, len(self.clients))]
            report['fullCoverage'] = (len(self.clients) >= 2 and
                not report['summary']['FAIL'] and
                any(r['id'] == 'SCALE-DIRECTORY' and r['status'] == 'PASS' for r in self.cases) and
                [r['id'] for r in rounds] == expected and
                all(r['status'] == 'PASS' and r.get('facts', {}).get('offset') == i and
                    r['facts'].get('directedPairs') == len(self.clients)
                    for i, r in enumerate(rounds, 1)))
        return report

    async def setup(self):
        if self.args.local_relay:
            check(not self.args.participants, '--local-relay only applies to local participants')
            self.relay = await asyncio.create_subprocess_exec(str(self.args.binary),'--relay',
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            ready=json.loads(await asyncio.wait_for(self.relay.stdout.readline(),20))
            check(ready.get('relayEndpoint'), 'local relay readiness missing endpoint')
            config=json.loads(self.args.config.read_text())
            config['bootstrap_peers']=[ready['relayEndpoint']]
            config['enable_p2p']=False
            self.args.config=self.args.private_dir/'local-relay-config.json'
            self.args.config.write_text(json.dumps(config))
        if self.args.participants:
            participants = json.loads(self.args.participants.read_text())
        else:
            participants = [dict(name=f'client-{i}', command=[str(self.args.binary), '--config',
                str(self.args.config), '--state-dir', str(self.args.private_dir/f'client-{i}'),
                '--store-mode', self.args.store_mode])
                for i in range(self.args.n)]
        check(len(participants) >= (3 if self.args.suite=='api' else 2), 'N below suite minimum')
        for participant in participants:
            client = Client(participant['name'], participant['command'], self)
            self.clients.append(client)
            await client.start()
            devices = await client.devices()
            check(len(devices)==1 and devices[0].get('isLocal'), 'initial directory must contain self only')
            client.identity = devices[0]['deviceId']
            check(devices[0].get('presence')=='OFFLINE', 'initial self must be offline')
        check(len({c.identity for c in self.clients}) == len(self.clients), 'installation identities must be independent')
        CURRENT.get()['facts']=dict(independentInstallations=len(self.clients))

    async def profile(self, client, suffix=''):
        result = await client.cmd('updatePublicProfile', dict(profile=dict(deviceName=client.name+suffix,
            publicConfig={'@type':'type.googleapis.com/cyberbus.example.v1.PublicConfig', 'applicationVersion':'0.1.0'},
            configSemanticVersion='1.0.0'), expectedRevision=str(client.revision), updateMask='deviceName,publicConfig,configSemanticVersion'))
        client.revision = int(result['publicProfile']['configRevision'])

    async def register(self, client, streaming):
        hid = ident()
        method = 'cyberbus.example.v1.Echo/' + ('Unary' if streaming=='UNARY' else 'Chat')
        cap = dict(methodId=method, requestTypeUrl=REQUEST, responseTypeUrl=RESPONSE,
                   streaming=streaming, semanticVersion='1.0.0', descriptorDigest=self.digest)
        await client.cmd('registerHandler', dict(handlerId=hid, capability=cap, descriptorSet=self.descriptor))
        client.handlers[streaming] = dict(handlerId=hid, capability=cap, descriptorSet=self.descriptor)

    async def offline_cases(self):
        a = self.clients[0]
        async def state():
            first = (await a.cmd('getAuthState'))['authState']
            second = (await a.cmd('getAuthState'))['authState']
            check(first==second and first['phase']=='LOGGED_OUT', 'auth query must be observational')
            check(not (await a.request('take_event_receiver'))['taken'], 'receiver must transfer once')
            check(await a.request('poll_event', timeoutMs=1) is None, 'poll after receiver transfer must be empty')
            await a.resume()
        await self.case('API-001', 'Client state, receiver ownership, poll and resume', state)
        async def watch():
            await a.cmd('watchDevices', dict(watchId=a.watch))
            event = await a.wait(lambda e: e.get('devices', {}).get('watchId')==a.watch)
            check(len(event['devices']['snapshot']['devices'])==1, 'watch initial snapshot missing self')
            await a.cmd('stopWatchDevices', dict(watchId=a.watch))
            await a.cmd('stopWatchDevices', dict(watchId=a.watch))
        await self.case('DIR-001', 'Offline watch snapshot and idempotent unsubscribe', watch)
        async def stopped():
            await a.cmd('networkStart', error=['UNAUTHENTICATED','INVALID_ARGUMENT'])
            await a.cmd('networkStop')
            await a.cmd('getBlockedDevices', dict(queryId=ident()), error='UNAUTHENTICATED')
        await self.case('NET-001', 'Unauthenticated admission and stopped refresh', stopped, 'negative')
        for name in self.metadata['shapes']['SdkCommand']:
            if name in ['authLogout','networkStart','networkStop','sdkClose','getAuthState']:
                continue
            async def invalid(name=name):
                await a.cmd(name, error=['INVALID_ARGUMENT','UNAUTHENTICATED','NOT_FOUND','PROTOCOL_ERROR'])
            await self.case('CMD-NEG-'+name, name+' missing required semantic fields', invalid, 'negative')
        async def binary():
            for encoded in ['', b64(b'\x0a\x10'+b'\x01'*16+b'\xc2\x02\x00\xc2\x02\x00'), b64(b'\xff')]:
                r = await a.request('execute_bytes', bytes=encoded)
                self.results.update(set(r['result'])-{'commandId'})
                check(r['result'].get('error',{}).get('code')=='PROTOCOL_ERROR', 'strict decoder must reject malformed or duplicate fields')
            raw = b'\x0a\x10'+b'\x02'*16+b'\xc2\x02\x00'  # get_auth_state field 40
            r = await a.request('execute_bytes', bytes=b64(raw))
            check(r['result']['authState']['phase']=='LOGGED_OUT', 'valid bytes command failed')
            check(r['result']['commandId']==b64(b'\x02'*16), 'bytes correlation failed')
        await self.case('API-002', 'Strict bytes dispatch valid, malformed and ambiguous commands', binary, 'negative')
        async def cancel():
            for intent in ['LOGIN','REGISTER']:
                r = (await a.cmd('authStart',dict(intent=intent)))['authStarted']
                check(r.get('authorizationUri') and r.get('operationId'), 'auth operation missing SDK URI or id')
                op = dict(operationId=r['operationId'])
                await a.cmd('authCancel', op)
                await a.cmd('authCancel', op)
                await a.cmd('authCallback', dict(**op,callbackUri='http://127.0.0.1:18765/callback?error=access_denied'),
                            error=['CANCELLED','NOT_FOUND','CONFLICT','INVALID_ARGUMENT'])
        await self.case('AUTH-001', 'Login/register intent, repeated cancel and late callback', cancel, 'cancel')
        async def restore():
            await self.restore_without_grant(a)
        await self.case('AUTH-002', 'Memory-only cold restore requires fresh authorization', restore, 'negative')
        for c in self.clients:
            async def prepare(c=c):
                await self.profile(c)
                await self.register(c, 'UNARY')
                await self.register(c, 'BIDI')
                await c.cmd('subscribeData', dict(subscriptionId=c.subscription,typeUrls=[REQUEST]))
                await c.cmd('watchDevices', dict(watchId=c.watch))
            await self.case('SETUP-'+c.name, 'Public profile, typed handlers, subscription and watch', prepare)

    async def restore_without_grant(self, client):
        operation=ident()
        marker=client.mark()
        result=await client.cmd('authRestore', dict(operationId=operation))
        check('ok' in result,'no-grant restore must be accepted')
        terminal=(await client.wait(lambda e:e.get('auth',{}).get('operationId')==operation and
                              e['auth'].get('phase')=='FAILED', since=marker))['auth']
        phases=[m['event']['auth']['phase'] for m in client.events_since(marker)
                if m.get('event',{}).get('auth',{}).get('operationId')==operation]
        check(phases==['RESTORING','FAILED'] and terminal.get('error',{}).get('code')=='UNAUTHENTICATED',
              'grantless restore must be accepted then RESTORING/FAILED UNAUTHENTICATED')

    async def restore_without_grant_after_logout(self, client):
        closed=(await client.cmd('authLogout',dict(cloudPolicy='LOCAL_ONLY')))['authLogout']
        check(closed.get('localClosed') and not closed.get('localError') and not closed.get('cloudError'),
              'no-grant restore requires successful local logout')
        state=(await client.cmd('getAuthState'))['authState']
        check(state.get('phase')=='LOGGED_OUT' and not state.get('refreshSupported') and not state.get('account'),
              'local logout did not establish grantless logged-out state')
        await self.restore_without_grant(client)

    async def restore_authenticated(self, client):
        before=(await client.cmd('getAuthState'))['authState']
        check(before.get('phase')=='AUTHENTICATED' and before.get('account') and before.get('refreshSupported'),
              'authenticated restore requires a verified SDK-owned grant/account')
        operation=ident()
        marker=client.mark()
        invalid_marker=len(self.invalid_sdk)
        accepted=await client.cmd('authRestore',dict(operationId=operation))
        check('ok' in accepted,'authenticated restore must be accepted')
        terminal=(await client.wait(lambda e:e.get('auth',{}).get('operationId')==operation and
            e['auth'].get('phase') in ['AUTHENTICATED','FAILED','AUTH_CANCELLED','REAUTH_REQUIRED','CONFIGURATION_ERROR'],
            timeout=40,since=marker))['auth']
        events=[m['event']['auth'] for m in client.events_since(marker)
                if m.get('event',{}).get('auth',{}).get('operationId')==operation]
        check([e.get('phase') for e in events]==['RESTORING','AUTHENTICATED'] and not terminal.get('error'),
              'owned-grant restore must reach one authenticated terminal')
        check(not events[0].get('account') and terminal.get('account')==before['account'],
              'restore progress must omit account; authenticated terminal must preserve binding')
        check(int(events[1]['stateRevision'])>int(events[0]['stateRevision']), 'restore revision did not advance')
        check(not any(e.get('client')==client.name for e in self.invalid_sdk[invalid_marker:]),
              'authenticated restore emitted a strict-invalid SDK object')
        after=(await client.cmd('getAuthState'))['authState']
        check(after.get('phase')=='AUTHENTICATED' and after.get('account')==before['account'] and after.get('refreshSupported'),
              'restore lost the actual auth owner/grant binding')
        check(after.get('lastOnlineValidationAt') and after.get('validationLeaseExpiresAt'), 'restore lease timestamps missing')

    async def login(self, client):
        check(self.args.login_driver, 'live run requires --login-driver')
        marker=client.mark()
        r = (await client.cmd('authStart', dict(intent='LOGIN')))['authStarted']
        driver = await asyncio.create_subprocess_exec(*shlex.split(self.args.login_driver),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            callback, _ = await asyncio.wait_for(driver.communicate(r['authorizationUri'].encode()), 125)
        except BaseException:
            driver.kill()
            await driver.wait()
            raise
        check(driver.returncode==0 and callback.startswith(b'http'), 'callback-only hosted driver failed')
        await client.cmd('authCallback', dict(operationId=r['operationId'],callbackUri=callback.decode().strip()))
        terminal=(await client.wait(lambda e:e.get('auth',{}).get('operationId')==r['operationId'] and
            e['auth'].get('phase') in ['AUTHENTICATED','FAILED','AUTH_CANCELLED','REAUTH_REQUIRED','CONFIGURATION_ERROR'],
            timeout=40,since=marker))['auth']
        check(terminal.get('phase')=='AUTHENTICATED' and 'error' not in terminal,
              'hosted callback did not produce authenticated operation terminal')
        state = (await client.cmd('getAuthState'))['authState']
        check(state['phase']=='AUTHENTICATED' and state.get('refreshSupported'), 'hosted login must establish verified refresh-supported grant')
        check(state.get('validationLeaseExpiresAt') and state.get('lastOnlineValidationAt'), 'verified lease timestamps missing')
        check(not any(e.get('event',{}).get('network',{}).get('running') for e in client.events_since(marker)), 'login must not start network')

    async def converge(self):
        expected = {c.identity for c in self.clients}
        deadline = time.monotonic()+self.args.converge_timeout
        progress=time.monotonic()+30
        while time.monotonic() < deadline:
            views = await settle_all((dict(client=c.name), c.devices()) for c in self.clients)
            if all({d['deviceId'] for d in view if d.get('presence')=='ONLINE'}==expected for view in views):
                return
            if time.monotonic()>=progress:
                counts=[len({d['deviceId'] for d in view if d.get('presence')=='ONLINE'}) for view in views]
                print('PROGRESS directory',len(self.clients),'clients; min/max online',min(counts),max(counts),flush=True)
                progress=time.monotonic()+30
            await asyncio.sleep(0.5)
        raise AssertionError('N simultaneous real SDK peers did not converge')

    async def data(self, a, b, mode='processed'):
        mid = ident()
        payload = fragment(a.name+'>'+b.name)
        timeout = '0.300s' if mode=='deadline' else '10s'
        await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=mid,
            requestedAck='PROCESSED',timeout=timeout,fragment=payload)))
        received = (await b.wait(lambda e:e.get('dataReceived',{}).get('message',{}).get('messageId')==mid))['dataReceived']
        check(received['peerDeviceId']==a.identity and received['subscriptionId']==b.subscription,
              'data authenticated sender/subscription mismatch')
        check(received['message']['fragment']==payload, 'exact protobuf payload mismatch')
        if mode=='cancel':
            await a.cmd('cancelData',dict(peerDeviceId=b.identity,messageId=mid))
            await b.wait(lambda e:e.get('peerDataCancel',{}).get('messageId')==mid)
        elif mode=='processed':
            await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,stage='PROCESSED'))
        elif mode=='error':
            await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,error=dict(code='PERMISSION_DENIED',message='test rejection')))
        status = (await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and
                      ('error' in e['dataStatus'] or e['dataStatus'].get('stage')=='PROCESSED')))['dataStatus']
        if mode=='processed':
            stages = [m['event']['dataStatus'].get('stage') for m in a.events
                      if m.get('event',{}).get('dataStatus',{}).get('messageId')==mid]
            check(stages==['RECEIVED','ACCEPTED','PROCESSED'], 'ACK stages must be received, accepted, then explicit processed')
            if CURRENT.get() and self.args.suite=='api':
                CURRENT.get()['facts']=dict(sender=a.name,receiver=b.name,ackStages=stages,exactProtobuf=True)
        else:
            allowed = {'cancel':['CANCELLED'], 'deadline':['DEADLINE_EXCEEDED','UNKNOWN_OUTCOME'], 'error':['PERMISSION_DENIED']}[mode]
            check(status.get('error',{}).get('code') in allowed, 'data terminal error differs from requested scenario')

    def rpc_request(self, call, streaming='BIDI', timeout='10s'):
        return dict(callId=call, methodId='cyberbus.example.v1.Echo/'+('Unary' if streaming=='UNARY' else 'Chat'),
                    requestTypeUrl=REQUEST,responseTypeUrl=RESPONSE,streaming=streaming,
                    semanticVersion='1.0.0',timeout=timeout)

    async def rpc_event(self, c, call, body, peer=None):
        event=(await c.wait(lambda e:e.get('rpc',{}).get(body,{}).get('callId')==call))['rpc']
        if peer is not None:
            check(event.get('peerDeviceId')==peer, 'RPC authenticated peer mismatch')
        return event[body]

    async def rpc(self, a, b, streaming='UNARY', mode='echo'):
        call = ident()
        submitted=self.rpc_request(call,streaming,'0.300s' if mode=='deadline' else '10s')
        await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=submitted))
        request=await self.rpc_event(b,call,'request',a.identity)
        check_rpc_request(request,submitted)
        if mode=='cancel':
            await a.cmd('rpcCancel',dict(peerDeviceId=b.identity,cancel=dict(callId=call,error=dict(code='CANCELLED',message='test cancellation'))))
            await self.rpc_event(b,call,'cancel')
            await a.cmd('rpcChunk',dict(peerDeviceId=b.identity,chunk=dict(callId=call,direction='REQUEST',fragment=fragment('late'))),error='PROTOCOL_ERROR')
            return
        if mode=='deadline':
            event = await self.rpc_event(a,call,'cancel')
            check(event['error']['code']=='DEADLINE_EXCEEDED', 'RPC deadline must cancel call')
            return
        payload = fragment('echo-'+streaming)
        await a.cmd('rpcChunk',dict(peerDeviceId=b.identity,chunk=dict(callId=call,direction='REQUEST',fragment=payload)))
        request = await self.rpc_event(b,call,'chunk',a.identity)
        check(request['fragment']==payload, 'RPC request payload differs')
        check(request.get('direction')=='REQUEST' and int(request.get('itemSequence',0))==0,
              'RPC request chunk direction/sequence differs')
        if mode=='window':
            # Receiver replenishes one item after consuming it. Bytes are SDK-managed.
            await b.cmd('rpcWindow',dict(peerDeviceId=a.identity,window=dict(callId=call,direction='REQUEST',itemCredit=1)))
            await a.wait(lambda e:e.get('rpc',{}).get('window',{}).get('callId')==call and e['rpc']['window'].get('itemCredit')==1)
            await b.cmd('rpcWindow',dict(peerDeviceId=a.identity,window=dict(callId=call,direction='REQUEST',itemCredit=1)),error='PROTOCOL_ERROR')
        await a.cmd('rpcEnd',dict(peerDeviceId=b.identity,end=dict(callId=call,direction='REQUEST',itemCount='1')))
        request_end=await self.rpc_event(b,call,'end',a.identity)
        check(request_end.get('direction')=='REQUEST' and int(request_end.get('itemCount',0))==1
              and 'error' not in request_end, 'RPC request end direction/count/error differs')
        reply = fragment('echo-'+streaming, True)
        await b.cmd('rpcChunk',dict(peerDeviceId=a.identity,chunk=dict(callId=call,direction='RESPONSE',fragment=reply)))
        r = await self.rpc_event(a,call,'chunk',b.identity)
        check(r['fragment']==reply, 'RPC response protobuf mismatch')
        check(r.get('direction')=='RESPONSE' and int(r.get('itemSequence',0))==0,
              'RPC response chunk direction/sequence differs')
        await b.cmd('rpcEnd',dict(peerDeviceId=a.identity,end=dict(callId=call,direction='RESPONSE',itemCount='1')))
        end = await self.rpc_event(a,call,'end',b.identity)
        check(end.get('direction')=='RESPONSE' and int(end.get('itemCount',0))==1
              and 'error' not in end, 'RPC response end direction/count/error differs')

    async def rpc_unsupported(self, a, b):
        outcomes=[]
        for streaming in ['CLIENT_STREAMING','SERVER_STREAMING']:
            # Chat exists in the descriptor as BIDI. The reserved one-way declaration
            # must be rejected, rather than pretending a nonexistent method registered.
            request=self.rpc_request(ident(),streaming)
            registered=dict(handlerId=ident(), capability={k:v for k,v in request.items()
                if k not in ['callId','timeout']}, descriptorSet=self.descriptor)
            registered['capability']['descriptorDigest']=self.digest
            rejected=await b.cmd('registerHandler',registered,error=['UNSUPPORTED','TYPE_MISMATCH'])
            # A rejected registration alone is not proof of invoke's UNSUPPORTED.
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=request),error='UNSUPPORTED')
            outcomes.append(dict(streaming=streaming,registrationError=rejected['error']['code'],invokeError='UNSUPPORTED'))
        if CURRENT.get() is not None:
            CURRENT.get().setdefault('facts',{})['unsupportedStreaming']=outcomes

    async def live_cases(self):
        for c in self.clients:
            if not await self.case('AUTH-LIVE-'+c.name, 'Independent callback-only hosted PKCE login', lambda c=c:self.login(c)):
                return
        await self.case('AUTH-RESTORE-AUTHENTICATED','Authenticated in-memory grant restore emits strict progress and success',
                        lambda:self.restore_authenticated(self.clients[0]))
        async def start():
            await asyncio.gather(*(c.cmd('networkStart') for c in self.clients))
            await self.converge()
        if not await self.case('N-001', 'N real simultaneous SDK peers fully visible', start):
            return
        await asyncio.gather(*(self.case('N-DATA-'+a.name+'-'+b.name,
            'All-direction exact data and ordered ACKs',lambda a=a,b=b:self.data(a,b))
            for a,b in itertools.permutations(self.clients,2)))
        a,b = self.clients[:2]
        async def repeat_start():
            await a.cmd('networkStart',error='CONFLICT')
            await a.cmd('networkStart',dict(privateConfig={'@type':'type.googleapis.com/cyberbus.example.v1.PublicConfig','applicationVersion':'private'}),error='UNSUPPORTED')
        await self.case('NET-REPEAT','Repeated start conflicts and optional private config is unsupported',repeat_start,'negative')
        for variant in ['empty','any','1MiB','dedupe']:
            async def payload_boundary(variant=variant):
                mid=ident()
                payload=fragment('boundary')
                if variant=='empty':
                    payload=dict(applicationTypeUrl=REQUEST,encoding='PROTOBUF_MESSAGE')
                elif variant=='any':
                    inner=base64.b64decode(payload['protobufBytes'])
                    url=REQUEST.encode()
                    raw=b'\x0a'+bytes([len(url)])+url+b'\x12'+bytes([len(inner)])+inner
                    payload=dict(applicationTypeUrl=REQUEST,encoding='PROTOBUF_ANY',totalSize=len(raw),protobufBytes=b64(raw))
                elif variant=='1MiB':
                    length=1024*1024-4
                    encoded=[]
                    n=length
                    while n>=128:
                        encoded.append((n&127)|128)
                        n>>=7
                    encoded.append(n)
                    raw=b'\x0a'+bytes(encoded)+b'x'*length
                    check(len(raw)==1024*1024,'test 1MiB protobuf boundary is incorrect')
                    payload=dict(applicationTypeUrl=REQUEST,encoding='PROTOBUF_MESSAGE',totalSize=len(raw),protobufBytes=b64(raw))
                message=dict(messageId=mid,requestedAck='PROCESSED',timeout='10s',fragment=payload)
                await a.cmd('send',dict(peerDeviceId=b.identity,message=message))
                received=(await b.wait(lambda e:e.get('dataReceived',{}).get('message',{}).get('messageId')==mid))['dataReceived']['message']['fragment']
                check(received.get('protobufBytes','')==payload.get('protobufBytes','') and received['encoding']==payload['encoding'],'complete protobuf payload boundary mismatch')
                await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,stage='PROCESSED'))
                await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and e['dataStatus'].get('stage')=='PROCESSED')
                if variant=='dedupe':
                    mark=a.mark()
                    await a.cmd('send',dict(peerDeviceId=b.identity,message=message))
                    await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and e['dataStatus'].get('stage')=='PROCESSED',since=mark)
                    check(sum(e.get('event',{}).get('dataReceived',{}).get('message',{}).get('messageId')==mid for e in b.events)==1,'duplicate message redispatched application callback')
                    mark=a.mark()
                    await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(message,fragment=fragment('different-content'))))
                    status=(await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and 'error' in e['dataStatus'],since=mark))['dataStatus']
                    check(status['error']['code']=='CONFLICT','same ID with different content must conflict')
                CURRENT.get()['facts']=dict(encoding=payload['encoding'],bytes=payload.get('totalSize',0))
            await self.case('DATA-PAYLOAD-'+variant,'Real data protobuf boundary '+variant,payload_boundary)

        for mode in ['cancel','deadline','error']:
            await self.case('DATA-'+mode, 'Data '+mode+' terminal and peer notification',lambda mode=mode:self.data(a,b,mode),mode)
        for streaming in ['UNARY','BIDI']:
            for source,target in itertools.permutations(self.clients,2):
                await self.case('RPC-'+streaming+'-'+source.name+'-'+target.name, 'Typed RPC request/response and half-close',lambda source=source,target=target,streaming=streaming:self.rpc(source,target,streaming))
        for mode in ['cancel','deadline','window']:
            await self.case('RPC-'+mode, 'RPC '+mode+' behavior',lambda mode=mode:self.rpc(a,b,'BIDI',mode),mode)
        async def exhausted_window():
            call=ident()
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=self.rpc_request(call)))
            await self.rpc_event(b,call,'request')
            for sequence in range(4):
                await a.cmd('rpcChunk',dict(peerDeviceId=b.identity,chunk=dict(callId=call,direction='REQUEST',itemSequence=str(sequence),fragment=fragment('window'))))
                await b.wait(lambda e:e.get('rpc',{}).get('chunk',{}).get('callId')==call and int(e['rpc']['chunk'].get('itemSequence',0))==sequence)
            chunk=dict(callId=call,direction='REQUEST',itemSequence='4',fragment=fragment('fifth'))
            await a.cmd('rpcChunk',dict(peerDeviceId=b.identity,chunk=chunk),error='RESOURCE_EXHAUSTED')
            await b.cmd('rpcWindow',dict(peerDeviceId=a.identity,window=dict(callId=call,direction='REQUEST',itemCredit=1)))
            await a.wait(lambda e:e.get('rpc',{}).get('window',{}).get('callId')==call and e['rpc']['window'].get('itemCredit')==1)
            await a.cmd('rpcChunk',dict(peerDeviceId=b.identity,chunk=chunk))
            await b.wait(lambda e:e.get('rpc',{}).get('chunk',{}).get('callId')==call and e['rpc']['chunk'].get('itemSequence')=='4')
            await a.cmd('rpcEnd',dict(peerDeviceId=b.identity,end=dict(callId=call,direction='REQUEST',itemCount='5')))
            await self.rpc_event(b,call,'end')
            await b.cmd('rpcEnd',dict(peerDeviceId=a.identity,end=dict(callId=call,direction='RESPONSE',itemCount='0')))
            await self.rpc_event(a,call,'end')
        await self.case('RPC-WINDOW-EXHAUST','Four-item window exhaustion, explicit grant and resumed fifth item',exhausted_window,'window')
        async def rpc_negative():
            await self.rpc_unsupported(a,b)
            call = ident()
            req = self.rpc_request(call)
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=req))
            await self.rpc_event(b,call,'request')
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=req),error='CONFLICT')
            for chunk in [dict(direction='RESPONSE',fragment=fragment('wrong',True)),
                          dict(direction='REQUEST',itemSequence='1',fragment=fragment('wrong'))]:
                await a.cmd('rpcChunk',dict(peerDeviceId=b.identity,chunk=dict(callId=call,**chunk)),error=['PROTOCOL_ERROR','TYPE_MISMATCH'])
            await a.cmd('rpcEnd',dict(peerDeviceId=b.identity,end=dict(callId=call,direction='REQUEST',itemCount='1')),error='PROTOCOL_ERROR')
            await a.cmd('rpcCancel',dict(peerDeviceId=b.identity,cancel=dict(callId=call)))
            missing = ident()
            req = self.rpc_request(missing)
            req['methodId']='cyberbus.example.v1.Echo/Missing'
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=req),error='METHOD_NOT_EXPOSED')
        await self.case('RPC-NEG', 'Unsupported kinds, duplicate call, wrong direction, sequence and cardinality', rpc_negative,'negative')
        async def descriptors():
            r = await a.query('pullDescriptor','descriptor',peerDeviceId=b.identity,digest=self.digest,timeout='5s')
            check(r.get('descriptorSet')==self.descriptor, 'remote descriptor bytes or digest differ')
            r = await a.query('pullDescriptor','descriptor',peerDeviceId=b.identity,digest=b64(b'\x01'*32),timeout='5s')
            check(r.get('error',{}).get('code')=='NOT_FOUND', 'unknown descriptor digest must fail')
            r = await a.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=b.identity)
            revision = r['profile']['configRevision']
            r = await a.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=b.identity,conditionalRevision=revision)
            check(r.get('unchanged')==revision, 'conditional descriptor revision failed')
            r = await a.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=b64(b'\x02'*32))
            check(r.get('error',{}).get('code')=='NOT_FOUND', 'unknown authenticated descriptor must fail')
            r = await a.query('refreshDevices','refreshDevices',budget='2s')
            check(not r.get('error') and int(r.get('verified',0))>=len(self.clients)-1, 'refresh did not verify peers')
        await self.case('META-001', 'Schema pull, missing digest, conditional profile, refresh', descriptors)
        async def profile_update():
            before = (await a.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=b.identity))['profile']['configRevision']
            # register_handler increments profile revision: query current before applying optimistic update.
            b.revision = int(before)
            await self.profile(b,'-updated')
            await a.wait(lambda e:e.get('devices',{}).get('updated',{}).get('device',{}).get('profile',{}).get('deviceName')==b.name+'-updated')
            await b.cmd('updatePublicProfile',dict(profile=dict(deviceName='stale',configSemanticVersion='1.0.0'),expectedRevision=before,updateMask='deviceName,configSemanticVersion'),error='STALE_REVISION')
        await self.case('META-002', 'Revision update propagates; stale writer rejected', profile_update)
        for i,source in enumerate(self.clients):
            target=self.clients[(i+1)%len(self.clients)]
            async def per_client(source=source,target=target):
                schema=await source.query('pullDescriptor','descriptor',peerDeviceId=target.identity,digest=self.digest,timeout='5s')
                check(schema.get('descriptorSet')==self.descriptor,'per-client remote schema mismatch')
                profile=(await source.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=source.identity))['profile']
                source.revision=int(profile['configRevision'])
                await self.profile(source,'-all-api')
                await target.wait(lambda e:e.get('devices',{}).get('updated',{}).get('device',{}).get('profile',{}).get('deviceName')==source.name+'-all-api')
            await self.case('META-N-'+source.name,'Every client pulls schema and publishes updated profile',per_client)

        await self.contract_cases()
        async def unsubscribe():
            mark = b.mark()
            await b.cmd('unsubscribeData',dict(subscriptionId=b.subscription))
            try:
                mid = ident()
                await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=mid,requestedAck='PROCESSED',timeout='1s',fragment=fragment('unsubscribed'))))
                status = (await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and 'error' in e['dataStatus']))['dataStatus']
                check(status['error']['code']=='NOT_FOUND', 'unsubscribed receiver must reject data with NOT_FOUND')
                check(not any(e.get('event',{}).get('dataReceived',{}).get('message',{}).get('messageId')==mid for e in b.events_since(mark)), 'unsubscribed callback started')
            finally:
                await b.cmd('subscribeData',dict(subscriptionId=b.subscription,typeUrls=[REQUEST]))
        await self.case('SUB-001', 'Unsubscribe stops delivery and reports NOT_FOUND',unsubscribe,'cancel')
        async def unregister_delivery():
            marker=a.mark()
            await b.cmd('unregisterHandler',dict(handlerId=b.handlers['UNARY']['handlerId']))
            try:
                await a.wait(lambda e:e.get('devices',{}).get('updated',{}).get('device',{}).get('deviceId')==b.identity and
                    'capabilities' in e['devices']['updated']['device'].get('profile',{}) and
                    not any(c['streaming']=='UNARY' for c in e['devices']['updated']['device']['profile']['capabilities']),since=marker)
                await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=self.rpc_request(ident(),'UNARY')),error='METHOD_NOT_EXPOSED')
            finally:
                await self.register(b,'UNARY')
        await self.case('HANDLER-STOP','Unregistered handler stops accepting new calls',unregister_delivery,'cancel')
        async def block():
            for op in ['blockDevice','unblockDevice']:
                await a.cmd(op,dict(peerDeviceId=a.identity),error=['INVALID_ARGUMENT','PERMISSION_DENIED'])
            r=await a.cmd('blockDevice',dict(peerDeviceId=b.identity))
            state=r['deviceBlock']['state']
            check(state.get('blocked') and state.get('persistedBlocked') and not state.get('persistencePending'),'block must persist effective deny')
            q=await a.query('getBlockedDevices','blockedDevices',peerDeviceId=b.identity)
            check(len(q['snapshot']['devices'])==1 and q['snapshot']['devices'][0]['blocked'],'filtered block query must report deny')
            await a.wait(lambda e:e.get('devices',{}).get('removed',{}).get('deviceId')==b.identity)
            await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=ident(),requestedAck='PROCESSED',timeout='1s',fragment=fragment('blocked'))),error=['DEVICE_UNREACHABLE','PERMISSION_DENIED'])
            r=await a.cmd('unblockDevice',dict(peerDeviceId=b.identity))
            state=r['deviceBlock']['state']
            check(not state.get('blocked') and not state.get('persistedBlocked'),'unblock must persist before opening')
            q=await a.query('getBlockedDevices','blockedDevices')
            check(not any(d.get('blocked') for d in q['snapshot'].get('devices',[])),'block list retained released deny')
            await self.converge()
            await self.data(a,b)
        await self.case('BLOCK-001','Persisted block, filtered/all queries, deny, unblock and rediscovery',block)
        async def watch_stop():
            await a.cmd('stopWatchDevices',dict(watchId=a.watch))
            mark=a.mark()
            current=(await b.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=b.identity))['profile']
            b.revision=int(current['configRevision'])
            await self.profile(b,'-unwatched')
            await asyncio.sleep(0.5)
            check(not any(e.get('event',{}).get('devices',{}).get('watchId')==a.watch for e in a.events_since(mark)),'stopped watch received a new callback')
        await self.case('DIR-STOP','Watch cancellation prevents subsequent callbacks',watch_stop,'cancel')
        async def close_pending():
            call=ident()
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=self.rpc_request(call)))
            await self.rpc_event(b,call,'request')
            await a.cmd('networkStop')
            r=await self.rpc_event(a,call,'cancel')
            check(r.get('error',{}).get('code') in ['CANCELLED','UNKNOWN_OUTCOME','NETWORK_NOT_READY'],'network stop did not cancel pending RPC')
            check(len(await a.devices())==1,'stop must reset directory to self')
        await self.case('CLOSE-PENDING','Network stop cancels pending operation and resets directory',close_pending,'close')
        for policy in ['END_SESSION','REVOKE_AND_END_SESSION','REVOKE_GRANT']:
            async def cloud(policy=policy):
                # Test with a real owned grant; no-grant UNSUPPORTED is not revocation proof.
                await self.login(a)
                r=(await a.cmd('authLogout',dict(cloudPolicy=policy,cloudBudget='30s')))['authLogout']
                check(r.get('localClosed') and not r.get('localError'),'cloud policy must still clean local state')
                if policy=='REVOKE_GRANT':
                    check(r['cloudStatus']=='CLOUD_LOGOUT_STATUS_SUCCEEDED' and not r.get('cloudError'), 'real refresh-grant revocation did not succeed')
                else:
                    check(r['cloudStatus']=='CLOUD_LOGOUT_STATUS_UNSUPPORTED' and r.get('cloudError',{}).get('code')=='UNSUPPORTED', 'reserved browser end-session must explicitly report unsupported')
            await self.case('CLOUD-'+policy, 'Cloud logout '+policy+' with real SDK-owned grant',cloud)


    async def offline_contract_cases(self):
        a=self.clients[0]
        async def watch_duplicate():
            wid=ident()
            try:
                await a.cmd('watchDevices',dict(watchId=wid))
                await a.cmd('watchDevices',dict(watchId=wid),error='CONFLICT')
            finally:
                await a.cmd('stopWatchDevices',dict(watchId=wid))
        await self.case('D06-WATCH-DUP','Duplicate watch ID must conflict',watch_duplicate,'negative')
        async def fifth_watch():
            watches=[ident() for _ in range(4)]
            await a.cmd('stopWatchDevices',dict(watchId=a.watch))
            try:
                for wid in watches:
                    await a.cmd('watchDevices',dict(watchId=wid))
                extra=ident()
                watches.append(extra)
                await a.cmd('watchDevices',dict(watchId=extra),error='RESOURCE_EXHAUSTED')
            finally:
                for wid in watches:
                    await a.cmd('stopWatchDevices',dict(watchId=wid))
        await self.case('D06-WATCH-LIMIT','Fifth watch exceeds four-watch contract',fifth_watch,'negative')
        async def restore_events():
            await self.restore_without_grant_after_logout(a)
        await self.case('AUTH-RESTORE-TERMINAL','No-grant restore operation phases and one failure terminal',restore_events,'negative')
        async def stopped_refresh():
            await a.cmd('networkStop')
            await a.cmd('refreshDevices',dict(queryId=ident(),budget='0.100s'),error='NETWORK_NOT_READY')
        await self.case('D02-STOPPED','Stopped refresh rejects admission synchronously',stopped_refresh,'negative')

    async def contract_cases(self):
        a,b=self.clients[:2]
        for command,event,args in [
            ('getDevices','devicesQuery',{}),
            ('refreshDevices','refreshDevices',dict(budget='1s')),
            ('getDeviceDescriptor','deviceDescriptor',dict(peerDeviceId=b.identity)),
            ('getBlockedDevices','blockedDevices',{}),
            ('pullDescriptor','descriptor',dict(peerDeviceId=b.identity,digest=self.digest,timeout='5s'))]:
            async def duplicate(command=command,event=event,args=args):
                qid=ident()
                await a.cmd(command,dict(queryId=qid,**args))
                await a.wait(lambda e:e.get(event,{}).get('queryId')==qid)
                await a.cmd(command,dict(queryId=qid,**args),error='CONFLICT')
                await asyncio.sleep(0.1)
                count=sum(e.get('event',{}).get(event,{}).get('queryId')==qid for e in a.events)
                check(count==1,'duplicate query produced a second terminal')
            await self.case('D07-DUP-'+command,'Duplicate query identity: '+command,duplicate,'negative')
        async def cross_query():
            qid=ident()
            await a.cmd('getDevices',dict(queryId=qid))
            await a.wait(lambda e:e.get('devicesQuery',{}).get('queryId')==qid)
            await a.cmd('getBlockedDevices',dict(queryId=qid),error='CONFLICT')
        await self.case('D07-CROSS','Query namespace must be shared across command types',cross_query,'negative')
        async def inflight_pull():
            if self.args.participants:
                raise Skip('per-peer in-flight test pauses only owned local SDK processes')
            qid=ident()
            os.kill(b.process.pid,signal.SIGSTOP)
            try:
                await a.cmd('pullDescriptor',dict(queryId=qid,peerDeviceId=b.identity,digest=self.digest,timeout='3s'))
                await a.cmd('pullDescriptor',dict(queryId=ident(),peerDeviceId=b.identity,digest=self.digest,timeout='3s'),error='RESOURCE_EXHAUSTED')
            finally:
                os.kill(b.process.pid,signal.SIGCONT)
            await a.wait(lambda e:e.get('descriptor',{}).get('queryId')==qid)
        await self.case('D07-INFLIGHT-PULL','One in-flight descriptor pull per session',inflight_pull,'negative')

        async def overlap():
            other=ident()
            try:
                await b.cmd('subscribeData',dict(subscriptionId=other,typeUrls=[REQUEST]),error='CONFLICT')
            finally:
                await b.cmd('unsubscribeData',dict(subscriptionId=other))
        await self.case('M01-OVERLAP','Overlapping typed subscription rejects ambiguous owner',overlap,'negative')
        async def subscription_duplicate():
            await b.cmd('subscribeData',dict(subscriptionId=b.subscription,typeUrls=[REQUEST]),error='CONFLICT')
        await self.case('M01-SUB-ID','Duplicate subscription ID must conflict',subscription_duplicate,'negative')
        async def unknown_cancel():
            await a.cmd('cancelData',dict(peerDeviceId=b64(b'\x42'*32),messageId=ident()))
        await self.case('M01-CANCEL-UNKNOWN','Unknown valid data cancellation is locally idempotent',unknown_cancel,'cancel')

        for ack in ['RECEIVED','ACCEPTED']:
            async def ack_limit(ack=ack):
                mid=ident()
                await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=mid,requestedAck=ack,timeout='2s',fragment=fragment('ack-limit'))))
                await b.wait(lambda e:e.get('dataReceived',{}).get('message',{}).get('messageId')==mid)
                await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and e['dataStatus'].get('stage')==ack)
                await asyncio.sleep(0.25)
                stages=[m['event']['dataStatus'].get('stage') for m in a.events if m.get('event',{}).get('dataStatus',{}).get('messageId')==mid]
                expected=['RECEIVED'] if ack=='RECEIVED' else ['RECEIVED','ACCEPTED']
                check(stages==expected,'sender API exposed a stage above requested ACK' )
                # This checks sender API observations; encrypted wire ACKs are not captured.
                # Explicit completion cannot emit a higher stage than requested.
                await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,stage='PROCESSED'))
                await asyncio.sleep(0.1)
                stages=[m['event']['dataStatus'].get('stage') for m in a.events if m.get('event',{}).get('dataStatus',{}).get('messageId')==mid]
                check(stages==expected,'application completion exceeded requested ACK ceiling')
            await self.case('M01-ACK-'+ack,'Sender-observed requested_ack ceiling '+ack,ack_limit)
        async def accepted_completion():
            mid=ident()
            await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=mid,requestedAck='PROCESSED',timeout='2s',fragment=fragment('accepted'))))
            await b.wait(lambda e:e.get('dataReceived',{}).get('message',{}).get('messageId')==mid)
            try:
                await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,stage='ACCEPTED'))
                await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,stage='ACCEPTED'))
            finally:
                await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,stage='PROCESSED'))
        await self.case('M01-ACCEPTED','Application ACCEPTED completion is idempotent',accepted_completion)
        async def terminal_completion():
            mid=ident()
            await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=mid,requestedAck='PROCESSED',timeout='2s',fragment=fragment('terminal'))))
            await b.wait(lambda e:e.get('dataReceived',{}).get('message',{}).get('messageId')==mid)
            await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,error=dict(code='CANCELLED')))
            await a.wait(lambda e:e.get('dataStatus',{}).get('messageId')==mid and 'error' in e['dataStatus'])
            mark=a.mark()
            result=await b.request('execute',command=dict(commandId=ident(),completeData=dict(peerDeviceId=a.identity,messageId=mid,stage='PROCESSED')))
            check('error' in result,'terminal failure must not turn into completion success')
            await asyncio.sleep(0.15)
            check(not any(e.get('event',{}).get('dataStatus',{}).get('messageId')==mid for e in a.events_since(mark)),'late completion emitted another terminal')
        await self.case('M01-TERMINAL','Data error is final; late success must not overwrite',terminal_completion,'negative')
        async def cancellation_completion():
            mid=ident()
            await a.cmd('send',dict(peerDeviceId=b.identity,message=dict(messageId=mid,requestedAck='PROCESSED',timeout='2s',fragment=fragment('cancel-complete'))))
            await b.wait(lambda e:e.get('dataReceived',{}).get('message',{}).get('messageId')==mid)
            await a.cmd('cancelData',dict(peerDeviceId=b.identity,messageId=mid))
            await b.wait(lambda e:e.get('peerDataCancel',{}).get('messageId')==mid)
            await b.cmd('completeData',dict(peerDeviceId=a.identity,messageId=mid,error=dict(code='CANCELLED')))
        await self.case('M01-CANCEL-COMPLETE','Peer cancellation permits explicit CANCELLED application completion',cancellation_completion,'cancel')
        async def handler_result():
            # Same method registration atomically replaces the existing registration.
            result=await b.cmd('registerHandler',b.handlers['UNARY'])
            check('publicProfile' in result,'RegisterHandler must return final public_profile')
        await self.case('H01-REPLACE','Register handler replaces same method and returns public profile',handler_result)
        async def handler_unregister():
            result=await b.cmd('unregisterHandler',dict(handlerId=b.handlers['UNARY']['handlerId']))
            try:
                check('publicProfile' in result,'UnregisterHandler must return final public_profile')
            finally:
                await self.register(b,'UNARY')
        await self.case('H01-UNREGISTER-RESULT','Unregister returns final public profile',handler_unregister)
        async def invalid_method():
            hid=ident()
            cap=dict(b.handlers['UNARY']['capability'],methodId='cyberbus.example.v1.Echo/NotInDescriptor')
            try:
                await b.cmd('registerHandler',dict(handlerId=hid,capability=cap,descriptorSet=self.descriptor),error=['INVALID_ARGUMENT','TYPE_MISMATCH','METHOD_NOT_EXPOSED'])
            finally:
                await b.cmd('unregisterHandler',dict(handlerId=hid))
        await self.case('H01-DESCRIPTOR-METHOD','Descriptor must actually declare registered method',invalid_method,'negative')
        async def duplicate_terminal():
            call=ident()
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=self.rpc_request(call)))
            await self.rpc_event(b,call,'request')
            await a.cmd('rpcEnd',dict(peerDeviceId=b.identity,end=dict(callId=call,direction='REQUEST',itemCount='0')))
            await self.rpc_event(b,call,'end')
            end=dict(callId=call,direction='RESPONSE',itemCount='0')
            await b.cmd('rpcEnd',dict(peerDeviceId=a.identity,end=end))
            await self.rpc_event(a,call,'end')
            mark=a.mark()
            await b.cmd('rpcEnd',dict(peerDeviceId=a.identity,end=end))
            await asyncio.sleep(0.15)
            count=sum(m.get('event',{}).get('rpc',{}).get('end',{}).get('callId')==call for m in a.events_since(mark))
            check(count==0,'duplicate RPC terminal reached caller twice')
        await self.case('R01-END-DUP','Duplicate response end is idempotent with one caller terminal',duplicate_terminal,'negative')
        async def completed_replay():
            call=ident()
            req=self.rpc_request(call)
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=req))
            await self.rpc_event(b,call,'request')
            await a.cmd('rpcCancel',dict(peerDeviceId=b.identity,cancel=dict(callId=call)))
            await self.rpc_event(b,call,'cancel')
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=req),error='CONFLICT')
        await self.case('R01-REPLAY','Cancelled call ID cannot dispatch handler again',completed_replay,'negative')
        async def slow_handler():
            call=ident()
            await a.cmd('rpcRequest',dict(peerDeviceId=b.identity,request=self.rpc_request(call,timeout='0.250s')))
            await self.rpc_event(b,call,'request')
            await asyncio.sleep(0.5)
            result=await b.request('execute',command=dict(commandId=ident(),rpcChunk=dict(peerDeviceId=a.identity,chunk=dict(callId=call,direction='RESPONSE',fragment=fragment('late',True)))))
            code=result.get('error',{}).get('code')
            check(code in ['DEADLINE_EXCEEDED','CANCELLED','PROTOCOL_ERROR'],'slow handler emitted a success after deadline')
        await self.case('R03-SLOW-HANDLER','Expired call rejects late slow-handler response',slow_handler,'deadline')
        async def self_descriptor():
            r=await a.query('getDeviceDescriptor','deviceDescriptor',peerDeviceId=a.identity)
            check(not r.get('fromCache'),'local self profile must not claim authenticated remote cache')
        await self.case('D-META-SELF','Self descriptor has valid local provenance',self_descriptor)

    async def poll_api(self):
        # An extra independent installation specifically exercises the alternative consumer.
        argv=[str(self.args.binary),'--config',str(self.args.config),'--state-dir',
              str(self.args.private_dir/'poll-probe'),'--events','poll']
        identity=None
        for attempt in range(2):
            # Initial mode is trusted run intent. Reopen is always installed-only,
            # even if files were deleted between launches.
            mode = self.args.store_mode if attempt == 0 else 'open'
            c=Client('poll-probe',argv+['--store-mode',mode],self)
            self.probes.append(c)
            await c.start()
            qid=ident()
            await c.cmd('getDevices',dict(queryId=qid))
            event=(await c.request('poll_event',timeoutMs=1000))['event']
            check(event['devicesQuery']['queryId']==qid,'poll query correlation failed')
            local=event['devicesQuery']['snapshot']['devices'][0]
            if identity:
                check(local['deviceId']==identity,'reopened installation identity changed')
            identity=local['deviceId']
            check(await c.request('poll_event',timeoutMs=1) is None,'empty poll should return null')
            if attempt:
                check((await c.request('take_event_receiver'))['taken'],'first receiver transfer failed')
                check(not (await c.request('take_event_receiver'))['taken'],'second receiver transfer succeeded')
            await c.terminate()

    async def restore_lifecycle(self):
        if self.args.offline:
            raise Skip('hosted restore not executed in offline mode')
        check(self.args.login_driver,'restore lifecycle requires callback-only --login-driver')
        # Explicit test opt-in, private copied public config. Default samples remain memory-only.
        config=json.loads(self.args.config.read_text())
        config['persist_grant']=True
        selected=self.args.private_dir/'restore-public-config.json'
        selected.write_text(json.dumps(config))
        selected.chmod(0o600)
        state=self.args.private_dir/'restore-installation'
        argv=[str(self.args.binary),'--config',str(selected),'--state-dir',str(state)]
        first=Client('restore-authorize',argv+['--store-mode','provision'],self)
        self.probes.append(first)
        await first.start()
        first.identity=(await first.devices())[0]['deviceId']
        await self.login(first)  # Only SDK authorization URL -> hosted callback; never import a token.
        await self.restore_authenticated(first)  # Same operation contract with durable grant opt-in.
        authorized=(await first.cmd('getAuthState'))['authState']
        closed=(await first.cmd('sdkClose'))['sdkClosed']
        check(closed.get('closed') and not closed.get('cleanupError'),'explicit SDK close failed')
        await first.terminate()  # SDK close, deliberately NO AuthLogout.
        second=Client('restore-reopen',argv+['--store-mode','open'],self)
        self.probes.append(second)
        await second.start()
        check((await second.devices())[0]['deviceId']==first.identity,'restore changed installation identity')
        cold=(await second.cmd('getAuthState'))['authState']
        check(cold['phase']!='AUTHENTICATED' and not any(cold.get(k) for k in
              ['validationLeaseExpiresAt','lastOnlineValidationAt','validationRequestStartedAt','accessTokenExpiresAt']),
              'cold reopen inherited validation/access lease state')
        check(not any(m.get('event',{}).get('network',{}).get('running') for m in second.events),
              'cold reopen automatically started network')
        operation=ident()
        marker=second.mark()
        accepted=await second.cmd('authRestore',dict(operationId=operation))
        check('ok' in accepted,'restore must be accepted')
        terminal=(await second.wait(lambda e:e.get('auth',{}).get('operationId')==operation and
            e['auth'].get('phase') in ['AUTHENTICATED','FAILED','AUTH_CANCELLED','REAUTH_REQUIRED','CONFIGURATION_ERROR'],
            timeout=40,since=marker))['auth']
        phases=[m['event']['auth']['phase'] for m in second.events_since(marker)
                if m.get('event',{}).get('auth',{}).get('operationId')==operation]
        check(phases==['RESTORING','AUTHENTICATED'] and 'error' not in terminal,
              'restore must emit one RESTORING then AUTHENTICATED terminal')
        check(terminal.get('validationRequestStartedAt') and terminal.get('lastOnlineValidationAt')
              and terminal.get('validationLeaseExpiresAt'),'restore omitted real issuance/validation lease timestamps')
        restored=(await second.cmd('getAuthState'))['authState']
        check(restored['phase']=='AUTHENTICATED' and restored.get('account')==authorized.get('account')
              and restored.get('refreshSupported') and not restored.get('refreshGrantFrozen'),
              'restore did not reestablish the same account with an available grant')
        check(not any(m.get('event',{}).get('network',{}).get('running') for m in second.events),
              'restore automatically started network')
        # Public SDK requires a published local profile before explicit network start.
        await self.profile(second)
        await second.cmd('networkStart')
        await second.wait(lambda e:e.get('network',{}).get('running'))
        await second.cmd('networkStop')
        logout=(await second.cmd('authLogout',dict(cloudPolicy='LOCAL_ONLY')))['authLogout']
        check(logout.get('localClosed') and not logout.get('localError'),'explicit logout cleanup failed')
        await second.terminate()
        check([m['event']['auth']['phase'] for m in second.events_since(marker)
               if m.get('event',{}).get('auth',{}).get('operationId')==operation]
              ==['RESTORING','AUTHENTICATED'],'restore emitted a repeated operation terminal')
        third=Client('restore-after-logout',argv+['--store-mode','open'],self)
        self.probes.append(third)
        await third.start()
        check((await third.devices())[0]['deviceId']==first.identity,'logout erased installation identity')
        operation=ident()
        marker=third.mark()
        await third.cmd('authRestore',dict(operationId=operation))
        failed=(await third.wait(lambda e:e.get('auth',{}).get('operationId')==operation and
                                e['auth'].get('phase')=='FAILED',since=marker))['auth']
        phases=[m['event']['auth']['phase'] for m in third.events_since(marker)
                if m.get('event',{}).get('auth',{}).get('operationId')==operation]
        check(phases==['RESTORING','FAILED'] and failed.get('error',{}).get('code')=='UNAUTHENTICATED',
              'AuthLogout did not erase persisted grant')
        await third.terminate()
        check([m['event']['auth']['phase'] for m in third.events_since(marker)
               if m.get('event',{}).get('auth',{}).get('operationId')==operation]
              ==['RESTORING','FAILED'],'grantless restore emitted a repeated operation terminal')
        CURRENT.get()['facts']=dict(sdkOwnedHostedExchange=True,persistGrantOptIn=True,
            sequentialSdkProcesses=3,sameInstallation=True,coldLeaseAbsent=True,restorePhases=['RESTORING','AUTHENTICATED'],
            explicitSdkClose=True,explicitNetworkStart=True,logoutErasedGrant=True,
            afterLogoutPhases=['RESTORING','FAILED'],leaseTimes={key:terminal[key] for key in
                ['validationRequestStartedAt','lastOnlineValidationAt','validationLeaseExpiresAt']})

    async def large_cases(self):
        login_title = 'Independent callback-only hosted PKCE login'
        restore_case = ('AUTH-RESTORE-AUTHENTICATED', 'Authenticated in-memory grant restore emits strict progress and success')
        directory_case = ('SCALE-DIRECTORY', 'All real clients simultaneously online and full authenticated directory')
        business_plan = ([('SCALE-ROUND-'+str(i), 'Directed data/processed ACK round '+str(i))
                          for i in range(1, len(self.clients))] if self.args.suite == 'scale' else [
            ('STABILITY-STEADY', 'Real steady-state directory/data/ACK checks'),
            ('STABILITY-RESTART', 'Repeated real network stop/start and rediscovery')])

        async def skip_remaining(blocking_case, plan):
            async def not_run():
                raise Skip('not executed after '+blocking_case+' failed')
            for cid, title in plan:
                await self.case(cid, title, not_run)

        for index, c in enumerate(self.clients):
            cid = 'AUTH-LIVE-'+c.name
            if not await self.case(cid, login_title, lambda c=c:self.login(c)):
                await skip_remaining(cid, [('AUTH-LIVE-'+c.name, login_title)
                    for c in self.clients[index+1:]]+[restore_case, directory_case]+business_plan)
                return
        await self.case(*restore_case, lambda:self.restore_authenticated(self.clients[0]))
        async def startup():
            semaphore=asyncio.Semaphore(self.args.network_concurrency)
            async def start(c):
                async with semaphore:
                    await c.cmd('networkStart')
            await settle_all((dict(client=c.name), start(c)) for c in self.clients)
            await self.converge()
            CURRENT.get()['facts']=dict(simultaneousClients=len(self.clients),fullAuthenticatedDirectory=True)
        if not await self.case(*directory_case, startup):
            await skip_remaining(directory_case[0], business_plan)
            return
        if self.args.suite=='scale':
            # N-1 rounds, one outbound/inbound per client in each round. Covers every
            # directed pair without exceeding per-peer queue limits or printing 65k rows.
            for offset in range(1,len(self.clients)):
                cid, title = business_plan[offset-1]
                async def round_(offset=offset):
                    CURRENT.get()['facts']=dict(directedPairs=len(self.clients),offset=offset)
                    await settle_all((dict(sender=a.name, receiver=b.name), self.data(a,b))
                        for i,a in enumerate(self.clients)
                        for b in [self.clients[(i+offset)%len(self.clients)]])
                if not await self.case(cid, title, round_):
                    await skip_remaining(cid, business_plan[offset:])
                    break
        else:
            async def steady():
                deadline=time.monotonic()+self.args.stability_seconds
                rounds=0
                progress=time.monotonic()+30
                while time.monotonic()<deadline:
                    await settle_all((dict(sender=a.name, receiver=b.name), self.data(a,b))
                        for i,a in enumerate(self.clients)
                        for b in [self.clients[(i+1)%len(self.clients)]])
                    await self.converge()
                    rounds+=1
                    if time.monotonic()>=progress:
                        print('PROGRESS stability completed rounds',rounds,flush=True)
                        progress=time.monotonic()+30
                    await asyncio.sleep(min(10,max(0,deadline-time.monotonic())))
                CURRENT.get()['facts']=dict(seconds=self.args.stability_seconds,rounds=rounds)
            await self.case('STABILITY-STEADY','Real steady-state directory/data/ACK checks',steady)
            async def cycles():
                for _ in range(self.args.restart_cycles):
                    for c in self.clients:
                        await c.cmd('networkStop')
                        check(len(await c.devices())==1,'stop retained remote directory')
                    for c in self.clients:
                        await c.cmd('networkStart')
                    await self.converge()
                    await self.data(self.clients[0],self.clients[1])
                CURRENT.get()['facts']=dict(restartCycles=self.args.restart_cycles)
            await self.case('STABILITY-RESTART','Repeated real network stop/start and rediscovery',cycles)

    async def cleanup_cases(self):
        for c in self.clients:
            async def cleanup(c=c):
                r=await c.cmd('authLogout',dict(cloudPolicy='LOCAL_ONLY'))
                check(r['authLogout'].get('localClosed') and not r['authLogout'].get('localError'),'logout local cleanup failed')
                closing=time.monotonic()
                r=await c.cmd('sdkClose')
                check(time.monotonic()-closing<=5.25,'SDK close exceeded fixed five-second budget')
                check(r['sdkClosed'].get('closed') is True and 'cleanupError' not in r['sdkClosed'],'SDK close failed')
                await c.wait(lambda e:e.get('eventsClosed'),raw=True)
                closed=await c.request('close')
                check(closed.get('sdkClosed')==r['sdkClosed'],'repeat close must return same SdkClosed result')
            await self.case('CLOSE-'+c.name,'Logout, final event EOF and idempotent close',cleanup,'close')
            async def reject(c=c):
                await c.cmd('getAuthState',error='CANCELLED')
            await self.case('CLOSE-REJECT-'+c.name,'Closed handle rejects new command with CANCELLED',reject,'close')


async def run(args):
    os.umask(0o077)
    args.private_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(args.private_dir,0o700)
    # Shared target may be rebuilt by another owner during a long scale run.
    # Pin the tested artifact so every local participant uses the same bytes.
    original=args.binary.resolve()
    pinned=args.private_dir/'cyberbus-test-client'
    shutil.copyfile(original,pinned)
    pinned.chmod(0o700)
    args.binary=pinned.resolve()
    metadata=json.loads(subprocess.check_output([str(args.binary),'--describe']))
    suite=Suite(args,metadata)
    try:
        if args.suite=='restore':
            await suite.case('AUTH-RESTORE-GRANT','SDK hosted authorization, close/reopen, real restore, explicit start and logout',suite.restore_lifecycle)
            async def strict_restore():
                check(not suite.invalid_sdk,'SDK restore result/event failed its strict codec')
            await suite.case('SCHEMA-SDK-OUTPUT','Every restore SDK result/event strictly validates',strict_restore)
        elif await suite.case('N-000','Create N independent real SDK installations',suite.setup):
            await suite.case('API-003','Actual poll receiver, timeout and persisted installation reopen',suite.poll_api)
            await suite.offline_cases()
            if args.offline:
                async def skipped():
                    raise Skip('offline mode requested; hosted integration not executed')
                await suite.case('N-001','N hosted simultaneous login, visibility and all-direction exchange',skipped)
            else:
                if args.suite=='api':
                    await suite.live_cases()
                else:
                    await suite.large_cases()
            for cid,title,reason in [
                ('AUTH-RESTORE-GRANT','Successful real grant restoration','Run the separate --suite restore with explicit persistent-grant opt-in'),
                ('AUTH-REGISTER-COMPLETE','New-account hosted registration callback','Existing test account driver; registration intent/cancel only'),
                ('EVENT-OFFLINE','Probe-based remote offline classification','Requires slow offline-probe/core scheduling acceptance'),
                ('D07-FOUR-INFLIGHT','Four global in-flight queries with independent remote stalls','N3 gives two remote sessions; dedicated five-peer pending-query saturation is not executed in this default run'),
                ('RPC-LOW-NEGOTIATED','Peer negotiated window smaller than 64KiB/4 items','ClientConfig currently has no receive-limit negotiation override; fixed-window exhaustion is tested separately'),
                ('FAULT-PERSISTENCE','Storage failure and restart fault boundaries','No fault injection into real secure store in this suite')]:
                async def skip(reason=reason):
                    raise Skip(reason)
                await suite.case(cid,title,skip)
            await suite.offline_contract_cases()
            await suite.cleanup_cases()
            async def strict_sdk():
                check(not suite.invalid_sdk,'SDK returned/emitted '+str(len(suite.invalid_sdk))+' objects rejected by its strict codec')
            await suite.case('SCHEMA-SDK-OUTPUT','Every real SDK result/event strictly validates',strict_sdk)
    finally:
        for c in suite.clients:
            if hasattr(c,'process'):
                await suite.case('PROCESS-'+c.name,'SDK process cleanup and zero exit',c.terminate,'close')
        for c in suite.probes:
            if hasattr(c,'process') and c.process.returncode is None:
                if args.suite=='restore' and not c.sdk_closed:
                    async def discard_test_grant(c=c):
                        result=(await c.cmd('authLogout',dict(cloudPolicy='LOCAL_ONLY')))['authLogout']
                        check(result.get('localClosed') and not result.get('localError'),'failed restore probe grant cleanup failed')
                    await suite.case('GRANT-CLEANUP-'+c.name,'Erase owned test grant after failed restore case',discard_test_grant,'close')
                await suite.case('PROCESS-PROBE-'+c.name,'Probe SDK process cleanup and zero exit',c.terminate,'close')
        if suite.relay:
            suite.relay.stdin.close()
            try:
                await asyncio.wait_for(suite.relay.wait(),10)
            except asyncio.TimeoutError:
                suite.relay.kill()
                await suite.relay.wait()
        report=suite.report()
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2)+'\n')
        print('Report:',args.report,'Summary:',json.dumps(report['summary']),flush=True)
    return 1 if report['summary']['FAIL'] else 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'target/debug/cyberbus-test-client')
    p.add_argument('--sdk-source',type=Path,default=ROOT,help='source tree used to build the supplied binary; recorded separately from harness provenance')
    p.add_argument('--config',type=Path,default=ROOT/'deploy/test-client.json')
    p.add_argument('--n',type=int,default=3)
    p.add_argument('--suite',choices=['api','scale','stability','restore'],default='api')
    p.add_argument('--local-relay',action='store_true',help='own independent loopback EasyTier relay, no public data path')
    p.add_argument('--converge-timeout',type=float,default=180)
    p.add_argument('--network-concurrency',type=int,default=4)
    p.add_argument('--stability-seconds',type=float,default=1800)
    p.add_argument('--restart-cycles',type=int,default=100)
    p.add_argument('--private-dir',type=Path,default=ROOT/'target/multiclient-private'/time.strftime('%Y%m%d-%H%M%S'))
    p.add_argument('--report',type=Path,default=ROOT/'target/multiclient-report.json')
    p.add_argument('--participants',type=Path,help='JSON array of {name,command:[argv...]}, local or SSH')
    p.add_argument('--login-driver',help='private callback-only command; stdin authorization URI, stdout callback URI')
    p.add_argument('--store-mode',choices=['provision','open','migrate'],default='provision',
                   help='trusted local startup intent; no missing-file or open-error fallback')
    p.add_argument('--offline',action='store_true',help='real SDK lifecycle only; explicitly skip hosted/network tests')
    args=p.parse_args()
    if args.network_concurrency<1 or args.stability_seconds<0 or args.restart_cycles<0:
        p.error('invalid concurrency or duration/cycle count')
    if args.suite=='restore' and (args.participants or args.local_relay):
        p.error('restore uses three sequential local SDK processes and the configured public bootstrap')
    return asyncio.run(run(args))


if __name__=='__main__':
    raise SystemExit(main())
