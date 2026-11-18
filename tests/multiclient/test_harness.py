"""Harness fault regressions only; these are not real SDK integration evidence."""
import asyncio
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).parent))
from runner import Client, Suite, check_rpc_request

PEER = '''import json,sys
mode=sys.argv[1]
print(json.dumps({"ready":True}),flush=True)
for line in sys.stdin:
 r=json.loads(line)
 if mode=="eof": break
 if r["op"]=="on_resume":
  value={"error":{"code":"UNAVAILABLE"}}
 elif r["op"]=="poll_event":
  value={"event":{"eventSequence":"1"},"sdkValid":False}
 elif r["op"]=="execute_bytes":
  print(json.dumps({"id":r["id"],"ok":True,"sdkValid":False,"result":{"result":{"commandId":"bad"},"bytes":""}}),flush=True)
  continue
 elif mode=="error":
  value={"error":{"code":"UNAVAILABLE"}}
 elif mode=="cleanup_error":
  value={"sdkClosed":{"closed":True,"cleanupError":{"code":"UNAVAILABLE"}}}
 elif mode=="not_closed":
  value={"sdkClosed":{"closed":False}}
 else:
  value={"sdkClosed":{"closed":True}}
 print(json.dumps({"id":r["id"],"ok":True,"result":value}),flush=True)
 if r["op"]=="shutdown": break
'''

POLL_SEQUENCE_PEER = '''import json,sys
mode=sys.argv[1]
print(json.dumps({"ready":True}),flush=True)
sequence=iter([2,1] if mode=="reversed" else [1,2])
for line in sys.stdin:
 r=json.loads(line)
 if r["op"]=="poll_event":
  value={"event":{"eventSequence":str(next(sequence))},"sdkValid":mode!="invalid"}
 else:
  value={"sdkClosed":{"closed":True}}
 print(json.dumps({"id":r["id"],"ok":True,"result":value}),flush=True)
 if r["op"]=="shutdown": break
'''


SMOKE_PEER = '''import json,os,sys
mode=os.environ["SMOKE_FAULT"]
print(json.dumps({"ready":True}),flush=True)
for line in sys.stdin:
 r=json.loads(line)
 op=r["op"]
 if op=="execute":
  value={"commandId":r["command"]["commandId"],"authState":{"phase":"LOGGED_OUT"}}
 elif op=="on_resume":
  value={"error":{"code":"UNAVAILABLE"}} if mode=="resume" else {}
 else:
  if mode=="eof": break
  value={"sdkClosed":{"closed":True}}
  if mode=="shutdown": value={"error":{"code":"UNAVAILABLE"}}
  if mode=="not_closed": value={"sdkClosed":{"closed":False}}
  if mode=="cleanup_error": value["sdkClosed"]["cleanupError"]={"code":"UNAVAILABLE"}
 print(json.dumps({"id":r["id"],"ok":True,"result":value}),flush=True)
 if op=="shutdown":
  if mode!="no_event_eof": print(json.dumps({"eventsClosed":True}),flush=True)
  break
'''


class FaultSuite:
    def __init__(self):
        self.invalid_sdk=[]
        self.observed=[]
        self.results=set()
    def observe(self,event):
        self.observed.append(event)


class HarnessErrors(unittest.IsolatedAsyncioTestCase):
    async def client(self,mode):
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        script=Path(directory.name)/'wire.py'
        script.write_text(PEER)
        client=Client('protocol-fault',[sys.executable,str(script),mode],FaultSuite())
        await client.start()
        return client

    async def test_sdk_resume_error_inside_ok_envelope_fails(self):
        client=await self.client('valid')
        with self.assertRaisesRegex(AssertionError,'on_resume failed'):
            await client.resume()
        await client.terminate()
        self.assertEqual(client.process.returncode,0)

    async def test_shutdown_errors_fail_even_when_process_exits_zero(self):
        for mode in ['error','cleanup_error','not_closed']:
            with self.subTest(mode=mode):
                client=await self.client(mode)
                with self.assertRaisesRegex(AssertionError,'successful SDK cleanup'):
                    await client.terminate()
                self.assertEqual(client.process.returncode,0)

    async def test_premature_process_eof_is_not_successful_cleanup(self):
        client=await self.client('eof')
        with self.assertRaises(AssertionError):
            await client.terminate()

    async def test_nested_poll_and_bytes_invalidity_enter_strict_gate(self):
        for operation in ['poll_event','execute_bytes']:
            with self.subTest(operation=operation):
                client=await self.client('valid')
                with self.assertRaisesRegex(AssertionError,'strict validation'):
                    await client.request(operation)
                self.assertEqual(len(client.suite.invalid_sdk),1)
                await client.terminate()

    async def test_real_read_poll_sequence_shares_observer_without_duplicate_events(self):
        for mode in ['ordered','reversed','invalid']:
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as temporary:
                    script=Path(temporary)/'poll.py'
                    script.write_text(POLL_SEQUENCE_PEER)
                    suite=FaultSuite()
                    client=Client('poll-sequence',[sys.executable,str(script),mode],suite)
                    await client.start()
                    if mode=='invalid':
                        with self.assertRaisesRegex(AssertionError,'strict validation'):
                            await client.request('poll_event')
                        self.assertEqual(len(suite.invalid_sdk),1)
                    else:
                        await client.request('poll_event')
                        self.assertEqual(client.sequence,1 if mode=='ordered' else 2)
                        if mode=='reversed':
                            with self.assertRaises(AssertionError):
                                await client.request('poll_event')
                            self.assertEqual(client.sequence,2)
                            self.assertIsNotNone(client.fatal)
                        else:
                            await client.request('poll_event')
                            self.assertEqual(client.sequence,2)
                            self.assertEqual(len(suite.observed),2)
                    self.assertFalse(any('event' in message for message in client.events))
                    if mode=='reversed':
                        client.process.stdin.close()
                        await asyncio.wait_for(client.process.wait(),3)
                        await client.reader
                    else:
                        await client.terminate()

    async def test_rpc_remaining_budget_and_corrupt_metadata_case_gate(self):
        # Real Suite.rpc/rpc_event and Client.wait predicates, with deterministic
        # controller events instead of a network. No SDK evidence is claimed.
        for fault in ['valid_shorter_timeout','valid_equal_timeout',
                      'request_method','request_type','response_type','streaming','version',
                      'timeout_zero','timeout_negative','timeout_overrun','timeout_missing','timeout_malformed',
                      'request_end_direction','request_end_count','request_end_error',
                      'response_end_direction','response_end_count','response_end_error',
                      'request_chunk_direction','request_chunk_sequence','response_chunk_direction',
                      'response_chunk_sequence','peer']:
            with self.subTest(fault=fault):
                suite=Suite.__new__(Suite)
                suite.cases=[]
                a=Client('a',[],FaultSuite()); a.identity='a'
                b=Client('b',[],FaultSuite()); b.identity='b'
                async def command(sender,name,value):
                    peer=b if sender is a else a
                    body={'rpcRequest':'request','rpcChunk':'chunk','rpcEnd':'end'}[name]
                    event=dict(value[body])
                    direction='request' if sender is a else 'response'
                    if body=='request':
                        event['timeout']='9.999999999s'
                        for scenario,key,bad in [('request_method','methodId','cyberbus.example.v1.Echo/Wrong'),
                            ('request_type','requestTypeUrl','type.googleapis.com/cyberbus.example.v1.WrongRequest'),
                            ('response_type','responseTypeUrl','type.googleapis.com/cyberbus.example.v1.WrongReply'),
                            ('streaming','streaming','BIDI'),('version','semanticVersion','2.0.0'),
                            ('valid_equal_timeout','timeout','10s'),('timeout_zero','timeout','0s'),
                            ('timeout_negative','timeout','-0.001s'),('timeout_overrun','timeout','10.000000001s'),
                            ('timeout_malformed','timeout','NaNs')]:
                            if fault==scenario: event[key]=bad
                        if fault=='timeout_missing': event.pop('timeout')
                    if fault==direction+'_'+body+'_direction': event['direction']='RESPONSE' if sender is a else 'REQUEST'
                    if fault==direction+'_'+body+'_sequence': event['itemSequence']='999'
                    if fault==direction+'_'+body+'_count': event['itemCount']='999'
                    if fault==direction+'_'+body+'_error': event['error']={'code':'UNAVAILABLE'}
                    peer.events.append({'event':{'rpc':{'peerDeviceId':'wrong' if fault=='peer' else sender.identity,body:event}}})
                async def acmd(name,value): await command(a,name,value)
                async def bcmd(name,value): await command(b,name,value)
                a.cmd=acmd; b.cmd=bcmd
                passed=await suite.case('RPC-FAULT','corrupt controller RPC metadata',lambda:suite.rpc(a,b))
                expected=fault.startswith('valid_')
                self.assertEqual(passed,expected)
                self.assertEqual(suite.cases[-1]['status'],'PASS' if expected else 'FAIL')

    def test_rpc_request_comparison_preserves_call_and_all_metadata(self):
        suite=Suite.__new__(Suite)
        submitted=suite.rpc_request('call','UNARY','0.300s')
        check_rpc_request(dict(submitted,timeout='0.299999999s'),submitted)
        check_rpc_request(dict(submitted,timeout='0.000000001s'),submitted)
        for key,value in [('callId','other-call'),('methodId','other-method'),
                          ('requestTypeUrl','other-request'),('responseTypeUrl','other-response'),
                          ('streaming','BIDI'),('semanticVersion','2.0.0'),('extra','unexpected'),
                          ('timeout','0.300000001s'),('timeout','0s'),('timeout','Infinitys')]:
            with self.subTest(key=key,value=value):
                with self.assertRaises(AssertionError):
                    check_rpc_request(dict(submitted,**{key:value}),submitted)

    async def test_rpc_unsupported_requires_both_registration_rejection_and_invoke_unsupported(self):
        for registration,invoke,passes in [('TYPE_MISMATCH','UNSUPPORTED',True),
                ('UNSUPPORTED','UNSUPPORTED',True), (None,'UNSUPPORTED',False),
                ('INVALID_ARGUMENT','UNSUPPORTED',False),('TYPE_MISMATCH','TYPE_MISMATCH',False),
                ('TYPE_MISMATCH',None,False)]:
            with self.subTest(registration=registration,invoke=invoke):
                suite=Suite.__new__(Suite)
                suite.descriptor='controller-descriptor'; suite.digest='controller-digest'
                a=Client('a',[],FaultSuite()); a.identity='a'
                b=Client('b',[],FaultSuite()); b.identity='b'
                registered=[]; invoked=[]
                async def callee(op,command):
                    self.assertEqual(op,'execute')
                    registered.append(command['registerHandler'])
                    return dict(commandId=command['commandId'],**({'error':{'code':registration}} if registration else {'ok':{}}))
                async def caller(op,command):
                    self.assertEqual(op,'execute')
                    invoked.append(command['rpcRequest']['request'])
                    return dict(commandId=command['commandId'],**({'error':{'code':invoke}} if invoke else {'ok':{}}))
                a.request=caller; b.request=callee
                if passes:
                    await suite.rpc_unsupported(a,b)
                    self.assertEqual(len(registered),2)
                    self.assertEqual(len(invoked),2)
                    self.assertEqual([r['streaming'] for r in invoked],['CLIENT_STREAMING','SERVER_STREAMING'])
                    for declaration,request in zip(registered,invoked):
                        self.assertEqual(declaration['capability']['methodId'],'cyberbus.example.v1.Echo/Chat')
                        self.assertEqual(declaration['capability']['streaming'],request['streaming'])
                else:
                    with self.assertRaises(AssertionError):
                        await suite.rpc_unsupported(a,b)


class SmokeExitTests(unittest.TestCase):
    def test_cli_faults_fail_report_and_exit_nonzero(self):
        smoke=Path(__file__).parents[1]/'cross-network'/'machine-smoke.py'
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            peer=directory/'peer'
            peer.write_text('#!'+sys.executable+'\n'+SMOKE_PEER)
            peer.chmod(0o700)
            for fault in ['valid','resume','shutdown','not_closed','cleanup_error','eof','no_event_eof']:
                with self.subTest(fault=fault):
                    report=directory/(fault+'.json')
                    result=subprocess.run([sys.executable,str(smoke),'--binary',str(peer),
                        '--config',str(directory/'public.json'),'--state-dir',str(directory/fault),
                        '--report',str(report)],capture_output=True,text=True,
                        env=dict(os.environ,SMOKE_FAULT=fault),timeout=10)
                    expected='passed' if fault=='valid' else 'failed'
                    self.assertEqual(json.loads(report.read_text())['status'],expected)
                    self.assertEqual(result.returncode,0 if fault=='valid' else 1)


if __name__=='__main__':
    unittest.main()
