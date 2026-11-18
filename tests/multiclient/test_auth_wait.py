"""Real Client.read/command dispatch with a delayed controller fixture, not SDK evidence."""
import asyncio
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest

from runner import Client, Suite


PEER = '''import base64,json,sys,threading
mode=sys.argv[1]
lock=threading.RLock()
sequence=0
account={"issuer":"https://example.invalid/oidc","subject":"public-subject","productId":"cyberbus"}
authenticated={"phase":"AUTHENTICATED","account":account,"refreshSupported":True,"stateRevision":"9","lastOnlineValidationAt":"2026-11-17T17:00:00Z","validationLeaseExpiresAt":"2026-11-17T17:10:00Z"}
state=dict(authenticated) if mode.startswith(("authenticated-","logout-")) else {"phase":"LOGGED_OUT"}
operation=base64.b64encode(bytes([1])*16).decode()
def out(value):
 with lock: print(json.dumps(value),flush=True)
def event(auth):
 global sequence
 with lock:
  sequence+=1
  out({"event":{"eventSequence":str(sequence),"auth":auth},"sdkValid":not (mode=="authenticated-invalid" and auth.get("phase")=="RESTORING")})
def login_done():
 global state
 if mode=="login-no-terminal": return
 if mode=="login-success":
  event({"operationId":base64.b64encode(bytes([2])*16).decode(),"phase":"FAILED","error":{"code":"UNAUTHENTICATED"}})
  state={"phase":"AUTHENTICATED","refreshSupported":True,"lastOnlineValidationAt":"2026-11-17T17:00:00Z","validationLeaseExpiresAt":"2026-11-17T17:10:00Z"}
  event(dict(state,operationId=operation))
 else:
  phase="AUTHENTICATED" if mode=="login-error-terminal" else "FAILED"
  event({"operationId":operation,"phase":phase,"error":{"code":"UNAUTHENTICATED"}})
def restore_done(oid):
 global state
 if mode.startswith("authenticated-"):
  if mode=="authenticated-no-terminal": return
  if mode=="authenticated-duplicate": event({"operationId":oid,"phase":"RESTORING","stateRevision":"10"})
  state=dict(authenticated,stateRevision="11")
  if mode=="authenticated-changed-account": state["account"]=dict(account,subject="other-subject")
  terminal=dict(state,operationId=oid)
  if mode=="authenticated-failed": terminal.update(phase="FAILED",error={"code":"UNAUTHENTICATED"})
  if mode=="authenticated-error-terminal": terminal["error"]={"code":"UNAVAILABLE"}
  event(terminal)
  return
 if mode=="restore-no-terminal": return
 if mode=="restore-duplicate-stage": event({"operationId":oid,"phase":"RESTORING"})
 event({"operationId":oid,"phase":"FAILED","error":{"code":"UNAVAILABLE" if mode=="restore-wrong-code" else "UNAUTHENTICATED"}})
out({"ready":True})
for line in sys.stdin:
 r=json.loads(line)
 if r["op"]=="shutdown":
  out({"id":r["id"],"ok":True,"result":{"sdkClosed":{"closed":True}}}); break
 c=r["command"]
 value={"commandId":c["commandId"]}
 after=None
 if "authStart" in c: value["authStarted"]={"operationId":operation,"authorizationUri":"https://example.invalid/authorize"}
 elif "authCallback" in c:
  value["ok"]={}; after=login_done
 elif "getAuthState" in c: value["authState"]=state
 elif "authLogout" in c:
  if c["authLogout"].get("cloudPolicy")!="LOCAL_ONLY": value["error"]={"code":"INVALID_ARGUMENT"}
  else:
   value["authLogout"]={"localClosed":mode!="logout-not-closed"}
   if mode=="logout-local-error": value["authLogout"]["localError"]={"code":"INTERNAL"}
   state={"phase":"LOGGED_OUT"}
   if mode=="logout-retained-grant": state["refreshSupported"]=True
   if mode=="logout-retained-account": state["account"]=account
   if mode=="logout-wrong-phase": state=dict(authenticated)
 elif "authRestore" in c:
  oid=c["authRestore"]["operationId"]
  if mode=="restore-sync-error" or (mode.startswith("logout-") and state.get("phase")=="AUTHENTICATED"): value["error"]={"code":"UNAUTHENTICATED"}
  else:
   value["ok"]={}
   after=lambda oid=oid:restore_done(oid)
 else: value["ok"]={}
 out({"id":r["id"],"ok":True,"result":value,"sdkValid":True})
 if "authRestore" in c and after:
  progress={"operationId":oid,"phase":"RESTORING","stateRevision":"10"}
  if mode=="authenticated-progress-account": progress["account"]=account
  event(progress)
 if after: threading.Timer(0.05,after).start()
'''


class AuthWait(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, mode, login, passes, restore_mode=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            peer = directory / 'peer.py'
            peer.write_text(PEER)
            driver = directory / 'driver.py'
            driver.write_text('import sys\nsys.stdin.read()\nprint("http://127.0.0.1/callback?code=controller-fixture")\n')
            suite = Suite.__new__(Suite)
            suite.args = SimpleNamespace(login_driver=shlex.join([sys.executable, str(driver)]))
            suite.results, suite.events = set(), set()
            suite.nested, suite.invalid_sdk = {}, []
            client = Client('auth-wait', [sys.executable, str(peer), mode], suite)
            await client.start()
            original_wait = client.wait

            async def bounded_wait(*args, **kwargs):
                kwargs['timeout'] = 1
                return await original_wait(*args, **kwargs)

            client.wait = bounded_wait
            try:
                action = suite.login if login else suite.restore_without_grant
                if restore_mode=='logout': action=suite.restore_without_grant_after_logout
                if restore_mode=='authenticated': action=suite.restore_authenticated
                if passes:
                    await action(client)
                else:
                    with self.assertRaises(AssertionError):
                        await action(client)
                if mode=='authenticated-invalid':
                    self.assertEqual(len(suite.invalid_sdk), 1)
                else:
                    self.assertEqual(suite.invalid_sdk, [])
            finally:
                await client.terminate()

    async def test_login_waits_for_own_delayed_success_and_ignores_unrelated_failure(self):
        await self.exercise('login-success', login=True, passes=True)

    async def test_accepted_callback_without_valid_terminal_never_passes(self):
        for mode in ['login-failed', 'login-error-terminal', 'login-no-terminal']:
            with self.subTest(mode=mode):
                await self.exercise(mode, login=True, passes=False)

    async def test_grantless_restore_accepts_then_requires_restoring_failed_unauthenticated(self):
        await self.exercise('restore-success', login=False, passes=True)

    async def test_grantless_restore_rejects_old_sync_error_wrong_error_duplicates_and_missing_terminal(self):
        for mode in ['restore-sync-error', 'restore-wrong-code', 'restore-duplicate-stage', 'restore-no-terminal']:
            with self.subTest(mode=mode):
                await self.exercise(mode, login=False, passes=False)

    async def test_scale_grantless_restore_explicitly_logs_out_and_checks_state(self):
        await self.exercise('logout-success', login=False, passes=True, restore_mode='logout')

    async def test_grantless_restore_refuses_failed_logout_or_retained_grant_account_and_phase(self):
        for mode in ['logout-not-closed','logout-local-error','logout-retained-grant','logout-retained-account','logout-wrong-phase']:
            with self.subTest(mode=mode):
                await self.exercise(mode, login=False, passes=False, restore_mode='logout')

    async def test_authenticated_restore_accepts_owned_grant_success_and_valid_progress(self):
        await self.exercise('authenticated-success', login=False, passes=True, restore_mode='authenticated')

    async def test_authenticated_restore_rejects_bad_binding_progress_error_missing_terminal_and_invalid_sdk(self):
        for mode in ['authenticated-failed','authenticated-error-terminal','authenticated-changed-account',
                     'authenticated-progress-account','authenticated-duplicate','authenticated-no-terminal','authenticated-invalid']:
            with self.subTest(mode=mode):
                await self.exercise(mode, login=False, passes=False, restore_mode='authenticated')


if __name__ == '__main__':
    unittest.main()
