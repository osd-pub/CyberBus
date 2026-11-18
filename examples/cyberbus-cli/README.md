# Desktop sample

Run from the repository root after the public deployment configuration is available:

```sh
mkdir -m 700 /tmp/cyberbus-installation-a
./scripts/run-sample.sh --config deploy/test-client.json \
  --store /tmp/cyberbus-installation-a/state.json --create-store --name Desktop-A
```

Use `--create-store` only for a new installation. Subsequent launches use the same store path
without that option. Identity, public revision and local policy persist; OAuth grants remain
in memory, so a new process signs in through the browser again.

`login` and `register` open the system browser and accept the exact registered
http://127.0.0.1:18765/callback redirect. The listener binds before browser authorization starts.
The console never prints the authorization URL, callback, code, token or seed. Login does not
start the network. Only one desktop login can own the loopback port at a time.

`AuthCallback` admission does not complete login. The existing event consumer
matches the original operation ID and waits for `AUTHENTICATED` before printing
`LOGIN_COMPLETE` and `OK login`/`OK register`. Failed, cancelled or expired auth,
callback rejection and event EOF fail the command and final process exit. Browser
callback plus terminal waiting share the existing 600-second limit; this wait
does not start networking or consume SDK events through another receiver.

```text
login
start
devices
refresh
send <64-hex-device-id> hello
rpc <64-hex-device-id> unary hello
stream <64-hex-device-id> bidi hello
config <64-hex-device-id>
name New name
schema <64-hex-device-id>
block <64-hex-device-id>
unblock <64-hex-device-id>
auth
stop
logout
quit
```

`send`, `rpc`, `stream` and `config` also accept `@peer` for the first authenticated remote device. The
sample implements the generated EchoRequest/EchoReply messages and unary/bidi Echo handlers.
Received data is displayed before explicit PROCESSED completion. ACK output reports RECEIVED,
ACCEPTED and PROCESSED independently of the local `OK send` admission line.

For scripts, stdin accepts the same commands. `wait-devices <total-count>` waits up to 40 seconds
for authenticated directory discovery; `sleep <milliseconds>` permits asynchronous outcomes.
EOF on stdin closes the SDK gracefully. A failed command produces a nonzero final process
exit status. An automation can inspect the ordered ACK/result output. `--no-browser --authorization-file /private/new-file` saves the SDK-generated URL to a
new 0600 file instead of opening a browser. Use the deployment callback-only hosted interaction
driver and deliver its callback to the local loopback listener; the SDK retains PKCE/nonce and
performs its own code exchange. No saved token import exists. See `deploy/README.md` for private
driver handling. Keep scripts' callback/authorization files private and delete after delivery.

RPC uses a bounded asynchronous application adapter. `stream <peer> text` exchanges five
BIDI items, while `stream-large <peer>` exchanges five items of exactly 1 MiB of serialized
Protobuf each. `rpc-large <peer>` exercises a 1 MiB unary exchange. The adapter reassembles
all fragments before decoding, explicitly returns item credit after application consumption,
and verifies each reply's text digest and the terminal item count. `RPC_END` without an
error is printed only after a validated successful remote response end. Sender work runs
separately from event delivery, so waiting for credit cannot prevent receiving windows.
`rpc-cancel <peer>` explicitly cancels a live BIDI call and checks CANCELLED;
`rpc-deadline <peer>` leaves a live call idle with a one second deadline and checks
DEADLINE_EXCEEDED. Both accept `@peer`. A failed payload, send, cancellation check or
terminal count makes the command fail and the process eventually exit nonzero.

`config <peer>` calls the real UNARY `cyberbus.example.v1.Echo/GetPublicConfig`
handler. Its reply carries the sample's SDK-accepted public `PublicConfig`, device
name, semantic version and configuration revision. `name New name` changes that
declaration; a subsequent remote `config` reads the updated accepted declaration.
The handler never reads deployment configuration or private storage. It uses an
independent request ID and validates the reply correlation, one response item and
the SDK's successful remote response end before printing `OK config`.
`RPC_CONFIG` displays the decoded public fields; `RPC_CONFIG_END` is the successful
terminal. An intermediate reply alone does not establish success. Example messages
and the method are additive; standard wire/sdk messages are unchanged. Both peers
must advertise the new method, so the frozen70 CLI cannot serve this new RPC.

The focused real verifier at `tests/config_smoke.py` uses two actual CLI processes,
two newly provisioned stores, serial callback-only login and an owned loopback
relay. It compares both directions with each callee's SDK-accepted declaration,
then changes each callee's name and checks the new revision through `@peer`.
It requires matching callee request events, caller SDK response-end events and
clean process/relay shutdown, and removes all private test material. It does not
rerun the previous RPC matrix. Invoke it from the repository root with your own
immutable candidate CLI and its embedded descriptor, retaining the old pins:

```sh
python3 examples/cyberbus-cli/tests/config_smoke.py \
  --binary /absolute/candidate/cyberbus-cli \
  --revision COMMIT \
  --descriptor /absolute/candidate/cyberbus.bin \
  --relay-binary /absolute/immutable/cyberbus-test-client \
  --private-dir /absolute/new-private-directory \
  --report /absolute/new-result.json
```

The store path is an existing trusted installation by default. `--create-store` explicitly
provisions a new installation only when both vault and its `.auth-install` marker are absent.
`--migrate-store` explicitly migrates a complete legacy vault without a marker; it cannot
be combined with `--create-store`. Missing/corrupt vaults or markers fail closed and never
trigger automatic creation or migration.
