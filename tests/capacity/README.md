# Live 256 → 257 capacity sidecar

This controller reuses one cohort of 256 actual SDK processes. It imports an
explicit, SHA-256 pinned N-client runner, subclasses its Suite, and hooks the end
of `large_cases`. It does not change the runner, SDK, protobuf, capacity limit or
directory contents. Run live only after independent controller review and the
parent's N128/resource gate. No live N256 run is established by the fixture tests.

The SDK is fixed to source commit
`70f5f991b9d590fafba9346b33c503bed9f4b21c`, with a clean source checkout and the
existing native artifact SHA-256
`18113d4b132c3405ce6801e0de20549159130b4afa4a83d856bf9e437e91814b`.
There is no build step. The base runner must contain the reviewed absolute-cursor
fix from `329acc9a6101c5a56ae84b157af48e91f93021c1`: exact runner file SHA-256
`3ed12f2f0af14de42d66a3038a1adffd786d41cd1d124d77aaebfd088eceb6d1`.
The combined harness commit can differ; the exact file digest and cursor APIs are
required. Any later runner edit needs a separate reviewed compatibility update.

The base runner executes its normal setup, independent hosted PKCE logins,
256-client full ONLINE directory and 255 data/PROCESSED-ACK rounds, covering
65,280 directed pairs. Only after every round passes and a fresh exact full view
passes does the sidecar provision client-256 and authorize its own SDK through
the same private callback-only login driver. It never restarts/relogs the original
cohort for the capacity phase. Failed base cases stay failed and prevent the extra
installation from starting; remaining capacity stages are explicitly SKIP.

The 257 identities are sorted by decoded raw 32-byte device ID, not base64 text or
startup order. Every selected client must have exactly those same 256 IDs, sorted,
with exactly the correct self and every entry ONLINE. The excluded client can be
any of the original cohort or the newcomer. Its directory must contain only self,
OFFLINE, and its latest network event must be running, unreachable, with
CAPACITY_EXCEEDED. Selected clients must remain reachable without a network error.

These are the existing contracts in `docs/design.md` §4.1, `docs/protocol.md` §6
and `docs/sdk-api.md` directory semantics. In frozen SDK 70f5f99,
`runtime/directory.rs::ensure_peer` rejects excluded local Send with
PERMISSION_DENIED; an admitted sender has no excluded directory/session and
`session::unavailable` returns DEVICE_UNREACHABLE. The sidecar checks both public
Send directions for all 256 admitted peers, using fresh valid typed messages.
Any accepted Send or different error fails. All observed probe failures are kept
in case facts. Two admitted clients also exchange real data in both directions,
including the newcomer when selected.

The default capacity convergence budget is 300 seconds. Before first exact
convergence valid transient views may settle; query, strict-codec and process
failures fail immediately. After convergence, a 15-second observation must stay
exact; instability fails without restarting the window. Incremental event
observers count forbidden Data/RPC business callbacks involving the excluded
identity, independently of retained event history. The final gate has a two-second
bounded callback observation and another full view check. This does not prove
partition behavior, later re-admission, or indefinite callback absence.

The base runner owns logout, SDK close, EOF/idempotence and process termination for
all clients, including the appended client after partial setup failure. The final
capacity verdict additionally requires every one of the 257 CLOSE, CLOSE-REJECT
and PROCESS cases to PASS, actual zero exits, strict output validity, zero forbidden
callbacks and an owned relay's zero exit. All inherited FAIL and SKIP rows remain
in the report. The extra `capacity` section records SDK/artifact, base runner
commit/dirty/file hash, cursor-fix commit and this controller's commit/dirty/file
hash separately. Inherited base limitations are preserved, not rewritten as PASS.

After independent review, use absolute paths to the clean frozen SDK checkout,
the reviewed combined harness and the already-built frozen native binary:

```sh
python3 /abs/reviewed-harness/tests/capacity/controller.py \
  --base-runner /abs/reviewed-harness/tests/multiclient/runner.py \
  --base-runner-sha256 3ed12f2f0af14de42d66a3038a1adffd786d41cd1d124d77aaebfd088eceb6d1 \
  --controller-sha256 REVIEWED_CONTROLLER_FILE_SHA256 \
  --binary /abs/frozen/cyberbus-test-client \
  --sdk-source /abs/clean-sdk-70f5f99 \
  --config /abs/reviewed-harness/deploy/test-client.json \
  --login-driver 'python3 /abs/reviewed-harness/scripts/test-multiclient-hosted.py' \
  --local-relay \
  --private-dir /abs/private/fresh-capacity-run \
  --report /abs/reports/capacity-256-257.json
```

`--controller-sha256` is the SHA-256 of the reviewed controller file; record that
value at review/freeze time. A fresh private directory is required. The base runner
pins a copy of the native binary there and uses that same copy for all 257 clients.
No participants override, capacity override, offline acceptance or fixture mode
exists in the live entry point. The script never prints OAuth URI/callback/token
values; external exceptions are reported only by class. Original detailed safe
case failures remain in the base report and cause a nonzero exit.

Run rejection regressions without hosted login, Cargo, relay or real SDK clients:

```sh
CAPACITY_BASE_RUNNER=/abs/reviewed-harness/tests/multiclient/runner.py \
  python3 -m unittest discover -s tests/capacity -p 'test_*.py' -v
```

Fixtures exercise wrong/duplicate/unsorted membership, incorrect presence/self,
capacity state, missing/failed ordered-pair rounds, forbidden callbacks, accepted
or wrongly rejected Sends, strict event sequencing, expired absolute cursors and
all-client cleanup requirements. A small Python JSONL subprocess also verifies
that the actual base Client rejects a nonzero process exit after apparent SDK
close success. These fixtures are controller rejection evidence only.
