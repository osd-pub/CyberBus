# Real SDK machine client

Build `cargo +stable build --locked -p cyberbus-test-client` (no optional features).
Set `PROTOC` to the vendored platform compiler if protoc is not on PATH. The binary
links the actual `cyberbus` SDK and EasyTier; no token/seed import API exists.

```
cyberbus-test-client --config deploy/test-client.json --state-dir /private/client-1 --store-mode provision
# After that process closes, reopen the same installation:
cyberbus-test-client --config deploy/test-client.json --state-dir /private/client-1 --store-mode open
```

The state directory is 0700, identities are DevelopmentFileStore, OAuth grants
remain memory-only. Use a different directory per installation. Reusing a directory
opens the same identity (exclusive lock); never share it between processes.

`--store-mode` defaults to installed-only `open`. A trusted host must explicitly
select `provision` once for a new installation, or `migrate` for an existing valid
legacy vault without an installation marker. Missing/corrupt installed vaults and
missing markers fail closed. Never retry failed open with provision or infer
migration permission from a missing marker. Migration preserves the identity.
For existing Linux/SSH launch wrappers, explicitly set
`CYBERBUS_DEVELOPMENT_STORE_MODE=provision` on first launch and `open` thereafter;
the command-line option takes precedence. Do not permanently configure provision
as an automatic recovery policy. Public configuration is validated before any
installation marker is created. Default public configuration keeps grants in memory.

Protocol version `cyberbus-test-client/1`: UTF-8 JSONL, one object per line. Readiness
is `{"ready":true,"protocol":"cyberbus-test-client/1","events":"receiver"}`.
Requests carry any JSON `id`; responses echo it, including parse/operation errors.
No prompts, human text, or tracing logs are written to stdout.

| op | Input fields | result |
| --- | --- | --- |
| execute | command: standard protobuf JSON SdkCommand | standard protobuf JSON SdkResult |
| execute_bytes | bytes: base64 strict protobuf SdkCommand | {bytes: base64 SdkResult, result: JSON SdkResult} |
| on_resume | none | {} or {error: ProtocolError} |
| poll_event | timeoutMs: 0..30000 | null or {event: SdkEvent} |
| take_event_receiver | none | {taken: bool}; successful transfer starts event pump |
| describe | none | protocol, all command/result/event names, clientApi, descriptorSet |
| close | none | SdkResult; process stays alive to test closed handle |
| shutdown | none | SdkResult; gracefully closes and exits |

`ok:true` means the harness operation succeeded. An SDK refusal remains
`result.error` with its real ErrorCode. Machine/schema parsing failures have
`ok:false` and a fixed, sanitized harness error. The `commandId` inside SdkResult
is independent of outer request id and comes from the SDK unchanged. `sdkValid` on execute/close responses and events reports strict SDK codec validation; it never repairs invalid SDK output.

Standard protobuf JSON means bytes are base64, 64-bit numbers are strings, enums
are names, Duration is `"1s"`, FieldMask is a comma-separated camelCase string,
and Any includes `@type`. `--describe` outputs the complete FileDescriptorSet
(including the Echo example and WKTs) to generate bindings or inspect every API.

Events are unsolicited `{"event":<SdkEvent>,"sdkValid":true}` with SDK eventSequence/runtimeId;
`{"eventsClosed":true}` follows receiver EOF. Events may precede command responses.
The default takes the unique receiver on startup. `--events poll` leaves ownership
with Client::poll_event until explicitly transferred. EOF on stdin also closes SDK.
`close` is SDK terminal; `shutdown` additionally exits the harness.

**The machine pipe is private:** authStarted.authorizationUri and authCallback
contain sensitive OAuth material. Do not tee stdout/stdin to CI logs. The provided
runner never serializes raw commands/events into its public report. Hosted drivers
read the SDK URI privately and return only the callback; the SDK exchanges the code.
See [suite documentation](../../tests/multiclient/README.md) for local/SSH orchestration.

`cyberbus-test-client --relay` starts a separate owned EasyTier bootstrap/relay on
an ephemeral loopback TCP listener and prints `{ready:true,relayEndpoint:...}`.
One input line or EOF closes it. It uses an unrelated public test-network identity,
no SDK grant, and never injects credentials into CyberBus clients. The runner copies
only the public bootstrap endpoint and disables P2P when selecting this local mode.
The embedded SDK runtime and the harness use two Tokio worker threads for scale runs.
