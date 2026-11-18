# Frozen public AAR on Android ART/JNI

This is an independent, test-only Java Android application consuming the exact
sealed `70f5f991b9d590fafba9346b33c503bed9f4b21c` public AAR. It imports
`io.cyberbus.sdk.CyberBus` and `DevelopmentFileStore` from that AAR and generated
protobuf types from its classes.jar. It contains no SDK source, private demo JNI
imports, Rust build, NDK invocation, proto generation, hosted account or token.

The application ID is `io.cyberbus.aarconsumer`, distinct from `io.cyberbus.demo`.
The suite requests no authentication or network command. Its own manifest does
not declare network permissions, but the final merged APK inherits INTERNET and
ACCESS_NETWORK_STATE from the AAR; permission isolation is not part of this test.
Every invocation explicitly provisions a new UUID directory beneath its own
no-backup directory. The lost-record case deletes only that invocation's test
record, retains its installed marker, and verifies that provisioning cannot
bypass it. Old test directories remain isolated; the runner never clears sample
data, deletes a real installation marker or uninstalls the sample.

## Run on the exclusively reserved phone

Prerequisites are the existing cached Gradle 8.14.3, AGP 8.9.1, JDK 17, SDK35 and
protobuf-javalite 4.26.1. The build is offline. The default sealed AAR is root
`target/artifacts/final-70f5f99/android/cyberbus-sdk-70f5f99.aar`; `--aar` may name
another physical copy only if its SHA-256 is identical. Set ANDROID_HOME and
JAVA_HOME if the documented host defaults differ. Nothing downloads a new SDK
or copies a native build cache.

```sh
python3 tests/android-aar-consumer/run.py --serial DEVICE_SERIAL \
  --result tests/android-aar-consumer/results/70f5f99-sm-g9500.json
```

The driver verifies the original AAR and runtime hashes, builds/lints the tiny
Java app, installs only its test-only APK (`adb install -t -r`), runs its custom
Instrumentation and force-stops only this consumer afterward. The Activity is a
minimal visible surface; public SDK work runs on the instrumentation worker.
The expected thirteen cases must all pass, both SdkClose EOFs must be observed,
and the instrumentation must finish RESULT_OK. A crash, deadline, unexpected
exception, bad result code, missing JSON or incomplete case set fails the driver
with nonzero exit. It never infers success merely from shell exit zero.

The build's `keepDebugSymbols` preserves the already sealed AAR native bytes.
The driver reads the installed base APK back through ADB and requires its whole
hash to equal the built APK. It then requires the installed APK library bytes to
match the original AAR's JNI SHA-256. No native library is rebuilt or substituted.

## Actual public boundaries checked

| Cases | Required behavior |
|---|---|
| First explicit provision and public CyberBus constructor | Installed marker and record persisted through the actual AAR store and JNI |
| Typed execute GetDevices | Correlated successful result and query event containing the sole local self with actual 32-byte identity |
| Byte-array execute WatchDevices | Matching watch event through public pollEvent; runtime identity and event sequences checked |
| Malformed protobuf | The nonempty truncated varint is rejected by native strict codec with exactly PROTOCOL_ERROR, nonretryable, valid result ID |
| Duplicate owner, same process | Public store throws the expected ownership error |
| Duplicate owner, separate ART process | A private service with a distinct positive PID exercises the AAR's OS lock and rejects with the ownership error |
| First SdkClose | Matching command ID, closed=true, no cleanup_error, exact native event-channel EOF, then public close and store release |
| Existing installation reopen | Public openExisting and CyberBus recreate the same actual self ID |
| Second SdkClose | Same successful result, EOF and release requirements |
| Lost installed record, live store | Public load fails rather than returning null |
| Lost installed record, JNI create | Public CyberBus constructor fails rather than letting FFI create a new installation |
| Lost installed record, reopen | Public openExisting fails |
| Lost installed record, reprovision | Public provisionNew fails while the original marker remains |

Expected negative-path exceptions are confined to the specific cases above;
all other errors fail. The app emits only bounded case names, exception classes,
stage, identity, PIDs and counts; it never emits config contents, records, URLs,
credentials, native exception messages or tokens. Build logs, the installed APK
copy and raw instrumentation framing stay in ignored `build/`; the committed
JSON contains sanitized outcomes and hashes.

## Development attempt retained

`results/attempt-01-invalid-negative-expectation.json` records the initial FAIL:
the consumer incorrectly expected INVALID_ARGUMENT for malformed protobuf.
The frozen protocol maps malformed bytes to PROTOCOL_ERROR. Only that consumer
expectation was corrected; the SDK/AAR/native bytes were unchanged. The failed
attempt also demonstrates that non-success instrumentation is not accepted as
PASS. It is distinct from the final run of the corrected source.

`results/attempt-02-close-assertion.json` retains the next FAIL. It had passed
the malformed-byte and both process ownership cases, then incorrectly required
the old runtime_id while draining SdkClose. Closing stops the runtime and rotates
its epoch. The consumer now permits runtime changes only after it has begun
SdkClose, while retaining its sequence checks, no-running-network check,
successful correlated SdkClosed and exact EOF requirements. SDK/AAR bytes remain
unchanged.

This suite closes the public AAR's physical Android ART/JNI consumer boundary.
It does not replace hosted-auth, cross3 messaging, full API, RPC, scale, long
stability or host-JVM JNI tests. Those retain their independent evidence.
