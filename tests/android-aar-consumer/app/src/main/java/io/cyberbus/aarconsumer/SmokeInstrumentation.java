package io.cyberbus.aarconsumer;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.os.ResultReceiver;
import android.os.SystemClock;
import com.google.protobuf.ByteString;
import cyberbus.easytier.v1.Common;
import cyberbus.easytier.v1.Sdk;
import io.cyberbus.sdk.CyberBus;
import io.cyberbus.sdk.DevelopmentFileStore;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** No private NativeBridge imports, reflection, SDK sources, authentication or network. */
public final class SmokeInstrumentation extends Instrumentation {
    private final JSONArray cases = new JSONArray();
    private String stage = "activity";
    private CyberBus client;
    private DevelopmentFileStore store;
    private long sequence;
    private ByteString runtime = ByteString.EMPTY;
    private int receivedEvents;
    private int closeEofs;
    private int probePid;
    private boolean closing;
    private int closeEpochChanges;

    private static void require(boolean value) { if (!value) throw new AssertionError("Contract mismatch"); }
    private static ByteString id() { byte[] b = new byte[16]; new SecureRandom().nextBytes(b); return ByteString.copyFrom(b); }
    private void pass(String name) throws Exception { cases.put(new JSONObject().put("id", name).put("status", "PASS")); }
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }

    private Sdk.SdkResult execute(Sdk.SdkCommand command, boolean raw) throws Exception {
        Sdk.SdkResult result = raw ? Sdk.SdkResult.parseFrom(client.execute(command.toByteArray())) : client.execute(command);
        require(result.getCommandId().equals(command.getCommandId()) && !result.hasError());
        return result;
    }
    private Sdk.SdkEvent event() throws Exception {
        Sdk.SdkEvent event = client.pollEvent(100);
        if (event != null) {
            require(event.getRuntimeId().size() == 16 && event.getEventSequence() > sequence);
            if (runtime.isEmpty()) runtime = event.getRuntimeId();
            if (!runtime.equals(event.getRuntimeId())) {
                // SdkClose stops the runtime and rotates its ID before final events.
                require(closing);
                runtime = event.getRuntimeId(); closeEpochChanges++;
            }
            sequence = event.getEventSequence();
            require(!event.hasNetwork() || !event.getNetwork().getRunning());
            receivedEvents++;
        }
        return event;
    }
    private ByteString self(Common.DevicesSnapshot snapshot) {
        require(snapshot.getDevicesCount() == 1 && snapshot.getRuntimeId().equals(runtime));
        Common.DeviceSnapshot self = snapshot.getDevices(0);
        require(self.getIsLocal() && self.getDeviceId().size() == 32 && self.getInstallationPublicKey().size() == 32 && self.getBootId().size() == 16);
        return self.getDeviceId();
    }
    private ByteString querySelf() throws Exception {
        ByteString query = id();
        require(execute(Sdk.SdkCommand.newBuilder().setCommandId(id()).setGetDevices(Sdk.GetDevices.newBuilder().setQueryId(query)).build(), false).hasOk());
        long deadline = SystemClock.elapsedRealtime() + 10_000;
        while (SystemClock.elapsedRealtime() < deadline) {
            Sdk.SdkEvent e = event();
            if (e != null && e.hasDevicesQuery() && e.getDevicesQuery().getQueryId().equals(query)) {
                require(e.getDevicesQuery().hasSnapshot() && !e.getDevicesQuery().hasError());
                return self(e.getDevicesQuery().getSnapshot());
            }
        }
        throw new AssertionError("Query event deadline");
    }
    private void watch(ByteString identity) throws Exception {
        ByteString watch = id();
        require(execute(Sdk.SdkCommand.newBuilder().setCommandId(id()).setWatchDevices(Sdk.WatchDevices.newBuilder().setWatchId(watch)).build(), true).hasOk());
        long deadline = SystemClock.elapsedRealtime() + 10_000;
        while (SystemClock.elapsedRealtime() < deadline) {
            Sdk.SdkEvent e = event();
            if (e != null && e.hasDevices() && e.getDevices().getWatchId().equals(watch)) {
                require(e.getDevices().hasSnapshot() && self(e.getDevices().getSnapshot()).equals(identity));
                return;
            }
        }
        throw new AssertionError("Watch event deadline");
    }
    private void closeAndDrain() throws Exception {
        String prefix = stage;
        closing = true; stage = prefix + "-command";
        Sdk.SdkResult r = execute(Sdk.SdkCommand.newBuilder().setCommandId(id()).setSdkClose(Sdk.SdkClose.getDefaultInstance()).build(), false);
        stage = prefix + "-result";
        require(r.hasSdkClosed() && r.getSdkClosed().getClosed() && !r.getSdkClosed().hasCleanupError());
        stage = prefix + "-drain";
        boolean eof = false;
        long deadline = SystemClock.elapsedRealtime() + 10_000;
        while (SystemClock.elapsedRealtime() < deadline && !eof) {
            try { event(); }
            catch (IllegalStateException end) {
                if (!"native event channel closed".equals(end.getMessage())) throw end;
                eof = true;
            }
        }
        require(eof); closeEofs++;
        stage = prefix + "-release";
        client.close(); client.close();
        try { client.poll(0); throw new AssertionError("Released client accepted poll"); }
        catch (IllegalStateException expected) { require("Client is closed".equals(expected.getMessage())); }
        client = null;
        store.close(); store = null;
        closing = false;
    }
    private void rejectOwner(File directory) throws Exception {
        try (DevelopmentFileStore ignored = DevelopmentFileStore.openExisting(directory)) { throw new AssertionError("Duplicate owner admitted"); }
        catch (IOException expected) { require("Store already owned".equals(expected.getMessage())); pass("duplicate-owner-same-process-rejected"); }
        CountDownLatch done = new CountDownLatch(1);
        Bundle[] answer = new Bundle[1];
        ResultReceiver receiver = new ResultReceiver(null) {
            @Override protected void onReceiveResult(int code, Bundle data) { answer[0] = data; done.countDown(); }
        };
        require(getTargetContext().startService(new Intent(getTargetContext(), LockProbeService.class)
            .putExtra("directory", directory.getPath()).putExtra("reply", receiver)) != null);
        require(done.await(10, TimeUnit.SECONDS));
        probePid = answer[0].getInt("pid");
        require(probePid > 0 && probePid != android.os.Process.myPid() && answer[0].getBoolean("rejected") && !answer[0].getBoolean("unexpected"));
        pass("duplicate-owner-separate-art-process-rejected");
    }
    @Override public void onStart() {
        JSONObject report = new JSONObject();
        boolean passed = false;
        Activity activity = null;
        try {
            activity = startActivitySync(new Intent(getTargetContext(), SmokeActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            String config;
            try (java.io.InputStream input = getTargetContext().getAssets().open("public-config.json")) {
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[4096]; int n;
                while ((n = input.read(buffer)) != -1) bytes.write(buffer, 0, n);
                config = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
            }
            File directory = new File(getTargetContext().getNoBackupFilesDir(), "public-aar-" + java.util.UUID.randomUUID());
            require(directory.mkdir());
            File marker = new File(directory, "cyberbus.installed"), record = new File(directory, "cyberbus.record");
            stage = "provision-public-constructor";
            store = DevelopmentFileStore.provisionNew(directory);
            client = new CyberBus(config, store);
            require(marker.isFile() && Files.readAllBytes(marker.toPath()).length == 1 && Files.readAllBytes(marker.toPath())[0] == 1 && record.length() > 0);
            pass("explicit-first-provision-public-constructor-persisted");
            stage = "query-and-events";
            require(client.onResume());
            ByteString identity = querySelf();
            pass("typed-execute-getdevices-correlated-self-event");
            watch(identity); pass("bytes-execute-watch-correlated-event-receiver");
            stage = "malformed-protobuf-negative";
            Sdk.SdkResult malformed = Sdk.SdkResult.parseFrom(client.execute(new byte[] {(byte) 0x80}));
            report.put("malformedProtobufErrorCode", malformed.getError().getCode().name());
            require(malformed.hasError() && malformed.getError().getCode() == Common.ErrorCode.PROTOCOL_ERROR &&
                !malformed.getError().getRetryable() && malformed.getCommandId().size() == 16);
            pass("malformed-protobuf-native-rejected");
            stage = "duplicate-owner"; rejectOwner(directory);
            stage = "first-sdkclose-eof"; closeAndDrain(); pass("first-sdkclose-correlated-cleanup-eof-release");
            stage = "reopen-existing";
            store = DevelopmentFileStore.openExisting(directory); client = new CyberBus(config, store);
            sequence = 0; runtime = ByteString.EMPTY;
            require(querySelf().equals(identity)); pass("existing-record-public-reopen-same-identity");
            stage = "second-sdkclose-eof"; closeAndDrain(); pass("second-sdkclose-correlated-cleanup-eof-release");
            stage = "lost-installed-record";
            store = DevelopmentFileStore.openExisting(directory);
            Files.delete(record.toPath());
            try { store.load("consumer-loss-probe"); throw new AssertionError("Missing installed record accepted"); }
            catch (IllegalStateException expected) { pass("live-store-missing-installed-record-rejected"); }
            try (CyberBus unexpected = new CyberBus(config, store)) { throw new AssertionError("Native recreated lost record"); }
            catch (IllegalStateException expected) { pass("public-jni-constructor-missing-installed-record-rejected"); }
            store.close(); store = null;
            try (DevelopmentFileStore ignored = DevelopmentFileStore.openExisting(directory)) { throw new AssertionError("Lost record reopened"); }
            catch (IOException expected) { pass("missing-installed-record-open-rejected"); }
            try (DevelopmentFileStore ignored = DevelopmentFileStore.provisionNew(directory)) { throw new AssertionError("Marker bypassed by provision"); }
            catch (IOException expected) { pass("missing-installed-record-reprovision-rejected"); }
            require(marker.isFile() && !record.exists());
            report.put("identityHex", hex(identity.toByteArray())).put("eventCount", receivedEvents).put("sdkCloseEofCount", closeEofs);
            report.put("mainPid", android.os.Process.myPid()).put("lockProbePid", probePid).put("vmName", System.getProperty("java.vm.name"));
            report.put("closeEpochChanges", closeEpochChanges);
            passed = true;
        } catch (Throwable failure) {
            try { report.put("failureStage", stage).put("failureClass", failure.getClass().getSimpleName()); } catch (Exception ignored) { }
        } finally {
            // Unexpected errors still release both public owners and report cleanup failures.
            try { if (client != null) client.close(); }
            catch (Throwable failure) { passed = false; safeFailure(report, "public-close-cleanup", failure); }
            try { if (store != null) store.close(); }
            catch (Throwable failure) { passed = false; safeFailure(report, "store-close-cleanup", failure); }
            getTargetContext().stopService(new Intent(getTargetContext(), LockProbeService.class));
            Activity finalActivity = activity;
            if (finalActivity != null) runOnMainSync(finalActivity::finish);
        }
        try { report.put("status", passed ? "PASS" : "FAIL").put("cases", cases).put("authOrNetworkRequested", false); }
        catch (Exception ignored) { passed = false; }
        Bundle result = new Bundle(); result.putString("report", report.toString());
        finish(passed ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
    }
    private static void safeFailure(JSONObject report, String stage, Throwable error) {
        try { report.put("failureStage", stage).put("failureClass", error.getClass().getSimpleName()); } catch (Exception ignored) { }
    }
    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(); for (byte b : bytes) value.append(String.format("%02x", b & 255)); return value.toString();
    }
}
