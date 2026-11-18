import io.cyberbus.sdk.*;
import cyberbus.easytier.v1.Sdk;
import cyberbus.example.v1.EchoOuterClass;
import com.google.protobuf.ByteString;
import com.google.protobuf.DescriptorProtos;
import java.nio.file.*;
import java.util.Arrays;

/** Host JVM test of unchanged production JNI implementation; NOT Android runtime validation. */
public final class BoundarySmoke {
    static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    // Explicit volatile TEST store only. Production hosts must supply durable storage.
    public static final class TestStore implements SecureStore {
        byte[] record; boolean readError, writeError;
        public synchronized byte[] load(String key) {
            if (readError) throw new IllegalStateException("TEST storage read failure");
            return record == null ? null : record.clone();
        }
        public synchronized boolean save(String key, byte[] value) {
            if (writeError) return false;
            record = value.clone(); return true;
        }
    }
    static void rejects(String config, TestStore store) {
        try (CyberBus ignored = new CyberBus(config, store)) { throw new AssertionError("storage failure accepted"); }
        catch (IllegalStateException expected) { }
    }
    static void developmentStoreDecisions() throws Exception {
        // These checks exercise the real AAR Java implementation's decision,
        // marker and FileLock logic on the host. Android Os.rename/fsync is NOT
        // invoked here and still requires Android framework/device validation.
        Path dir = Files.createTempDirectory("cyberbus-aar-store-");
        Path record = dir.resolve("cyberbus.record"), marker = dir.resolve("cyberbus.installed");
        try {
            try { DevelopmentFileStore.openExisting(dir.toFile()); throw new AssertionError(); }
            catch (java.io.IOException expected) { }
            try (DevelopmentFileStore fresh = DevelopmentFileStore.provisionNew(dir.toFile())) {
                check(fresh.load("opaque") == null);
                try { DevelopmentFileStore.provisionNew(dir.toFile()); throw new AssertionError(); }
                catch (java.io.IOException expected) { }
                Files.write(marker, new byte[]{1}); Files.write(record, new byte[]{4,5,6});
                check(Arrays.equals(fresh.load("opaque"), new byte[]{4,5,6}));
                Files.delete(record);
                try { fresh.load("opaque"); throw new AssertionError(); } catch (IllegalStateException expected) { }
                Files.delete(marker);
                try { fresh.load("opaque"); throw new AssertionError(); } catch (IllegalStateException expected) { }
            }
            Files.write(marker, new byte[]{1});
            try { DevelopmentFileStore.provisionNew(dir.toFile()); throw new AssertionError(); }
            catch (java.io.IOException expected) { }
            try { DevelopmentFileStore.openExisting(dir.toFile()); throw new AssertionError(); }
            catch (java.io.IOException expected) { }
            Files.write(record, new byte[]{4,5,6}); Files.write(marker, new byte[]{0});
            try { DevelopmentFileStore.openExisting(dir.toFile()); throw new AssertionError(); }
            catch (java.io.IOException expected) { }
        } finally {
            Files.deleteIfExists(record); Files.deleteIfExists(marker);
            Files.deleteIfExists(dir.resolve("cyberbus.lock")); Files.deleteIfExists(dir);
        }
        System.out.println("PASS AAR Java store decisions: explicit provision/open, process lock, missing installed record/marker and corrupt marker fail closed; Android fsync not exercised");
    }
    public static void main(String[] args) throws Exception {
        developmentStoreDecisions();
        String config = Files.readString(Path.of(args[0]));
        TestStore read = new TestStore(); read.readError = true; rejects(config, read); check(read.record == null);
        TestStore write = new TestStore(); write.writeError = true; rejects(config, write); check(write.record == null);
        TestStore corrupt = new TestStore(); corrupt.record = new byte[]{1, 2, 3}; rejects(config, corrupt);
        TestStore store = new TestStore();
        CyberBus client = new CyberBus(config, store);
        check(store.record != null && store.record.length > 0);
        byte[] id = new byte[16]; Arrays.fill(id, (byte) 9);
        Sdk.SdkCommand query = Sdk.SdkCommand.newBuilder().setCommandId(ByteString.copyFrom(id))
            .setGetAuthState(Sdk.GetAuthState.getDefaultInstance()).build();
        check(client.poll(0) == null);
        check(client.onResume());
        Sdk.SdkResult result = client.execute(query);
        check(result.getCommandId().equals(query.getCommandId()) && result.hasAuthState());
        check(DescriptorProtos.FileDescriptorSet.parseFrom(new byte[0]).getFileCount() == 0);
        check(EchoOuterClass.EchoRequest.parseFrom(EchoOuterClass.EchoRequest.newBuilder().setText("JNI bytes").build().toByteArray()).getText().equals("JNI bytes"));
        result = client.execute(Sdk.SdkCommand.newBuilder().setCommandId(ByteString.copyFrom(id))
            .setSdkClose(Sdk.SdkClose.getDefaultInstance()).build());
        check(result.hasSdkClosed() && result.getSdkClosed().getClosed());
        boolean eof = false;
        for (int i = 0; i < 100; i++) {
            try { client.pollEvent(100); }
            catch (IllegalStateException terminal) { check(terminal.getMessage().contains("event channel closed")); eof = true; break; }
        }
        check(eof); client.close(); client.close();
        try { client.execute(query); throw new AssertionError(); } catch (IllegalStateException expected) { }
        // Reopen opaque record through the same public JNI API.
        try (CyberBus reopened = new CyberBus(config, store)) { check(reopened.execute(query).hasAuthState()); }
        System.out.println("PASS host JNI: public package, generated SDK/WKT/example, query/resume/close/EOF/reopen; read/write/corrupt store fail closed");
    }
}
