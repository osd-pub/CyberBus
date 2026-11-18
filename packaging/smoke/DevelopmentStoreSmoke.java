import io.cyberbus.sdk.DevelopmentFileStore;
import java.io.*;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;

/** Host test of production store ownership; Android Os persistence is not invoked. */
public final class DevelopmentStoreSmoke {
    interface Attempt { void run() throws Exception; }
    static void rejects(Attempt attempt) throws Exception {
        try { attempt.run(); throw new AssertionError("Duplicate or invalid store accepted"); }
        catch (IOException expected) { }
    }
    static Process child(String mode, Path dir, String... extra) throws IOException {
        java.util.List<String> args = new java.util.ArrayList<>(java.util.List.of(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            DevelopmentStoreSmoke.class.getName(), mode, dir.toString()));
        args.addAll(java.util.List.of(extra));
        return new ProcessBuilder(args).redirectError(ProcessBuilder.Redirect.INHERIT).start();
    }
    static void finished(Process process) throws Exception {
        if (!process.waitFor(15, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("Store probe timed out");
        }
        if (process.exitValue() != 0) throw new AssertionError("Store probe failed");
    }
    static void probe(Path dir, boolean available) throws Exception {
        finished(child("probe", dir, Boolean.toString(available)));
    }
    static void probeChild(Path dir, boolean available) throws Exception {
        try (RandomAccessFile file = new RandomAccessFile(dir.resolve("cyberbus.lock").toFile(), "rw")) {
            FileLock lock = file.getChannel().tryLock();
            if ((lock != null) != available) throw new AssertionError("External lock availability changed");
            if (lock != null) lock.release();
        }
        if (available) {
            try (DevelopmentFileStore ignored = DevelopmentFileStore.openExisting(dir.toFile())) { }
        } else {
            rejects(() -> DevelopmentFileStore.openExisting(dir.toFile()));
        }
    }
    static void ownership(Path dir, Path alias) throws Exception {
        DevelopmentFileStore first = DevelopmentFileStore.provisionNew(dir.toFile());
        try {
            Files.write(dir.resolve("cyberbus.installed"), new byte[] {1});
            Files.write(dir.resolve("cyberbus.record"), new byte[] {4, 5, 6});
            probe(dir, false);
            rejects(() -> DevelopmentFileStore.openExisting(dir.toFile()));
            probe(dir, false);
            rejects(() -> DevelopmentFileStore.openExisting(dir.resolve(".").toFile()));
            probe(dir, false);
            rejects(() -> DevelopmentFileStore.openExisting(alias.toFile()));
            probe(dir, false);
        } finally { first.close(); }
        probe(dir, true);
        try (DevelopmentFileStore reopened = DevelopmentFileStore.openExisting(alias.toFile())) {
            first.close(); // An old owner's repeated close must not remove the new claim.
            rejects(() -> DevelopmentFileStore.openExisting(dir.toFile()));
            probe(dir, false);
        }
        probe(dir, true);
    }
    static void failedConstruction(Path dir) throws Exception {
        Path lock = dir.resolve("cyberbus.lock");
        Files.createDirectory(lock); // Fail before a descriptor can be opened.
        rejects(() -> DevelopmentFileStore.provisionNew(dir.toFile()));
        Files.delete(lock);
        rejects(() -> DevelopmentFileStore.openExisting(dir.toFile())); // Missing installation.
        try (DevelopmentFileStore ignored = DevelopmentFileStore.provisionNew(dir.toFile())) { }
        Files.write(dir.resolve("cyberbus.installed"), new byte[] {0});
        Files.write(dir.resolve("cyberbus.record"), new byte[] {1});
        rejects(() -> DevelopmentFileStore.openExisting(dir.toFile())); // Invalid marker.
        Files.write(dir.resolve("cyberbus.installed"), new byte[] {1});
        Process holder = child("hold", dir);
        try {
            BufferedReader ready = new BufferedReader(new InputStreamReader(holder.getInputStream()));
            if (!"LOCKED".equals(ready.readLine())) throw new AssertionError("External owner failed");
            rejects(() -> DevelopmentFileStore.openExisting(dir.toFile())); // tryLock returns null.
        } finally {
            holder.getOutputStream().close();
            finished(holder);
        }
        probe(dir, true);
        try (DevelopmentFileStore ignored = DevelopmentFileStore.openExisting(dir.toFile())) { }
    }
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("probe")) {
            probeChild(Path.of(args[1]), Boolean.parseBoolean(args[2]));
            return;
        }
        if (args.length > 0 && args[0].equals("hold")) {
            try (RandomAccessFile file = new RandomAccessFile(Path.of(args[1], "cyberbus.lock").toFile(), "rw");
                 FileLock lock = file.getChannel().tryLock()) {
                if (lock == null) throw new AssertionError("External owner unavailable");
                System.out.println("LOCKED"); System.out.flush();
                System.in.read();
            }
            return;
        }
        Path root = Files.createTempDirectory("cyberbus-aar-owner-");
        try {
            Path dir = Files.createDirectory(root.resolve("store"));
            Path alias = Files.createSymbolicLink(root.resolve("alias"), dir);
            ownership(dir, alias);
            failedConstruction(Files.createDirectory(root.resolve("failed")));
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path p : paths.sorted(java.util.Comparator.reverseOrder()).toArray(Path[]::new))
                    Files.deleteIfExists(p);
            }
        }
        System.out.println("PASS AAR store ownership: duplicates/aliases preserve external exclusion, close permits reopen, constructor failures release claims");
    }
}
