package io.cyberbus.sdk;

import android.system.Os;
import android.system.OsConstants;
import java.io.*;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;

/** DEVELOPMENT plaintext store, not Keystore. Use an existing app-private
 * directory excluded from Android backup. Durable installed marker prevents a
 * missing record being mistaken for first use. A corrupt existing record is
 * returned to Rust for validation. Close only AFTER the CyberBus instance.
 */
public final class DevelopmentFileStore implements SecureStore, AutoCloseable {
    private static final Set<String> owners = new HashSet<>();
    private final String ownerPath;
    private final File directory, record, marker;
    private final RandomAccessFile lockFile;
    private final FileLock lock;
    private boolean closed, installed, provisionAuthorized;
    /** Open an already installed record; never implicitly provisions. */
    public DevelopmentFileStore(File directory) throws IOException { this(directory, false); }
    public static DevelopmentFileStore openExisting(File directory) throws IOException {
        return new DevelopmentFileStore(directory, false);
    }
    /** Trusted first-install decision; never select this after an open/read error. */
    public static DevelopmentFileStore provisionNew(File directory) throws IOException {
        return new DevelopmentFileStore(directory, true);
    }
    private DevelopmentFileStore(File directory, boolean provisionNew) throws IOException {
        this.directory = directory.getCanonicalFile();
        if (!this.directory.isDirectory()) throw new IOException("Existing app-private directory required");
        ownerPath = this.directory.getPath();
        record = new File(this.directory, "cyberbus.record");
        marker = new File(this.directory, "cyberbus.installed");
        installed = marker.exists();
        // Claim before opening another descriptor: closing even an unlocked fd can
        // release the first owner's process-scoped POSIX lock on the same file.
        synchronized (owners) {
            if (!owners.add(ownerPath)) throw new IOException("Store already owned");
        }
        RandomAccessFile opened = null;
        boolean ready = false;
        try {
            opened = new RandomAccessFile(new File(this.directory, "cyberbus.lock"), "rw");
            lockFile = opened;
            lock = lockFile.getChannel().tryLock();
            if (lock == null) throw new IOException("Store already owned");
            // Record absence is accepted only in a reliably new directory.
            if (provisionNew) {
                if (marker.exists() || record.exists()) throw new IOException("Installation already exists");
                provisionAuthorized = true;
            } else if (!marker.exists() || !record.exists()) {
                throw new IOException("Installed marker and record required");
            }
            if (installed) validateMarker();
            ready = true;
        } catch (Exception error) {
            throw new IOException("Store unavailable", error);
        } finally {
            if (!ready) {
                try { if (opened != null) opened.close(); }
                finally { synchronized (owners) { owners.remove(ownerPath); } }
            }
        }
    }
    private void validateMarker() throws IOException {
        byte[] bytes = Files.readAllBytes(marker.toPath());
        if (bytes.length != 1 || bytes[0] != 1) throw new IOException("Invalid installed marker");
    }
    private void requireOpen() { if (closed) throw new IllegalStateException("Store closed"); }
    @Override public synchronized byte[] load(String key) {
        requireOpen();
        try {
            if (!record.exists()) {
                if (!provisionAuthorized || installed || marker.exists()) throw new IOException("Installed record missing");
                return null;
            }
            validateMarker();
            installed = true;
            long size = record.length();
            if (size < 1 || size > 8 * 1024 * 1024) throw new IOException("Invalid record size");
            return Files.readAllBytes(record.toPath());
        } catch (IOException error) { throw new IllegalStateException("Store read failed", error); }
    }
    private void syncDirectory() throws Exception {
        FileDescriptor fd = Os.open(directory.getPath(), OsConstants.O_RDONLY, 0);
        try { Os.fsync(fd); } finally { Os.close(fd); }
    }
    private void replace(File destination, byte[] bytes) throws Exception {
        File temp = File.createTempFile(".cyberbus-", ".tmp", directory);
        try {
            try (FileOutputStream out = new FileOutputStream(temp)) { out.write(bytes); out.getFD().sync(); }
            Os.rename(temp.getPath(), destination.getPath());
            syncDirectory();
        } finally { Files.deleteIfExists(temp.toPath()); }
    }
    @Override public synchronized boolean save(String key, byte[] value) {
        requireOpen();
        if (value == null || value.length == 0 || value.length > 8 * 1024 * 1024) return false;
        try {
            // Marker first: interrupted initial writes fail closed on the next open.
            if (!installed) {
                if (!provisionAuthorized || marker.exists() || record.exists()) return false;
                replace(marker, new byte[] {1});
                installed = true;
            } else if (!marker.exists() || !record.exists()) {
                return false;
            }
            validateMarker();
            replace(record, value);
            provisionAuthorized = false;
            return true;
        } catch (Exception error) { return false; }
    }
    @Override public synchronized void close() throws IOException {
        if (!closed) {
            closed = true;
            try { lock.release(); }
            finally {
                try { lockFile.close(); }
                finally { synchronized (owners) { owners.remove(ownerPath); } }
            }
        }
    }
}
