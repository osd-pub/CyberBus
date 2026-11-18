package io.cyberbus.sdk;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import com.google.protobuf.InvalidProtocolBufferException;
import cyberbus.easytier.v1.Sdk;

/** Blocking bytes API: use worker threads, with one event consumer per client.
 * Execute SdkClose, drain poll to terminal EOF, then close to release the handle.
 * Closing directly is supported but discards undrained events. No finalizer owns
 * the native handle; callers must close it explicitly.
 */
public final class CyberBus implements AutoCloseable {
    private final AtomicLong handle;
    public CyberBus(String publicConfigJson, SecureStore store) {
        NativeBridge.load();
        long created = NativeBridge.nativeCreate(Objects.requireNonNull(publicConfigJson), Objects.requireNonNull(store));
        if (created == 0) throw new IllegalStateException("Native create returned an invalid handle");
        handle = new AtomicLong(created);
    }
    private long current() {
        long value = handle.get();
        if (value == 0) throw new IllegalStateException("Client is closed");
        return value;
    }
    public byte[] execute(byte[] command) { return NativeBridge.nativeExecute(current(), Objects.requireNonNull(command)); }
    public Sdk.SdkResult execute(Sdk.SdkCommand command) throws InvalidProtocolBufferException {
        return Sdk.SdkResult.parseFrom(execute(command.toByteArray()));
    }
    public byte[] poll(int timeoutMs) { return NativeBridge.nativePoll(current(), timeoutMs); }
    public Sdk.SdkEvent pollEvent(int timeoutMs) throws InvalidProtocolBufferException {
        byte[] bytes = poll(timeoutMs);
        return bytes == null ? null : Sdk.SdkEvent.parseFrom(bytes);
    }
    public boolean onResume() { return NativeBridge.nativeOnResume(current()); }
    @Override public void close() {
        long value = handle.getAndSet(0);
        if (value != 0) NativeBridge.nativeClose(value);
    }
}
