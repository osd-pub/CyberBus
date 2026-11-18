package io.cyberbus.sdk;

/** Opaque whole-record storage. Callbacks may run on native worker threads.
 * load returns null ONLY for a reliably absent first installation. Read errors,
 * missing records after installation, corruption and save/fsync failures must
 * throw or return false. Never persist OAuth grants. Native clears byte arrays
 * after each callback: copy values you retain. One store owner per instance.
 */
public interface SecureStore {
    byte[] load(String key);
    boolean save(String key, byte[] value);
}
