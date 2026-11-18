#ifndef CYBERBUS_H
#define CYBERBUS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define CYBERBUS_ABI_VERSION 1u
#define CYBERBUS_STORE_MAX_BYTES (8u * 1024u * 1024u)
typedef uint64_t CyberbusHandle;
typedef enum CyberbusStatus {
    CYBERBUS_OK = 0,
    CYBERBUS_TIMEOUT = 1,
    CYBERBUS_EOF = 2,
    CYBERBUS_INVALID_ARGUMENT = 3,
    CYBERBUS_INVALID_HANDLE = 4,
    CYBERBUS_ERROR = 5,
    CYBERBUS_PANIC = 6
} CyberbusStatus;

/* Library-owned binary buffer. Free exactly once with cyberbus_buffer_free.
 * Do not mutate it, change its length, use another allocator, or read after free. */
typedef struct CyberbusBuffer { const uint8_t *data; size_t len; } CyberbusBuffer;
typedef struct CyberbusResponse {
    int32_t status;
    CyberbusHandle handle;
    CyberbusBuffer buffer;
} CyberbusResponse;

/* Synchronous opaque whole-blob store callbacks, serialized by the native owner.
 * They may be invoked from different native threads. Context remains exclusively
 * owned by this adapter until destroy. Never let exceptions/panics cross C ABI.
 * load: 0=present (borrowed data/len), 1=reliably absent, anything else=I/O error.
 * A present blob stays valid until release, which runs after the native copy.
 * replace: 0=durable atomic success, anything else=error. Do not persist OAuth
 * grants. The SDK owns the entire record format. No implicit MemoryStore exists.
 * C callbacks must actually meet the host's chosen local-store guarantees. */
typedef int32_t (*CyberbusStoreLoad)(void *, const uint8_t **, size_t *);
typedef int32_t (*CyberbusStoreReplace)(void *, const uint8_t *, size_t);
typedef void (*CyberbusStoreRelease)(void *, const uint8_t *, size_t);
typedef void (*CyberbusStoreDestroy)(void *);
typedef struct CyberbusStore {
    void *context;
    CyberbusStoreLoad load;
    CyberbusStoreReplace replace;
    CyberbusStoreRelease release;
    CyberbusStoreDestroy destroy;
} CyberbusStore;

uint32_t cyberbus_abi_version(void);
/* Ownership of a valid store transfers to create even if Client creation fails.
 * JSON contains public pins/config only. Response buffer on error is a sanitized
 * ProtocolError. CreateNew is selected only on a successful absent store read;
 * corrupt/read-failed records never fall back to provisioning. */
CyberbusResponse cyberbus_create(const uint8_t *config_json, size_t config_len,
                                const CyberbusStore *store);
/* Explicit DEVELOPMENT plaintext file mode, NOT protected platform storage.
 * Path must point inside an existing trusted app/user-private directory. Grants
 * remain memory-only. Ordinary create opens an INSTALLED vault+*.auth-install
 * marker only. Either missing/corrupt file fails closed; never retry with _new
 * or _migrate automatically. The existing function signature/ABI version stay 1. */
CyberbusResponse cyberbus_create_development(const uint8_t *config_json, size_t config_len,
                                            const uint8_t *store_path, size_t path_len);
/* Trusted FIRST INSTALL only: refuses any existing vault OR marker, including
 * interrupted/corrupt state. A durable marker is created before the first vault. */
CyberbusResponse cyberbus_create_development_new(const uint8_t *config_json, size_t config_len,
                                                const uint8_t *store_path, size_t path_len);
/* Explicit trusted LEGACY UPGRADE only: requires a complete valid legacy vault
 * and no marker; preserves identity/policy/highwater/profile. Marker absence is
 * NOT authorization to call this. It is never an open-failure recovery fallback. */
CyberbusResponse cyberbus_create_development_migrate(const uint8_t *config_json, size_t config_len,
                                                    const uint8_t *store_path, size_t path_len);
/* Command/result/event bytes are unframed binary local SDK protobufs. */
CyberbusResponse cyberbus_execute(CyberbusHandle, const uint8_t *, size_t);
CyberbusResponse cyberbus_poll(CyberbusHandle, uint32_t timeout_ms);
CyberbusResponse cyberbus_on_resume(CyberbusHandle);
/* Releases handle. Performs typed SDK close first if not already requested.
 * Explicit SdkClose through Execute leaves the handle alive for draining Poll.
 * Poll reports EOF only after queued terminal events have been read. */
CyberbusResponse cyberbus_close(CyberbusHandle);
/* Invalid/double frees are rejected without dereferencing an unknown pointer. */
int32_t cyberbus_buffer_free(CyberbusBuffer);

#ifdef __cplusplus
}
#endif
#endif
