/* Explicit DEVELOPMENT plaintext callback store for the Windows C sample.
 * The directory must already be private. UTF-8 path -> Win32 UTF-16. No DPAPI.
 * Marker/record writes are flushed and MoveFileEx is write-through. Errors
 * never become absence. Context and its process-exclusive lock belong to Rust.
 */
#ifndef CYBERBUS_WINDOWS_STORE_H
#define CYBERBUS_WINDOWS_STORE_H
#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
typedef struct WindowsStore { WCHAR path[32768], marker[32768], temp[32768]; HANDLE lock; int installed; } WindowsStore;
static int win_absent(const WCHAR *path) {
    DWORD attr = GetFileAttributesW(path);
    if (attr != INVALID_FILE_ATTRIBUTES) return 0;
    return GetLastError() == ERROR_FILE_NOT_FOUND ? 1 : -1;
}
static int32_t win_load(void *context, const uint8_t **data, size_t *length) {
    WindowsStore *store = (WindowsStore *)context;
    int missing = win_absent(store->path);
    int marker_missing = win_absent(store->marker);
    if (missing == 1 && marker_missing == 1 && !store->installed) return 1;
    if (missing != 0 || marker_missing != 0) return -1;
    store->installed = 1;
    HANDLE file = CreateFileW(store->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > CYBERBUS_STORE_MAX_BYTES) { CloseHandle(file); return -1; }
    uint8_t *bytes = (uint8_t *)malloc((size_t)size.QuadPart);
    if (!bytes) { CloseHandle(file); return -1; }
    DWORD read = 0; BOOL ok = ReadFile(file, bytes, (DWORD)size.QuadPart, &read, NULL); CloseHandle(file);
    if (!ok || read != (DWORD)size.QuadPart) { SecureZeroMemory(bytes,(size_t)size.QuadPart); free(bytes); return -1; }
    *data = bytes; *length = read; return 0;
}
static int win_replace(WindowsStore *store, const WCHAR *destination, const uint8_t *bytes, size_t length) {
    HANDLE file = CreateFileW(store->temp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    DWORD written = 0; BOOL ok = WriteFile(file, bytes, (DWORD)length, &written, NULL);
    if (!FlushFileBuffers(file)) ok = FALSE;
    if (!CloseHandle(file)) ok = FALSE;
    if (!ok || written != length) { DeleteFileW(store->temp); return -1; }
    if (!MoveFileExW(store->temp, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { DeleteFileW(store->temp); return -1; }
    return 0;
}
static int32_t win_save(void *context, const uint8_t *data, size_t length) {
    WindowsStore *store = (WindowsStore *)context;
    if (!data || !length || length > CYBERBUS_STORE_MAX_BYTES) return -1;
    int absent = win_absent(store->marker); if (absent < 0) return -1;
    const uint8_t marker = 1;
    if (store->installed) {
        if (absent != 0 || win_absent(store->path) != 0) return -1;
    } else {
        if (absent != 1 || win_absent(store->path) != 1) return -1;
        if (win_replace(store, store->marker, &marker, 1)) return -1;
        store->installed = 1;
    }
    return win_replace(store, store->path, data, length);
}
static void win_release(void *ctx, const uint8_t *bytes, size_t length) {
    (void)ctx; if (bytes) { SecureZeroMemory((void *)bytes,length); free((void *)bytes); }
}
static void win_destroy(void *context) {
    WindowsStore *store = (WindowsStore *)context; CloseHandle(store->lock); SecureZeroMemory(store,sizeof(*store)); free(store);
}
/* Call only for a trusted first installation, never as an open-error fallback. */
static int windows_store_provision_new(const char *path, CyberbusStore *callbacks) {
    WindowsStore *store = (WindowsStore *)calloc(1,sizeof(*store)); if (!store) return -1;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, store->path, 32700);
    if (!n) { free(store); return -1; }
    wcscpy_s(store->marker,32768,store->path); wcscat_s(store->marker,32768,L".installed");
    wcscpy_s(store->temp,32768,store->path); wcscat_s(store->temp,32768,L".tmp");
    WCHAR lock_path[32768]; wcscpy_s(lock_path,32768,store->path); wcscat_s(lock_path,32768,L".lock");
    store->lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (store->lock == INVALID_HANDLE_VALUE) { free(store); return -1; }
    if (win_absent(store->path) != 1 || win_absent(store->marker) != 1) { win_destroy(store); return -1; }
    callbacks->context = store; callbacks->load = win_load; callbacks->replace = win_save;
    callbacks->release = win_release; callbacks->destroy = win_destroy;
    return 0;
}
#endif
