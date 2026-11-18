#include "cyberbus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "C ABI smoke failed at line %d\n", __LINE__); return 1; } } while (0)
int main(int argc, char **argv) {
    CHECK(argc == 2);
    FILE *file = fopen(argv[1], "rb"); CHECK(file != NULL);
    unsigned char config[65537];
    size_t config_len = fread(config, 1, sizeof(config), file);
    fclose(file); CHECK(config_len > 0 && config_len <= 65536);
    char directory[] = "/tmp/cyberbus-ffi-c-smoke-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char path[512]; snprintf(path, sizeof(path), "%s/development-state", directory);
    CHECK(cyberbus_abi_version() == CYBERBUS_ABI_VERSION);
    CyberbusResponse response = cyberbus_create_development(config, config_len, (const uint8_t *)path, strlen(path));
    CHECK(response.status == CYBERBUS_ERROR && response.handle == 0);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    response = cyberbus_create_development_new(config, config_len, (const uint8_t *)path, strlen(path));
    CHECK(response.status == CYBERBUS_OK && response.handle != 0);
    CyberbusHandle handle = response.handle;
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    response = cyberbus_poll(handle, 0);
    CHECK(response.status == CYBERBUS_TIMEOUT);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    response = cyberbus_on_resume(handle);
    CHECK(response.status == CYBERBUS_OK);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    /* Actual protobuf SdkCommand: 16-byte command_id, GetAuthState field 40. */
    uint8_t query[] = {0x0a,0x10,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0xc2,0x02,0x00};
    response = cyberbus_execute(handle, query, sizeof(query));
    CHECK(response.status == CYBERBUS_OK && response.buffer.len > 18);
    CHECK(response.buffer.data[0] == 0x0a && response.buffer.data[1] == 16);
    CHECK(memcmp(response.buffer.data + 2, query + 2, 16) == 0);
    CyberbusBuffer owned = response.buffer;
    CHECK(cyberbus_buffer_free(owned) == CYBERBUS_OK);
    CHECK(cyberbus_buffer_free(owned) == CYBERBUS_INVALID_ARGUMENT);
    response = cyberbus_close(handle); CHECK(response.status == CYBERBUS_OK);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    response = cyberbus_poll(handle, 0); CHECK(response.status == CYBERBUS_INVALID_HANDLE);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    /* Native state must persist; this is not a MemoryStore or generated fake identity. */
    file = fopen(path, "rb"); CHECK(file != NULL); fclose(file);
    response = cyberbus_create_development(config, config_len, (const uint8_t *)path, strlen(path));
    /* The SDK actor releases its file lock asynchronously after close. Wait a bounded moment. */
    for (int i = 0; response.status != CYBERBUS_OK && i < 100; ++i) {
        CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
        usleep(10000);
        response = cyberbus_create_development(config, config_len, (const uint8_t *)path, strlen(path));
    }
    CHECK(response.status == CYBERBUS_OK);
    handle = response.handle; CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    response = cyberbus_close(handle); CHECK(response.status == CYBERBUS_OK);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    /* Wait for release before asserting the deleted installed record stays closed. */
    for (int i = 0; i < 100; ++i) {
        response = cyberbus_create_development(config, config_len, (const uint8_t *)path, strlen(path));
        int status = response.status;
        handle = response.handle;
        CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
        if (status == CYBERBUS_OK) {
            response = cyberbus_close(handle); CHECK(response.status == CYBERBUS_OK);
            CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
            break;
        }
        usleep(10000);
    }
    CHECK(unlink(path) == 0);
    response = cyberbus_create_development(config, config_len, (const uint8_t *)path, strlen(path));
    CHECK(response.status == CYBERBUS_ERROR && response.handle == 0);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    response = cyberbus_create_development_new(config, config_len, (const uint8_t *)path, strlen(path));
    CHECK(response.status == CYBERBUS_ERROR && response.handle == 0);
    CHECK(cyberbus_buffer_free(response.buffer) == CYBERBUS_OK);
    snprintf(path, sizeof(path), "%s/development-state.auth-install", directory); unlink(path);
    snprintf(path, sizeof(path), "%s/development-state.auth-lock", directory); unlink(path);
    rmdir(directory);
    puts("PASS: actual C SDK create/query/resume/close/reopen, owned buffers, stale handles; development file store");
    return 0;
}
