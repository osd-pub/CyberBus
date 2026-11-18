#include "cyberbus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"C boundary failure at %d\n",__LINE__); return 1; } } while(0)
static int32_t bad_load(void *ctx, const uint8_t **data, size_t *len) { (void)ctx; (void)data; (void)len; return -1; }
static int32_t bad_save(void *ctx, const uint8_t *data, size_t len) { (void)ctx; (void)data; (void)len; return -1; }
static void release(void *ctx, const uint8_t *data, size_t len) { (void)ctx; (void)data; (void)len; }
static int destroyed;
static void destroy(void *ctx) { (void)ctx; destroyed++; }
int main(int argc, char **argv) {
    CHECK(argc == 3); /* public config JSON, development store in an existing private directory */
    FILE *f = fopen(argv[1],"rb"); CHECK(f);
    uint8_t config[65537]; size_t n = fread(config,1,sizeof(config),f); fclose(f);
    CHECK(n > 0 && n <= 65536 && cyberbus_abi_version() == 1);
    CyberbusStore bad = {NULL,bad_load,bad_save,release,destroy};
    CyberbusResponse r = cyberbus_create(config,n,&bad);
    CHECK(r.status == CYBERBUS_ERROR && r.handle == 0 && destroyed == 1);
    CHECK(cyberbus_buffer_free(r.buffer) == CYBERBUS_OK);
    /* The smoke is explicitly a trusted FIRST installation, never an open-error fallback. */
    r = cyberbus_create_development_new(config,n,(const uint8_t *)argv[2],strlen(argv[2]));
    CHECK(r.status == CYBERBUS_OK && r.handle != 0);
    CyberbusHandle h = r.handle; CHECK(cyberbus_buffer_free(r.buffer) == 0);
    r = cyberbus_poll(h,0); CHECK(r.status == CYBERBUS_TIMEOUT); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    r = cyberbus_on_resume(h); CHECK(r.status == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    uint8_t query[] = {10,16,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0xc2,2,0};
    r = cyberbus_execute(h,query,sizeof(query)); CHECK(r.status == 0 && r.buffer.len > 18);
    CHECK(!memcmp(r.buffer.data,query,18)); CyberbusBuffer owned = r.buffer;
    CHECK(cyberbus_buffer_free(owned) == 0); CHECK(cyberbus_buffer_free(owned) == CYBERBUS_INVALID_ARGUMENT);
    query[18] = 0x8a; /* SdkClose */
    r = cyberbus_execute(h,query,sizeof(query)); CHECK(r.status == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    int eof = 0;
    for (int i=0;i<100;i++) {
        r = cyberbus_poll(h,100); CHECK(r.status == 0 || r.status == 1 || r.status == 2);
        eof = r.status == CYBERBUS_EOF; CHECK(cyberbus_buffer_free(r.buffer) == 0); if(eof) break;
    }
    CHECK(eof); r = cyberbus_close(h); CHECK(r.status == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    r = cyberbus_poll(h,0); CHECK(r.status == CYBERBUS_INVALID_HANDLE); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    /* Reopen only; bounded retries permit asynchronous release of the previous native owner. */
    for (int i=0;;i++) {
        r = cyberbus_create_development(config,n,(const uint8_t *)argv[2],strlen(argv[2]));
        if (r.status == CYBERBUS_OK) break;
        CHECK(cyberbus_buffer_free(r.buffer) == 0); CHECK(i < 300);
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }
    h = r.handle; CHECK(h != 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    query[18] = 0xc2; /* GetAuthState on the existing identity store. */
    r = cyberbus_execute(h,query,sizeof(query)); CHECK(r.status == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    r = cyberbus_close(h); CHECK(r.status == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    CHECK(remove(argv[2]) == 0);
    r = cyberbus_create_development(config,n,(const uint8_t *)argv[2],strlen(argv[2]));
    CHECK(r.status == CYBERBUS_ERROR && r.handle == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    r = cyberbus_create_development_new(config,n,(const uint8_t *)argv[2],strlen(argv[2]));
    CHECK(r.status == CYBERBUS_ERROR && r.handle == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    r = cyberbus_create_development_migrate(config,n,(const uint8_t *)argv[2],strlen(argv[2]));
    CHECK(r.status == CYBERBUS_ERROR && r.handle == 0); CHECK(cyberbus_buffer_free(r.buffer) == 0);
    puts("PASS C: explicit provision/reopen/lost-record refusal; query/resume/SdkClose/EOF; buffers/stale handle/store error+destroy");
    return 0;
}
