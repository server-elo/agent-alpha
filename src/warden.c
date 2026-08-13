#include "warden.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/resource.h>
#include <CommonCrypto/CommonDigest.h>

int warden_sha256_file(const char *path, char out_hex[65]) {
    if (!path || !out_hex) return WARDEN_ERR_PARAM;
    FILE *f = fopen(path, "rb");
    if (!f) return WARDEN_ERR_OPEN;

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
    }

    if (ferror(f)) {
        fclose(f);
        return WARDEN_ERR_READ;
    }
    fclose(f);

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    }
    out_hex[64] = 0;
    return WARDEN_OK;
}

int warden_hash_paths(const char *base_dir, const char *const *paths, size_t count, char out_hashes[][65]) {
    if (!paths || !out_hashes) return WARDEN_ERR_PARAM;
    for (size_t i = 0; i < count; i++) {
        char full[PATH_MAX];
        if (base_dir && base_dir[0]) {
            snprintf(full, sizeof(full), "%s/%s", base_dir, paths[i]);
        } else {
            snprintf(full, sizeof(full), "%s", paths[i]);
        }
        int rc = warden_sha256_file(full, out_hashes[i]);
        if (rc != WARDEN_OK) {
            /* If file doesn't exist or unreadable, record a placeholder hash */
            snprintf(out_hashes[i], 65, "%064d", 0);
        }
    }
    return WARDEN_OK;
}

int warden_apply_rlimits(int cpu_sec, size_t max_bytes) {
    struct rlimit rl;

    if (cpu_sec > 0) {
        rl.rlim_cur = (rlim_t)cpu_sec;
        rl.rlim_max = (rlim_t)cpu_sec + 2;
        setrlimit(RLIMIT_CPU, &rl);
    }

    if (max_bytes > 0) {
#ifdef RLIMIT_AS
        rl.rlim_cur = (rlim_t)max_bytes;
        rl.rlim_max = (rlim_t)max_bytes;
        setrlimit(RLIMIT_AS, &rl);
#endif
    }

    return 0;
}
