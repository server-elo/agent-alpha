#include "warden.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* CommonCrypto is macOS-only. Linux gets the self-contained SHA-256 below
 * (public-domain-style, no external deps). WARDEN_FORCE_PORTABLE_SHA256
 * compiles the portable path on any host so it can be compile-checked and
 * exercised from a macOS build — same trick as ALPHA_FORCE_PT_PROC in
 * tools.c. */
#if defined(__APPLE__) && !defined(WARDEN_FORCE_PORTABLE_SHA256)
#include <CommonCrypto/CommonDigest.h>
#define WARDEN_SHA256_CC 1
#else
#include <stdint.h>

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} wsha256_ctx;

static const uint32_t wsha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define WSHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void wsha256_transform(wsha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    for (int i = 0; i < 16; i++)
        m[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | (uint32_t)data[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = WSHA256_ROTR(m[i - 15], 7) ^ WSHA256_ROTR(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = WSHA256_ROTR(m[i - 2], 17) ^ WSHA256_ROTR(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = WSHA256_ROTR(e, 6) ^ WSHA256_ROTR(e, 11) ^ WSHA256_ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + wsha256_k[i] + m[i];
        uint32_t s0 = WSHA256_ROTR(a, 2) ^ WSHA256_ROTR(a, 13) ^ WSHA256_ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void wsha256_init(wsha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void wsha256_update(wsha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            wsha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void wsha256_final(wsha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;
    /* 0x80, zero-pad to 56 mod 64, then the bit length big-endian. */
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        wsha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;
    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    for (int s = 0; s < 8; s++)
        ctx->data[63 - s] = (uint8_t)(ctx->bitlen >> (s * 8));
    wsha256_transform(ctx, ctx->data);
    for (i = 0; i < 8; i++) {
        hash[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}
#endif /* WARDEN_SHA256_CC */

warden_limits_t warden_limits_default(void) {
    warden_limits_t lim;
    lim.timeout_ms = 30000;
    lim.cpu_sec = 10;
    lim.max_bytes = 512 * 1024 * 1024; /* 512 MB */
    return lim;
}

int warden_sha256_file(const char *path, char out_hex[65]) {
    if (!path || !out_hex) return WARDEN_ERR_PARAM;
    FILE *f = fopen(path, "rb");
    if (!f) return WARDEN_ERR_OPEN;

#ifdef WARDEN_SHA256_CC
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
#else
    wsha256_ctx ctx;
    wsha256_init(&ctx);
#endif

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
#ifdef WARDEN_SHA256_CC
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
#else
        wsha256_update(&ctx, buf, n);
#endif
    }

    if (ferror(f)) {
        fclose(f);
        return WARDEN_ERR_READ;
    }
    fclose(f);

    unsigned char hash[32];
#ifdef WARDEN_SHA256_CC
    CC_SHA256_Final(hash, &ctx);
#else
    wsha256_final(&ctx, hash);
#endif

    for (int i = 0; i < 32; i++) {
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

int warden_execute_capture(const char *cwd, const char *cmd_path, char *const argv[], const warden_limits_t *limits, char *out_buf, size_t out_cap) {
    if (!cmd_path || !argv || !out_buf || out_cap == 0) return WARDEN_ERR_PARAM;
    out_buf[0] = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) return WARDEN_ERR_FORK;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return WARDEN_ERR_FORK;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        if (cwd && cwd[0]) {
            if (chdir(cwd) != 0) _exit(127);
        }

        if (limits) {
            warden_apply_rlimits(limits->cpu_sec, limits->max_bytes);
        }

        execvp(cmd_path, argv);
        _exit(127);
    }

    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);

    int timeout_ms = (limits && limits->timeout_ms > 0) ? limits->timeout_ms : 30000;
    int waited_ms = 0;
    size_t out_len = 0;
    int status = 0;
    int timed_out = 0;

    while (waited_ms < timeout_ms) {
        char chunk[1024];
        ssize_t n = read(pipefd[0], chunk, sizeof(chunk));
        if (n > 0) {
            if (out_len + (size_t)n < out_cap) {
                memcpy(out_buf + out_len, chunk, (size_t)n);
                out_len += (size_t)n;
                out_buf[out_len] = 0;
            }
        }

        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            /* Drain pipe */
            while ((n = read(pipefd[0], chunk, sizeof(chunk))) > 0) {
                if (out_len + (size_t)n < out_cap) {
                    memcpy(out_buf + out_len, chunk, (size_t)n);
                    out_len += (size_t)n;
                    out_buf[out_len] = 0;
                }
            }
            break;
        }

        usleep(50000); /* 50ms */
        waited_ms += 50;
        if (waited_ms >= timeout_ms) {
            timed_out = 1;
        }
    }

    close(pipefd[0]);

    if (timed_out) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return WARDEN_ERR_TIMEOUT;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return WARDEN_OK;
    }

    return WARDEN_ERR_EXEC;
}
