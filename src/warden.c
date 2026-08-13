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
#include <CommonCrypto/CommonDigest.h>

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
