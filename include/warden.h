#ifndef WARDEN_H
#define WARDEN_H

#include <stddef.h>

#define WARDEN_OK 0
#define WARDEN_ERR_OPEN 1
#define WARDEN_ERR_READ 2
#define WARDEN_ERR_PARAM 3
#define WARDEN_ERR_FORK 4
#define WARDEN_ERR_TIMEOUT 5
#define WARDEN_ERR_EXEC 6

typedef struct {
    int timeout_ms;
    int cpu_sec;
    size_t max_bytes;
} warden_limits_t;

warden_limits_t warden_limits_default(void);

/* Calculate SHA-256 hash of a file at path, output hex string (65 bytes incl. NUL). */
int warden_sha256_file(const char *path, char out_hex[65]);

/* Calculate SHA-256 hashes for an array of paths relative to base_dir.
 * out_hashes must be array of char[65]. */
int warden_hash_paths(const char *base_dir, const char *const *paths, size_t count, char out_hashes[][65]);

/* Apply OS-level resource limits (rlimit) for sandbox child execution. */
int warden_apply_rlimits(int cpu_sec, size_t max_bytes);

/* Execute command with limits and capture stdout/stderr into out_buf. */
int warden_execute_capture(const char *cwd, const char *cmd_path, char *const argv[], const warden_limits_t *limits, char *out_buf, size_t out_cap);

#endif /* WARDEN_H */
