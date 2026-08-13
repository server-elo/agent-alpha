#ifndef WARDEN_H
#define WARDEN_H

#include <stddef.h>

#define WARDEN_OK 0
#define WARDEN_ERR_OPEN 1
#define WARDEN_ERR_READ 2
#define WARDEN_ERR_PARAM 3

/* Calculate SHA-256 hash of a file at path, output hex string (65 bytes incl. NUL). */
int warden_sha256_file(const char *path, char out_hex[65]);

/* Calculate SHA-256 hashes for an array of paths relative to base_dir.
 * out_hashes must be array of char[65]. */
int warden_hash_paths(const char *base_dir, const char *const *paths, size_t count, char out_hashes[][65]);

/* Apply OS-level resource limits (rlimit) for sandbox child execution.
 * CPU cap (seconds), Memory cap (bytes). */
int warden_apply_rlimits(int cpu_sec, size_t max_bytes);

#endif /* WARDEN_H */
