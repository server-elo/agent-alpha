#include "alpha.h"
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <regex.h>
#include <fnmatch.h>
#include <curl/curl.h>
#include <sys/file.h>

/* Descendant tracking needs the kernel process table, and there is no portable
 * way to read it. macOS has no /proc, so it goes through sysctl + libproc;
 * Linux has no libproc, so it reads /proc. ALPHA_FORCE_PT_PROC selects the
 * /proc implementation on any host, which is how the Linux branch is compiled
 * and exercised from a macOS build. */
#if defined(__APPLE__) && !defined(ALPHA_FORCE_PT_PROC)
#define ALPHA_PT_DARWIN 1
#include <sys/sysctl.h>
#include <libproc.h>
#include <sys/proc_info.h>
#else
#define ALPHA_PT_PROC 1
#endif

/* NO security: any path, any shell. User asked open coding shell. */

/* --- Binary extension detection (ported from Hermes Agent -------------------
 * tools/binary_extensions.py)
 *
 * Fast, pure-string check: does the file path end with a known binary
 * extension? No I/O needed — just the path string. Used by read_file to
 * give a clear error before attempting to read binary files as text.
 *
 * The set covers images, video, audio, archives, executables, fonts,
 * bytecode, databases, design files, and lock/profiling data. */

static int has_binary_extension(const char *path) {
    if (!path) return 0;
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    /* Compare case-insensitively */
    const char *ext = dot; /* includes the dot */
    size_t len = strlen(ext);

    /* Sorted by frequency of encounter for early-out */
    static const char *binary[] = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".tif",
        ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wmv", ".flv", ".m4v", ".mpeg", ".mpg",
        ".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma", ".aiff", ".opus",
        ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz", ".z", ".tgz", ".iso",
        ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".obj", ".lib",
        ".app", ".msi", ".deb", ".rpm",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".odt", ".ods", ".odp",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".pyc", ".pyo", ".class", ".jar", ".war", ".ear", ".node", ".wasm", ".rlib",
        ".sqlite", ".sqlite3", ".db", ".mdb", ".idx",
        ".psd", ".ai", ".eps", ".sketch", ".fig", ".xd", ".blend", ".3ds", ".max",
        ".swf", ".fla",
        ".lockb", ".dat", ".data",
        NULL
    };
    for (int i = 0; binary[i]; i++) {
        if (len == strlen(binary[i]) && strcasecmp(ext, binary[i]) == 0)
            return 1;
    }
    return 0;
}

static sds read_file_all(const char *path, size_t max_bytes) {
    /* On macOS fopen("somedir", "rb") succeeds but fread returns 0 and sets
     * ferror. Detect this early so the caller gets a clear error instead of
     * an empty string that looks like a zero-byte file. */
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return sdscatprintf(sdsempty(), "ERROR: %s is a directory, not a file", path);
    FILE *f = fopen(path, "rb");
    if (!f) return sdscatprintf(sdsempty(), "ERROR open %s: %s", path, strerror(errno));
    sds out = sdsempty();
    char buf[8192];
    size_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (total + n > max_bytes) {
            out = sdscatlen(out, buf, max_bytes - total);
            /* "… truncated" alone does not say how much is missing, so the
             * model cannot tell 5% of a file from 95% of one and answers from
             * the fragment as if it were whole. State the size of the gap. */
            long long size = -1;
            if (fseek(f, 0, SEEK_END) == 0) size = ftell(f);
            if (size > (long long)max_bytes)
                out = sdscatprintf(out,
                    "\n…[TRUNCATED: %zu of %lld bytes shown, %lld NOT read — "
                    "use execute_bash with sed/tail to see the rest]",
                    max_bytes, size, size - (long long)max_bytes);
            else
                out = sdscatprintf(out,
                    "\n…[TRUNCATED at %zu bytes; the rest was NOT read — "
                    "use execute_bash with sed/tail to see it]", max_bytes);
            break;
        }
        out = sdscatlen(out, buf, n);
        total += n;
    }
    fclose(f);
    return out;
}

/* A NUL byte anywhere means the text cannot survive the round trip.
 *
 * The tool result is handed to cJSON_CreateString, which stops at the first
 * NUL: read_file returned 31 bytes of which the model saw 6. edit_file was
 * worse -- it rebuilt the file with strstr/strlen, so everything past the NUL
 * was dropped and a 31-byte file was rewritten as 3 bytes, reported "OK".
 * Refuse instead: these are text tools, and shell_run can handle binaries. */
static int has_nul(const char *p, size_t len) {
    return memchr(p, 0, len) != NULL;
}

/* mkdir -p without a shell. Never pass a path through system(): a path like
 * /tmp/x$(touch /tmp/PWNED)y would execute the substitution. */
static int mkdir_p(const char *dir) {
    if (!dir || !dir[0]) return -1;
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", dir) >= (int)sizeof(tmp)) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int write_file_all(const char *path, const char *data, size_t len) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = 0;
        if (mkdir_p(dir) != 0) return -1;
    }
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* Descendant tracking.
 *
 * kill(-pgid) alone is NOT enough: a grandchild that calls setsid() leaves our
 * process group and survives every time (measured: 20/20 leaks). macOS has no
 * /proc and hides other processes' env, so we sample the kernel process table
 * and remember every PID that is ever seen linked to our tree — by process
 * group, or by parent chain — before it can detach. */
#define ALPHA_MAX_TRACKED 512
/* Membership bitmap over the pid space so pt_has() is O(1) instead of a linear
 * scan run 4 x 666 x 5000 times a second. */
#define ALPHA_PID_BITS   (1 << 18)          /* covers default pid_max */
#define ALPHA_PID_WORDS  (ALPHA_PID_BITS / 32)

typedef struct {
    pid_t pids[ALPHA_MAX_TRACKED];
    int n;
    uint32_t seen[ALPHA_PID_WORDS];
} proctrack_t;

static int pt_has(const proctrack_t *t, pid_t p) {
    if (p <= 0 || p >= ALPHA_PID_BITS) return 0;
    return (t->seen[p >> 5] >> (p & 31)) & 1u;
}

static void pt_add(proctrack_t *t, pid_t p) {
    /* A pid outside the bitmap could never be marked seen, so it would be
     * appended again on every pass and fill the array. Ignore it instead. */
    if (p <= 1 || p >= ALPHA_PID_BITS) return;
    if (pt_has(t, p) || t->n >= ALPHA_MAX_TRACKED) return;
    t->seen[p >> 5] |= 1u << (p & 31);
    t->pids[t->n++] = p;
}

#ifdef ALPHA_PT_DARWIN

/* Scratch buffer reused across samples: the old code malloc'd and freed a full
 * ~430 KB process-table snapshot on every pass (~2 GB/s of churn). */
typedef struct {
    struct kinfo_proc *buf;
    size_t cap;
} pt_scratch_t;

/* One pass over the kernel process table; add anything belonging to our tree. */
static void pt_sample_buf(proctrack_t *t, pid_t root, pt_scratch_t *sc) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) return;
    if (len > sc->cap) {
        size_t want = len + len / 2;            /* headroom, avoid realloc churn */
        struct kinfo_proc *nb = realloc(sc->buf, want);
        if (!nb) return;
        sc->buf = nb;
        sc->cap = want;
    }
    len = sc->cap;
    if (sysctl(mib, 4, sc->buf, &len, NULL, 0) != 0) return;
    int count = (int)(len / sizeof(struct kinfo_proc));
    /* Repeat so multi-level chains are captured in the same sample. Stop as
     * soon as a pass adds nothing new instead of always running 4 passes. */
    for (int pass = 0; pass < 4; pass++) {
        int before = t->n;
        for (int i = 0; i < count; i++) {
            pid_t pid  = sc->buf[i].kp_proc.p_pid;
            pid_t ppid = sc->buf[i].kp_eproc.e_ppid;
            pid_t pgid = sc->buf[i].kp_eproc.e_pgid;
            if (pid <= 1) continue;
            if (pgid == root || pid == root || pt_has(t, ppid) || pt_has(t, pgid))
                pt_add(t, pid);
        }
        if (t->n == before) break;
    }
}

/* Convenience wrapper for the one-shot calls outside the sampler thread. */
static void pt_sample(proctrack_t *t, pid_t root) {
    pt_scratch_t sc = { .buf = NULL, .cap = 0 };
    pt_sample_buf(t, root, &sc);
    free(sc.buf);
}

/* Sampling by ppid/pgid is a race the sampler cannot reliably win: a
 * grandchild calls setsid() microseconds after fork, and once it does the
 * ancestry link is gone (it reparents to launchd). So identify descendants by
 * something they cannot shed — the stdout/stderr file this run created. fds
 * are inherited across fork, exec and setsid, and the temp file's inode is
 * unique to this command.
 *
 * This also sidesteps pid reuse: the check is "does this live process hold
 * our file right now", not "was this number ours a minute ago".
 *
 * Known hole: a child that both calls setsid() and closes its inherited fds —
 * the textbook daemonization sequence — sheds every marker we have and is not
 * killed. Measured: it survives with PPID 1 and its own PGID. None of the
 * three strategies here can reach it. kill(-pgid) misses it by definition (it
 * left the group), ancestry sampling misses it (it reparented to launchd), and
 * this scan misses it (no fd left to match). Closing it needs a per-command
 * uid or a sandbox; that is out of scope for a tool whose README already
 * declares security off. */
static void pt_sample_fd(proctrack_t *t, uint64_t ino, pid_t self) {
    /* proc_pidfdinfo hangs in the kernel on File Provider-backed fds (iCloud,
     * Desktop). SIGALRM cannot interrupt an uninterruptible kernel wait, so
     * the scan runs in a child process that is killed if it takes too long.
     * Without this a single hung call blocks the entire timeout cleanup path,
     * and the daemonizing-grandchild test never finishes. */
    int pipefd[2];
    if (pipe(pipefd) != 0) return;
    pid_t child = fork();
    if (child < 0) { close(pipefd[0]); close(pipefd[1]); return; }
    if (child == 0) {
        close(pipefd[0]);
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
        size_t len = 0;
        if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) _exit(0);
        struct kinfo_proc *procs = malloc(len);
        if (!procs) _exit(0);
        if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); _exit(0); }
        int count = (int)(len / sizeof(struct kinfo_proc));

        struct proc_fdinfo *fds = NULL;
        int fds_cap = 0;
        for (int i = 0; i < count; i++) {
            pid_t pid = procs[i].kp_proc.p_pid;
            if (pid <= 1 || pid == self) continue;
            int sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
            if (sz <= 0) continue;
            if (sz > fds_cap) {
                struct proc_fdinfo *nb = realloc(fds, (size_t)sz);
                if (!nb) break;
                fds = nb;
                fds_cap = sz;
            }
            sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fds_cap);
            if (sz <= 0) continue;
            int nfd = sz / (int)sizeof(struct proc_fdinfo);
            for (int f = 0; f < nfd; f++) {
                if (fds[f].proc_fdtype != PROX_FDTYPE_VNODE) continue;
                /* PROC_PIDFDVNODEINFO, not PROC_PIDFDVNODEPATHINFO: we only
                 * need the inode, and the path-resolving variant hangs in the
                 * kernel on File Provider-backed fds (iCloud, Desktop). */
                struct vnode_fdinfo v;
                if (proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDVNODEINFO,
                                   &v, sizeof(v)) < (int)sizeof(v)) continue;
                if (v.pvi.vi_stat.vst_ino == ino) {
                    /* Write the found pid to the pipe, one at a time. */
                    pid_t found = pid;
                    if (write(pipefd[1], &found, sizeof(found)) != sizeof(found)) break;
                }
            }
        }
        free(fds);
        free(procs);
        close(pipefd[1]);
        _exit(0);
    }

    /* Parent: read results with a 5s timeout. */
    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        pid_t found = 0;
        ssize_t r = read(pipefd[0], &found, sizeof(found));
        if (r == sizeof(found)) pt_add(t, found);
        int status = 0;
        if (waitpid(child, &status, WNOHANG) == child) {
            /* Drain any remaining pids. */
            while (read(pipefd[0], &found, sizeof(found)) == sizeof(found))
                pt_add(t, found);
            break;
        }
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (double)(t1.tv_sec - t0.tv_sec) +
                    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (el > 5.0) {
            kill(child, SIGKILL);
            /* SIGKILL cannot kill a process stuck in D-state (uninterruptible
             * kernel wait — proc_pidfdinfo on a File Provider fd). A blocking
             * waitpid would hang forever, so poll with a short grace period
             * and give up if the child is still alive. It will be reaped by
             * launchd when the kernel call eventually returns. */
            int grace = 0;
            while (grace < 20) {  /* 20 * 100ms = 2s grace */
                if (waitpid(child, &status, WNOHANG) == child) break;
                usleep(100000);
                grace++;
            }
            break;
        }
        usleep(20000);
    }
    close(pipefd[0]);
}

#else  /* ALPHA_PT_PROC — Linux and anything else with a /proc filesystem */

/* Same two questions as the Darwin code, asked of /proc instead of sysctl:
 * which live pids belong to our tree, and which hold this command's output
 * file open. The answers come from /proc/<pid>/stat (ppid and pgid) and from
 * /proc/<pid>/fd (symlinks the kernel resolves for us), so no equivalent of
 * libproc is needed and no scratch buffer is worth keeping.
 *
 * The root is overridable so the suite can build a synthetic /proc and run
 * this code on a host that has none -- otherwise the Linux path could only
 * ever be compile-checked. */
#ifndef ALPHA_PROC_ROOT
#define ALPHA_PROC_ROOT "/proc"
#endif

static int proc_stat_ids(pid_t pid, pid_t *out_ppid, pid_t *out_pgid) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), ALPHA_PROC_ROOT "/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return 0;
    buf[n] = 0;
    /* comm is field 2 and may contain spaces and ')', so scan from the LAST
     * ')' rather than tokenising from the start. A process named "a) b" would
     * otherwise shift every field and yield a wrong ppid. */
    char *p = strrchr(buf, ')');
    if (!p || !p[1]) return 0;
    p++;                                    /* now at " S ppid pgid ..." */
    int ppid = 0, pgid = 0;
    char state = 0;
    if (sscanf(p, " %c %d %d", &state, &ppid, &pgid) != 3) return 0;
    if (out_ppid) *out_ppid = (pid_t)ppid;
    if (out_pgid) *out_pgid = (pid_t)pgid;
    return 1;
}

/* Snapshot of live pids, so the multi-pass walk below does not re-read /proc
 * four times. */
typedef struct {
    pid_t *pids;
    int n;
} pt_scan_t;

static pt_scan_t pt_scan_pids(void) {
    pt_scan_t s = { .pids = NULL, .n = 0 };
    DIR *d = opendir(ALPHA_PROC_ROOT);
    if (!d) return s;
    int cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char *end = NULL;
        long v = strtol(de->d_name, &end, 10);
        if (!end || *end || v <= 1) continue;
        if (s.n == cap) {
            int want = cap ? cap * 2 : 256;
            pid_t *nb = realloc(s.pids, (size_t)want * sizeof(pid_t));
            if (!nb) break;
            s.pids = nb;
            cap = want;
        }
        s.pids[s.n++] = (pid_t)v;
    }
    closedir(d);
    return s;
}

static void pt_sample(proctrack_t *t, pid_t root) {
    pt_scan_t s = pt_scan_pids();
    for (int pass = 0; pass < 4; pass++) {
        int before = t->n;
        for (int i = 0; i < s.n; i++) {
            pid_t pid = s.pids[i], ppid = 0, pgid = 0;
            if (!proc_stat_ids(pid, &ppid, &pgid)) continue;
            if (pgid == root || pid == root || pt_has(t, ppid) || pt_has(t, pgid))
                pt_add(t, pid);
        }
        if (t->n == before) break;
    }
    free(s.pids);
}

static void pt_sample_fd(proctrack_t *t, uint64_t ino, pid_t self) {
    pt_scan_t s = pt_scan_pids();
    for (int i = 0; i < s.n; i++) {
        pid_t pid = s.pids[i];
        if (pid == self || pt_has(t, pid)) continue;
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), ALPHA_PROC_ROOT "/%d/fd", (int)pid);
        DIR *d = opendir(dir);
        if (!d) continue;                   /* gone, or not ours to inspect */
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char link[PATH_MAX];
            snprintf(link, sizeof(link), "%s/%s", dir, de->d_name);
            struct stat st;
            /* stat() follows the symlink to the file itself, which is exactly
             * the inode comparison the Darwin path makes. */
            if (stat(link, &st) != 0) continue;
            if (!S_ISREG(st.st_mode)) continue;
            if ((uint64_t)st.st_ino == ino) { pt_add(t, pid); break; }
        }
        closedir(d);
    }
    free(s.pids);
}

#endif /* ALPHA_PT_DARWIN */

static void pt_kill_all(proctrack_t *t) {
    for (int i = 0; i < t->n; i++) kill(t->pids[i], SIGKILL);
}

/* --- ANSI escape stripping (ported from Hermes Agent ansi_strip.py) ---------
 *
 * ANSI escape sequences in command output confuse the model and cause it to
 * copy escape sequences into file writes. Strip them from shell_run output
 * before returning it to the model.
 *
 * Covers: CSI (ESC[), OSC (ESC]), DCS/SOS/PM/APC strings, nF multi-byte
 * escapes, Fp/Fe/Fs single-byte escapes, and 8-bit C1 control characters
 * (0x80-0x9F). */

/* Fast-path check: does the string contain any ESC or C1 byte? */
static int has_escape_bytes(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1b || (c >= 0x80 && c <= 0x9f)) return 1;
    }
    return 0;
}

/* Strip ANSI escape sequences in-place. Returns the new length. */
static size_t strip_ansi(char *s) {
    if (!s || !s[0]) return 0;
    size_t len = strlen(s);
    if (!has_escape_bytes(s, len)) return len;

    char *w = s;
    const char *r = s;
    while (*r) {
        unsigned char c = (unsigned char)*r;
        if (c == 0x1b) {
            r++;
            if (!*r) break;
            c = (unsigned char)*r;
            if (c == '[') {
                /* CSI: ESC[ param* intermediate* final */
                r++;
                /* Skip parameter bytes (0x30-0x3F) */
                while (*r && (unsigned char)*r >= 0x30 && (unsigned char)*r <= 0x3f) r++;
                /* Skip intermediate bytes (0x20-0x2F) */
                while (*r && (unsigned char)*r >= 0x20 && (unsigned char)*r <= 0x2f) r++;
                /* Consume final byte (0x40-0x7E) */
                if (*r && (unsigned char)*r >= 0x40 && (unsigned char)*r <= 0x7e) r++;
            } else if (c == ']') {
                /* OSC: ESC] ... (BEL or ST) */
                r++;
                while (*r && *r != 0x07 && !(*r == 0x1b && r[1] == '\\')) r++;
                if (*r == 0x07) r++;
                else if (*r == 0x1b && r[1] == '\\') r += 2;
            } else if (c == 'P' || c == 'X' || c == '^' || c == '_') {
                /* DCS/SOS/PM/APC: ESC P/X/^/_ ... ST */
                r++;
                while (*r && !(*r == 0x1b && r[1] == '\\')) r++;
                if (*r == 0x1b && r[1] == '\\') r += 2;
            } else if (c >= 0x20 && c <= 0x2f) {
                /* nF escape: ESC nF* final */
                r++;
                while (*r && (unsigned char)*r >= 0x20 && (unsigned char)*r <= 0x2f) r++;
                if (*r && (unsigned char)*r >= 0x30 && (unsigned char)*r <= 0x7e) r++;
            } else if (c >= 0x30 && c <= 0x7e) {
                /* Fp/Fe/Fs single-byte */
                r++;
            } else {
                /* Unknown escape, skip the ESC */
                /* (already advanced past ESC) */
            }
        } else if (c >= 0x80 && c <= 0x9f) {
            /* 8-bit C1 control character */
            if (c == 0x9b) {
                /* 8-bit CSI */
                r++;
                while (*r && (unsigned char)*r >= 0x30 && (unsigned char)*r <= 0x3f) r++;
                while (*r && (unsigned char)*r >= 0x20 && (unsigned char)*r <= 0x2f) r++;
                if (*r && (unsigned char)*r >= 0x40 && (unsigned char)*r <= 0x7e) r++;
            } else if (c == 0x9d) {
                /* 8-bit OSC */
                r++;
                while (*r && (unsigned char)*r != 0x07 && (unsigned char)*r != 0x9c) r++;
                if (*r) r++;
            } else {
                r++;
            }
        } else {
            *w++ = *r++;
        }
    }
    *w = 0;
    return (size_t)(w - s);
}

/* /bin/zsh is the macOS default but is frequently absent on Linux, where
 * exec'ing it left every command failing with 127. Take ALPHA_SHELL if set,
 * else the first shell that actually exists. /bin/sh is guaranteed by POSIX,
 * so the list cannot come up empty. Termux (Android) has no /bin at all —
 * its tools live under $PREFIX, and the stock fallback is /system/bin/sh. */
static const char *shell_path(void) {
    const char *env = getenv("ALPHA_SHELL");
    if (env && env[0] && access(env, X_OK) == 0) return env;
    const char *prefix = getenv("PREFIX");
    if (prefix && prefix[0]) {
        static char tsh[PATH_MAX];
        snprintf(tsh, sizeof(tsh), "%s/bin/bash", prefix);
        if (access(tsh, X_OK) == 0) return tsh;
        snprintf(tsh, sizeof(tsh), "%s/bin/sh", prefix);
        if (access(tsh, X_OK) == 0) return tsh;
    }
    static const char *candidates[] = { "/bin/zsh", "/bin/bash", "/bin/sh", "/system/bin/sh" };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    return "/bin/sh";
}

/* Single-quote a string for safe embedding in a POSIX shell command.
 * Each embedded single quote becomes '\'' (close, escaped quote, reopen). */
static sds shell_quote(const char *s) {
    if (!s) s = "";
    sds out = sdscatlen(sdsempty(), "'", 1);
    for (const char *p = s; *p; p++) {
        if (*p == '\'') out = sdscatlen(out, "'\\''", 4);
        else out = sdscatlen(out, p, 1);
    }
    return sdscatlen(out, "'", 1);
}

/* Temp files for shell_run: /tmp does not exist on Android/Termux, which
 * sets $TMPDIR into the app's private storage instead. Honour it anywhere it
 * is set and writable, fall back to /tmp otherwise. */
static const char *alpha_tmpdir(void) {
    const char *td = getenv("TMPDIR");
    if (td && td[0] && access(td, W_OK) == 0) return td;
    return "/tmp";
}

static sds shell_run(const char *cmd, const char *cwd) {
    if (!cmd || !cmd[0]) return sdsnew("ERROR: empty command");

    /* Write command to temp script to avoid quoting hell.
     * fdopen the mkstemp fd directly — never reopen by name (symlink race in /tmp). */
    char script[PATH_MAX];
    snprintf(script, sizeof(script), "%s/alpha-cmd-XXXXXX", alpha_tmpdir());
    int sfd = mkstemp(script);
    if (sfd < 0) return sdsnew("ERROR mkstemp script");
    FILE *sf = fdopen(sfd, "w");
    if (!sf) {
        close(sfd);
        unlink(script);
        return sdsnew("ERROR write script");
    }
    const char *sh = shell_path();
    fprintf(sf, "#!%s\nset +e\n", sh);
    if (cwd && cwd[0]) {
        fprintf(sf, "cd ");
        /* single-quote cwd */
        fputc('\'', sf);
        for (const char *p = cwd; *p; p++) {
            if (*p == '\'') fputs("'\\''", sf);
            else fputc(*p, sf);
        }
        fputc('\'', sf);
        fputs(" || exit 90\n", sf);
    }
    fputs("(\n", sf);
    fputs(cmd, sf);
    fputs("\n)\nEC=$?\necho\necho __ALPHA_EXIT:$EC\nexit $EC\n", sf);
    fflush(sf);
    fchmod(fileno(sf), 0700);
    fclose(sf);

    char outf[PATH_MAX];
    snprintf(outf, sizeof(outf), "%s/alpha-out-XXXXXX", alpha_tmpdir());
    int ofd = mkstemp(outf);
    if (ofd < 0) {
        unlink(script);
        return sdsnew("ERROR mkstemp out");
    }

    /* Every descendant inherits this fd as stdout/stderr, so the inode
     * identifies the tree even after a child calls setsid(). */
    uint64_t out_ino = 0;
    struct stat ost;
    if (fstat(ofd, &ost) == 0) out_ino = (uint64_t)ost.st_ino;

    /* Hard cap shell (60s). Run in its own process group so a timeout kills
     * the whole tree, not just the top shell (background children survived before). */
    int timed_out = 0;
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        dup2(ofd, STDOUT_FILENO);
        dup2(ofd, STDERR_FILENO);
        close(ofd);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        execl(sh, sh, script, (char *)NULL);
        _exit(127);
    }
    if (pid < 0) {
        close(ofd);
        unlink(script);
        unlink(outf);
        return sdsnew("ERROR fork");
    }
    close(ofd);

    int status = 0;
    int cancelled = 0;
    int max_waits = ALPHA_SHELL_TIMEOUT_MS / 100;   /* 100ms per tick */
    for (int waited = 0; waited < max_waits; waited++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) { timed_out = 0; break; }
        if (r < 0) break;
        /* Ctrl-C must reach the command, not just the agent: without this a
         * 60s sleep still had to run to completion before the interrupt was
         * noticed. Same teardown as a timeout, since the child may have left
         * the process group. */
        if (alpha_cancel) { cancelled = 1; timed_out = 1; break; }
        usleep(100000);
        if (waited == max_waits - 1) timed_out = 1;
    }

    if (timed_out) {
        proctrack_t track = { .n = 0 };
        /* Group first: reaps everything that stayed in our process group. */
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        /* Then the ones that left it, by ancestry and by the output file they
         * still hold open. A descendant that did both — setsid() and closed
         * its fds — survives all three; see pt_sample_fd. */
        pt_sample(&track, pid);
        pt_sample_fd(&track, out_ino, getpid());
        pt_kill_all(&track);
        /* The shell itself is unlikely to be in D-state, but a blocking
         * waitpid is still a risk: poll with a short grace period. */
        int grace = 0;
        while (grace < 20) {  /* 20 * 100ms = 2s grace */
            if (waitpid(pid, &status, WNOHANG) == pid) break;
            usleep(100000);
            grace++;
        }
    }

    sds out = read_file_all(outf, 200000);
    unlink(script);
    unlink(outf);
    if (!out || !out[0]) {
        if (out) sdsfree(out);
        out = sdsnew("(no output)");
    }
    /* Strip ANSI escape sequences before the model sees them. ANSI codes in
     * command output confuse the model and cause it to copy escape sequences
     * into file writes. The strip is done in-place on the sds buffer. */
    strip_ansi(out);
    if (cancelled)
        out = sdscat(out, "\nERROR: command interrupted by the user.");
    else if (timed_out)
        out = sdscatprintf(out,
            "\nERROR: command exceeded %dms timeout — killed (process group, "
            "plus descendants still holding this command's output file). "
            "A process that called setsid() and closed its inherited fds "
            "may still be running.", ALPHA_SHELL_TIMEOUT_MS);
    return out;
}

/* macOS Desktop/iCloud File Provider often hangs opendir forever — refuse early.
 * Elsewhere ~/Desktop is an ordinary directory and refusing it would be a bug,
 * so this is a macOS-only guard. */
static int path_is_hang_prone(const char *path) {
#ifndef ALPHA_PT_DARWIN
    (void)path;
    return 0;
#else
    if (!path || !path[0]) return 0;
    if (strstr(path, "/Desktop") || strstr(path, "/Desktop/") ||
        strcmp(path, "Desktop") == 0 || strncmp(path, "Desktop/", 8) == 0 ||
        strstr(path, "/Library/Mobile Documents") ||
        strstr(path, "com~apple~CloudDocs"))
        return 1;
    return 0;
#endif
}

static sds list_dir_sync(const char *p) {
    DIR *d = opendir(p);
    if (!d) return sdscatprintf(sdsempty(), "ERROR opendir %s: %s", p, strerror(errno));
    sds out = sdsempty();
    struct dirent *de;
    char names[512][256];
    int n = 0;
    while ((de = readdir(d)) != NULL && n < 512) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        snprintf(names[n], sizeof(names[n]), "%s", de->d_name);
        n++;
    }
    closedir(d);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (strcasecmp(names[i], names[j]) > 0) {
                char t[256];
                snprintf(t, sizeof(t), "%s", names[i]);
                snprintf(names[i], sizeof(names[i]), "%s", names[j]);
                snprintf(names[j], sizeof(names[j]), "%s", t);
            }
    for (int i = 0; i < n; i++) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", p, names[i]);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode))
            out = sdscatprintf(out, "dir  %s\n", names[i]);
        else
            out = sdscatprintf(out, "file %s\n", names[i]);
    }
    if (n == 0) out = sdscat(out, "(empty)\n");
    return out;
}

/* list_dir with hard fail-closed on Desktop + 8s wall timeout via fork. */
static sds list_dir(const char *path) {
    const char *p = (path && path[0]) ? path : ".";
    if (path_is_hang_prone(p)) {
        return sdscatprintf(sdsempty(),
            "ERROR: path is served by the macOS File Provider (Desktop/iCloud Drive) "
            "and can block indefinitely: %s\n"
            "Copy what you need to a local directory first.\n", p);
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) return list_dir_sync(p);

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return list_dir_sync(p);
    }
    if (pid == 0) {
        /* child */
        close(pipefd[0]);
        alarm(8);
        sds out = list_dir_sync(p);
        size_t len = out ? sdslen(out) : 0;
        if (out && len) {
            /* write length + body */
            uint32_t n = (uint32_t)len;
            if (write(pipefd[1], &n, sizeof(n)) == (ssize_t)sizeof(n))
                write(pipefd[1], out, len);
        } else {
            uint32_t n = 0;
            write(pipefd[1], &n, sizeof(n));
        }
        if (out) sdsfree(out);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);
    /* parent: wait up to 9s */
    int status = 0;
    int waited = 0;
    while (waited < 90) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        usleep(100000);
        waited++;
    }
    if (waited >= 90) {
        kill(pid, SIGKILL);
        /* SIGKILL cannot kill a process stuck in D-state (uninterruptible
         * kernel wait — opendir on a File Provider directory). Poll with a
         * short grace period instead of blocking forever. */
        int grace = 0;
        while (grace < 20) {  /* 20 * 100ms = 2s grace */
            if (waitpid(pid, &status, WNOHANG) == pid) break;
            usleep(100000);
            grace++;
        }
        close(pipefd[0]);
        return sdscatprintf(sdsempty(),
            "ERROR: list_dir timed out after 8s on %s\n"
            "Prefer ~/projects or ~/agent-desktop (Desktop often hangs).\n", p);
    }

    uint32_t n = 0;
    ssize_t nr = read(pipefd[0], &n, sizeof(n));
    sds out = sdsempty();
    if (nr == (ssize_t)sizeof(n) && n > 0 && n < 2000000) {
        char *buf = malloc(n + 1);
        if (buf) {
            size_t got = 0;
            while (got < n) {
                ssize_t r = read(pipefd[0], buf + got, n - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            buf[got] = 0;
            out = sdscatlen(out, buf, got);
            free(buf);
        }
    }
    close(pipefd[0]);
    if (!out[0]) {
        sdsfree(out);
        return sdscatprintf(sdsempty(), "ERROR: list_dir empty/fail on %s", p);
    }
    return out;
}

/* --- web_search: DuckDuckGo HTML (no API key, no JS) ----------------------
 *
 * Fetches the non-JS HTML search at html.duckduckgo.com/html/ and extracts
 * title, URL, and snippet from each result. No API key, no rate limit, no
 * JavaScript — just a single HTTP GET and a small HTML parser.
 *
 * The HTML structure is stable: each result is a <div class="result"> with
 * <h2 class="result__title"><a class="result__a" href="...">title</a></h2>
 * and <a class="result__snippet">snippet</a>. The URL is extracted from the
 * href on the title link, which goes through DuckDuckGo's redirector
 * (//duckduckgo.com/l/?uddg=ENCODED_URL&rut=...). We decode the uddg
 * parameter to get the real URL.
 *
 * Timeout: 8s connect, 12s total. Returns up to 20 results. */

/* libcurl write callback: append to sds */
struct ws_buf { sds data; };
static size_t ws_write_cb(char *ptr, size_t sz, size_t nmemb, void *ud) {
    struct ws_buf *b = ud;
    size_t n = sz * nmemb;
    b->data = sdscatlen(b->data, ptr, n);
    return n;
}

/* Decode a URL-encoded string in-place. Returns the new length. */
static size_t url_decode_inplace(char *s) {
    char *w = s;
    for (const char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            int hi = r[1] >= 'a' ? r[1] - 'a' + 10 : r[1] >= 'A' ? r[1] - 'A' + 10 : r[1] - '0';
            int lo = r[2] >= 'a' ? r[2] - 'a' + 10 : r[2] >= 'A' ? r[2] - 'A' + 10 : r[2] - '0';
            *w++ = (char)((hi << 4) | lo);
            r += 2;
        } else if (*r == '+') {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
    }
    *w = 0;
    return (size_t)(w - s);
}

/* Extract the real URL from a DuckDuckGo redirector href like:
 * //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=... */
static sds ddg_decode_url(const char *href) {
    if (!href) return sdsempty();
    /* Find uddg= parameter */
    const char *p = strstr(href, "uddg=");
    if (!p) {
        /* Not a redirector link — use as-is, stripping leading // */
        if (href[0] == '/' && href[1] == '/') href += 2;
        return sdsnew(href);
    }
    p += 5; /* skip "uddg=" */
    /* Copy until & or end */
    sds enc = sdsempty();
    while (*p && *p != '&') { enc = sdscatlen(enc, p, 1); p++; }
    url_decode_inplace(enc);
    return enc;
}

/* Strip HTML tags from a string in-place. Also decodes common entities. */
static void strip_html(char *s) {
    char *w = s;
    int in_tag = 0;
    for (const char *r = s; *r; r++) {
        if (*r == '<') { in_tag = 1; continue; }
        if (*r == '>') { in_tag = 0; continue; }
        if (in_tag) continue;
        /* Decode common entities */
        if (strncmp(r, "&amp;", 5) == 0) { *w++ = '&'; r += 4; continue; }
        if (strncmp(r, "&lt;", 4) == 0)  { *w++ = '<'; r += 3; continue; }
        if (strncmp(r, "&gt;", 4) == 0)  { *w++ = '>'; r += 3; continue; }
        if (strncmp(r, "&quot;", 6) == 0) { *w++ = '"'; r += 5; continue; }
        if (strncmp(r, "&#x27;", 6) == 0) { *w++ = '\''; r += 5; continue; }
        if (strncmp(r, "&#39;", 5) == 0) { *w++ = '\''; r += 4; continue; }
        *w++ = *r;
    }
    *w = 0;
}

/* Collapse whitespace: replace runs of space/tab/newline with a single space,
 * trim leading/trailing. */
static void collapse_ws(char *s) {
    char *w = s;
    int space = 0;
    for (const char *r = s; *r; r++) {
        if (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r') {
            if (w > s) space = 1;
            continue;
        }
        if (space) { *w++ = ' '; space = 0; }
        *w++ = *r;
    }
    *w = 0;
    /* Trim trailing space */
    while (w > s && (w[-1] == ' ' || w[-1] == '\t')) { w--; *w = 0; }
}

static sds web_search(const char *query, int max_results) {
    if (!query || !query[0])
        return sdsnew("ERROR: query required for web_search");

    if (max_results <= 0 || max_results > 20) max_results = 10;

    /* URL-encode the query */
    sds enc = sdsempty();
    for (const unsigned char *p = (const unsigned char *)query; *p; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' ||
            *p == '~')
            enc = sdscatlen(enc, (const char *)p, 1);
        else if (*p == ' ')
            enc = sdscatlen(enc, "+", 1);
        else
            enc = sdscatprintf(enc, "%%%02X", *p);
    }

    /* Build POST body: q=<encoded query>. Must live until curl_easy_cleanup
     * because CURLOPT_POSTFIELDS uses the pointer directly, not a copy. */
    sds post_body = sdscatprintf(sdsempty(), "q=%s", enc);
    sdsfree(enc);

    CURL *curl = curl_easy_init();
    if (!curl) { sdsfree(post_body); return sdsnew("ERROR: curl_easy_init failed"); }

    struct ws_buf buf = { .data = sdsempty() };
    curl_easy_setopt(curl, CURLOPT_URL, "https://html.duckduckgo.com/html/");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ws_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 12L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     "Mozilla/5.0 (compatible; AgentAlpha/1.0)");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    /* post_body freed AFTER curl_easy_cleanup — CURLOPT_POSTFIELDS borrows it */
    sdsfree(post_body);

    if (rc != CURLE_OK) {
        sdsfree(buf.data);
        return sdscatprintf(sdsempty(),
            "ERROR: web_search request failed: %s", curl_easy_strerror(rc));
    }
    if (http_code != 200) {
        sdsfree(buf.data);
        return sdscatprintf(sdsempty(),
            "ERROR: web_search returned HTTP %ld", http_code);
    }

    /* Detect DuckDuckGo CAPTCHA / bot-detection page */
    if (strstr(buf.data, "anomaly-modal") || strstr(buf.data, "g-recaptcha")) {
        sdsfree(buf.data);
        return sdsnew("ERROR: web_search was rate-limited (CAPTCHA). "
                      "Wait a moment and try again.");
    }

    /* Parse the HTML. We look for <div class="result ..."> blocks and extract
     * the title link and snippet from each. This is a deliberate minimal
     * parser — no full HTML parse tree, just strstr on the known class names.
     * DuckDuckGo's HTML output is machine-generated and stable. */
    sds out = sdscatprintf(sdsempty(), "WEB SEARCH RESULTS for \"%s\"\n\n", query);
    const char *html = buf.data;
    int found = 0;
    const char *pos = html;

    while (found < max_results) {
        /* Find next result block */
        const char *div = strstr(pos, "class=\"result");
        if (!div) break;
        /* Make sure it's a result div, not some other "result*" class */
        if (div[13] != '"' && div[13] != ' ') { pos = div + 13; continue; }
        pos = div + 1;

        /* Extract title: <h2 class="result__title"><a ...>TITLE</a></h2> */
        const char *h2 = strstr(div, "result__title");
        if (!h2) continue;
        const char *a_start = strstr(h2, "<a ");
        if (!a_start) continue;
        const char *href_start = strstr(a_start, "href=\"");
        if (!href_start) { /* try href=' */
            href_start = strstr(a_start, "href='");
            if (!href_start) continue;
        }
        char quote = href_start[5]; /* " or ' */
        href_start += 6; /* skip href=" */
        const char *href_end = strchr(href_start, quote);
        if (!href_end) continue;
        size_t href_len = (size_t)(href_end - href_start);
        char href_buf[2048];
        if (href_len >= sizeof(href_buf)) href_len = sizeof(href_buf) - 1;
        memcpy(href_buf, href_start, href_len);
        href_buf[href_len] = 0;

        /* Decode the real URL from the DDG redirector */
        sds real_url = ddg_decode_url(href_buf);

        /* Extract title text between <a ...> and </a> */
        const char *title_start = strchr(a_start, '>');
        if (!title_start) { sdsfree(real_url); continue; }
        title_start++; /* skip > */
        const char *title_end = strstr(title_start, "</a>");
        if (!title_end) { sdsfree(real_url); continue; }
        size_t title_len = (size_t)(title_end - title_start);
        char title_buf[512];
        if (title_len >= sizeof(title_buf)) title_len = sizeof(title_buf) - 1;
        memcpy(title_buf, title_start, title_len);
        title_buf[title_len] = 0;
        strip_html(title_buf);
        collapse_ws(title_buf);

        /* Extract snippet: <a class="result__snippet" ...>SNIPPET</a> */
        const char *snip_tag = strstr(div, "result__snippet");
        const char *snip_start = NULL;
        const char *snip_end = NULL;
        if (snip_tag) {
            snip_start = strchr(snip_tag, '>');
            if (snip_start) {
                snip_start++;
                snip_end = strstr(snip_start, "</a>");
            }
        }
        char snip_buf[1024] = "";
        if (snip_start && snip_end && snip_end > snip_start) {
            size_t snip_len = (size_t)(snip_end - snip_start);
            if (snip_len >= sizeof(snip_buf)) snip_len = sizeof(snip_buf) - 1;
            memcpy(snip_buf, snip_start, snip_len);
            snip_buf[snip_len] = 0;
            strip_html(snip_buf);
            collapse_ws(snip_buf);
        }

        found++;
        out = sdscatprintf(out, "%d. %s\n   %s\n", found, title_buf, real_url);
        if (snip_buf[0])
            out = sdscatprintf(out, "   %s\n", snip_buf);
        out = sdscat(out, "\n");
        sdsfree(real_url);
    }

    sdsfree(buf.data);

    if (found == 0)
        out = sdscat(out, "(no results)\n");

    return out;
}

/* --- todo tool (ported from Hermes Agent todo_tool.py) -------------------- */

#define ALPHA_MAX_TODO_ITEMS 256
#define ALPHA_MAX_TODO_CONTENT 4000

typedef struct {
    char id[64];
    char content[ALPHA_MAX_TODO_CONTENT];
    char status[16]; /* pending, in_progress, completed, cancelled */
} todo_item_t;

typedef struct {
    todo_item_t items[ALPHA_MAX_TODO_ITEMS];
    int count;
} todo_store_t;

static todo_store_t g_todo_store = { .count = 0 };
static pthread_mutex_t g_todo_lock = PTHREAD_MUTEX_INITIALIZER;

static int todo_valid_status(const char *st) {
    if (!st) return 0;
    return strcmp(st, "pending") == 0 ||
           strcmp(st, "in_progress") == 0 ||
           strcmp(st, "completed") == 0 ||
           strcmp(st, "cancelled") == 0;
}

static sds todo_tool_run(cJSON *args) {
    pthread_mutex_lock(&g_todo_lock);

    cJSON *todos = cJSON_GetObjectItem(args, "todos");
    cJSON *merge_item = cJSON_GetObjectItem(args, "merge");
    int merge = (merge_item && cJSON_IsBool(merge_item)) ? cJSON_IsTrue(merge_item) : 0;

    if (todos && cJSON_IsArray(todos)) {
        if (!merge) {
            /* Replace mode */
            g_todo_store.count = 0;
            int n = cJSON_GetArraySize(todos);
            for (int i = 0; i < n && g_todo_store.count < ALPHA_MAX_TODO_ITEMS; i++) {
                cJSON *item = cJSON_GetArrayItem(todos, i);
                if (!cJSON_IsObject(item)) continue;
                const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(item, "id"));
                const char *cnt = cJSON_GetStringValue(cJSON_GetObjectItem(item, "content"));
                const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(item, "status"));
                if (!id || !id[0]) continue;
                todo_item_t *t = &g_todo_store.items[g_todo_store.count++];
                snprintf(t->id, sizeof(t->id), "%s", id);
                snprintf(t->content, sizeof(t->content), "%s", cnt ? cnt : "(no description)");
                snprintf(t->status, sizeof(t->status), "%s", todo_valid_status(st) ? st : "pending");
            }
        } else {
            /* Merge mode: update existing by ID, append new */
            int n = cJSON_GetArraySize(todos);
            for (int i = 0; i < n; i++) {
                cJSON *item = cJSON_GetArrayItem(todos, i);
                if (!cJSON_IsObject(item)) continue;
                const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(item, "id"));
                const char *cnt = cJSON_GetStringValue(cJSON_GetObjectItem(item, "content"));
                const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(item, "status"));
                if (!id || !id[0]) continue;

                int found = -1;
                for (int j = 0; j < g_todo_store.count; j++) {
                    if (strcmp(g_todo_store.items[j].id, id) == 0) {
                        found = j;
                        break;
                    }
                }
                if (found >= 0) {
                    if (cnt && cnt[0]) snprintf(g_todo_store.items[found].content, sizeof(g_todo_store.items[found].content), "%s", cnt);
                    if (st && todo_valid_status(st)) snprintf(g_todo_store.items[found].status, sizeof(g_todo_store.items[found].status), "%s", st);
                } else if (g_todo_store.count < ALPHA_MAX_TODO_ITEMS) {
                    todo_item_t *t = &g_todo_store.items[g_todo_store.count++];
                    snprintf(t->id, sizeof(t->id), "%s", id);
                    snprintf(t->content, sizeof(t->content), "%s", cnt ? cnt : "(no description)");
                    snprintf(t->status, sizeof(t->status), "%s", todo_valid_status(st) ? st : "pending");
                }
            }
        }
    }

    /* Build JSON summary response */
    cJSON *res = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    int pending = 0, in_prog = 0, comp = 0, canc = 0;

    for (int i = 0; i < g_todo_store.count; i++) {
        todo_item_t *t = &g_todo_store.items[i];
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", t->id);
        cJSON_AddStringToObject(obj, "content", t->content);
        cJSON_AddStringToObject(obj, "status", t->status);
        cJSON_AddItemToArray(arr, obj);

        if (strcmp(t->status, "pending") == 0) pending++;
        else if (strcmp(t->status, "in_progress") == 0) in_prog++;
        else if (strcmp(t->status, "completed") == 0) comp++;
        else if (strcmp(t->status, "cancelled") == 0) canc++;
    }

    cJSON_AddItemToObject(res, "todos", arr);
    cJSON *sum = cJSON_CreateObject();
    cJSON_AddNumberToObject(sum, "total", g_todo_store.count);
    cJSON_AddNumberToObject(sum, "pending", pending);
    cJSON_AddNumberToObject(sum, "in_progress", in_prog);
    cJSON_AddNumberToObject(sum, "completed", comp);
    cJSON_AddNumberToObject(sum, "cancelled", canc);
    cJSON_AddItemToObject(res, "summary", sum);

    pthread_mutex_unlock(&g_todo_lock);

    char *json_s = cJSON_PrintUnformatted(res);
    sds out = sdsnew(json_s ? json_s : "{}");
    if (json_s) free(json_s);
    cJSON_Delete(res);
    return out;
}

/* --- memory tool: persistent curated memory across sessions -----------------
 *
 * Two file-backed stores under ~/.alpha/memory/:
 *   MEMORY.md — agent's personal notes (environment facts, conventions, lessons)
 *   USER.md   — what the agent knows about the user (preferences, style)
 *
 * Entries are §-delimited (section sign). The tool supports add, replace, and
 * remove actions via substring matching (no IDs). A frozen snapshot is injected
 * into the system prompt at session start; mid-session writes update the files
 * on disk immediately but do NOT change the system prompt — this preserves the
 * prefix cache for the entire session.
 *
 * Character limits (not tokens) because char counts are model-independent:
 *   MEMORY.md: 2200 chars, USER.md: 1375 chars.
 *
 * Design ported from Hermes Agent's memory_tool.py (tools/memory_tool.py).
 *
 * Arena allocator (from clay.h): entries are bump-allocated from a fixed
 * buffer instead of individual strdup/free calls. This makes memory_free_store
 * O(1) instead of O(n), eliminates per-entry malloc churn, and avoids
 * fragmentation. The arena is sized to hold the maximum possible content
 * (char_limit + delimiters + overhead). */

#define ALPHA_MEMORY_DIR       ".alpha/memory"
#define ALPHA_MEMORY_ENTRY_SEP "\n§\n"
#define ALPHA_MEMORY_MAX_ENTRIES 64
#define ALPHA_MEMORY_CHAR_LIMIT   2200
#define ALPHA_USER_CHAR_LIMIT     1375
/* Arena size: char_limit + room for delimiters + safety margin.
 * Each store gets its own arena so resetting one does not affect the other. */
#define ALPHA_MEMORY_ARENA_SIZE 4096

/* Bump allocator (arena) — ported from clay.h's Clay_Arena pattern.
 * O(1) alloc, O(1) free-all. No individual free() calls needed.
 *
 * The buffer is embedded in the struct so the arena is always valid without
 * a separate init call — zero-initialization sets offset=0 and the buf[]
 * exists at a fixed address. This matters when the memory module is compiled
 * as part of a test that does not call memory_init(). */
typedef struct {
    char buf[ALPHA_MEMORY_ARENA_SIZE];
    size_t offset;
} arena_t;

static void arena_init(arena_t *a) {
    a->offset = 0;
}

static void arena_reset(arena_t *a) {
    a->offset = 0;
}

static char *arena_alloc(arena_t *a, size_t sz) {
    /* Align to 8 bytes so subsequent allocations are naturally aligned. */
    size_t aligned = (sz + 7) & ~(size_t)7;
    if (a->offset + aligned > sizeof(a->buf)) return NULL;
    char *p = a->buf + a->offset;
    a->offset += aligned;
    return p;
}

typedef struct {
    char *entries[ALPHA_MEMORY_MAX_ENTRIES];
    int count;
    int char_limit;
    arena_t arena;                /* bump allocator for this store's entries */
} memory_store_t;

static memory_store_t g_memory_store = { .count = 0, .char_limit = ALPHA_MEMORY_CHAR_LIMIT };
static memory_store_t g_user_store    = { .count = 0, .char_limit = ALPHA_USER_CHAR_LIMIT };
static pthread_mutex_t g_memory_lock = PTHREAD_MUTEX_INITIALIZER;

/* Resolve the memory directory, creating it if needed. Returns a static buffer
 * that is valid until the next call. ALPHA_MEMORY_DIR overrides the default
 * location — the evolution driver uses it to keep benchmark subprocess writes
 * out of the real store. */
static const char *memory_dir(void) {
    static char dir[PATH_MAX];
    const char *env = getenv("ALPHA_MEMORY_DIR");
    if (env && env[0]) {
        snprintf(dir, sizeof(dir), "%s", env);
        mkdir_p(dir);
        return dir;
    }
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = "/tmp";
    snprintf(dir, sizeof(dir), "%s/" ALPHA_MEMORY_DIR, home);
    mkdir_p(dir);
    return dir;
}

static const char *memory_path(const char *target) {
    static char path[PATH_MAX];
    const char *dir = memory_dir();
    if (strcmp(target, "user") == 0)
        snprintf(path, sizeof(path), "%s/USER.md", dir);
    else
        snprintf(path, sizeof(path), "%s/MEMORY.md", dir);
    return path;
}

/* Parse a memory file into entries, allocating from the store's arena.
 * Returns the number of entries parsed into store->entries[]. */
static int memory_parse_into_store(const char *raw, memory_store_t *store) {
    if (!raw || !raw[0]) return 0;
    /* Work on a copy so we can tokenize */
    char *copy = strdup(raw);
    if (!copy) return 0;

    char *save = NULL;
    char *tok = strtok_r(copy, ALPHA_MEMORY_ENTRY_SEP, &save);
    while (tok) {
        /* Trim leading/trailing whitespace */
        while (*tok == ' ' || *tok == '\t' || *tok == '\n' || *tok == '\r') tok++;
        char *end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t' ||
                             end[-1] == '\n' || end[-1] == '\r')) end--;
        *end = 0;
        if (tok[0] && store->count < ALPHA_MEMORY_MAX_ENTRIES) {
            /* Check for duplicate */
            int dup = 0;
            for (int i = 0; i < store->count; i++) {
                if (strcmp(store->entries[i], tok) == 0) { dup = 1; break; }
            }
            if (!dup) {
                size_t len = strlen(tok);
                char *p = arena_alloc(&store->arena, len + 1);
                if (!p) break; /* arena full */
                memcpy(p, tok, len + 1);
                store->entries[store->count++] = p;
            }
        }
        tok = strtok_r(NULL, ALPHA_MEMORY_ENTRY_SEP, &save);
    }
    free(copy);
    return store->count;
}

/* Read a memory file and parse it into a store. Returns 0 on success. */
static int memory_load(const char *target, memory_store_t *store) {
    const char *path = memory_path(target);
    FILE *f = fopen(path, "rb");
    if (!f) {
        /* No file yet — empty store is fine */
        store->count = 0;
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1048576) { fclose(f); store->count = 0; return 0; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;

    /* Reset arena and parse into store */
    arena_reset(&store->arena);
    store->count = 0;
    memory_parse_into_store(buf, store);
    free(buf);
    return 0;
}

/* Write a store back to its file. Uses atomic temp-file + rename. */
static int memory_save(const char *target, memory_store_t *store) {
    const char *path = memory_path(target);
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    for (int i = 0; i < store->count; i++) {
        if (i > 0) fputs(ALPHA_MEMORY_ENTRY_SEP, f);
        fputs(store->entries[i], f);
    }
    int ok = (fflush(f) == 0);
    if (ok) ok = (fsync(fileno(f)) == 0);
    fclose(f);
    if (ok) ok = (rename(tmp, path) == 0);
    else unlink(tmp);
    return ok ? 0 : -1;
}

/* Compute the total char count of a store (including delimiters). */
static int memory_char_count(memory_store_t *store) {
    if (store->count == 0) return 0;
    int total = 0;
    for (int i = 0; i < store->count; i++) {
        if (i > 0) total += (int)strlen(ALPHA_MEMORY_ENTRY_SEP);
        total += (int)strlen(store->entries[i]);
    }
    return total;
}

/* Free all entries in a store. O(1) — just resets the bump arena.
 * Non-static because the test suite (which #includes this file) calls it. */
void memory_free_store(memory_store_t *store) {
    arena_reset(&store->arena);
    store->count = 0;
}

/* Initialize both stores from disk. Called once at startup. */
void memory_init(void) {
    pthread_mutex_lock(&g_memory_lock);
    arena_init(&g_memory_store.arena);
    arena_init(&g_user_store.arena);
    g_memory_store.count = 0;
    g_user_store.count = 0;
    memory_load("memory", &g_memory_store);
    memory_load("user", &g_user_store);
    pthread_mutex_unlock(&g_memory_lock);
}

/* Format a store as a system-prompt block. Returns an sds (caller frees).
 * This is the frozen snapshot — it reflects the state at session start. */
sds memory_format_for_prompt(const char *target) {
    pthread_mutex_lock(&g_memory_lock);
    memory_store_t *store = (strcmp(target, "user") == 0) ? &g_user_store : &g_memory_store;
    if (store->count == 0) {
        pthread_mutex_unlock(&g_memory_lock);
        return sdsempty();
    }
    const char *header = (strcmp(target, "user") == 0)
        ? "USER PROFILE (who the user is)"
        : "MEMORY (your personal notes)";
    int current = memory_char_count(store);
    int limit = store->char_limit;
    int pct = limit > 0 ? (current * 100 / limit) : 0;
    if (pct > 100) pct = 100;

    sds out = sdscatprintf(sdsempty(),
        "══════════════════════════════════════════════\n"
        "%s [%d%% — %d/%d chars]\n"
        "══════════════════════════════════════════════\n",
        header, pct, current, limit);
    for (int i = 0; i < store->count; i++) {
        if (i > 0) out = sdscat(out, ALPHA_MEMORY_ENTRY_SEP);
        out = sdscat(out, store->entries[i]);
    }
    pthread_mutex_unlock(&g_memory_lock);
    return out;
}

/* --- memory tool dispatch ------------------------------------------------ */

static memory_store_t *memory_store_for(const char *target) {
    return (strcmp(target, "user") == 0) ? &g_user_store : &g_memory_store;
}

static sds memory_tool_add(memory_store_t *store, const char *content) {
    if (!content || !content[0])
        return sdsnew("ERROR: content cannot be empty");

    /* Reject exact duplicates */
    for (int i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i], content) == 0)
            return sdsnew("ERROR: entry already exists (no duplicate added)");
    }

    /* Check budget */
    int current = memory_char_count(store);
    int new_total = current;
    if (store->count > 0) new_total += (int)strlen(ALPHA_MEMORY_ENTRY_SEP);
    new_total += (int)strlen(content);
    if (new_total > store->char_limit) {
        return sdscatprintf(sdsempty(),
            "ERROR: memory at %d/%d chars. Adding this entry (%zu chars) would "
            "exceed the limit. Use 'replace' to merge overlapping entries or "
            "'remove' to delete stale ones, then retry.",
            current, store->char_limit, strlen(content));
    }

    if (store->count >= ALPHA_MEMORY_MAX_ENTRIES)
        return sdsnew("ERROR: maximum number of entries reached");

    char *p = arena_alloc(&store->arena, strlen(content) + 1);
    if (!p)
        return sdsnew("ERROR: arena full — use 'remove' to free space");
    strcpy(p, content);
    store->entries[store->count++] = p;
    return sdscatprintf(sdsempty(), "OK added entry (%d/%d chars now)",
                        new_total, store->char_limit);
}

static sds memory_tool_replace(memory_store_t *store, const char *old_text,
                                const char *new_content) {
    if (!old_text || !old_text[0])
        return sdsnew("ERROR: old_text cannot be empty");
    if (!new_content || !new_content[0])
        return sdsnew("ERROR: new_content cannot be empty (use 'remove' to delete)");

    /* Find matching entries */
    int matches[ALPHA_MEMORY_MAX_ENTRIES];
    int nmatch = 0;
    for (int i = 0; i < store->count; i++) {
        if (strstr(store->entries[i], old_text))
            matches[nmatch++] = i;
    }
    if (nmatch == 0)
        return sdsnew("ERROR: no entry matched old_text");
    if (nmatch > 1) {
        /* Check if all matches are identical */
        int same = 1;
        for (int i = 1; i < nmatch; i++) {
            if (strcmp(store->entries[matches[0]], store->entries[matches[i]]) != 0) {
                same = 0;
                break;
            }
        }
        if (!same)
            return sdsnew("ERROR: multiple distinct entries matched — be more specific");
    }

    int idx = matches[0];
    /* Check budget */
    int current = memory_char_count(store);
    int new_total = current
        - (int)strlen(store->entries[idx])
        + (int)strlen(new_content);
    if (new_total > store->char_limit) {
        return sdscatprintf(sdsempty(),
            "ERROR: replacement would put memory at %d/%d chars. "
            "Shorten the new content or remove other entries first.",
            new_total, store->char_limit);
    }

    /* Arena alloc: the old entry's memory is still in the arena but will be
     * overwritten on the next arena_reset. This is fine — the old pointer is
     * no longer referenced. */
    char *p = arena_alloc(&store->arena, strlen(new_content) + 1);
    if (!p)
        return sdsnew("ERROR: arena full — use 'remove' to free space");
    strcpy(p, new_content);
    store->entries[idx] = p;
    return sdscatprintf(sdsempty(), "OK replaced entry (%d/%d chars now)",
                        new_total, store->char_limit);
}

static sds memory_tool_remove(memory_store_t *store, const char *old_text) {
    if (!old_text || !old_text[0])
        return sdsnew("ERROR: old_text cannot be empty");

    int matches[ALPHA_MEMORY_MAX_ENTRIES];
    int nmatch = 0;
    for (int i = 0; i < store->count; i++) {
        if (strstr(store->entries[i], old_text))
            matches[nmatch++] = i;
    }
    if (nmatch == 0)
        return sdsnew("ERROR: no entry matched old_text");
    if (nmatch > 1) {
        int same = 1;
        for (int i = 1; i < nmatch; i++) {
            if (strcmp(store->entries[matches[0]], store->entries[matches[i]]) != 0) {
                same = 0;
                break;
            }
        }
        if (!same)
            return sdsnew("ERROR: multiple distinct entries matched — be more specific");
    }

    int idx = matches[0];
    /* Arena-allocated: no individual free. Just shift the array down. */
    for (int i = idx; i < store->count - 1; i++)
        store->entries[i] = store->entries[i + 1];
    store->count--;

    int current = memory_char_count(store);
    return sdscatprintf(sdsempty(), "OK removed entry (%d/%d chars now)",
                        current, store->char_limit);
}

static sds memory_tool_run(cJSON *args) {
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    const char *target = cJSON_GetStringValue(cJSON_GetObjectItem(args, "target"));
    const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(args, "content"));
    const char *old_text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_text"));

    if (!target) target = "memory";
    if (strcmp(target, "memory") != 0 && strcmp(target, "user") != 0)
        return sdsnew("ERROR: target must be 'memory' or 'user'");

    if (!action) {
        /* Read-only: return current entries */
        pthread_mutex_lock(&g_memory_lock);
        memory_store_t *store = memory_store_for(target);
        cJSON *res = cJSON_CreateObject();
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < store->count; i++)
            cJSON_AddItemToArray(arr, cJSON_CreateString(store->entries[i]));
        cJSON_AddItemToObject(res, "entries", arr);
        int current = memory_char_count(store);
        cJSON_AddNumberToObject(res, "char_count", current);
        cJSON_AddNumberToObject(res, "char_limit", store->char_limit);
        cJSON_AddNumberToObject(res, "entry_count", store->count);
        pthread_mutex_unlock(&g_memory_lock);

        char *json_s = cJSON_PrintUnformatted(res);
        sds out = sdsnew(json_s ? json_s : "{}");
        if (json_s) free(json_s);
        cJSON_Delete(res);
        return out;
    }

    pthread_mutex_lock(&g_memory_lock);
    memory_store_t *store = memory_store_for(target);
    sds result = NULL;

    if (strcmp(action, "add") == 0) {
        result = memory_tool_add(store, content);
    } else if (strcmp(action, "replace") == 0) {
        result = memory_tool_replace(store, old_text, content);
    } else if (strcmp(action, "remove") == 0) {
        result = memory_tool_remove(store, old_text);
    } else {
        result = sdsnew("ERROR: unknown action — use add, replace, or remove");
    }

    /* Persist on success */
    if (result && strncmp(result, "OK", 2) == 0)
        memory_save(target, store);

    pthread_mutex_unlock(&g_memory_lock);
    return result;
}

/* --- working_diff: git working-tree diff (ported from Hermes Agent ----------
 * tools/working_diff.py)
 *
 * Collects a git diff of the working directory. Supports three modes:
 *   working (default): unstaged changes + untracked files
 *   staged: changes staged for commit (git diff --cached)
 *   all: everything since HEAD (staged + unstaged) + untracked files
 *
 * Untracked files are folded in via git diff --no-index /dev/null <file> so
 * brand-new files show up as additions instead of being invisible.
 *
 * Returns the diff as text. On failure (no git, not a repo, timeout) returns
 * an ERROR string. */

#define ALPHA_DIFF_TIMEOUT 15
#define ALPHA_DIFF_MAX_UNTRACKED 50

/* Run git with args, capture stdout. Returns 0 on success, -1 on failure.
 * Never raises — all errors are caught. */
static int git_run(const char *cwd, char **argv, int argc, sds *out) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (cwd && cwd[0]) chdir(cwd);
        /* Build argv array with NULL terminator */
        const char **args = malloc((size_t)(argc + 1) * sizeof(char *));
        if (!args) _exit(1);
        for (int i = 0; i < argc; i++) args[i] = argv[i];
        args[argc] = NULL;
        execvp("git", (char *const *)args);
        _exit(127);
    }
    close(pipefd[1]);

    /* Read with timeout */
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
    *out = sdsempty();
    char buf[8192];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int status = 0;
    for (;;) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) *out = sdscatlen(*out, buf, (size_t)n);
        if (waitpid(pid, &status, WNOHANG) == pid) {
            /* Drain remaining */
            while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
                *out = sdscatlen(*out, buf, (size_t)n);
            break;
        }
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (double)(t1.tv_sec - t0.tv_sec) +
                    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (el > (double)ALPHA_DIFF_TIMEOUT) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            sdsfree(*out);
            *out = NULL;
            close(pipefd[0]);
            return -1;
        }
        usleep(50000);
    }
    close(pipefd[0]);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static sds working_diff(const char *cwd, const char *mode) {
    if (!mode || !mode[0]) mode = "working";
    if (strcmp(mode, "working") != 0 && strcmp(mode, "staged") != 0 &&
        strcmp(mode, "all") != 0)
        return sdscatprintf(sdsempty(),
            "ERROR: unknown mode '%s'. Use: working, staged, all", mode);

    /* Check git is available and we're in a repo */
    {
        char *argv[] = { "git", "-c", "core.quotePath=false", "rev-parse",
                         "--is-inside-work-tree" };
        sds test_out = NULL;
        int rc = git_run(cwd, argv, 5, &test_out);
        if (test_out) sdsfree(test_out);
        if (rc != 0)
            return sdsnew("ERROR: not a git repository (or git not found)");
    }

    /* Build diff args */
    char *diff_args[8];
    int diff_argc = 0;
    diff_args[diff_argc++] = "git";
    diff_args[diff_argc++] = "-c";
    diff_args[diff_argc++] = "core.quotePath=false";
    if (strcmp(mode, "staged") == 0) {
        diff_args[diff_argc++] = "diff";
        diff_args[diff_argc++] = "--cached";
    } else if (strcmp(mode, "all") == 0) {
        diff_args[diff_argc++] = "diff";
        diff_args[diff_argc++] = "HEAD";
    } else {
        diff_args[diff_argc++] = "diff";
    }

    /* Get stat */
    sds stat_out = NULL;
    diff_args[diff_argc++] = "--stat";
    int rc = git_run(cwd, diff_args, diff_argc, &stat_out);
    diff_argc--; /* remove --stat */
    if (rc != 0 && rc != 1) { /* diff exits 1 when there are changes */
        if (stat_out) sdsfree(stat_out);
        return sdsnew("ERROR: git diff --stat failed");
    }

    /* Get full diff */
    sds diff_out = NULL;
    rc = git_run(cwd, diff_args, diff_argc, &diff_out);
    if (rc != 0 && rc != 1) {
        if (stat_out) sdsfree(stat_out);
        if (diff_out) sdsfree(diff_out);
        return sdsnew("ERROR: git diff failed");
    }

    /* Get untracked files (only for working and all modes) */
    sds untracked_diff = NULL;
    if (strcmp(mode, "working") == 0 || strcmp(mode, "all") == 0) {
        char *ls_args[] = { "git", "-c", "core.quotePath=false",
                            "ls-files", "--others", "--exclude-standard" };
        sds untracked_list = NULL;
        rc = git_run(cwd, ls_args, 5, &untracked_list);
        if (rc == 0 && untracked_list && untracked_list[0]) {
            /* Parse untracked file list and diff each one */
            untracked_diff = sdsempty();
            int count = 0;
            char *save = NULL;
            char *line = strtok_r(untracked_list, "\n", &save);
            while (line && count < ALPHA_DIFF_MAX_UNTRACKED) {
                /* Trim whitespace */
                while (*line == ' ' || *line == '\t') line++;
                if (line[0]) {
                    char *noindex_args[] = {
                        "git", "-c", "core.quotePath=false",
                        "diff", "--no-index", "--", "/dev/null", line
                    };
                    sds file_diff = NULL;
                    /* --no-index exits 1 when files differ — that's success */
                    git_run(cwd, noindex_args, 8, &file_diff);
                    if (file_diff && file_diff[0]) {
                        untracked_diff = sdscat(untracked_diff, file_diff);
                        if (!strchr(file_diff, '\n') ||
                            file_diff[sdslen(file_diff) - 1] != '\n')
                            untracked_diff = sdscat(untracked_diff, "\n");
                    }
                    if (file_diff) sdsfree(file_diff);
                    count++;
                }
                line = strtok_r(NULL, "\n", &save);
            }
            /* Count remaining untracked files */
            int remaining = 0;
            while (line) {
                while (*line == ' ' || *line == '\t') line++;
                if (line[0]) remaining++;
                line = strtok_r(NULL, "\n", &save);
            }
            if (remaining > 0)
                untracked_diff = sdscatprintf(untracked_diff,
                    "... (%d more untracked files not shown)\n", remaining);
        }
        if (untracked_list) sdsfree(untracked_list);
    }

    /* Build result */
    sds result = sdsempty();
    if (stat_out && stat_out[0]) {
        result = sdscat(result, stat_out);
        result = sdscat(result, "\n\n");
    }
    if (diff_out && diff_out[0]) {
        result = sdscat(result, diff_out);
    }
    if (untracked_diff && untracked_diff[0]) {
        if (sdslen(result) > 0 && result[sdslen(result) - 1] != '\n')
            result = sdscat(result, "\n");
        result = sdscat(result, untracked_diff);
    }

    if (stat_out) sdsfree(stat_out);
    if (diff_out) sdsfree(diff_out);
    if (untracked_diff) sdsfree(untracked_diff);

    if (sdslen(result) == 0)
        result = sdscat(result, "(no changes)\n");

    return result;
}

/* Build a resolved path from a tool argument and the current working directory.
 *
 * Every tool that accepts a path must go through this function so that tilde
 * expansion and relative-path resolution are applied the same way everywhere.
 * Before this helper existed only list_dir expanded ~; read_file, write_file
 * and edit_file treated "~/notes.txt" as a literal directory named "~". */
static void resolve_path(char out[PATH_MAX], const char *path, const char *cwd) {
    if (!path || !path[0]) {
        if (cwd && cwd[0]) snprintf(out, PATH_MAX, "%s", cwd);
        else snprintf(out, PATH_MAX, ".");
        return;
    }
    if (path[0] == '/' || !cwd || !cwd[0])
        snprintf(out, PATH_MAX, "%s", path);
    else
        snprintf(out, PATH_MAX, "%s/%s", cwd, path);
    /* Expand leading ~ to the home directory (only ~ and ~/ are handled;
     * ~user is rare in practice and would need getpwnam). */
    if (out[0] == '~') {
        const char *home = getenv("HOME");
        if (home && home[0] && (out[1] == '/' || out[1] == 0)) {
            char exp[PATH_MAX];
            snprintf(exp, sizeof(exp), "%s%s", home, out + 1);
            snprintf(out, PATH_MAX, "%s", exp);
        }
    }
}

/* ======================================================================
 * diff/patch engine — line-based unified diff (Myers-style LCS)
 *
 * A self-contained diff engine producing and consuming the unified diff
 * format (the same shape `git diff` and `patch(1)` use). It exists so the
 * agent can compute and apply patches without shelling out, and so edits can
 * be expressed as small context-bearing hunks rather than whole-file rewrites.
 *
 * The line diff is a longest-common-subsequence DP over the two line
 * sequences; the resulting edit script is grouped into hunks with configurable
 * context and rendered in unified form. unified_apply() parses that format
 * back and verifies every context line before committing, so a patch that
 * does not match its target fails loudly instead of corrupting the file.
 * ======================================================================
 */

#ifndef ALPHA_DIFF_MAX_LINES
#define ALPHA_DIFF_MAX_LINES 20000   /* cap the O(N*M) DP against OOM */
#endif

#define ALPHA_DIFF_DEFAULT_CONTEXT 3

/* A single line of a rendered hunk. */
typedef enum { DL_CONTEXT = 0, DL_DELETE = 1, DL_INSERT = 2 } diffline_kind_t;

typedef struct {
    diffline_kind_t kind;
    int a_line;   /* 0-based index in the "from" file, or -1 */
    int b_line;   /* 0-based index in the "to" file, or -1 */
    const char *text;
} diffline_t;

/* Split text into lines (each without its trailing newline). had_trailing_nl
 * is set when text ends in '\n' so the caller can reproduce the exact byte
 * layout on output. An empty string yields zero lines. Returns a malloc'd
 * array of NULL-terminated strings (free with line_free). */
static char **line_split(const char *text, size_t *out_n, int *had_trailing_nl) {
    if (out_n) *out_n = 0;
    if (had_trailing_nl) *had_trailing_nl = 0;
    if (!text || !text[0]) return NULL;

    size_t nlines = 1;
    for (const char *p = text; *p; p++)
        if (*p == '\n') nlines++;
    if (text[strlen(text) - 1] == '\n') {
        if (had_trailing_nl) *had_trailing_nl = 1;
        nlines--;   /* a trailing newline does not begin a new line */
    }
    if (nlines == 0) return NULL;

    char **lines = malloc(sizeof(char *) * nlines);
    if (!lines) return NULL;
    size_t idx = 0;
    const char *start = text;
    for (const char *p = text; ; p++) {
        if (*p == '\n' || *p == 0) {
            size_t len = (size_t)(p - start);
            lines[idx] = malloc(len + 1);
            if (!lines[idx]) {
                for (size_t k = 0; k < idx; k++) free(lines[k]);
                free(lines);
                return NULL;
            }
            memcpy(lines[idx], start, len);
            lines[idx][len] = 0;
            if (++idx >= nlines) break;
            if (*p == 0) break;
            start = p + 1;
        }
    }
    if (out_n) *out_n = idx;
    return lines;
}

static void line_free(char **lines, size_t n) {
    if (!lines) return;
    for (size_t i = 0; i < n; i++) free(lines[i]);
    free(lines);
}

/* Edit operations produced by the LCS backtrack. */
typedef enum { OP_KEEP = 0, OP_DEL = 1, OP_INS = 2 } opkind_t;
typedef struct { opkind_t op; int idx; } edit_t;

/* Compute the edit script turning a[0..n_a) into b[0..n_b) via LCS. Returns a
 * malloc'd array of ne edits (caller frees) or NULL on allocation failure /
 * input too large. */
static edit_t *line_diff(const char **a, size_t n_a,
                         const char **b, size_t n_b, size_t *out_n) {
    if (out_n) *out_n = 0;
    if (n_a > ALPHA_DIFF_MAX_LINES || n_b > ALPHA_DIFF_MAX_LINES) return NULL;

    size_t cols = n_b + 1;
    size_t rows = n_a + 1;
    /* dp[i][j] = LCS length of a[i..n_a) and b[j..n_b). Flat row-major. */
    int *dp = malloc(sizeof(int) * rows * cols);
    if (!dp) return NULL;
    memset(dp, 0, sizeof(int) * rows * cols);

    for (size_t i = n_a; i-- > 0;) {
        for (size_t j = n_b; j-- > 0;) {
            if (strcmp(a[i], b[j]) == 0)
                dp[i * cols + j] = dp[(i + 1) * cols + (j + 1)] + 1;
            else {
                int down  = dp[(i + 1) * cols + j];
                int right = dp[i * cols + (j + 1)];
                dp[i * cols + j] = (down >= right) ? down : right;
            }
        }
    }

    edit_t *edits = malloc(sizeof(edit_t) * (n_a + n_b + 1));
    if (!edits) { free(dp); return NULL; }
    size_t ne = 0;
    size_t i = n_a, j = n_b;
    while (i > 0 && j > 0) {
        if (strcmp(a[i - 1], b[j - 1]) == 0) {
            edits[ne] = (edit_t){ OP_KEEP, (int)(i - 1) }; ne++;
            i--; j--;
        } else if (dp[(i - 1) * cols + j] >= dp[i * cols + (j - 1)]) {
            edits[ne] = (edit_t){ OP_DEL, (int)(i - 1) }; ne++;
            i--;
        } else {
            edits[ne] = (edit_t){ OP_INS, (int)(j - 1) }; ne++;
            j--;
        }
    }
    while (i > 0) { edits[ne] = (edit_t){ OP_DEL, (int)(i - 1) }; ne++; i--; }
    while (j > 0) { edits[ne] = (edit_t){ OP_INS, (int)(j - 1) }; ne++; j--; }

    /* Backtrack produced the script in reverse; flip it forward in place. */
    for (size_t x = 0, y = ne; x < y; x++, y--) {
        edit_t t = edits[x]; edits[x] = edits[y]; edits[y] = t;
    }
    free(dp);
    if (out_n) *out_n = ne;
    return edits;
}

/* Flatten the edit script into a sequence of rendered diff lines. */
static diffline_t *build_difflines(const char **a, size_t n_a,
                                   const char **b, size_t n_b,
                                   edit_t *edits, size_t ne, size_t *out_n) {
    (void)n_a;
    (void)n_b;
    diffline_t *dl = malloc(sizeof(diffline_t) * (ne + 1));
    if (!dl) { *out_n = 0; return NULL; }
    size_t idx = 0;
    for (size_t e = 0; e < ne; e++) {
        if (edits[e].op == OP_KEEP)
            dl[idx] = (diffline_t){ DL_CONTEXT, (int)edits[e].idx, (int)edits[e].idx, a[edits[e].idx] };
        else if (edits[e].op == OP_DEL)
            dl[idx] = (diffline_t){ DL_DELETE, (int)edits[e].idx, -1, a[edits[e].idx] };
        else
            dl[idx] = (diffline_t){ DL_INSERT, -1, (int)edits[e].idx, b[edits[e].idx] };
        idx++;
    }
    *out_n = idx;
    return dl;
}

/* Emit one hunk covering difflines[start..end) in unified format. */
static void emit_hunk(sds *out, diffline_t *dl, size_t start, size_t end) {
    int a_count = 0, b_count = 0;
    for (size_t i = start; i < end; i++) {
        if (dl[i].kind == DL_CONTEXT || dl[i].kind == DL_DELETE) a_count++;
        if (dl[i].kind == DL_CONTEXT || dl[i].kind == DL_INSERT) b_count++;
    }
    int a_start = (a_count == 0) ? 0 : dl[start].a_line + 1;
    int b_start = (b_count == 0) ? 0 : dl[start].b_line + 1;
    *out = sdscatprintf(*out, "@@ -%d,%d +%d,%d @@\n", a_start, a_count, b_start, b_count);
    for (size_t i = start; i < end; i++) {
        char p = ' ';
        if (dl[i].kind == DL_DELETE) p = '-';
        else if (dl[i].kind == DL_INSERT) p = '+';
        *out = sdscatprintf(*out, "%c%s\n", p, dl[i].text ? dl[i].text : "");
    }
}

/* Group difflines into hunks separated by >= 2*context context lines, expand
 * each by `context` lines on either side, and emit them. */
static void emit_hunks(sds *out, diffline_t *dl, size_t nd, int context) {
    size_t i = 0;
    while (i < nd) {
        while (i < nd && dl[i].kind == DL_CONTEXT) i++;
        if (i >= nd) break;
        size_t run_start = i, run_end = i;
        while (run_end < nd && dl[run_end].kind != DL_CONTEXT) run_end++;
        /* Merge later runs that sit within 2*context of this one. */
        size_t hunk_end = run_end;
        for (;;) {
            size_t ctx = hunk_end;
            while (ctx < nd && dl[ctx].kind == DL_CONTEXT) ctx++;
            size_t gap = ctx - hunk_end;
            if (ctx < nd && gap <= (size_t)(2 * context)) {
                hunk_end = ctx;
                while (hunk_end < nd && dl[hunk_end].kind != DL_CONTEXT) hunk_end++;
            } else break;
        }
        size_t hs = (run_start > (size_t)context) ? run_start - (size_t)context : 0;
        size_t he = (hunk_end + (size_t)context < nd) ? hunk_end + (size_t)context : nd;
        emit_hunk(out, dl, hs, he);
        i = he;
    }
}

/* Build a unified diff between old_text and new_text. path_a/path_b label the
 * two sides (any strings; callers pass "a/file", "b/file", etc.). context is
 * the number of surrounding lines kept in each hunk (clamped to >= 0). */
static sds unified_diff(const char *path_a, const char *path_b,
                        const char *old_text, const char *new_text, int context) {
    if (context < 0) context = 0;
    size_t n_a = 0, n_b = 0, ne = 0, nd = 0;
    int had_a = 0, had_b = 0;
    char **a = line_split(old_text, &n_a, &had_a);
    char **b = line_split(new_text, &n_b, &had_b);
    edit_t *edits = line_diff((const char **)a, n_a, (const char **)b, n_b, &ne);
    diffline_t *dl = edits ? build_difflines((const char **)a, n_a, (const char **)b, n_b, edits, ne, &nd) : NULL;

    sds out = sdsempty();
    out = sdscatprintf(out, "--- %s\n", path_a ? path_a : "a/file");
    out = sdscatprintf(out, "+++ %s\n", path_b ? path_b : "b/file");
    if (dl) emit_hunks(&out, dl, nd, context);

    free(edits);
    free(dl);
    line_free(a, n_a);
    line_free(b, n_b);
    return out;
}

/* ----------------------------------------------------------------------
 * unified_apply — apply a unified diff to `content`.
 *
 * Parses hunks in order. Each hunk declares the line range it replaces in the
 * original (-l,s) and the result (+l,s); the context lines are checked against
 * the actual content before the change is written, so a patch aimed at the
 * wrong location is rejected rather than silently misapplied. Returns the
 * patched text as an sds, or NULL if the patch is malformed or does not match.
 * ======================================================================
 */

typedef struct {
    int a_l, a_s;   /* -l,s header */
    int b_l, b_s;   /* +l,s header */
    diffline_kind_t *ops;   /* per-line kind: CONTEXT / DELETE / INSERT */
    char **texts;           /* the line text for each op (dup'd) */
    size_t nops;
    size_t cap;
} patch_hunk_t;

static int parse_hunk_header(const char *hdr, int *a_l, int *a_s, int *b_l, int *b_s) {
    /* hdr points at "@@ ...". Two ranges: -l[,s] and +l[,s]. */
    const char *p = hdr;
    while (*p && *p != '-') p++;
    if (!*p) return 0;
    p++;
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p) return 0;
    int l = (int)v; p = end;
    int s = 1;
    if (*p == ',') { p++; v = strtol(p, &end, 10); if (end == p) return 0; s = (int)v; p = end; }
    while (*p == ' ') p++;
    if (*p != '+') return 0;
    p++;
    v = strtol(p, &end, 10); if (end == p) return 0; int bl = (int)v; p = end;
    s = 1;
    if (*p == ',') { p++; v = strtol(p, &end, 10); if (end == p) return 0; s = (int)v; p = end; }
    *a_l = l; *a_s = s; *b_l = bl; *b_s = s;
    return 1;
}

static sds unified_apply(const char *content, const char *patch) {
    if (!content) content = "";
    if (!patch) return NULL;

    size_t n_content = 0;
    int had_nl = 0;
    char **clines = line_split(content, &n_content, &had_nl);

    /* Parse the patch line by line into hunks. */
    size_t pn = 0;
    char **plines = line_split(patch, &pn, NULL);
    patch_hunk_t *hunks = NULL;
    size_t nhunks = 0, hcap = 0;
    patch_hunk_t *cur = NULL;

    for (size_t li = 0; li < pn; li++) {
        const char *pl = plines[li];
        if (strncmp(pl, "@@", 2) == 0) {
            int a_l, a_s, b_l, b_s;
            if (!parse_hunk_header(pl, &a_l, &a_s, &b_l, &b_s)) {
                free(hunks); free(plines); line_free(clines, n_content);
                return NULL;
            }
            if (nhunks == hcap) {
                size_t nc = hcap ? hcap * 2 : 8;
                patch_hunk_t *nb = realloc(hunks, nc * sizeof(patch_hunk_t));
                if (!nb) { free(hunks); free(plines); line_free(clines, n_content); return NULL; }
                hcap = nc; hunks = nb;
            }
            cur = &hunks[nhunks++];
            cur->a_l = a_l; cur->a_s = a_s; cur->b_l = b_l; cur->b_s = b_s;
            cur->ops = NULL; cur->texts = NULL; cur->nops = 0; cur->cap = 0;
        } else if (cur && (pl[0] == ' ' || pl[0] == '-' || pl[0] == '+')) {
            if (cur->nops == cur->cap) {
                size_t nc = cur->cap ? cur->cap * 2 : 8;
                diffline_kind_t *no = realloc(cur->ops, nc * sizeof(diffline_kind_t));
                if (!no) { free(hunks); free(plines); line_free(clines, n_content); return NULL; }
                cur->ops = no; cur->cap = nc;
                char **nt = realloc(cur->texts, nc * sizeof(char *));
                if (!nt) { free(hunks); free(plines); line_free(clines, n_content); return NULL; }
                cur->texts = nt;
            }
            if (pl[0] == ' ') cur->ops[cur->nops] = DL_CONTEXT;
            else if (pl[0] == '-') cur->ops[cur->nops] = DL_DELETE;
            else cur->ops[cur->nops] = DL_INSERT;
            cur->texts[cur->nops] = strdup(pl + 1);
            cur->nops++;
        }
        /* "---", "+++", "\\" and blank lines are ignored here. */
    }

    /* Apply hunks sequentially against the content line array. */
    char **out = NULL;
    size_t out_n = 0, out_cap = 0;
    size_t pos = 1;   /* 1-based cursor into content */
    int failed = 0;

    for (size_t h = 0; h < nhunks && !failed; h++) {
        patch_hunk_t *hk = &hunks[h];
        /* The hunk's first original line is 1-based a_l when a_s>0, else the
         * insertion sits before line a_l+1. */
        size_t expect = (hk->a_s > 0) ? (size_t)hk->a_l : (size_t)hk->a_l + 1;
        if (pos != expect) { failed = 1; break; }
        for (size_t o = 0; o < hk->nops; o++) {
            if (hk->ops[o] == DL_CONTEXT) {
                if (pos > n_content || strcmp(clines[pos - 1], hk->texts[o]) != 0) {
                    failed = 1; break;
                }
                if (out_n == out_cap) {
                    size_t nc = out_cap ? out_cap * 2 : 64;
                    char **nb = realloc(out, nc * sizeof(char *));
                    if (!nb) { failed = 2; break; }
                    out_cap = nc; out = nb;
                }
                out[out_n++] = strdup(clines[pos - 1]);
                pos++;
            } else if (hk->ops[o] == DL_DELETE) {
                if (pos > n_content) { failed = 1; break; }
                pos++;   /* line dropped */
            } else { /* INSERT */
                if (out_n == out_cap) {
                    size_t nc = out_cap ? out_cap * 2 : 64;
                    char **nb = realloc(out, nc * sizeof(char *));
                    if (!nb) { failed = 2; break; }
                    out_cap = nc; out = nb;
                }
                out[out_n++] = strdup(hk->texts[o]);
            }
        }
    }

    if (!failed) {
        for (; pos <= n_content; pos++) {
            if (out_n == out_cap) {
                size_t nc = out_cap ? out_cap * 2 : 64;
                char **nb = realloc(out, nc * sizeof(char *));
                if (!nb) { failed = 2; break; }
                out_cap = nc; out = nb;
            }
            out[out_n++] = strdup(clines[pos - 1]);
        }
    }

    sds result;
    if (failed) {
        result = NULL;
    } else {
        result = sdsempty();
        for (size_t i = 0; i < out_n; i++) {
            if (i > 0) sdscat(result, "\n");
            sdscat(result, out[i]);
        }
        if (had_nl && out_n > 0) sdscat(result, "\n");
    }

    /* Free everything allocated above. */
    for (size_t i = 0; i < out_n; i++) free(out[i]);
    free(out);
    for (size_t i = 0; i < nhunks; i++) {
        for (size_t o = 0; o < hunks[i].nops; o++) free(hunks[i].texts[o]);
        free(hunks[i].ops);
        free(hunks[i].texts);
    }
    free(hunks);
    free(plines);
    line_free(clines, n_content);
    return result;
}

/* ======================================================================
 * grep: shell-free recursive regex search
 *
 * A self-contained recursive regex search over files and directories, using
 * POSIX regex(3) so it is fast, free of shell-injection risk, and returns
 * structured "path:line:text" results. The agent already has execute_bash to
 * call grep(1), but shelling out for every search is slow and cannot be
 * reasoned about when the pattern or path contains shell metacharacters.
 *
 * Supported args (JSON object):
 *   pattern      (required) POSIX extended regex to search for
 *   path         (optional) file or directory to search; default "."
 *   recursive    (optional) recurse into directories when path is one
 *   max_results  (optional) cap reported matches (default 1000)
 *   file_pattern (optional) only search files whose name matches this glob,
 *                            e.g. "*.c" or "test_*"
 *
 * Returns a text report: one "path:line_no:line" per match, or an ERROR.
 * ======================================================================
 */

#define ALPHA_GREP_DEFAULT_MAX 1000
#define ALPHA_GREP_MAX_LINE    (1u << 20)   /* 1 MiB cap on a single line */
#define ALPHA_GREP_BINARY_SNAP 8192         /* bytes sniffed to detect binary */
#define ALPHA_GREP_MAX_DEPTH   40

/* True if the first `snap` bytes of the file contain a NUL. A NUL means the
 * text cannot survive the cJSON round trip, so the file is treated as binary
 * and skipped rather than reported as a (truncated) match. */
static int file_has_nul(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char buf[ALPHA_GREP_BINARY_SNAP];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    return memchr(buf, 0, n) != NULL;
}

/* A file is binary if it has a known-binary extension or a NUL in its head. */
static int file_is_binary(const char *path) {
    if (has_binary_extension(path)) return 1;
    return file_has_nul(path);
}

/* Search one file for lines matching `re`. Each match is appended to *out as
 * "path:line_no:line\n". Returns 0 on success, -1 if the file could not be
 * opened. `count` is incremented per match and capped by `max_results`. */
static int grep_file(const char *path, regex_t *re, sds *out, long *count,
                     long max_results) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    long lineno = 0;

    while ((linelen = getline(&line, &linecap, f)) != -1) {
        if (*count >= max_results) break;
        lineno++;
        /* Strip a single trailing newline for clean output. */
        if (linelen > 0 && line[linelen - 1] == '\n') line[linelen - 1] = 0;
        /* A line longer than the cap is skipped rather than matched: it is
         * almost always binary noise and would waste memory in a growable
         * getline buffer. lineno still advances so line numbers stay correct. */
        if ((size_t)linelen <= ALPHA_GREP_MAX_LINE &&
            regexec(re, line, 0, NULL, 0) == 0) {
            *out = sdscatprintf(*out, "%s:%ld:%s\n", path, lineno, line);
            (*count)++;
        }
    }

    free(line);
    fclose(f);
    return 0;
}

/* Recursively search a directory. `depth` guards against pathological trees. */
static void grep_walk(const char *dir, regex_t *re, sds *out, long *count,
                      long max_results, const char *file_pattern, int depth) {
    if (depth > ALPHA_GREP_MAX_DEPTH) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);

        struct stat st;
        if (stat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            grep_walk(full, re, out, count, max_results, file_pattern, depth + 1);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;

        /* Optional name filter (glob against the basename). */
        if (file_pattern && file_pattern[0] &&
            fnmatch(file_pattern, de->d_name, 0) != 0)
            continue;

        if (file_is_binary(full)) continue;
        grep_file(full, re, out, count, max_results);
    }
    closedir(d);
}

/* ----------------------------------------------------------------------
 * code_search helpers (ported from codegraph).
 * ---------------------------------------------------------------------- */

/* Case-insensitive substring test. Empty needle matches everything. */
static int cg_ci_contains(const char *hay, const char *needle) {
    if (!needle || !needle[0]) return 1;
    if (!hay) return 0;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t k = 0;
        while (k < nl &&
               tolower((unsigned char)p[k]) == tolower((unsigned char)needle[k])) k++;
        if (k == nl) return 1;
    }
    return 0;
}

/* Structured code-search query. Defined here — before cg_lang_filter_ok and
 * the rest of the code_search helpers that dereference it — so the field
 * access below compiles. The parser that fills it in (cg_parse_query) lives
 * further down the file and is forward-declared near code_search_tool. */
typedef struct {
    char *text;
    char *kinds[32];      int n_kinds;
    char *languages[32];  int n_langs;
    char *pathFilters[32]; int n_paths;
    char *nameFilters[32]; int n_names;
} cg_query_t;

/* Map a file path to a codegraph language by extension, or NULL. */
static const char *cg_file_language(const char *path) {
    if (!path) return NULL;
    const char *dot = strrchr(path, '.');
    if (!dot || !dot[1]) return NULL;
    const char *ext = dot + 1;
    char buf[64];
    size_t k = 0;
    while (ext[k] && ext[k] != '/' && ext[k] != '\\' && k < sizeof(buf) - 1) {
        buf[k] = (char)tolower((unsigned char)ext[k]);
        k++;
    }
    buf[k] = 0;
    if (!buf[0]) return NULL;
    if (strcmp(buf, "c") == 0 || strcmp(buf, "h") == 0) return "c";
    if (strcmp(buf, "cpp") == 0 || strcmp(buf, "cc") == 0 || strcmp(buf, "cxx") == 0 ||
        strcmp(buf, "c++") == 0 || strcmp(buf, "hpp") == 0 || strcmp(buf, "hh") == 0)
        return "cpp";
    if (strcmp(buf, "rs") == 0) return "rust";
    if (strcmp(buf, "py") == 0) return "python";
    if (strcmp(buf, "go") == 0) return "go";
    if (strcmp(buf, "java") == 0) return "java";
    if (strcmp(buf, "cs") == 0) return "csharp";
    if (strcmp(buf, "ts") == 0 || strcmp(buf, "mts") == 0 || strcmp(buf, "cts") == 0)
        return "typescript";
    if (strcmp(buf, "js") == 0 || strcmp(buf, "mjs") == 0 || strcmp(buf, "cjs") == 0)
        return "javascript";
    if (strcmp(buf, "tsx") == 0) return "tsx";
    if (strcmp(buf, "jsx") == 0) return "jsx";
    if (strcmp(buf, "rb") == 0) return "ruby";
    if (strcmp(buf, "swift") == 0) return "swift";
    if (strcmp(buf, "kt") == 0 || strcmp(buf, "kts") == 0) return "kotlin";
    if (strcmp(buf, "dart") == 0) return "dart";
    if (strcmp(buf, "php") == 0) return "php";
    if (strcmp(buf, "vue") == 0) return "vue";
    if (strcmp(buf, "svelte") == 0) return "svelte";
    if (strcmp(buf, "lua") == 0) return "lua";
    if (strcmp(buf, "r") == 0) return "r";
    if (strcmp(buf, "tf") == 0 || strcmp(buf, "terraform") == 0) return "terraform";
    if (strcmp(buf, "yaml") == 0 || strcmp(buf, "yml") == 0) return "yaml";
    if (strcmp(buf, "xml") == 0) return "xml";
    return NULL;
}

static int cg_lang_filter_ok(const char *path, cg_query_t *q) {
    if (q->n_langs == 0) return 1;
    const char *lang = cg_file_language(path);
    if (!lang) return 0;
    for (int i = 0; i < q->n_langs; i++)
        if (strcmp(lang, q->languages[i]) == 0) return 1;
    return 0;
}

static int cg_path_filter_ok(const char *relpath, cg_query_t *q) {
    if (q->n_paths == 0) return 1;
    for (int i = 0; i < q->n_paths; i++)
        if (cg_ci_contains(relpath, q->pathFilters[i])) return 1;
    return 0;
}

/* Heuristic kind detector: does a lowercased source line look like a symbol of
 * this kind? Keyword-based so it is fast and predictable. Unknown kinds fall
 * back to a substring match on the kind name itself. */
static int cg_line_matches_kind(const char *line, const char *kind) {
    if (strcmp(kind, "class") == 0) return strstr(line, "class") != NULL;
    if (strcmp(kind, "struct") == 0) return strstr(line, "struct") != NULL;
    if (strcmp(kind, "interface") == 0) return strstr(line, "interface") != NULL;
    if (strcmp(kind, "trait") == 0) return strstr(line, "trait") != NULL;
    if (strcmp(kind, "protocol") == 0) return strstr(line, "protocol") != NULL;
    if (strcmp(kind, "enum") == 0) return strstr(line, "enum") != NULL;
    if (strcmp(kind, "namespace") == 0) return strstr(line, "namespace") != NULL;
    if (strcmp(kind, "import") == 0) return strstr(line, "import") != NULL || strstr(line, "include") != NULL;
    if (strcmp(kind, "export") == 0) return strstr(line, "export") != NULL;
    if (strcmp(kind, "module") == 0) return strstr(line, "module") != NULL;
    if (strcmp(kind, "route") == 0) return strstr(line, "route") != NULL || strstr(line, "router") != NULL;
    if (strcmp(kind, "component") == 0) return strstr(line, "component") != NULL;
    if (strcmp(kind, "union") == 0) return strstr(line, "union") != NULL;
    if (strcmp(kind, "property") == 0) return strstr(line, "property") != NULL;
    if (strcmp(kind, "field") == 0) return strstr(line, "field") != NULL;
    if (strcmp(kind, "method") == 0) return strstr(line, "method") != NULL;
    if (strcmp(kind, "parameter") == 0) return strstr(line, "param") != NULL;
    if (strcmp(kind, "file") == 0) return strstr(line, "file") != NULL;
    if (strcmp(kind, "function") == 0)
        return strstr(line, "function ") || strstr(line, "def ") || strstr(line, "fn ") ||
               strstr(line, "func ") || strstr(line, "void ") || strstr(line, "int ") ||
               strstr(line, "static ") || strstr(line, "def(");
    if (strcmp(kind, "variable") == 0)
        return strstr(line, "var ") || strstr(line, "let ") || strstr(line, "const ") ||
               strstr(line, "int ") || strstr(line, "float ");
    if (strcmp(kind, "constant") == 0)
        return strstr(line, "const ") || strstr(line, "#define") != NULL ||
               strstr(line, "constexpr") != NULL;
    if (strcmp(kind, "type_alias") == 0)
        return strstr(line, "type ") || strstr(line, "typedef") != NULL;
    return strstr(line, kind) != NULL;
}

/* Does a line satisfy every line-level filter (kinds AND names AND text)? */
static int cg_line_matches(cg_query_t *q, regex_t *re, const char *line_lower, const char *line) {
    for (int i = 0; i < q->n_kinds; i++)
        if (!cg_line_matches_kind(line_lower, q->kinds[i])) return 0;
    for (int i = 0; i < q->n_names; i++)
        if (!cg_ci_contains(line_lower, q->nameFilters[i])) return 0;
    if (re && regexec(re, line, 0, NULL, 0) != 0) return 0;
    return 1;
}

/* ----------------------------------------------------------------------
 * code_search tool driver.
 *
 * A field-qualified search that layers structured filters on top of the same
 * recursive POSIX-regex walk grep already uses. Filters narrow the candidate
 * set (language + path at file scope; kind + name + free text at line scope),
 * so `kind:function name:auth path:src/api` finds function-definition lines
 * containing "auth" in files under src/api. Returns a text report.
 * ---------------------------------------------------------------------- */

/* Forward declarations — the query parser lives below tools_run(). */
static cg_query_t *cg_parse_query(const char *raw);
static void cg_free_query(cg_query_t *q);

static void cg_search_file(const char *path, cg_query_t *q, regex_t *re,
                           sds *out, long *count, long max_results) {
    if (!cg_lang_filter_ok(path, q)) return;
    if (!cg_path_filter_ok(path, q)) return;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char *line = NULL;
    size_t cap = 0;
    ssize_t linelen;
    long lineno = 0;
    while ((linelen = getline(&line, &cap, f)) != -1) {
        if (*count >= max_results) break;
        lineno++;
        if (linelen > 0 && line[linelen - 1] == '\n') line[linelen - 1] = 0;
        char lower[1024];
        size_t k = 0;
        for (ssize_t p = 0; line[p] && k < sizeof(lower) - 1; p++)
            lower[k++] = (char)tolower((unsigned char)line[p]);
        lower[k] = 0;
        if (cg_line_matches(q, re, lower, line)) {
            *out = sdscatprintf(*out, "%s:%ld:%s\n", path, lineno, line);
            (*count)++;
        }
    }
    free(line);
    fclose(f);
}

static void cg_walk(const char *dir, cg_query_t *q, regex_t *re,
                    sds *out, long *count, long max_results, int depth) {
    if (depth > 40) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { cg_walk(full, q, re, out, count, max_results, depth + 1); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        if (file_is_binary(full)) continue;
        cg_search_file(full, q, re, out, count, max_results);
    }
    closedir(d);
}

static sds cg_filters_summary(cg_query_t *q) {
    sds s = sdsempty();
    int first = 1;
    if (q->n_kinds) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "kinds=");
        for (int i = 0; i < q->n_kinds; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->kinds[i]); }
    }
    if (q->n_langs) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "lang=");
        for (int i = 0; i < q->n_langs; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->languages[i]); }
    }
    if (q->n_paths) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "path=");
        for (int i = 0; i < q->n_paths; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->pathFilters[i]); }
    }
    if (q->n_names) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "name=");
        for (int i = 0; i < q->n_names; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->nameFilters[i]); }
    }
    if (q->text && q->text[0]) {
        if (!first) s = sdscat(s, " ");
        s = sdscat(s, "text="); s = sdscat(s, q->text);
    }
    if (sdslen(s) == 0) s = sdscat(s, "(none)");
    return s;
}

sds code_search_tool(cJSON *args, const char *cwd) {
    const char *query = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
    if (!query || !query[0]) return sdsnew("ERROR: query required for code_search");

    cg_query_t *q = cg_parse_query(query);
    if (!q) return sdsnew("ERROR: out of memory parsing query");
    if (q->n_kinds == 0 && q->n_langs == 0 && q->n_paths == 0 && q->n_names == 0 &&
        (!q->text || !q->text[0])) {
        cg_free_query(q);
        return sdsnew("ERROR: query produced no filters or text to search");
    }

    regex_t re;
    int have_re = 0;
    if (q->text && q->text[0]) {
        int rc = regcomp(&re, q->text, REG_EXTENDED | REG_NOSUB | REG_ICASE);
        if (rc != 0) {
            char msg[256];
            regerror(rc, &re, msg, sizeof(msg));
            cg_free_query(q);
            return sdscatprintf(sdsempty(), "ERROR: invalid search text '%s': %s", q->text, msg);
        }
        have_re = 1;
    }

    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    if (!path || !path[0]) path = ".";
    long max_results = ALPHA_GREP_DEFAULT_MAX;
    cJSON *mr = cJSON_GetObjectItem(args, "max_results");
    if (cJSON_IsNumber(mr)) { max_results = (long)mr->valueint; if (max_results <= 0) max_results = ALPHA_GREP_DEFAULT_MAX; }
    int recursive = 1;
    cJSON *rec = cJSON_GetObjectItem(args, "recursive");
    if (cJSON_IsBool(rec)) recursive = cJSON_IsTrue(rec);

    char resolved[PATH_MAX];
    resolve_path(resolved, path, cwd);

    sds out = sdscatprintf(sdsempty(), "CODE SEARCH\nQuery: %s\n", query);
    sds filters = cg_filters_summary(q);
    out = sdscat(out, "Filters: ");
    out = sdscat(out, filters);
    sdsfree(filters);
    out = sdscat(out, "\n\n");

    long count = 0;
    struct stat st;
    if (stat(resolved, &st) == 0 && S_ISREG(st.st_mode)) {
        if (!file_is_binary(resolved))
            cg_search_file(resolved, q, have_re ? &re : NULL, &out, &count, max_results);
    } else if (recursive) {
        cg_walk(resolved, q, have_re ? &re : NULL, &out, &count, max_results, 0);
    } else {
        DIR *d = opendir(resolved);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", resolved, de->d_name);
                struct stat fst;
                if (stat(full, &fst) == 0 && S_ISREG(fst.st_mode) && !file_is_binary(full))
                    cg_search_file(full, q, have_re ? &re : NULL, &out, &count, max_results);
            }
            closedir(d);
        }
    }

    if (have_re) regfree(&re);
    cg_free_query(q);

    if (count == 0) {
        sdsfree(out);
        return sdscatprintf(sdsempty(), "No matches for query in %s\n", resolved);
    }
    out = sdscatprintf(out, "\n(%ld result%s)\n", count, count == 1 ? "" : "s");
    return out;
}

sds grep_tool_run(cJSON *args, const char *cwd) {
    const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
    if (!pattern || !pattern[0])
        return sdsnew("ERROR: pattern is required");

    regex_t re;
    int rc = regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        char msg[256];
        regerror(rc, &re, msg, sizeof(msg));
        return sdscatprintf(sdsempty(), "ERROR: invalid regex '%s': %s", pattern, msg);
    }

    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    if (!path || !path[0]) path = ".";

    long max_results = ALPHA_GREP_DEFAULT_MAX;
    cJSON *mr = cJSON_GetObjectItem(args, "max_results");
    if (cJSON_IsNumber(mr)) {
        max_results = (long)mr->valuedouble;
        if (max_results <= 0) max_results = ALPHA_GREP_DEFAULT_MAX;
    }

    int recursive = 1;
    cJSON *rec = cJSON_GetObjectItem(args, "recursive");
    if (cJSON_IsBool(rec)) recursive = cJSON_IsTrue(rec);
    (void)recursive;

    const char *file_pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "file_pattern"));

    char resolved[PATH_MAX];
    resolve_path(resolved, path, cwd);

    sds out = sdsempty();
    long count = 0;
    struct stat st;
    if (stat(resolved, &st) == 0 && S_ISREG(st.st_mode)) {
        /* A single file: search it directly, bypassing the name filter. */
        if (!file_is_binary(resolved))
            grep_file(resolved, &re, &out, &count, max_results);
    } else {
        grep_walk(resolved, &re, &out, &count, max_results, file_pattern, 0);
    }

    regfree(&re);

    if (count == 0) {
        sdsfree(out);
        return sdscatprintf(sdsempty(), "No matches for '%s' in %s\n", pattern, resolved);
    }

    if (count >= max_results) {
        out = sdscatprintf(out, "\n... truncated at %ld results (use max_results to see more)\n", count);
    }
    return out;
}

/* ======================================================================
 * code_search — field-qualified code search query parser (ported from
 * codegraph src/search/query-parser.ts).
 *
 * Turns a raw query like
 *
 *     kind:function name:auth path:src/api authenticate
 *
 * into structured filters (kind=function, name="auth", path prefix "src/api")
 * plus a free-text portion ("authenticate"). Pure string work, no I/O, so it
 * is trivially testable and safe to run in any context. Unknown field prefixes
 * (e.g. `TODO:`) pass through as text so a literal search still works; only
 * recognised fields are consumed as filters. Quoting keeps whitespace in a
 * value: `path:"src/some path"`.
 * ======================================================================
 */

static const char *const CG_KINDS[] = {
    "file","module","class","struct","interface","trait","protocol",
    "function","method","property","field","variable","constant","enum",
    "enum_member","type_alias","namespace","parameter","import","export",
    "route","component","union", NULL };

static const char *const CG_LANGUAGES[] = {
    "typescript","javascript","tsx","jsx","arkts","python","go","rust","java",
    "c","cpp","csharp","razor","php","ruby","swift","kotlin","dart","svelte",
    "vue","astro","liquid","pascal","scala","lua","luau","objc","r","solidity",
    "nix","yaml","twig","xml","properties","cfml","cfscript","cfquery","cobol",
    "vbnet","erlang","terraform","unknown", NULL };

static int cg_set_has(const char *const *set, const char *v) {
    for (int i = 0; set[i]; i++) if (strcmp(set[i], v) == 0) return 1;
    return 0;
}

static void cg_add_str(char **arr, int *n, const char *v) {
    if (*n >= 32) return;
    arr[(*n)++] = strdup(v);
}

/* Append `tok` to the free-text accumulator as a standalone word. */
static sds cg_add_text(sds text, const char *tok) {
    text = sdscatlen(text, " ", 1);
    text = sdscat(text, tok);
    text = sdscatlen(text, " ", 1);
    return text;
}

/* Split `raw` on whitespace, keeping quoted spans (whitespace and all) as one
 * token. Returns a malloc'd array of n tokens (free each + the array). */
static char **cg_tokenize(const char *raw, int *out_n) {
    *out_n = 0;
    if (!raw) return NULL;
    size_t len = strlen(raw);
    char **tokens = NULL;
    size_t cap = 0;
    size_t i = 0;
    while (i < len) {
        while (i < len && isspace((unsigned char)raw[i])) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && !isspace((unsigned char)raw[i])) {
            if (raw[i] == '"') {
                size_t end = i + 1;
                while (end < len && raw[end] != '"') end++;
                if (end >= len) { i = len; break; }   /* unterminated: swallow rest */
                i = end + 1;
                continue;
            }
            i++;
        }
        size_t tlen = i - start;
        char *t = malloc(tlen + 1);
        if (!t) break;
        memcpy(t, raw + start, tlen);
        t[tlen] = 0;
        if (cap == 0) {
            cap = 8;
            tokens = malloc(cap * sizeof(*tokens));
            if (!tokens) { free(t); break; }
        } else if (*out_n >= (int)cap) {
            size_t nc = cap * 2;
            char **nt = realloc(tokens, nc * sizeof(*nt));
            if (!nt) { free(t); free(tokens); *out_n = 0; return NULL; }
            tokens = nt; cap = nc;
        }
        tokens[(*out_n)++] = t;
    }
    return tokens;
}

static cg_query_t *cg_parse_query(const char *raw) {
    cg_query_t *q = calloc(1, sizeof(*q));
    if (!q) return NULL;
    int n = 0;
    char **tokens = cg_tokenize(raw, &n);
    if (!tokens) { free(q); return NULL; }
    sds text = sdsempty();
    for (int ti = 0; ti < n; ti++) {
        char *tok = tokens[ti];
        size_t tlen = strlen(tok);
        size_t colon = 0;
        while (colon < tlen && tok[colon] != ':') colon++;
        if (colon <= 0 || colon >= tlen - 1) { text = cg_add_text(text, tok); free(tok); continue; }
        char *key = malloc(colon + 1);
        if (!key) { free(tok); continue; }
        memcpy(key, tok, colon); key[colon] = 0;
        for (char *p = key; *p; p++) *p = (char)tolower((unsigned char)*p);
        const char *vraw = tok + colon + 1;
        size_t vlen = tlen - colon - 1;
        const char *vstart = vraw;
        size_t vend = vlen;
        if (vlen >= 2 && vraw[0] == '"' && vraw[vlen - 1] == '"') { vstart = vraw + 1; vend = vlen - 2; }
        char *val = malloc(vend + 1);
        if (!val) { free(key); free(tok); continue; }
        memcpy(val, vstart, vend); val[vend] = 0;
        if (val[0] == 0) { free(key); free(val); free(tok); text = cg_add_text(text, tok); continue; }
        if (strcmp(key, "kind") == 0) {
            if (cg_set_has(CG_KINDS, val)) cg_add_str(q->kinds, &q->n_kinds, val);
            else text = cg_add_text(text, tok);
        } else if (strcmp(key, "lang") == 0 || strcmp(key, "language") == 0) {
            if (cg_set_has(CG_LANGUAGES, val)) cg_add_str(q->languages, &q->n_langs, val);
            else text = cg_add_text(text, tok);
        } else if (strcmp(key, "path") == 0) {
            cg_add_str(q->pathFilters, &q->n_paths, val);
        } else if (strcmp(key, "name") == 0) {
            cg_add_str(q->nameFilters, &q->n_names, val);
        } else {
            text = cg_add_text(text, tok);
        }
        free(key); free(val); free(tok);
    }
    free(tokens);
    sdstrim(text, " ");
    q->text = sdslen(text) ? sdsdup(text) : sdsnew("");
    sdsfree(text);
    return q;
}

static void cg_free_query(cg_query_t *q) {
    if (!q) return;
    for (int i = 0; i < q->n_kinds; i++) free(q->kinds[i]);
    for (int i = 0; i < q->n_langs; i++) free(q->languages[i]);
    for (int i = 0; i < q->n_paths; i++) free(q->pathFilters[i]);
    for (int i = 0; i < q->n_names; i++) free(q->nameFilters[i]);
    sdsfree(q->text);
    free(q);
}

/* --- phone control via ADB --------------------------------------------------
 * On the phone itself (Termux): enable wireless debugging and
 * `adb connect localhost:<port>` (or use Shizuku); also drives any device in
 * `adb devices` (USB, emulator, LAN). Every action is one adb call through
 * shell_run, so timeouts and Ctrl-C teardown behave like any other command. */

/* Models frequently send numbers as strings — accept both. */
static int args_num(cJSON *args, const char *key, int def) {
    cJSON *v = cJSON_GetObjectItem(args, key);
    if (cJSON_IsNumber(v)) return v->valueint;
    const char *s = cJSON_GetStringValue(v);
    if (s && s[0]) return atoi(s);
    return def;
}

static sds adb_run(sds cmd, const char *cwd) {
    sds wrapped = sdscatprintf(sdsempty(),
        "command -v adb >/dev/null 2>&1 || { echo 'ERROR: adb not found. "
        "Termux: pkg install android-tools'; exit 127; }; %s", cmd);
    sdsfree(cmd);
    sds out = shell_run(wrapped, cwd);
    sdsfree(wrapped);
    return out;
}

static sds phone_tool_run(cJSON *args, const char *cwd) {
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0])
        return sdsnew("ERROR: action required (see/shot/tap/swipe/type/key/open/apps)");

    if (strcmp(action, "see") == 0) {
        sds out = adb_run(sdscatprintf(sdsempty(),
            "adb shell uiautomator dump /sdcard/alpha-ui.xml >/dev/null && "
            "adb shell cat /sdcard/alpha-ui.xml"), cwd);
        /* UI trees on busy screens run to hundreds of KB — more than any model
         * can usefully read. Keep the head, say it was cut. */
        if (sdslen(out) > 60000) {
            sds head = sdsnewlen(out, 60000);
            sdsfree(out);
            out = sdscat(head, "\n...[UI tree truncated at 60000 bytes]");
        }
        return out;
    }
    if (strcmp(action, "shot") == 0) {
        sds path = sdscatprintf(sdsempty(), "%s/alpha-screen.png", alpha_tmpdir());
        sds out = adb_run(sdscatprintf(sdsempty(),
            "adb exec-out screencap -p > %s", shell_quote(path)), cwd);
        struct stat st;
        if (stat(path, &st) == 0 && st.st_size > 0)
            out = sdscatprintf(out, "\nOK screenshot saved: %s (%lld bytes)",
                               path, (long long)st.st_size);
        sdsfree(path);
        return out;
    }
    if (strcmp(action, "tap") == 0) {
        int x = args_num(args, "x", -1), y = args_num(args, "y", -1);
        if (x < 0 || y < 0)
            return sdsnew("ERROR: tap needs numeric x and y (take them from the bounds in 'see')");
        return adb_run(sdscatprintf(sdsempty(), "adb shell input tap %d %d", x, y), cwd);
    }
    if (strcmp(action, "swipe") == 0) {
        int x1 = args_num(args, "x1", -1), y1 = args_num(args, "y1", -1);
        int x2 = args_num(args, "x2", -1), y2 = args_num(args, "y2", -1);
        int ms = args_num(args, "ms", 300);
        if (x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0)
            return sdsnew("ERROR: swipe needs x1 y1 x2 y2 (screen centre out to the edge scrolls)");
        return adb_run(sdscatprintf(sdsempty(),
            "adb shell input swipe %d %d %d %d %d", x1, y1, x2, y2, ms), cwd);
    }
    if (strcmp(action, "type") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!text) return sdsnew("ERROR: text required");
        /* `input text` has no space character — %s stands in for it, so a
         * literal % must be encoded first (%25). Newlines are sent as ENTER
         * key events between text segments. */
        sds cmd = sdsempty();
        int first = 1;
        for (const char *p = text;;) {
            const char *nl = strchr(p, '\n');
            size_t seglen = nl ? (size_t)(nl - p) : strlen(p);
            sds seg = sdsempty();
            for (size_t i = 0; i < seglen; i++) {
                if (p[i] == '%') seg = sdscat(seg, "%25");
                else if (p[i] == ' ') seg = sdscat(seg, "%s");
                else seg = sdscatlen(seg, p + i, 1);
            }
            if (seglen)
                cmd = sdscatprintf(cmd, "%sadb shell input text %s",
                                   first ? "" : " && ", shell_quote(seg));
            sdsfree(seg);
            first = 0;
            if (!nl) break;
            cmd = sdscat(cmd, " && adb shell input keyevent KEYCODE_ENTER");
            p = nl + 1;
        }
        if (!cmd[0]) return sdsnew("ERROR: text is empty");
        return adb_run(cmd, cwd);
    }
    if (strcmp(action, "key") == 0) {
        const char *k = cJSON_GetStringValue(cJSON_GetObjectItem(args, "key"));
        if (!k) k = cJSON_GetStringValue(cJSON_GetObjectItem(args, "name"));
        if (!k || !k[0])
            return sdsnew("ERROR: key required (back/home/enter/recents/tab/del/power, or a raw KEYCODE_* name)");
        if (strcmp(k, "recents") == 0) k = "APP_SWITCH";
        /* Accept a friendly name or a raw KEYCODE_* name; allow only
         * [A-Za-z0-9_] so the shell command stays inert on junk input. */
        char code[80];
        int n = 0;
        const char *prefix = strncmp(k, "KEYCODE_", 8) == 0 ? "" : "KEYCODE_";
        for (const char *p = prefix; *p && n < (int)sizeof(code) - 1; p++) code[n++] = *p;
        for (const char *p = k; *p && n < (int)sizeof(code) - 1; p++) {
            char c = *p;
            if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
                return sdscatprintf(sdsempty(), "ERROR: invalid key name '%s'", k);
            code[n++] = c;
        }
        code[n] = 0;
        return adb_run(sdscatprintf(sdsempty(), "adb shell input keyevent %s", code), cwd);
    }
    if (strcmp(action, "open") == 0) {
        const char *pkg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "package"));
        if (!pkg) pkg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!pkg || !pkg[0]) return sdsnew("ERROR: package required (see action 'apps')");
        for (const char *p = pkg; *p; p++)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '.' || *p == '_'))
                return sdscatprintf(sdsempty(), "ERROR: invalid package name '%s'", pkg);
        return adb_run(sdscatprintf(sdsempty(),
            "adb shell monkey -p %s -c android.intent.category.LAUNCHER 1", pkg), cwd);
    }
    if (strcmp(action, "apps") == 0) {
        return adb_run(sdsnew(
            "adb shell pm list packages -3 | sed 's/^package://' | sort"), cwd);
    }
    return sdscatprintf(sdsempty(), "ERROR: unknown phone action '%s'", action);
}

static int checksum_hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into a freshly malloc'd buffer. Returns 0 on success,
 * -1 on odd length, -2 on non-hex characters. */
static int checksum_hex_decode(const char *hex, uint8_t **out, size_t *outlen) {
    if (!hex || !out || !outlen) return -2;
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    uint8_t *buf = malloc(n / 2 + 1);
    if (!buf) return -2;
    for (size_t i = 0; i < n; i += 2) {
        int hi = checksum_hex_nibble((unsigned char)hex[i]);
        int lo = checksum_hex_nibble((unsigned char)hex[i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -2; }
        buf[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf;
    *outlen = n / 2;
    return 0;
}

static uint32_t checksum_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1));
    }
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t checksum_adler32(const uint8_t *buf, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + buf[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

static uint64_t checksum_fnv1a64(const uint8_t *buf, size_t len) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < len; i++) {
        h ^= buf[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

/* --- intset_ops: port of redis/src/intset.c -------------------------------- */
#define IST_ENC_INT16 2u
#define IST_ENC_INT32 4u
#define IST_ENC_INT64 8u
#define IST_HDR 8u
#define IST_MAX_ENTRIES (1u << 20)

static uint32_t ist_enc_for(int64_t v) {
    if (v < INT32_MIN || v > INT32_MAX) return IST_ENC_INT64;
    if (v < INT16_MIN || v > INT16_MAX) return IST_ENC_INT32;
    return IST_ENC_INT16;
}

static void ist_header(unsigned char *b, uint32_t enc, uint32_t len) {
    b[0] = (unsigned char)(enc & 0xff); b[1] = (unsigned char)((enc >> 8) & 0xff);
    b[2] = (unsigned char)((enc >> 16) & 0xff); b[3] = (unsigned char)((enc >> 24) & 0xff);
    b[4] = (unsigned char)(len & 0xff); b[5] = (unsigned char)((len >> 8) & 0xff);
    b[6] = (unsigned char)((len >> 16) & 0xff); b[7] = (unsigned char)((len >> 24) & 0xff);
}

static int ist_parse_header(const unsigned char *b, size_t n, uint32_t *enc, uint32_t *len) {
    if (n < IST_HDR) return 0;
    uint32_t e = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    uint32_t l = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
    if (e != IST_ENC_INT16 && e != IST_ENC_INT32 && e != IST_ENC_INT64) return 0;
    if (l > IST_MAX_ENTRIES) return 0;
    if ((uint64_t)l * e + IST_HDR != (uint64_t)n) return 0;
    *enc = e; *len = l;
    return 1;
}

static int64_t ist_get(const unsigned char *b, uint32_t enc, uint32_t pos) {
    const unsigned char *p = b + IST_HDR + (size_t)pos * enc;
    uint64_t u = 0;
    for (uint32_t i = 0; i < enc; i++) u |= (uint64_t)p[i] << (8u * i);
    if (enc < 8u && (u & (1ull << (8u * enc - 1))))
        u |= ~0ull << (8u * enc);
    int64_t v;
    memcpy(&v, &u, sizeof v);
    return v;
}

static void ist_put(unsigned char *b, uint32_t enc, uint32_t pos, int64_t v) {
    unsigned char *p = b + IST_HDR + (size_t)pos * enc;
    uint64_t u;
    memcpy(&u, &v, sizeof u);
    for (uint32_t i = 0; i < enc; i++) p[i] = (unsigned char)((u >> (8u * i)) & 0xffu);
}

static int ist_search(const unsigned char *b, uint32_t enc, uint32_t len,
                      int64_t v, uint32_t *pos) {
    if (len == 0) { if (pos) *pos = 0; return 0; }
    if (v > ist_get(b, enc, len - 1)) { if (pos) *pos = len; return 0; }
    if (v < ist_get(b, enc, 0)) { if (pos) *pos = 0; return 0; }
    int64_t lo = 0, hi = (int64_t)len - 1;
    while (lo <= hi) {
        int64_t mid = lo + (hi - lo) / 2;
        int64_t cur = ist_get(b, enc, (uint32_t)mid);
        if (v > cur) lo = mid + 1;
        else if (v < cur) hi = mid - 1;
        else { if (pos) *pos = (uint32_t)mid; return 1; }
    }
    if (pos) *pos = (uint32_t)lo;
    return 0;
}

static void ist_read_header_raw(const unsigned char *b, uint32_t *enc, uint32_t *len) {
    *enc = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    *len = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
}

static unsigned char *ist_add(unsigned char *buf, size_t buf_n, int64_t v, int *added) {
    uint32_t enc = 0, len = 0;
    ist_read_header_raw(buf, &enc, &len);
    (void)buf_n;
    *added = 1;
    uint32_t newenc = ist_enc_for(v);
    if (newenc > enc) {
        unsigned char *nb = realloc(buf, IST_HDR + (size_t)(len + 1) * newenc);
        if (!nb) return NULL;
        uint32_t pre = (v < 0) ? 1u : 0u;
        for (int64_t i = (int64_t)len - 1; i >= 0; i--)
            ist_put(nb, newenc, (uint32_t)i + pre, ist_get(nb, enc, (uint32_t)i));
        ist_put(nb, newenc, pre ? 0u : len, v);
        ist_header(nb, newenc, len + 1);
        return nb;
    }
    uint32_t pos;
    if (ist_search(buf, enc, len, v, &pos)) { *added = 0; return buf; }
    unsigned char *nb = realloc(buf, IST_HDR + (size_t)(len + 1) * enc);
    if (!nb) return NULL;
    if (pos < len)
        memmove(nb + IST_HDR + (size_t)(pos + 1) * enc,
                nb + IST_HDR + (size_t)pos * enc,
                (size_t)(len - pos) * enc);
    ist_put(nb, enc, pos, v);
    ist_header(nb, enc, len + 1);
    return nb;
}

static unsigned char *ist_remove(unsigned char *buf, size_t buf_n, int64_t v, int *removed) {
    *removed = 0;
    uint32_t enc = 0, len = 0;
    ist_read_header_raw(buf, &enc, &len);
    (void)buf_n;
    if (ist_enc_for(v) > enc) return buf;
    uint32_t pos;
    if (!ist_search(buf, enc, len, v, &pos)) return buf;
    if (pos < len - 1)
        memmove(buf + IST_HDR + (size_t)pos * enc,
                buf + IST_HDR + (size_t)(pos + 1) * enc,
                (size_t)(len - 1 - pos) * enc);
    *removed = 1;
    size_t new_n = IST_HDR + (size_t)(len - 1) * enc;
    if (len - 1 == 0) new_n = IST_HDR;
    unsigned char *nb = realloc(buf, new_n);
    if (!nb) return buf;
    ist_header(nb, enc, len - 1);
    return nb;
}

static unsigned char *ist_hex_decode(const char *hex, size_t *out_n) {
    size_t hl = strlen(hex);
    if (hl == 0 || hl % 2 != 0) return NULL;
    size_t n = hl / 2;
    if (n > IST_HDR + (size_t)IST_MAX_ENTRIES * IST_ENC_INT64) return NULL;
    unsigned char *buf = malloc(n);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)hex[2 * i]) || !isxdigit((unsigned char)hex[2 * i + 1])) {
            free(buf);
            return NULL;
        }
        char bs[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        buf[i] = (unsigned char)strtoul(bs, NULL, 16);
    }
    *out_n = n;
    return buf;
}

static sds ist_hex_encode(const unsigned char *b, size_t n) {
    sds out = sdsempty();
    for (size_t i = 0; i < n; i++)
        out = sdscatprintf(out, "%02x", b[i]);
    return out;
}

static int ist_arg_int(const cJSON *item, int64_t *out) {
    if (cJSON_IsString(item) && item->valuestring) {
        errno = 0;
        char *end = NULL;
        long long v = strtoll(item->valuestring, &end, 10);
        if (errno == ERANGE || end == item->valuestring || (end && *end != '\0')) return 0;
        *out = (int64_t)v;
        return 1;
    }
    if (cJSON_IsNumber(item)) {
        double d = item->valuedouble;
        if (d < -9.2e18 || d > 9.2e18) return 0;
        if ((double)(int64_t)d != d) return 0;
        *out = (int64_t)d;
        return 1;
    }
    return 0;
}

sds tools_run(const char *name, cJSON *args, const char *cwd) {
    if (!name) return sdsnew("ERROR: no tool name");
    if (!args) args = cJSON_CreateObject();

    if (strcmp(name, "execute_powershell") == 0 || strcmp(name, "pwsh") == 0) {
        const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
        if (!cmd) cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "script"));
        if (!cmd || !cmd[0]) return sdsnew("ERROR: empty PowerShell command");
        /* Fail fast with an install hint instead of a bare exec-not-found. */
        if (access("/opt/homebrew/bin/pwsh", X_OK) != 0
            && system("command -v pwsh >/dev/null 2>&1") != 0)
            return sdsnew("ERROR: pwsh (PowerShell 7+) is not installed. "
                          "Install it with: brew install --cask powershell");
        /* Prefer Homebrew pwsh; fall back to PATH. -NoProfile keeps startup
         * fast and prevents user profile scripts from hijacking the agent. */
        sds pwsh_cmd = sdscatprintf(sdsempty(),
            "command -v pwsh >/dev/null 2>&1 && pwsh -NoProfile -NonInteractive -Command %s 2>&1 || /opt/homebrew/bin/pwsh -NoProfile -NonInteractive -Command %s 2>&1",
            shell_quote(cmd), shell_quote(cmd));
        sds out = shell_run(pwsh_cmd, cwd);
        sdsfree(pwsh_cmd);
        return out;
    }

    if (strcmp(name, "execute_bash") == 0 || strcmp(name, "bash") == 0) {
        const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
        if (!cmd) cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "cmd"));
        /* block known hang paths before 60s shell wait (macOS only) */
#ifdef ALPHA_PT_DARWIN
        if (cmd && (strstr(cmd, "/Desktop") || strstr(cmd, " ~/Desktop") ||
                    strstr(cmd, "Desktop/") || strstr(cmd, "ls Desktop"))) {
            return sdsnew(
                "ERROR: command touches Desktop, which is served by the macOS File "
                "Provider and can block indefinitely.\n"
                "Copy what you need to a local directory first.\n");
        }
#endif
        sds out = shell_run(cmd, cwd);
        /* A command may legitimately emit binary, so this one is not refused --
         * but the NULs still truncate the result at the first one when it is
         * serialised, hiding the rest of the output. Substitute them and say
         * how many, so what follows is still readable. */
        size_t nuls = 0;
        for (size_t i = 0; i < sdslen(out); i++)
            if (out[i] == 0) { out[i] = '.'; nuls++; }
        if (nuls)
            out = sdscatprintf(out, "\n[%zu NUL byte%s replaced with '.']",
                               nuls, nuls == 1 ? "" : "s");
        return out;
    }
    if (strcmp(name, "read_file") == 0) {
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        if (!path) return sdsnew("ERROR: path required");
        char full[PATH_MAX];
        resolve_path(full, path, cwd);
        /* Fast binary check by extension — no I/O, just the path string.
         * Catches images, archives, executables, etc. before we try to
         * read them as text and hit the NUL-byte check (which still runs
         * as a backstop for files with no extension or unknown ones). */
        if (has_binary_extension(full))
            return sdscatprintf(sdsempty(),
                "ERROR: %s has a binary extension (%s). "
                "Use execute_bash with xxd, strings, or file instead.",
                full, strrchr(full, '.') ? strrchr(full, '.') : "unknown");
        sds body = read_file_all(full, 250000);
        if (has_nul(body, sdslen(body))) {
            sdsfree(body);
            return sdscatprintf(sdsempty(),
                "ERROR: %s is binary (contains NUL bytes) and cannot be read as text. "
                "Use execute_bash with xxd, strings or file instead.", full);
        }
        return body;
    }
    if (strcmp(name, "write_file") == 0) {
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(args, "content"));
        if (!path) return sdsnew("ERROR: path required");
        if (!content) content = "";
        char full[PATH_MAX];
        resolve_path(full, path, cwd);
        if (write_file_all(full, content, strlen(content)) != 0)
            return sdscatprintf(sdsempty(), "ERROR write %s: %s", full, strerror(errno));
        return sdscatprintf(sdsempty(), "OK wrote %zu bytes → %s", strlen(content), full);
    }
    if (strcmp(name, "edit_file") == 0) {
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        const char *old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_str"));
        if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_text"));
        if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_string"));
        if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "find"));
        if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "target"));

        const char *new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_str"));
        if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_text"));
        if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_string"));
        if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "replace"));
        if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "replacement"));

        if (!path || !old_s) return sdsnew("ERROR: path + old_str required");
        if (!new_s) new_s = "";
        char full[PATH_MAX];
        resolve_path(full, path, cwd);
        /* read_file_all truncates silently at its cap and appends a marker.
         * Editing that result would write the truncated text back and destroy
         * everything past the cap, while still reporting "OK". Refuse instead:
         * the uniqueness check is unsound on a partial file anyway. */
        struct stat est;
        if (stat(full, &est) == 0 && (size_t)est.st_size > ALPHA_EDIT_MAX_BYTES)
            return sdscatprintf(sdsempty(),
                "ERROR: %s is %lld bytes, over the %zu byte edit limit. "
                "Editing it would truncate the file.",
                full, (long long)est.st_size, (size_t)ALPHA_EDIT_MAX_BYTES);
        sds body = read_file_all(full, ALPHA_EDIT_MAX_BYTES);
        if (strncmp(body, "ERROR", 5) == 0) return body;
        if (has_nul(body, sdslen(body))) {
            sdsfree(body);
            return sdscatprintf(sdsempty(),
                "ERROR: %s is binary (contains NUL bytes). Editing it as text "
                "would discard everything after the first NUL.", full);
        }
        /* is_already_applied: the most common edit failure in production is a
         * re-send of an edit that has already landed (old_str == new_str, or
         * old_str gone while new_str is present). Surface that as an explicit
         * success-shaped no-op so the model moves on instead of re-reading
         * and re-patching. Ported from Hermes Agent's fuzzy_match.py.
         *
         * Deliberately conservative:
         * - new_str must be non-trivial (>= 8 chars stripped) — a tiny target
         *   matching by coincidence must not mask a genuine typo'd edit;
         * - new_str must appear EXACTLY in the content (no fuzzy matching);
         * - when old_str differs from new_str, old_str must be GONE. */
        {
            /* Strip leading/trailing whitespace from new_str for the length check */
            const char *ns = new_s;
            while (*ns == ' ' || *ns == '\t' || *ns == '\n' || *ns == '\r') ns++;
            size_t ns_len = strlen(ns);
            while (ns_len > 0 && (ns[ns_len - 1] == ' ' || ns[ns_len - 1] == '\t' ||
                                  ns[ns_len - 1] == '\n' || ns[ns_len - 1] == '\r'))
                ns_len--;
            if (ns_len >= 8 && strstr(body, new_s)) {
                if (strcmp(old_s, new_s) == 0) {
                    sdsfree(body);
                    return sdsnew("OK (no change): old_str and new_str are identical, "
                                  "and the file already contains this text.");
                }
                if (!strstr(body, old_s)) {
                    sdsfree(body);
                    return sdsnew("OK (no change): the edit appears to be already "
                                  "applied — new_str is present and old_str is gone. "
                                  "Do not re-send this patch.");
                }
            }
        }

        char *pos = strstr(body, old_s);
        if (!pos) {
            sdsfree(body);
            return sdsnew("ERROR: old_str not found");
        }
        /* Search from pos+1, not pos+strlen(old_s): overlapping occurrences
         * (e.g. "aba" in "ababa", or "aa" in "aaa") would otherwise be
         * missed and the edit would silently pick the wrong one. */
        if (strstr(pos + 1, old_s)) {
            sdsfree(body);
            return sdsnew("ERROR: old_str not unique");
        }
        size_t pre = (size_t)(pos - body);
        sds out = sdsnewlen(body, pre);
        out = sdscat(out, new_s);
        out = sdscat(out, pos + strlen(old_s));
        sdsfree(body);
        if (write_file_all(full, out, sdslen(out)) != 0) {
            sdsfree(out);
            return sdscatprintf(sdsempty(), "ERROR write %s", full);
        }
        sds msg = sdscatprintf(sdsempty(), "OK edited %s (%zu bytes now)", full, sdslen(out));
        sdsfree(out);
        return msg;
    }
    if (strcmp(name, "list_dir") == 0 || strcmp(name, "ls") == 0) {
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        char full[PATH_MAX];
        resolve_path(full, path, cwd);
        return list_dir(full);
    }
    if (strcmp(name, "browser") == 0 || strcmp(name, "web_browser") == 0) {
        return browser_tool_run(args);
    }
    if (strcmp(name, "todo") == 0) {
        return todo_tool_run(args);
    }
    if (strcmp(name, "web_search") == 0) {
        const char *query = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
        if (!query || !query[0])
            return sdsnew("ERROR: query required for web_search");
        int max_results = 10;
        cJSON *mr = cJSON_GetObjectItem(args, "max_results");
        if (cJSON_IsNumber(mr)) max_results = mr->valueint;
        return web_search(query, max_results);
    }
    if (strcmp(name, "phone") == 0) {
        return phone_tool_run(args, cwd);
    }
    if (strcmp(name, "memory") == 0) {
        return memory_tool_run(args);
    }
    if (strcmp(name, "code_search") == 0) {
        const char *query = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
        if (!query || !query[0])
            return sdsnew("ERROR: query required for code_search");
        return code_search_tool(args, cwd);
    }
    if (strcmp(name, "working_diff") == 0 || strcmp(name, "diff") == 0) {
        const char *mode = cJSON_GetStringValue(cJSON_GetObjectItem(args, "mode"));
        return working_diff(cwd, mode);
    }
    if (strcmp(name, "patch") == 0) {
        const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
        if (!action) action = "diff";
        if (strcmp(action, "diff") == 0) {
            const char *old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old"));
            const char *new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new"));
            int context = ALPHA_DIFF_DEFAULT_CONTEXT;
            cJSON *c = cJSON_GetObjectItem(args, "context");
            if (cJSON_IsNumber(c)) context = c->valueint;
            const char *pa = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path_a"));
            const char *pb = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path_b"));
            return unified_diff(pa ? pa : "a/file", pb ? pb : "b/file",
                                old_s ? old_s : "", new_s ? new_s : "", context);
        }
        if (strcmp(action, "apply") == 0) {
            const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(args, "content"));
            const char *patch = cJSON_GetStringValue(cJSON_GetObjectItem(args, "patch"));
            sds result = unified_apply(content ? content : "", patch ? patch : "");
            if (!result)
                return sdsnew("ERROR: patch did not apply cleanly "
                              "(malformed or context mismatch)");
            return result;
        }
        return sdsnew("ERROR: unknown patch action — use diff or apply");
    }
    if (strcmp(name, "layout_solver") == 0) {
        const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
        if (!action) action = "bsp";
        if (strcmp(action, "bezier") == 0) {
            double p1x = 0.25, p1y = 0.1, p2x = 0.25, p2y = 1.0, t = 0.5;
            cJSON *item = cJSON_GetObjectItem(args, "t");
            if (cJSON_IsNumber(item)) t = item->valuedouble;
            item = cJSON_GetObjectItem(args, "p1x");
            if (cJSON_IsNumber(item)) p1x = item->valuedouble;
            item = cJSON_GetObjectItem(args, "p1y");
            if (cJSON_IsNumber(item)) p1y = item->valuedouble;
            item = cJSON_GetObjectItem(args, "p2x");
            if (cJSON_IsNumber(item)) p2x = item->valuedouble;
            item = cJSON_GetObjectItem(args, "p2y");
            if (cJSON_IsNumber(item)) p2y = item->valuedouble;

            double inv = 1.0 - t;
            double y = 3.0 * inv * inv * t * p1y + 3.0 * inv * t * t * p2y + t * t * t;
            double x = 3.0 * inv * inv * t * p1x + 3.0 * inv * t * t * p2x + t * t * t;
            return sdscatprintf(sdsempty(), "{\"action\":\"bezier\",\"t\":%.4f,\"x\":%.4f,\"y\":%.4f}", t, x, y);
        }
        /* BSP Tiling & Partitioning */
        int width = 1920, height = 1080, count = 2;
        cJSON *item = cJSON_GetObjectItem(args, "width");
        if (cJSON_IsNumber(item)) width = item->valueint;
        item = cJSON_GetObjectItem(args, "height");
        if (cJSON_IsNumber(item)) height = item->valueint;
        item = cJSON_GetObjectItem(args, "count");
        if (cJSON_IsNumber(item)) count = item->valueint;
        if (count <= 0) count = 1;
        if (count > 32) count = 32;

        sds out = sdscatprintf(sdsempty(), "{\"action\":\"bsp\",\"canvas\":{\"w\":%d,\"h\":%d},\"nodes\":[", width, height);
        int cur_x = 0, cur_y = 0, cur_w = width, cur_h = height;
        for (int i = 0; i < count; i++) {
            int node_w = cur_w, node_h = cur_h;
            if (i < count - 1) {
                if (cur_w >= cur_h) {
                    node_w = cur_w / 2;
                    out = sdscatprintf(out, "%s{\"id\":%d,\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d}",
                                       i > 0 ? "," : "", i + 1, cur_x, cur_y, node_w, node_h);
                    cur_x += node_w;
                    cur_w -= node_w;
                } else {
                    node_h = cur_h / 2;
                    out = sdscatprintf(out, "%s{\"id\":%d,\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d}",
                                       i > 0 ? "," : "", i + 1, cur_x, cur_y, node_w, node_h);
                    cur_y += node_h;
                    cur_h -= node_h;
                }
            } else {
                out = sdscatprintf(out, "%s{\"id\":%d,\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d}",
                                   i > 0 ? "," : "", i + 1, cur_x, cur_y, cur_w, cur_h);
            }
        }
        out = sdscat(out, "]}");
        return out;
    }
    if (strcmp(name, "hex_pattern_search") == 0) {
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
        if (!data_hex || !pattern)
            return sdsnew("ERROR: data and pattern parameters required for hex_pattern_search");

        /* Parse raw data bytes from hex */
        size_t dlen = strlen(data_hex);
        uint8_t *dbuf = malloc(dlen / 2 + 1);
        size_t dcount = 0;
        for (size_t i = 0; i + 1 < dlen; i += 2) {
            char byte_str[3] = { data_hex[i], data_hex[i+1], '\0' };
            char *endptr = NULL;
            unsigned long val = strtoul(byte_str, &endptr, 16);
            if (endptr && *endptr == '\0') dbuf[dcount++] = (uint8_t)val;
        }

        /* Parse pattern tokens: handles spaces and ?? wildcards */
        typedef struct { uint8_t byte; uint8_t is_wildcard; } hex_pat_t;
        hex_pat_t pat[128];
        size_t pcount = 0;
        const char *p = pattern;
        while (*p && pcount < 128) {
            while (*p == ' ') p++;
            if (!*p) break;
            if (p[0] == '?' && p[1] == '?') {
                pat[pcount].byte = 0;
                pat[pcount].is_wildcard = 1;
                pcount++;
                p += 2;
            } else if (isxdigit(p[0]) && isxdigit(p[1])) {
                char byte_str[3] = { p[0], p[1], '\0' };
                pat[pcount].byte = (uint8_t)strtoul(byte_str, NULL, 16);
                pat[pcount].is_wildcard = 0;
                pcount++;
                p += 2;
            } else {
                p++;
            }
        }

        sds out = sdscatprintf(sdsempty(), "{\"action\":\"hex_pattern_search\",\"pattern_length\":%zu,\"matches\":[", pcount);
        int matches = 0;
        if (pcount > 0 && dcount >= pcount) {
            for (size_t i = 0; i <= dcount - pcount; i++) {
                int ok = 1;
                for (size_t j = 0; j < pcount; j++) {
                    if (!pat[j].is_wildcard && dbuf[i + j] != pat[j].byte) {
                        ok = 0;
                        break;
                    }
                }
                if (ok) {
                    out = sdscatprintf(out, "%s%zu", matches > 0 ? "," : "", i);
                    matches++;
                }
            }
        }
        out = sdscatprintf(out, "],\"total_matches\":%d}", matches);
        free(dbuf);
        return out;
    }
    if (strcmp(name, "binary_patch_apply") == 0) {
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        const char *patch_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "patch"));
        cJSON *off_item = cJSON_GetObjectItem(args, "offset");
        if (!data_hex || !patch_hex || !cJSON_IsNumber(off_item))
            return sdsnew("ERROR: data, patch, and numeric offset required for binary_patch_apply");

        if (off_item->valueint < 0)
            return sdsnew("ERROR: offset must be non-negative for binary_patch_apply");

        size_t offset = (size_t)off_item->valueint;
        size_t dlen = strlen(data_hex);
        size_t plen = strlen(patch_hex);
        if (dlen % 2 != 0 || plen % 2 != 0)
            return sdsnew("ERROR: hex data and patch length must be even numbers of characters");

        size_t dcount = dlen / 2;
        size_t pcount = plen / 2;
        if (offset > dcount || pcount > dcount - offset)
            return sdsnew("ERROR: patch bounds exceed data buffer size");

        /* Decode binary data with strict hex validation */
        uint8_t *dbuf = malloc(dcount);
        for (size_t i = 0; i < dcount; i++) {
            if (!isxdigit(data_hex[i*2]) || !isxdigit(data_hex[i*2+1])) {
                free(dbuf);
                return sdsnew("ERROR: invalid non-hex character in data buffer");
            }
            char byte_str[3] = { data_hex[i*2], data_hex[i*2+1], '\0' };
            dbuf[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }

        /* Decode patch and capture original bytes for rollback */
        sds orig_hex = sdsempty();
        for (size_t i = 0; i < pcount; i++) {
            if (!isxdigit(patch_hex[i*2]) || !isxdigit(patch_hex[i*2+1])) {
                sdsfree(orig_hex);
                free(dbuf);
                return sdsnew("ERROR: invalid non-hex character in patch string");
            }
            char byte_str[3] = { patch_hex[i*2], patch_hex[i*2+1], '\0' };
            uint8_t pbyte = (uint8_t)strtoul(byte_str, NULL, 16);
            orig_hex = sdscatprintf(orig_hex, "%02x", dbuf[offset + i]);
            dbuf[offset + i] = pbyte;
        }

        /* Re-encode modified buffer */
        sds patched_hex = sdsempty();
        for (size_t i = 0; i < dcount; i++) {
            patched_hex = sdscatprintf(patched_hex, "%02x", dbuf[i]);
        }

        sds out = sdscatprintf(sdsempty(),
            "{\"action\":\"binary_patch_apply\",\"offset\":%zu,\"patch_bytes\":%zu,\"original\":\"%s\",\"patched\":\"%s\"}",
            offset, pcount, orig_hex, patched_hex);
        sdsfree(orig_hex);
        sdsfree(patched_hex);
        free(dbuf);
        return out;
    }
    if (strcmp(name, "boyer_moore_search") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
        if (!text || !pattern)
            return sdsnew("ERROR: text and pattern required for boyer_moore_search");

        size_t n = strlen(text);
        size_t m = strlen(pattern);
        if (m == 0)
            return sdsnew("ERROR: pattern must not be empty");

        /* Build Bad Character Shift Heuristic */
        int bad_char[256];
        for (int i = 0; i < 256; i++) bad_char[i] = (int)m;
        for (size_t i = 0; i < m; i++) bad_char[(unsigned char)pattern[i]] = (int)(m - 1 - i);

        /* Build Good Suffix Shift Heuristic */
        int *good_suffix = malloc(m * sizeof(int));
        int *suff = malloc(m * sizeof(int));
        for (size_t i = 0; i < m; i++) good_suffix[i] = (int)m;

        suff[m - 1] = (int)m;
        int g = (int)m - 1, f = 0;
        for (int i = (int)m - 2; i >= 0; --i) {
            if (i > g && suff[i + (int)m - 1 - f] < i - g) {
                suff[i] = suff[i + (int)m - 1 - f];
            } else {
                if (i < g) g = i;
                f = i;
                while (g >= 0 && pattern[g] == pattern[g + (int)m - 1 - f]) --g;
                suff[i] = f - g;
            }
        }

        int j = 0;
        for (int i = (int)m - 1; i >= -1; --i) {
            if (i == -1 || suff[i] == i + 1) {
                for (; j < (int)m - 1 - i; ++j) {
                    if (good_suffix[j] == (int)m) good_suffix[j] = (int)m - 1 - i;
                }
            }
        }
        for (size_t i = 0; i < m - 1; ++i) {
            good_suffix[m - 1 - suff[i]] = (int)(m - 1 - i);
        }
        free(suff);

        /* Execute Boyer-Moore Search */
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"boyer_moore_search\",\"pattern_length\":%zu,\"matches\":[", m);
        int matches = 0;
        int s = 0;
        while (s <= (int)(n - m)) {
            int k = (int)m - 1;
            while (k >= 0 && pattern[k] == text[s + k]) k--;
            if (k < 0) {
                out = sdscatprintf(out, "%s%d", matches > 0 ? "," : "", s);
                matches++;
                s += good_suffix[0];
            } else {
                int bc_shift = bad_char[(unsigned char)text[s + k]] - ((int)m - 1) + k;
                int gs_shift = good_suffix[k];
                int max_shift = gs_shift > bc_shift ? gs_shift : bc_shift;
                s += max_shift > 0 ? max_shift : 1;
            }
        }
        free(good_suffix);
        out = sdscatprintf(out, "],\"total_matches\":%d}", matches);
        return out;
    }
    if (strcmp(name, "multi_hex_edit") == 0) {
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        cJSON *changes = cJSON_GetObjectItem(args, "changes");
        if (!data_hex || !changes || !cJSON_IsArray(changes))
            return sdsnew("ERROR: data and changes array required for multi_hex_edit");

        size_t dlen = strlen(data_hex);
        if (dlen % 2 != 0)
            return sdsnew("ERROR: hex data length must be an even number of characters");

        size_t dcount = dlen / 2;
        uint8_t *dbuf = malloc(dcount);
        for (size_t i = 0; i < dcount; i++) {
            if (!isxdigit(data_hex[i*2]) || !isxdigit(data_hex[i*2+1])) {
                free(dbuf);
                return sdsnew("ERROR: invalid non-hex character in data buffer");
            }
            char byte_str[3] = { data_hex[i*2], data_hex[i*2+1], '\0' };
            dbuf[i] = (uint8_t)strtoul(byte_str, NULL, 16);
        }

        /* Validate all changes before applying any */
        int n_changes = cJSON_GetArrayItem(changes, 0) ? cJSON_GetArraySize(changes) : 0;
        if (n_changes == 0) {
            free(dbuf);
            return sdsnew("ERROR: changes array must not be empty");
        }

        for (int c = 0; c < n_changes; c++) {
            cJSON *item = cJSON_GetArrayItem(changes, c);
            cJSON *off_item = cJSON_GetObjectItem(item, "offset");
            const char *patch_hex = cJSON_GetStringValue(cJSON_GetObjectItem(item, "patch"));
            if (!off_item || !cJSON_IsNumber(off_item) || !patch_hex) {
                free(dbuf);
                return sdsnew("ERROR: each change item must contain numeric offset and string patch");
            }
            if (off_item->valueint < 0) {
                free(dbuf);
                return sdsnew("ERROR: offset must be non-negative");
            }
            size_t off = (size_t)off_item->valueint;
            size_t plen = strlen(patch_hex);
            if (plen % 2 != 0) {
                free(dbuf);
                return sdsnew("ERROR: patch hex length must be even");
            }
            size_t pcount = plen / 2;
            if (off > dcount || pcount > dcount - off) {
                free(dbuf);
                return sdsnew("ERROR: patch bounds exceed data buffer size");
            }
            for (size_t i = 0; i < plen; i++) {
                if (!isxdigit(patch_hex[i])) {
                    free(dbuf);
                    return sdsnew("ERROR: invalid non-hex character in patch");
                }
            }
        }

        /* Apply changes atomically and record rollbacks */
        cJSON *rollbacks = cJSON_CreateArray();
        for (int c = 0; c < n_changes; c++) {
            cJSON *item = cJSON_GetArrayItem(changes, c);
            size_t off = (size_t)cJSON_GetObjectItem(item, "offset")->valueint;
            const char *patch_hex = cJSON_GetStringValue(cJSON_GetObjectItem(item, "patch"));
            size_t pcount = strlen(patch_hex) / 2;

            sds orig_chunk = sdsempty();
            for (size_t i = 0; i < pcount; i++) {
                char byte_str[3] = { patch_hex[i*2], patch_hex[i*2+1], '\0' };
                uint8_t pbyte = (uint8_t)strtoul(byte_str, NULL, 16);
                orig_chunk = sdscatprintf(orig_chunk, "%02x", dbuf[off + i]);
                dbuf[off + i] = pbyte;
            }
            cJSON *rb = cJSON_CreateObject();
            cJSON_AddNumberToObject(rb, "offset", (double)off);
            cJSON_AddStringToObject(rb, "original", orig_chunk);
            sdsfree(orig_chunk);
            cJSON_AddItemToArray(rollbacks, rb);
        }

        sds patched_hex = sdsempty();
        for (size_t i = 0; i < dcount; i++) {
            patched_hex = sdscatprintf(patched_hex, "%02x", dbuf[i]);
        }
        free(dbuf);

        cJSON *res_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(res_obj, "action", "multi_hex_edit");
        cJSON_AddNumberToObject(res_obj, "applied_changes", n_changes);
        cJSON_AddItemToObject(res_obj, "rollbacks", rollbacks);
        cJSON_AddStringToObject(res_obj, "patched", patched_hex);
        sdsfree(patched_hex);

        char *json_str = cJSON_PrintUnformatted(res_obj);
        cJSON_Delete(res_obj);
        sds out = sdsnew(json_str);
        free(json_str);
        return out;
    }
    if (strcmp(name, "mdesk_tokenize") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!text)
            return sdsnew("ERROR: text parameter required for mdesk_tokenize");

        cJSON *sw_item = cJSON_GetObjectItem(args, "skip_whitespace");
        int skip_whitespace = (sw_item && cJSON_IsBool(sw_item)) ? cJSON_IsTrue(sw_item) : 1;

        size_t len = strlen(text);
        const uint8_t *p = (const uint8_t *)text;
        const uint8_t *end = p + len;

        cJSON *tok_arr = cJSON_CreateArray();
        int tok_count = 0;

        while (p < end) {
            const uint8_t *tok_start = p;
            const char *kind = "symbol";
            cJSON *flags = cJSON_CreateArray();

            /* 1. Whitespace (spaces, tabs, carriage returns) */
            if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\v') {
                kind = "whitespace";
                while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\v')) p++;
            }
            /* 2. Newline */
            else if (*p == '\n') {
                kind = "newline";
                p++;
            }
            /* 3. Single-line comment // */
            else if (p + 1 < end && p[0] == '/' && p[1] == '/') {
                kind = "comment";
                p += 2;
                int escaped = 0;
                while (p < end) {
                    if (escaped) {
                        escaped = 0;
                    } else {
                        if (*p == '\n') break;
                        if (*p == '\\') escaped = 1;
                    }
                    p++;
                }
            }
            /* 4. Multi-line comment */
            else if (p + 1 < end && p[0] == '/' && p[1] == '*') {
                kind = "comment";
                p += 2;
                int closed = 0;
                while (p < end) {
                    if (p + 1 < end && p[0] == '*' && p[1] == '/') {
                        p += 2;
                        closed = 1;
                        break;
                    }
                    p++;
                }
                if (!closed) {
                    cJSON_AddItemToArray(flags, cJSON_CreateString("broken_comment"));
                }
            }
            /* 5. Identifiers */
            else if (isalpha(*p) || *p == '_' || *p >= 0x80) {
                kind = "identifier";
                p++;
                while (p < end && (isalnum(*p) || *p == '_' || *p >= 0x80)) p++;
            }
            /* 6. Numerics */
            else if (isdigit(*p) || (*p == '.' && p + 1 < end && isdigit(p[1]))) {
                kind = "numeric";
                p++;
                while (p < end && (isalnum(*p) || *p == '_' || *p == '.')) p++;
            }
            /* 7. Triplet string literals (""", ''', ```) */
            else if (p + 2 < end && ((p[0] == '"' && p[1] == '"' && p[2] == '"') ||
                                     (p[0] == '\'' && p[1] == '\'' && p[2] == '\'') ||
                                     (p[0] == '`' && p[1] == '`' && p[2] == '`'))) {
                uint8_t q = p[0];
                kind = "string";
                cJSON_AddItemToArray(flags, cJSON_CreateString("triplet"));
                if (q == '\'') cJSON_AddItemToArray(flags, cJSON_CreateString("single_quote"));
                else if (q == '"') cJSON_AddItemToArray(flags, cJSON_CreateString("double_quote"));
                else if (q == '`') cJSON_AddItemToArray(flags, cJSON_CreateString("tick"));
                p += 3;
                int closed = 0;
                while (p + 2 < end) {
                    if (p[0] == q && p[1] == q && p[2] == q) {
                        p += 3;
                        closed = 1;
                        break;
                    }
                    p++;
                }
                if (!closed) {
                    p = end;
                    cJSON_AddItemToArray(flags, cJSON_CreateString("broken_string"));
                }
            }
            /* 8. Singlet string literals (", ', `) */
            else if (*p == '"' || *p == '\'' || *p == '`') {
                uint8_t q = *p;
                kind = "string";
                if (q == '\'') cJSON_AddItemToArray(flags, cJSON_CreateString("single_quote"));
                else if (q == '"') cJSON_AddItemToArray(flags, cJSON_CreateString("double_quote"));
                else if (q == '`') cJSON_AddItemToArray(flags, cJSON_CreateString("tick"));
                p++;
                int escaped = 0;
                int closed = 0;
                while (p < end && *p != '\n') {
                    if (!escaped && *p == '\\') {
                        escaped = 1;
                    } else if (!escaped && *p == q) {
                        p++;
                        closed = 1;
                        break;
                    } else {
                        escaped = 0;
                    }
                    p++;
                }
                if (!closed) {
                    cJSON_AddItemToArray(flags, cJSON_CreateString("broken_string"));
                }
            }
            /* 9. Symbols & Operators */
            else {
                kind = "symbol";
                p++;
            }

            size_t tok_len = (size_t)(p - tok_start);
            size_t tok_off = (size_t)(tok_start - (const uint8_t *)text);

            if (skip_whitespace && (strcmp(kind, "whitespace") == 0 || strcmp(kind, "newline") == 0)) {
                cJSON_Delete(flags);
                continue;
            }

            cJSON *tok_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(tok_obj, "kind", kind);
            char *tok_str = malloc(tok_len + 1);
            memcpy(tok_str, tok_start, tok_len);
            tok_str[tok_len] = '\0';
            cJSON_AddStringToObject(tok_obj, "text", tok_str);
            free(tok_str);
            cJSON_AddNumberToObject(tok_obj, "offset", (double)tok_off);
            cJSON_AddNumberToObject(tok_obj, "length", (double)tok_len);
            if (cJSON_GetArraySize(flags) > 0) {
                cJSON_AddItemToObject(tok_obj, "flags", flags);
            } else {
                cJSON_Delete(flags);
            }
            cJSON_AddItemToArray(tok_arr, tok_obj);
            tok_count++;
        }

        cJSON *res_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(res_obj, "action", "mdesk_tokenize");
        cJSON_AddNumberToObject(res_obj, "total_tokens", tok_count);
        cJSON_AddItemToObject(res_obj, "tokens", tok_arr);

        char *json_str = cJSON_PrintUnformatted(res_obj);
        cJSON_Delete(res_obj);
        sds out = sdsnew(json_str);
        free(json_str);
        return out;
    }
    if (strcmp(name, "cpp_symbol_extract") == 0) {
        cJSON *text_item = cJSON_GetObjectItem(args, "text");
        if (!text_item || !text_item->valuestring) {
            return sdsnew("ERROR: text parameter required for cpp_symbol_extract");
        }
        const char *text = text_item->valuestring;
        const char *p = text;
        const char *end = text + strlen(text);

        cJSON *sym_arr = cJSON_CreateArray();
        int sym_count = 0;
        int current_line = 1;

        while (p < end) {
            /* Skip spaces/tabs */
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
            if (p >= end) break;

            if (*p == '\n') {
                current_line++;
                p++;
                continue;
            }

            /* 1. Skip single line comment */
            if (p + 1 < end && p[0] == '/' && p[1] == '/') {
                while (p < end && *p != '\n') p++;
                continue;
            }

            /* 2. Skip multi-line comment */
            if (p + 1 < end && p[0] == '/' && p[1] == '*') {
                p += 2;
                while (p + 1 < end && !(p[0] == '*' && p[1] == '/')) {
                    if (*p == '\n') current_line++;
                    p++;
                }
                if (p + 1 < end) p += 2;
                continue;
            }

            /* 3. Preprocessor Directive (#define, #include) */
            if (*p == '#') {
                p++;
                while (p < end && (*p == ' ' || *p == '\t')) p++;
                if (p + 6 <= end && strncmp(p, "define", 6) == 0 && !isalnum(p[6])) {
                    p += 6;
                    while (p < end && (*p == ' ' || *p == '\t')) p++;
                    const char *name_start = p;
                    while (p < end && (isalnum(*p) || *p == '_')) p++;
                    if (p > name_start) {
                        char macro_name[256];
                        size_t len = (size_t)(p - name_start);
                        if (len >= sizeof(macro_name)) len = sizeof(macro_name) - 1;
                        memcpy(macro_name, name_start, len);
                        macro_name[len] = '\0';

                        cJSON *item = cJSON_CreateObject();
                        cJSON_AddStringToObject(item, "kind", "macro");
                        cJSON_AddStringToObject(item, "name", macro_name);
                        cJSON_AddNumberToObject(item, "line", current_line);
                        cJSON_AddItemToArray(sym_arr, item);
                        sym_count++;
                    }
                } else if (p + 7 <= end && strncmp(p, "include", 7) == 0 && !isalnum(p[7])) {
                    p += 7;
                    while (p < end && (*p == ' ' || *p == '\t')) p++;
                    if (p < end && (*p == '<' || *p == '"')) {
                        char delim = (*p == '<') ? '>' : '"';
                        p++;
                        const char *inc_start = p;
                        while (p < end && *p != delim && *p != '\n') p++;
                        if (p < end && *p == delim) {
                            char inc_name[256];
                            size_t len = (size_t)(p - inc_start);
                            if (len >= sizeof(inc_name)) len = sizeof(inc_name) - 1;
                            memcpy(inc_name, inc_start, len);
                            inc_name[len] = '\0';

                            cJSON *item = cJSON_CreateObject();
                            cJSON_AddStringToObject(item, "kind", "include");
                            cJSON_AddStringToObject(item, "name", inc_name);
                            cJSON_AddNumberToObject(item, "line", current_line);
                            cJSON_AddItemToArray(sym_arr, item);
                            sym_count++;
                        }
                    }
                }
                while (p < end && *p != '\n') p++;
                continue;
            }

            /* 4. Struct / Class / Enum / Typedef */
            if ((p + 6 <= end && strncmp(p, "struct", 6) == 0 && !isalnum(p[6])) ||
                (p + 5 <= end && strncmp(p, "class", 5) == 0 && !isalnum(p[5])) ||
                (p + 4 <= end && strncmp(p, "enum", 4) == 0 && !isalnum(p[4]))) {
                const char *kind_str = (strncmp(p, "struct", 6) == 0) ? "struct" :
                                       (strncmp(p, "class", 5) == 0) ? "class" : "enum";
                while (p < end && isalpha(*p)) p++;
                while (p < end && (*p == ' ' || *p == '\t')) p++;
                const char *name_start = p;
                while (p < end && (isalnum(*p) || *p == '_')) p++;
                if (p > name_start) {
                    char type_name[256];
                    size_t len = (size_t)(p - name_start);
                    if (len >= sizeof(type_name)) len = sizeof(type_name) - 1;
                    memcpy(type_name, name_start, len);
                    type_name[len] = '\0';

                    cJSON *item = cJSON_CreateObject();
                    cJSON_AddStringToObject(item, "kind", kind_str);
                    cJSON_AddStringToObject(item, "name", type_name);
                    cJSON_AddNumberToObject(item, "line", current_line);
                    cJSON_AddItemToArray(sym_arr, item);
                    sym_count++;
                }
                while (p < end && *p != ';' && *p != '{' && *p != '\n') p++;
                continue;
            }

            /* 5. Function / Method Declaration or Definition */
            const char *ident_start = p;
            while (p < end && (isalnum(*p) || *p == '_' || *p == ':')) p++;
            if (p > ident_start) {
                const char *after_ident = p;
                while (after_ident < end && (*after_ident == ' ' || *after_ident == '\t')) after_ident++;
                if (after_ident < end && *after_ident == '(') {
                    /* Found function call or definition */
                    char full_ident[256];
                    size_t len = (size_t)(p - ident_start);
                    if (len >= sizeof(full_ident)) len = sizeof(full_ident) - 1;
                    memcpy(full_ident, ident_start, len);
                    full_ident[len] = '\0';

                    /* Parse receiver if qualified (e.g. ClassName::methodName) */
                    char receiver[256] = {0};
                    char func_name[256] = {0};
                    char *colon = strstr(full_ident, "::");
                    if (colon) {
                        size_t rlen = (size_t)(colon - full_ident);
                        if (rlen >= sizeof(receiver)) rlen = sizeof(receiver) - 1;
                        memcpy(receiver, full_ident, rlen);
                        receiver[rlen] = '\0';
                        strncpy(func_name, colon + 2, sizeof(func_name) - 1);
                    } else {
                        strncpy(func_name, full_ident, sizeof(func_name) - 1);
                    }

                    if (strcmp(func_name, "if") != 0 && strcmp(func_name, "while") != 0 &&
                        strcmp(func_name, "for") != 0 && strcmp(func_name, "switch") != 0 &&
                        strcmp(func_name, "sizeof") != 0 && strcmp(func_name, "return") != 0) {
                        cJSON *item = cJSON_CreateObject();
                        cJSON_AddStringToObject(item, "kind", "function");
                        cJSON_AddStringToObject(item, "name", func_name);
                        cJSON_AddStringToObject(item, "qualified_name", full_ident);
                        if (receiver[0]) {
                            cJSON_AddStringToObject(item, "receiver", receiver);
                        }
                        cJSON_AddNumberToObject(item, "line", current_line);
                        cJSON_AddItemToArray(sym_arr, item);
                        sym_count++;
                    }
                    p = after_ident + 1;
                    continue;
                }
            }

            p++;
        }

        cJSON *res_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(res_obj, "action", "cpp_symbol_extract");
        cJSON_AddNumberToObject(res_obj, "total_symbols", sym_count);
        cJSON_AddItemToObject(res_obj, "symbols", sym_arr);

        char *json_str = cJSON_PrintUnformatted(res_obj);
        cJSON_Delete(res_obj);
        sds out = sdsnew(json_str);
        free(json_str);
        return out;
    }
    if (strcmp(name, "mesh_spatial_codec") == 0) {
        const char *action = "morton";
        cJSON *act_item = cJSON_GetObjectItem(args, "action");
        if (act_item && act_item->valuestring) {
            action = act_item->valuestring;
        }

        if (strcmp(action, "half_float") == 0) {
            cJSON *v_item = cJSON_GetObjectItem(args, "value");
            if (!v_item || !cJSON_IsNumber(v_item)) {
                return sdsnew("ERROR: numeric value required for half_float");
            }
            float val = (float)v_item->valuedouble;
            union { float f; uint32_t ui; } u = { val };
            uint32_t ui = u.ui;
            int s = (ui >> 16) & 0x8000;
            int em = ui & 0x7fffffff;
            int h = (em - (112 << 23) + (1 << 12)) >> 13;
            h = (em < (113 << 23)) ? 0 : h;
            h = (em >= (143 << 23)) ? 0x7c00 : h;
            h = (em > (255 << 23)) ? 0x7e00 : h;
            uint16_t half = (uint16_t)(s | h);

            cJSON *res_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(res_obj, "action", "half_float");
            cJSON_AddNumberToObject(res_obj, "input_value", val);
            cJSON_AddNumberToObject(res_obj, "half_int", half);
            char hex_buf[16];
            snprintf(hex_buf, sizeof(hex_buf), "0x%04X", half);
            cJSON_AddStringToObject(res_obj, "half_hex", hex_buf);

            char *json_str = cJSON_PrintUnformatted(res_obj);
            cJSON_Delete(res_obj);
            sds out = sdsnew(json_str);
            free(json_str);
            return out;
        }

        /* Morton 3D Coordinate Encoding */
        cJSON *points_item = cJSON_GetObjectItem(args, "points");
        if (!points_item || !cJSON_IsArray(points_item)) {
            /* Single point mode with x, y, z */
            cJSON *x_item = cJSON_GetObjectItem(args, "x");
            cJSON *y_item = cJSON_GetObjectItem(args, "y");
            cJSON *z_item = cJSON_GetObjectItem(args, "z");
            if (!x_item || !y_item || !z_item || !cJSON_IsNumber(x_item) || !cJSON_IsNumber(y_item) || !cJSON_IsNumber(z_item)) {
                return sdsnew("ERROR: either points array or x,y,z numeric coordinates required for mesh_spatial_codec");
            }
            uint32_t x = (uint32_t)(x_item->valuedouble < 0 ? 0 : x_item->valuedouble);
            uint32_t y = (uint32_t)(y_item->valuedouble < 0 ? 0 : y_item->valuedouble);
            uint32_t z = (uint32_t)(z_item->valuedouble < 0 ? 0 : z_item->valuedouble);

            /* 3D Morton interleave */
            uint64_t px = x & 0x000fffffULL;
            px = (px ^ (px << 32)) & 0x000f00000000ffffULL;
            px = (px ^ (px << 16)) & 0x000f0000ff0000ffULL;
            px = (px ^ (px << 8))  & 0x000f00f00f00f00fULL;
            px = (px ^ (px << 4))  & 0x00c30c30c30c30c3ULL;
            px = (px ^ (px << 2))  & 0x0249249249249249ULL;

            uint64_t py = y & 0x000fffffULL;
            py = (py ^ (py << 32)) & 0x000f00000000ffffULL;
            py = (py ^ (py << 16)) & 0x000f0000ff0000ffULL;
            py = (py ^ (py << 8))  & 0x000f00f00f00f00fULL;
            py = (py ^ (py << 4))  & 0x00c30c30c30c30c3ULL;
            py = (py ^ (py << 2))  & 0x0249249249249249ULL;

            uint64_t pz = z & 0x000fffffULL;
            pz = (pz ^ (pz << 32)) & 0x000f00000000ffffULL;
            pz = (pz ^ (pz << 16)) & 0x000f0000ff0000ffULL;
            pz = (pz ^ (pz << 8))  & 0x000f00f00f00f00fULL;
            pz = (pz ^ (pz << 4))  & 0x00c30c30c30c30c3ULL;
            pz = (pz ^ (pz << 2))  & 0x0249249249249249ULL;

            uint64_t code = px | (py << 1) | (pz << 2);

            cJSON *res_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(res_obj, "action", "morton");
            cJSON_AddNumberToObject(res_obj, "x", (double)x);
            cJSON_AddNumberToObject(res_obj, "y", (double)y);
            cJSON_AddNumberToObject(res_obj, "z", (double)z);
            cJSON_AddNumberToObject(res_obj, "morton_code", (double)code);
            char hex_code[32];
            snprintf(hex_code, sizeof(hex_code), "0x%llX", (unsigned long long)code);
            cJSON_AddStringToObject(res_obj, "morton_hex", hex_code);

            char *json_str = cJSON_PrintUnformatted(res_obj);
            cJSON_Delete(res_obj);
            sds out = sdsnew(json_str);
            free(json_str);
            return out;
        }

        /* Batch points mode with AABB bounding box computation */
        int pt_count = cJSON_GetArraySize(points_item);
        if (pt_count <= 0) {
            return sdsnew("ERROR: points array cannot be empty");
        }

        float min_x = 1e30f, min_y = 1e30f, min_z = 1e30f;
        float max_x = -1e30f, max_y = -1e30f, max_z = -1e30f;

        for (int i = 0; i < pt_count; i++) {
            cJSON *pt = cJSON_GetArrayItem(points_item, i);
            cJSON *px = cJSON_GetObjectItem(pt, "x");
            cJSON *py = cJSON_GetObjectItem(pt, "y");
            cJSON *pz = cJSON_GetObjectItem(pt, "z");
            if (px && py && pz && cJSON_IsNumber(px) && cJSON_IsNumber(py) && cJSON_IsNumber(pz)) {
                float vx = (float)px->valuedouble;
                float vy = (float)py->valuedouble;
                float vz = (float)pz->valuedouble;
                if (vx < min_x) min_x = vx;
                if (vy < min_y) min_y = vy;
                if (vz < min_z) min_z = vz;
                if (vx > max_x) max_x = vx;
                if (vy > max_y) max_y = vy;
                if (vz > max_z) max_z = vz;
            }
        }

        float extent_x = max_x - min_x;
        float extent_y = max_y - min_y;
        float extent_z = max_z - min_z;
        float max_extent = extent_x > extent_y ? extent_x : extent_y;
        if (extent_z > max_extent) max_extent = extent_z;
        float scale = max_extent > 1e-6f ? (65535.0f / max_extent) : 0.0f;

        cJSON *out_pts = cJSON_CreateArray();
        for (int i = 0; i < pt_count; i++) {
            cJSON *pt = cJSON_GetArrayItem(points_item, i);
            cJSON *px = cJSON_GetObjectItem(pt, "x");
            cJSON *py = cJSON_GetObjectItem(pt, "y");
            cJSON *pz = cJSON_GetObjectItem(pt, "z");
            float vx = (px && cJSON_IsNumber(px)) ? (float)px->valuedouble : 0.0f;
            float vy = (py && cJSON_IsNumber(py)) ? (float)py->valuedouble : 0.0f;
            float vz = (pz && cJSON_IsNumber(pz)) ? (float)pz->valuedouble : 0.0f;

            uint32_t qx = (uint32_t)((vx - min_x) * scale + 0.5f);
            uint32_t qy = (uint32_t)((vy - min_y) * scale + 0.5f);
            uint32_t qz = (uint32_t)((vz - min_z) * scale + 0.5f);

            uint64_t bitx = qx & 0x000fffffULL;
            bitx = (bitx ^ (bitx << 32)) & 0x000f00000000ffffULL;
            bitx = (bitx ^ (bitx << 16)) & 0x000f0000ff0000ffULL;
            bitx = (bitx ^ (bitx << 8))  & 0x000f00f00f00f00fULL;
            bitx = (bitx ^ (bitx << 4))  & 0x00c30c30c30c30c3ULL;
            bitx = (bitx ^ (bitx << 2))  & 0x0249249249249249ULL;

            uint64_t bity = qy & 0x000fffffULL;
            bity = (bity ^ (bity << 32)) & 0x000f00000000ffffULL;
            bity = (bity ^ (bity << 16)) & 0x000f0000ff0000ffULL;
            bity = (bity ^ (bity << 8))  & 0x000f00f00f00f00fULL;
            bity = (bity ^ (bity << 4))  & 0x00c30c30c30c30c3ULL;
            bity = (bity ^ (bity << 2))  & 0x0249249249249249ULL;

            uint64_t bitz = qz & 0x000fffffULL;
            bitz = (bitz ^ (bitz << 32)) & 0x000f00000000ffffULL;
            bitz = (bitz ^ (bitz << 16)) & 0x000f0000ff0000ffULL;
            bitz = (bitz ^ (bitz << 8))  & 0x000f00f00f00f00fULL;
            bitz = (bitz ^ (bitz << 4))  & 0x00c30c30c30c30c3ULL;
            bitz = (bitz ^ (bitz << 2))  & 0x0249249249249249ULL;

            uint64_t mcode = bitx | (bity << 1) | (bitz << 2);

            cJSON *res_pt = cJSON_CreateObject();
            cJSON_AddNumberToObject(res_pt, "index", i);
            cJSON_AddNumberToObject(res_pt, "x", vx);
            cJSON_AddNumberToObject(res_pt, "y", vy);
            cJSON_AddNumberToObject(res_pt, "z", vz);
            cJSON_AddNumberToObject(res_pt, "morton_code", (double)mcode);
            cJSON_AddItemToArray(out_pts, res_pt);
        }

        cJSON *res_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(res_obj, "action", "batch_order");
        cJSON_AddNumberToObject(res_obj, "point_count", pt_count);

        cJSON *aabb = cJSON_CreateObject();
        cJSON_AddNumberToObject(aabb, "min_x", min_x);
        cJSON_AddNumberToObject(aabb, "min_y", min_y);
        cJSON_AddNumberToObject(aabb, "min_z", min_z);
        cJSON_AddNumberToObject(aabb, "max_x", max_x);
        cJSON_AddNumberToObject(aabb, "max_y", max_y);
        cJSON_AddNumberToObject(aabb, "max_z", max_z);
        cJSON_AddNumberToObject(aabb, "extent", max_extent);
        cJSON_AddItemToObject(res_obj, "aabb", aabb);
        cJSON_AddItemToObject(res_obj, "points", out_pts);

        char *json_str = cJSON_PrintUnformatted(res_obj);
        cJSON_Delete(res_obj);
        sds out = sdsnew(json_str);
        free(json_str);
        return out;
    }
    if (strcmp(name, "checksum") == 0) {
        const char *algo = cJSON_GetStringValue(cJSON_GetObjectItem(args, "algorithm"));
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!algo)
            return sdsnew("ERROR: algorithm required for checksum (crc32, adler32, fnv1a64)");
        if (strcmp(algo, "crc32") != 0 && strcmp(algo, "adler32") != 0 &&
            strcmp(algo, "fnv1a64") != 0)
            return sdscatprintf(sdsempty(),
                "ERROR: unknown checksum algorithm %s (use crc32, adler32, or fnv1a64)", algo);

        uint8_t *decoded = NULL;
        const uint8_t *buf;
        size_t len;
        if (data_hex) {
            int rc = checksum_hex_decode(data_hex, &decoded, &len);
            if (rc == -1)
                return sdsnew("ERROR: hex data length must be an even number of characters");
            if (rc != 0)
                return sdsnew("ERROR: data contains non-hex characters");
            buf = decoded;
        } else if (text) {
            buf = (const uint8_t *)text;
            len = strlen(text);
        } else {
            return sdsnew("ERROR: data (hex) or text input required for checksum");
        }

        sds out;
        if (strcmp(algo, "crc32") == 0) {
            uint32_t v = checksum_crc32(buf, len);
            out = sdscatprintf(sdsempty(),
                "{\"action\":\"checksum\",\"algorithm\":\"crc32\",\"input_bytes\":%zu,"
                "\"value\":%lu,\"hex\":\"%08lx\"}",
                len, (unsigned long)v, (unsigned long)v);
        } else if (strcmp(algo, "adler32") == 0) {
            uint32_t v = checksum_adler32(buf, len);
            out = sdscatprintf(sdsempty(),
                "{\"action\":\"checksum\",\"algorithm\":\"adler32\",\"input_bytes\":%zu,"
                "\"value\":%lu,\"hex\":\"%08lx\"}",
                len, (unsigned long)v, (unsigned long)v);
        } else {
            uint64_t v = checksum_fnv1a64(buf, len);
            out = sdscatprintf(sdsempty(),
                "{\"action\":\"checksum\",\"algorithm\":\"fnv1a64\",\"input_bytes\":%zu,"
                "\"value\":%llu,\"hex\":\"%016llx\"}",
                len, (unsigned long long)v, (unsigned long long)v);
        }
        free(decoded);
        return out;
    }
    if (strcmp(name, "intset") == 0 || strcmp(name, "intset_ops") == 0) {
        const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
        if (!action) action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "op"));
        if (!action) return sdsnew("ERROR: intset requires action: create|add|remove|get|find|random|stats");
        for (const char *p = action; *p; p++) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_' ))
                return sdscatprintf(sdsempty(), "ERROR: invalid action '%s'", action);
        }

        if (strcmp(action, "create") == 0 || strcmp(action, "add") == 0) {
            const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
            cJSON *vals = cJSON_GetObjectItem(args, "values");
            cJSON *val_single = cJSON_GetObjectItem(args, "value");
            if (vals && !cJSON_IsArray(vals)) return sdsnew("ERROR: values must be an array");
            if (!vals && !val_single && !data_hex) {
                if (strcmp(action, "add") == 0) return sdsnew("ERROR: add requires 'value' or 'values'");
            }
            unsigned char *buf = NULL;
            size_t cur_n = 0;
            uint32_t enc = IST_ENC_INT16, len = 0;
            if (data_hex) {
                size_t hlen = strlen(data_hex);
                if (hlen == 0 || hlen % 2 != 0) return sdsnew("ERROR: data must be even-length hex string");
                for (size_t i = 0; i < hlen; i++) if (!isxdigit((unsigned char)data_hex[i])) return sdsnew("ERROR: data contains non-hex character");
                size_t buf_n = 0;
                buf = ist_hex_decode(data_hex, &buf_n);
                if (!buf) return sdsnew("ERROR: failed to decode data hex");
                if (!ist_parse_header(buf, buf_n, &enc, &len)) { free(buf); return sdsnew("ERROR: data header invalid"); }
                cur_n = buf_n;
            } else {
                buf = malloc(IST_HDR);
                if (!buf) return sdsnew("ERROR: allocation failed");
                ist_header(buf, IST_ENC_INT16, 0);
                cur_n = IST_HDR; enc = IST_ENC_INT16; len = 0;
            }
            int total_added = 0;
            if (vals && cJSON_IsArray(vals)) {
                int n = cJSON_GetArraySize(vals);
                if ((uint64_t)len + (uint64_t)n > IST_MAX_ENTRIES) { free(buf); return sdsnew("ERROR: add would exceed max entries"); }
                for (int i = 0; i < n; i++) {
                    int64_t v;
                    if (!ist_arg_int(cJSON_GetArrayItem(vals, i), &v)) { free(buf); return sdsnew("ERROR: values must be integers"); }
                    int added=0; unsigned char *nb = ist_add(buf, cur_n, v, &added);
                    if (!nb) { free(buf); return sdsnew("ERROR: allocation failed during add"); }
                    buf = nb; if (added) total_added++;
                    uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                }
            } else if (val_single) {
                int64_t v;
                if (!ist_arg_int(val_single, &v)) { free(buf); return sdsnew("ERROR: value must be integer"); }
                if (len + 1 > IST_MAX_ENTRIES) { free(buf); return sdsnew("ERROR: add would exceed max entries"); }
                int added=0; unsigned char *nb = ist_add(buf, cur_n, v, &added);
                if (!nb) { free(buf); return sdsnew("ERROR: allocation failed"); }
                buf = nb; if (added) total_added++;
                ist_read_header_raw(buf,&enc,&len); cur_n = IST_HDR + (size_t)len*enc;
            }
            sds hex = ist_hex_encode(buf, cur_n);
            const char *enc_s = enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64";
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"%s\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"added\":%d,\"values\":[", action, enc_s, len, len, total_added);
            for (uint32_t i=0;i<len;i++) {
                int64_t v = ist_get(buf, enc, i);
                out = sdscatprintf(out, "%s%lld", i?",":"", (long long)v);
            }
            out = sdscatprintf(out, "],\"data\":\"%s\"}", hex);
            sdsfree(hex); free(buf);
            return out;
        }
        if (strcmp(action, "remove") == 0) {
            const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
            cJSON *vals = cJSON_GetObjectItem(args, "values");
            cJSON *targets = cJSON_GetObjectItem(args, "targets");
            cJSON *val_single = cJSON_GetObjectItem(args, "value");
            unsigned char *buf = NULL;
            size_t cur_n = 0;
            uint32_t enc=0, len=0;
            cJSON *remove_list = NULL;
            int use_targets = 0;
            if (data_hex) {
                size_t hlen = strlen(data_hex);
                if (hlen == 0 || hlen % 2 != 0) return sdsnew("ERROR: data must be even-length hex string");
                for (size_t i = 0; i < hlen; i++) if (!isxdigit((unsigned char)data_hex[i])) return sdsnew("ERROR: data contains non-hex character");
                size_t buf_n=0;
                buf = ist_hex_decode(data_hex, &buf_n);
                if (!buf) return sdsnew("ERROR: failed to decode data hex");
                if (!ist_parse_header(buf, buf_n, &enc, &len)) { free(buf); return sdsnew("ERROR: data header invalid"); }
                cur_n = buf_n;
                if (vals && cJSON_IsArray(vals)) remove_list = vals;
                else if (val_single) remove_list = NULL;
                else if (targets && cJSON_IsArray(targets)) remove_list = targets;
                else return sdsnew("ERROR: remove requires 'value' or 'values'");
            } else {
                if (!vals || !cJSON_IsArray(vals)) return sdsnew("ERROR: remove requires 'values' array as base set");
                buf = malloc(IST_HDR);
                if (!buf) return sdsnew("ERROR: allocation failed");
                ist_header(buf, IST_ENC_INT16, 0);
                cur_n = IST_HDR; enc = IST_ENC_INT16; len = 0;
                int nbase = cJSON_GetArraySize(vals);
                for (int i=0;i<nbase;i++) {
                    int64_t v; if (!ist_arg_int(cJSON_GetArrayItem(vals,i),&v)) { free(buf); return sdsnew("ERROR: values must be integers"); }
                    int added=0; unsigned char *nb = ist_add(buf, cur_n, v, &added);
                    if (!nb) { free(buf); return sdsnew("ERROR: allocation failed"); }
                    buf=nb; uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                }
                if (targets && cJSON_IsArray(targets)) { remove_list = targets; use_targets=1; }
                else if (val_single) remove_list = NULL;
                else { free(buf); return sdsnew("ERROR: remove requires 'targets' array when using stateless values base"); }
            }
            sds removed_json = sdsnew("[");
            int first = 1;
            if (remove_list) {
                int n = cJSON_GetArraySize(remove_list);
                for (int i=0;i<n;i++) {
                    int64_t v; if (!ist_arg_int(cJSON_GetArrayItem(remove_list,i),&v)) { free(buf); sdsfree(removed_json); return sdsnew("ERROR: values must be integers"); }
                    int removed=0; unsigned char *nb = ist_remove(buf, cur_n, v, &removed);
                    buf = nb;
                    uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                    if (cur_n==IST_HDR) { enc=IST_ENC_INT16; len=0; }
                    if (!first) removed_json = sdscat(removed_json, ",");
                    removed_json = sdscat(removed_json, removed ? "true" : "false");
                    first = 0;
                }
            } else {
                cJSON *single = val_single ? val_single : cJSON_GetObjectItem(args, "target");
                if (!single) single = use_targets ? NULL : vals;
                int64_t v; if (!ist_arg_int(single,&v)) { free(buf); sdsfree(removed_json); return sdsnew("ERROR: value must be integer"); }
                int removed=0; unsigned char *nb = ist_remove(buf, cur_n, v, &removed);
                buf = nb;
                uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                removed_json = sdscat(removed_json, removed ? "true" : "false");
            }
            removed_json = sdscat(removed_json, "]");
            sds hex = ist_hex_encode(buf, cur_n);
            const char *enc_s = enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64";
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"remove\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"removed\":%s,\"data\":\"%s\",\"values\":[", enc_s, len, len, removed_json, hex);
            sdsfree(removed_json); sdsfree(hex);
            for (uint32_t i=0;i<len;i++) {
                int64_t v = ist_get(buf, enc, i);
                out = sdscatprintf(out, "%s%lld", i?",":"", (long long)v);
            }
            out = sdscatprintf(out, "]}");
            free(buf);
            return out;
        }
        {
            const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
            unsigned char *buf = NULL;
            size_t buf_n = 0;
            uint32_t enc=0, len=0;
            if (data_hex) {
                size_t hlen = strlen(data_hex);
                if (hlen == 0 || hlen % 2 != 0) return sdsnew("ERROR: data must be even-length hex string");
                for (size_t i = 0; i < hlen; i++) if (!isxdigit((unsigned char)data_hex[i])) return sdsnew("ERROR: data contains non-hex character");
                buf = ist_hex_decode(data_hex, &buf_n);
                if (!buf) return sdsnew("ERROR: failed to decode data hex");
                if (!ist_parse_header(buf, buf_n, &enc, &len)) { free(buf); return sdsnew("ERROR: data header invalid"); }
            } else {
                cJSON *vals = cJSON_GetObjectItem(args, "values");
                if (!vals) {
                    if (strcmp(action,"get")==0) return sdsnew("ERROR: get requires 'values' array or data");
                    if (strcmp(action,"find")==0 || strcmp(action,"contains")==0) return sdsnew("ERROR: find requires 'values' array or data");
                    if (strcmp(action,"random")==0 || strcmp(action,"rand")==0) return sdsnew("ERROR: random on empty intset");
                }
                if (vals && !cJSON_IsArray(vals)) return sdsnew("ERROR: values must be an array");
                buf = malloc(IST_HDR);
                if (!buf) return sdsnew("ERROR: allocation failed");
                ist_header(buf, IST_ENC_INT16, 0);
                buf_n = IST_HDR; enc = IST_ENC_INT16; len = 0;
                if (vals && cJSON_IsArray(vals)) {
                    int n = cJSON_GetArraySize(vals);
                    for (int i=0;i<n;i++) {
                        int64_t v; if (!ist_arg_int(cJSON_GetArrayItem(vals,i),&v)) { free(buf); return sdsnew("ERROR: values must be integers"); }
                        int added=0; unsigned char *nb = ist_add(buf, buf_n, v, &added);
                        if (!nb) { free(buf); return sdsnew("ERROR: allocation failed"); }
                        buf = nb; uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); buf_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                    }
                }
            }
            if (strcmp(action, "get") == 0) {
                cJSON *idx_item = cJSON_GetObjectItem(args, "index");
                if (!cJSON_IsNumber(idx_item)) { free(buf); return sdsnew("ERROR: get requires numeric 'index'"); }
                double d = idx_item->valuedouble;
                if (d < 0) { free(buf); return sdsnew("ERROR: index must be non-negative for intset get"); }
                if ((double)(int64_t)d != d) { free(buf); return sdsnew("ERROR: index must be integral"); }
                int64_t idx = (int64_t)d;
                if ((uint64_t)idx >= (uint64_t)len) { free(buf); return sdsnew("ERROR: index out of bounds for intset get"); }
                int64_t v = ist_get(buf, enc, (uint32_t)idx);
                sds out = sdscatprintf(sdsempty(), "{\"action\":\"get\",\"index\":%lld,\"value\":%lld,\"encoding\":\"%s\"}", (long long)idx, (long long)v, enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64");
                free(buf); return out;
            }
            if (strcmp(action, "find") == 0 || strcmp(action, "contains") == 0) {
                cJSON *val_item = cJSON_GetObjectItem(args, "value");
                if (!val_item) val_item = cJSON_GetObjectItem(args, "target");
                if (!val_item) { free(buf); return sdsnew("ERROR: find requires 'value'"); }
                int64_t v; if (!ist_arg_int(val_item,&v)) { free(buf); return sdsnew("ERROR: value must be integer"); }
                uint32_t pos=0; int found = ist_search(buf, enc, len, v, &pos);
                int64_t idx_out = found ? (int64_t)pos : -1;
                sds out = sdscatprintf(sdsempty(), "{\"action\":\"find\",\"value\":%lld,\"found\":%s,\"index\":%lld}", (long long)v, found?"true":"false", (long long)idx_out);
                free(buf); return out;
            }
            if (strcmp(action, "random") == 0 || strcmp(action, "rand") == 0) {
                if (len == 0) { free(buf); return sdsnew("ERROR: random on empty intset"); }
                int64_t seed = 0;
                cJSON *seed_item = cJSON_GetObjectItem(args, "seed");
                if (seed_item) {
                    if (!ist_arg_int(seed_item,&seed)) { free(buf); return sdsnew("ERROR: seed must be integer"); }
                    if (seed < 0) { free(buf); return sdsnew("ERROR: seed must be non-negative"); }
                } else {
                    seed = (int64_t)(time(NULL) ^ (intptr_t)buf);
                    if (seed < 0) seed = -seed;
                }
                uint64_t x = (uint64_t)seed + 0x9e3779b97f4a7c15ULL;
                x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
                x *= 0x2545F4914F6CDD1DULL;
                uint32_t idx = (uint32_t)(x % len);
                int64_t v = ist_get(buf, enc, idx);
                sds out = sdscatprintf(sdsempty(), "{\"action\":\"random\",\"index\":%u,\"value\":%lld}", idx, (long long)v);
                free(buf); return out;
            }
            if (strcmp(action, "stats") == 0 || strcmp(action, "info") == 0) {
                const char *enc_s = enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64";
                sds out = sdscatprintf(sdsempty(), "{\"action\":\"stats\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"bytes\":%zu", enc_s, len, len, buf_n);
                if (len > 0) {
                    int64_t mn = ist_get(buf, enc, 0);
                    int64_t mx = ist_get(buf, enc, len-1);
                    out = sdscatprintf(out, ",\"min\":%lld,\"max\":%lld", (long long)mn, (long long)mx);
                }
                out = sdscat(out, "}");
                free(buf); return out;
            }
            if (strcmp(action, "list") == 0 || strcmp(action, "dump") == 0) {
                sds out = sdscatprintf(sdsempty(), "{\"action\":\"list\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"values\":[", enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64", len, len);
                for (uint32_t i=0;i<len;i++) {
                    int64_t v = ist_get(buf, enc, i);
                    out = sdscatprintf(out, "%s%lld", i?",":"", (long long)v);
                    if (sdslen(out) > 8000) { out = sdscat(out, "]"); break; }
                }
                if (len <= 8000) out = sdscat(out, "]");
                out = sdscat(out, "}");
                free(buf); return out;
            }
            free(buf);
            return sdscatprintf(sdsempty(), "ERROR: unknown intset action '%s'", action);
        }
    }
    return sdscatprintf(sdsempty(), "ERROR: unknown tool %s", name);
}

cJSON *tools_schema(void) {
    const char *json =
        "["
        "{\"type\":\"function\",\"function\":{\"name\":\"execute_powershell\","
        "\"description\":\"Execute PowerShell 7+ via pwsh (pipelines, objects, scripts). macOS.\","
        "\"parameters\":{\"type\":\"object\",\"properties\":{"
        "\"command\":{\"type\":\"string\",\"description\":\"PowerShell command or script to run\"}},\"required\":[\"command\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"execute_bash\","
        "\"description\":\"Run any shell command (open; no sandbox).\","
        "\"parameters\":{\"type\":\"object\",\"properties\":{"
        "\"command\":{\"type\":\"string\"}},\"required\":[\"command\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"read_file\","
        "\"description\":\"Read a file (any path).\",\"parameters\":{\"type\":\"object\",\"properties\":{"
        "\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"write_file\","
        "\"description\":\"Write full file contents (creates parents).\",\"parameters\":{\"type\":\"object\",\"properties\":{"
        "\"path\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"}},\"required\":[\"path\",\"content\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"edit_file\","
        "\"description\":\"Replace unique old_str with new_str in file.\","
        "\"parameters\":{\"type\":\"object\",\"properties\":{"
        "\"path\":{\"type\":\"string\"},\"old_str\":{\"type\":\"string\"},\"new_str\":{\"type\":\"string\"}},"
        "\"required\":[\"path\",\"old_str\",\"new_str\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"list_dir\","
        "\"description\":\"List directory entries (any path).\",\"parameters\":{\"type\":\"object\",\"properties\":{"
        "\"path\":{\"type\":\"string\"}}}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"browser\",\"description\":\"Pure-C browser. ONE sticky CDP tab. Loop: status/tabs -> open/navigate -> snapshot -> click/type/press/eval. close_others cleans junk. NEVER bash for click. Login/OAuth: snapshot+one click then stop. PROOF required.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\"},\"url\":{\"type\":\"string\"},\"selector\":{\"type\":\"string\"},\"text\":{\"type\":\"string\"},\"expression\":{\"type\":\"string\"},\"tab_id\":{\"type\":\"string\"},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"phone\",\"description\":\"Control an Android phone over ADB (Termux: adb connect localhost:<port> after enabling wireless debugging). Loop: see -> tap/type/swipe -> see again. 'see' returns the screen's UI tree as XML — pick tap coordinates from the centre of an element's bounds=\\\"[l,t][r,b]\\\". Actions: see, shot (PNG screenshot, returns path), tap x y, swipe x1 y1 x2 y2 [ms], type text (newlines = ENTER), key back|home|enter|recents|tab|del|power, open package, apps (list user apps).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\"},\"text\":{\"type\":\"string\"},\"package\":{\"type\":\"string\"},\"key\":{\"type\":\"string\"},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"x1\":{\"type\":\"number\"},\"y1\":{\"type\":\"number\"},\"x2\":{\"type\":\"number\"},\"y2\":{\"type\":\"number\"},\"ms\":{\"type\":\"number\"}},\"required\":[\"action\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"web_search\",\"description\":\"Search the web via DuckDuckGo HTML (no API key, no JS). Returns title, URL, and snippet for each result. Fast: one HTTP GET, ~0.5-2s.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Search query\"},\"max_results\":{\"type\":\"integer\",\"description\":\"Max results (1-20, default 10)\"}},\"required\":[\"query\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"todo\",\"description\":\"Manage task list for current session. Omit todos to read, provide todos array to create/update items. Each item: {id, content, status: pending|in_progress|completed|cancelled}. merge=true updates by id.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"todos\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"},\"status\":{\"type\":\"string\"}},\"required\":[\"id\",\"content\",\"status\"]}},\"merge\":{\"type\":\"boolean\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"memory\",\"description\":\"Persistent curated memory that survives across sessions. Two stores: 'memory' for your notes (environment facts, conventions, lessons) and 'user' for user profile (preferences, style). Entries are §-delimited. Actions: add (append), replace (substring match), remove (substring match). Omit action to read current entries. Character limits: 2200 (memory), 1375 (user).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"add\",\"replace\",\"remove\"]},\"target\":{\"type\":\"string\",\"enum\":[\"memory\",\"user\"],\"description\":\"Which store: 'memory' (default) or 'user'\"},\"content\":{\"type\":\"string\",\"description\":\"Entry content for add/replace\"},\"old_text\":{\"type\":\"string\",\"description\":\"Substring identifying the entry for replace/remove\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"code_search\",\"description\":\"Field-qualified code search. Query like kind:function name:auth path:src/api authenticate splits into structured filters plus free text. Args: query (required), path, recursive, max_results.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Field-qualified query, e.g. kind:function name:auth\"},\"path\":{\"type\":\"string\",\"description\":\"File or directory to search (default .)\"},\"recursive\":{\"type\":\"boolean\"},\"max_results\":{\"type\":\"integer\",\"description\":\"Max results (default 1000)\"}},\"required\":[\"query\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"layout_solver\",\"description\":\"Dynamic 2D Vector Geometry & Binary Space Partitioning (BSP) Tree Layout Solver from Hyprland. Actions: 'bsp' (computes non-overlapping tiled rectangular bounding boxes for canvas width/height/count), 'bezier' (computes cubic Bézier easing curves for animation keyframes).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"bsp\",\"bezier\"]},\"width\":{\"type\":\"integer\"},\"height\":{\"type\":\"integer\"},\"count\":{\"type\":\"integer\"},\"t\":{\"type\":\"number\"},\"p1x\":{\"type\":\"number\"},\"p1y\":{\"type\":\"number\"},\"p2x\":{\"type\":\"number\"},\"p2y\":{\"type\":\"number\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"hex_pattern_search\",\"description\":\"Fast In-Memory Byte Signature & Wildcard Hex Pattern Scanner from RevokeMsgPatcher. Scans raw hex byte buffers with exact and ?? wildcard masks (e.g. '55 8B ?? 83 EC ?? '). Returns matching offset indexes.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded binary buffer string\"},\"pattern\":{\"type\":\"string\",\"description\":\"Hex pattern with optional ?? wildcards (e.g. '48 89 ?? 55')\"}},\"required\":[\"data\",\"pattern\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"binary_patch_apply\",\"description\":\"Safe In-Memory Binary Byte Patcher from RevokeMsgPatcher. Applies replacement byte hex sequences at specified offsets with bounds checking and original byte rollback capture.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\",\"description\":\"Original hex-encoded binary buffer\"},\"offset\":{\"type\":\"integer\",\"description\":\"Byte offset where patch should be applied\"},\"patch\":{\"type\":\"string\",\"description\":\"Hex replacement bytes to write at offset\"}},\"required\":[\"data\",\"offset\",\"patch\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"boyer_moore_search\",\"description\":\"High-Performance Boyer-Moore Substring Search Algorithm with Bad Character and Good Suffix Shift Heuristics from RevokeMsgPatcher. Scans large text buffers in sublinear O(N/M) time complexity.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"Target haystack text to search within\"},\"pattern\":{\"type\":\"string\",\"description\":\"Needle substring to match\"}},\"required\":[\"text\",\"pattern\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"multi_hex_edit\",\"description\":\"Atomic Multi-Location Binary Hex Patching Engine from RevokeMsgPatcher. Applies an array of multiple offset modifications transactionally with all-or-nothing validation and structured per-patch rollback logs.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\",\"description\":\"Original hex-encoded binary buffer\"},\"changes\":{\"type\":\"array\",\"description\":\"Array of change objects: [{'offset': 0, 'patch': '9090'}]\"}},\"required\":[\"data\",\"changes\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"mdesk_tokenize\",\"description\":\"Fast Metadesk Lexer & Code Tokenizer from EpicGames/raddebugger. Scans text, C/C++ code, and DSLs into structured tokens with identifiers, numerics, strings, triplet quotes, symbols, comments, and offset spans.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"Source code or data text to tokenize\"},\"skip_whitespace\":{\"type\":\"boolean\",\"description\":\"Filter out whitespace and newline tokens (default true)\"}},\"required\":[\"text\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"cpp_symbol_extract\",\"description\":\"Fast C/C++ AST Symbol Extractor from colbymchenry/codegraph. Scans source code and extracts functions, qualified methods (Class::method), classes, structs, enums, macros, and include headers.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"C/C++ source code text to analyze\"}},\"required\":[\"text\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"mesh_spatial_codec\",\"description\":\"Fast 3D Morton Space-Filling Curve & Spatial Quantizer from zeux/meshoptimizer. Actions: 'morton' (encodes 3D coordinates into 64-bit interleaved Z-order Morton spatial codes), 'batch_order' (computes AABB 3D bounding box and spatial codes for vertex arrays), 'half_float' (quantizes 32-bit floats to 16-bit IEEE-754 half floats with denormal flush and NaN preservation).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"morton\",\"batch_order\",\"half_float\"]},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"z\":{\"type\":\"number\"},\"value\":{\"type\":\"number\"},\"points\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"z\":{\"type\":\"number\"}}}}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"working_diff\",\"description\":\"Collect a git diff of the working directory. Modes: 'working' (unstaged + untracked, default), 'staged' (git diff --cached), 'all' (everything since HEAD + untracked). Untracked files are shown as new-file diffs via git diff --no-index /dev/null <file>. Returns the diff as text.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"mode\":{\"type\":\"string\",\"enum\":[\"working\",\"staged\",\"all\"],\"description\":\"Diff mode: working (default), staged, or all\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"checksum\",\"description\":\"Fast Checksum & Hash Suite from FFmpeg. Computes CRC-32 (IEEE reflected), Adler-32, and FNV-1a 64-bit digests over hex-encoded binary buffers or raw text.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"algorithm\":{\"type\":\"string\",\"enum\":[\"crc32\",\"adler32\",\"fnv1a64\"],\"description\":\"Digest algorithm\"},\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded binary buffer to digest\"},\"text\":{\"type\":\"string\",\"description\":\"Raw text to digest (used when data is absent)\"}},\"required\":[\"algorithm\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"intset\",\"description\":\"Compact sorted integer set ported from redis/src/intset.c. Auto-upgrades encoding int16→int32→int64. Serialized as 8-byte LE header + packed elements, hex-encoded. Actions: create, add, remove, get, find, random, stats, list.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"create\",\"add\",\"remove\",\"get\",\"find\",\"random\",\"stats\",\"list\"],\"description\":\"Operation\"},\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded intset blob\"},\"value\":{\"type\":\"string\",\"description\":\"Single integer value\"},\"values\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Array of integer values\"},\"index\":{\"type\":\"integer\",\"description\":\"Positional index for get\"},\"seed\":{\"type\":\"integer\",\"description\":\"Seed for random\"}},\"required\":[\"action\"]}}}"
        "]";
    return cJSON_Parse(json);
}
