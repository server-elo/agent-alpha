#include "alpha.h"
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <regex.h>
#include <fnmatch.h>
#include <curl/curl.h>
#include <sys/file.h>
#include <math.h>

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
 * Modular Tool Subsystems (Table-Driven Registry for 100+ Tools)
 * ====================================================================== */
#include "tools/tool_shell.c"
#include "tools/tool_fs.c"
#include "tools/tool_todo.c"
#include "tools/tool_memory.c"
#include "tools/tool_search.c"
#include "tools/tool_git.c"
#include "tools/tool_patch.c"
#include "tools/tool_layout.c"
#include "tools/tool_phone.c"
#include "tools/tool_browser.c"
#include "tools/tool_math_expr.c"
#include "tools/tool_peg_match.c"
#include "tools/tool_geom_spatial.c"
#include "tools/tool_url_codec.c"
#include "tools/tool_code_clone.c"
#include "tools/tool_intset.c"
#include "tools/tool_checksum.c"
#include "tools/tool_mesh_spatial.c"
#include "tools/tool_cpp_symbol.c"
#include "tools/tool_mdesk.c"
#include "tools/tool_binary.c"
#include "tools/tool_codecs.c"
#include "tools/tool_json_query.c"
#include "tools/tool_benchmark.c"
#include "tools/tool_mqtt.c"
#include "tools/tool_string_distance.c"
#include "tools/tool_stats.c"
#include "tools/tool_csv.c"
#include "tools/tool_ebnf.c"
#include "tools/tool_graph.c"
#include "tools/tool_semver.c"
#include "tools/tool_duration.c"
#include "tools/tool_der.c"
#include "tools/tool_linkage.c"
#include "tools/tool_railroad.c"
#include "tools/tool_resp.c"
#include "tools/tool_rules.c"
#include "tools/tool_scope_check.c"
#include "tools/tool_timecode.c"
#include "tools/tool_tokenizer.c"
#include "tools/tool_tswindow.c"
#include "tools/tool_wildmatch.c"
#include "tools/tool_colormap.c"
#include "tools/tool_html_codec.c"
#include "tools/tool_colormath.c"
#include "tools/tool_imhex_struct.c"
#include "tools/tool_bezier_easing.c"
#include "tools/tool_hll.c"
#include "tools/tool_gorilla.c"
#include "tools/tool_scc_dag.c"
#include "tools/tool_fse_ans.c"
#include "tools/tool_toolsearch.c"

/* Master Registry Table for all modular C11 tools */
static const alpha_tool_t *g_registered_tools[] = {
    &tool_bash,
    &tool_powershell,
    &tool_read_file,
    &tool_write_file,
    &tool_edit_file,
    &tool_list_dir,
    &tool_browser,
    &tool_phone,
    &tool_web_search,
    &tool_web_fetch,
    &tool_web_browse,
    &tool_web_fetch_parallel,
    &tool_web_job,
    &tool_github_search,
    &tool_todo,
    &tool_memory,
    &tool_code_search,
    &tool_working_diff,
    &tool_patch,
    &tool_layout_solver,
    &tool_math_expr,
    &tool_peg_match,
    &tool_geom_spatial,
    &tool_url_codec,
    &tool_code_clone,
    &tool_intset,
    &tool_checksum,
    &tool_mesh_spatial,
    &tool_cpp_symbol,
    &tool_mdesk,
    &tool_hex_pattern_search,
    &tool_binary_patch_apply,
    &tool_boyer_moore_search,
    &tool_multi_hex_edit,
    &tool_base64_codec,
    &tool_json_query,
    &tool_benchmark,
    &tool_mqtt,
    &tool_string_distance,
    &tool_stats,
    &tool_csv,
    &tool_ebnf,
    &tool_graph,
    &tool_semver,
    &tool_duration,
    &tool_der,
    &tool_linkage,
    &tool_railroad,
    &tool_resp,
    &tool_rules,
    &tool_scope_check,
    &tool_timecode,
    &tool_tokenizer,
    &tool_tswindow,
    &tool_wildmatch,
    &tool_colormap,
    &tool_html_codec,
    &tool_colormath,
    &tool_imhex_struct,
    &tool_bezier_easing,
    &tool_hll,
    &tool_gorilla,
    &tool_scc_dag,
    &tool_fse_ans,
    &tool_search_tools,
    &tool_describe_tools,
    NULL
};

/* ======================================================================
 * Runtime tool registry, schema cache, BM25 search and windowed delivery
 * ======================================================================
 *
 * g_registered_tools[] above is only the bootstrap manifest. Everything —
 * dispatch, schema, search — reads the runtime registry below: an
 * open-addressing FNV-1a hash from name/alias to registry entry. The registry
 * is populated lazily on first use, so lookup cost is O(1) no matter how large
 * the catalog grows (the linear scan it replaced was O(n) per tool call, and
 * tools_schema() re-parsed every schema_json literal on EVERY LLM request). */

typedef struct {
    const alpha_tool_t *tool;
    cJSON *schema;      /* schema_json parsed once, on first schema access */
    char **toks;        /* BM25 index: lowercase tokens, built on first search */
    double *tokw;       /* per-token field weight: name/alias 3, category 2, desc 1 */
    int ntok;
    double doclen;      /* sum of tokw — the BM25 document length */
} tool_entry_t;

static tool_entry_t *g_entries;
static int g_nentries;
static int g_entries_cap;

static const char **g_hkey;     /* slot key — points into the tool's own strings */
static int *g_hent;             /* slot value: index into g_entries */
static size_t g_hcap;           /* power of two, 0 = not yet allocated */
static int g_hused;

static cJSON *g_schema_cache;           /* full schema array; NULL = dirty */
static const alpha_tool_t **g_all_cache;
static int g_all_count = -1;

static int g_registry_booted;
static void tools_registry_boot(void);

static uint32_t tool_hash(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

static int reg_lookup(const char *key) {
    if (!g_hcap) return -1;
    size_t i = tool_hash(key) & (g_hcap - 1);
    while (g_hkey[i]) {
        if (strcmp(g_hkey[i], key) == 0) return g_hent[i];
        i = (i + 1) & (g_hcap - 1);
    }
    return -1;
}

static void reg_slot_insert(const char **keys, int *ents, size_t cap,
                            const char *key, int ent) {
    size_t i = tool_hash(key) & (cap - 1);
    while (keys[i]) i = (i + 1) & (cap - 1);
    keys[i] = key;
    ents[i] = ent;
}

static void reg_insert(const char *key, int ent) {
    /* grow at 70% load */
    if ((size_t)(g_hused + 1) * 10 >= g_hcap * 7) {
        size_t ncap = g_hcap ? g_hcap * 2 : 128;
        const char **nk = calloc(ncap, sizeof(*nk));
        int *ne = malloc(ncap * sizeof(*ne));
        if (!nk || !ne) { free(nk); free(ne); return; }
        for (size_t i = 0; i < g_hcap; i++)
            if (g_hkey[i]) reg_slot_insert(nk, ne, ncap, g_hkey[i], g_hent[i]);
        free(g_hkey);
        free(g_hent);
        g_hkey = nk;
        g_hent = ne;
        g_hcap = ncap;
    }
    reg_slot_insert(g_hkey, g_hent, g_hcap, key, ent);
    g_hused++;
}

/* Registration invalidates every derived structure: the schema array, the
 * tools_all() view. Per-entry parsed schemas and search tokens survive — they
 * describe the tool, not the set. */
static void registry_invalidate(void) {
    if (g_schema_cache) { cJSON_Delete(g_schema_cache); g_schema_cache = NULL; }
    g_all_count = -1;
}

int tools_register(const alpha_tool_t *t) {
    if (!g_registry_booted) tools_registry_boot();
    if (!t || !t->name || !t->name[0]) return 0;
    int existing = reg_lookup(t->name);
    if (existing >= 0) {
        if (g_entries[existing].tool == t) return 1;   /* idempotent re-register */
        fprintf(stderr, "[tools] registration rejected: name '%s' already taken by '%s'\n",
                t->name, g_entries[existing].tool->name);
        return 0;
    }
    if (g_nentries == g_entries_cap) {
        int ncap = g_entries_cap ? g_entries_cap * 2 : 64;
        tool_entry_t *ne = realloc(g_entries, (size_t)ncap * sizeof(*ne));
        if (!ne) return 0;
        g_entries = ne;
        g_entries_cap = ncap;
    }
    int idx = g_nentries++;
    memset(&g_entries[idx], 0, sizeof(g_entries[idx]));
    g_entries[idx].tool = t;
    reg_insert(t->name, idx);
    for (int a = 0; a < 4 && t->aliases[a]; a++) {
        int clash = reg_lookup(t->aliases[a]);
        if (clash >= 0 && g_entries[clash].tool != t) {
            fprintf(stderr, "[tools] registration rejected: alias '%s' of '%s' already "
                    "used by '%s'\n", t->aliases[a], t->name, g_entries[clash].tool->name);
            g_nentries--;   /* roll the entry back out */
            return 0;
        }
        reg_insert(t->aliases[a], idx);
    }
    registry_invalidate();
    return 1;
}

static void tools_registry_boot(void) {
    if (g_registry_booted) return;
    g_registry_booted = 1;      /* set first: tools_register() re-enters here */
    for (int i = 0; g_registered_tools[i]; i++)
        tools_register(g_registered_tools[i]);
}

const alpha_tool_t *tools_find(const char *name) {
    if (!name || !name[0]) return NULL;
    if (!g_registry_booted) tools_registry_boot();
    int idx = reg_lookup(name);
    return idx >= 0 ? g_entries[idx].tool : NULL;
}

int tools_count(void) {
    if (!g_registry_booted) tools_registry_boot();
    return g_nentries;
}

int tools_all(const alpha_tool_t ***out) {
    if (!g_registry_booted) tools_registry_boot();
    if (g_all_count != g_nentries) {
        free(g_all_cache);
        g_all_cache = malloc((size_t)(g_nentries ? g_nentries : 1) * sizeof(*g_all_cache));
        for (int i = 0; i < g_nentries; i++) g_all_cache[i] = g_entries[i].tool;
        g_all_count = g_nentries;
    }
    if (out) *out = g_all_cache;
    return g_nentries;
}

/* Unified Tool Dispatcher — hash lookup instead of the old linear scan. */
sds tools_run(const char *name, cJSON *args, const char *cwd) {
    if (!name || !name[0]) return sdsnew("ERROR: no tool name");
    if (!args) args = cJSON_CreateObject();
    const alpha_tool_t *t = tools_find(name);
    if (t) return t->run(args, cwd);
    return sdscatprintf(sdsempty(), "ERROR: unknown tool %s", name);
}

static cJSON *tool_schema_cached(tool_entry_t *e) {
    if (!e->schema && e->tool->schema_json)
        e->schema = cJSON_Parse(e->tool->schema_json);
    return e->schema;
}

/* Master Tool Schema Builder — served from a cache; each tool's schema_json is
 * parsed exactly once, and the assembled array survives until a registration
 * invalidates it. Callers still own the returned copy. */
cJSON *tools_schema(void) {
    if (!g_registry_booted) tools_registry_boot();
    if (!g_schema_cache) {
        g_schema_cache = cJSON_CreateArray();
        for (int i = 0; i < g_nentries; i++) {
            cJSON *s = tool_schema_cached(&g_entries[i]);
            if (s) cJSON_AddItemToArray(g_schema_cache, cJSON_Duplicate(s, 1));
        }
    }
    return cJSON_Duplicate(g_schema_cache, 1);
}

cJSON *tools_schema_window(const char **names, int n) {
    if (!g_registry_booted) tools_registry_boot();
    cJSON *root = cJSON_CreateArray();
    for (int i = 0; names && i < n; i++) {
        if (!names[i]) continue;
        int idx = reg_lookup(names[i]);
        if (idx < 0) continue;
        /* the same tool can be named twice (name + alias): skip repeats */
        int dup = 0;
        cJSON *it = NULL;
        cJSON_ArrayForEach(it, root) {
            const char *nm = cJSON_GetStringValue(cJSON_GetObjectItem(
                cJSON_GetObjectItem(it, "function"), "name"));
            if (nm && strcmp(nm, g_entries[idx].tool->name) == 0) { dup = 1; break; }
        }
        if (dup) continue;
        cJSON *s = tool_schema_cached(&g_entries[idx]);
        if (s) cJSON_AddItemToArray(root, cJSON_Duplicate(s, 1));
    }
    return root;
}

/* --- session-activated tools -------------------------------------------------
 * search_tools hits join the tool window on subsequent turns, so a model that
 * discovered a tool keeps its schema instead of having to re-search every turn. */
static const char **g_activated;
static int g_nactivated;
static int g_activated_cap;

void tools_activate(const char *name) {
    const alpha_tool_t *t = tools_find(name);
    if (!t) return;
    for (int i = 0; i < g_nactivated; i++)
        if (strcmp(g_activated[i], t->name) == 0) return;
    if (g_nactivated == g_activated_cap) {
        int ncap = g_activated_cap ? g_activated_cap * 2 : 16;
        const char **na = realloc(g_activated, (size_t)ncap * sizeof(*na));
        if (!na) return;
        g_activated = na;
        g_activated_cap = ncap;
    }
    g_activated[g_nactivated++] = t->name;   /* static string, no copy needed */
}

void tools_activation_reset(void) {
    g_nactivated = 0;
}

/* The window sent when the catalog outgrows ALPHA_TOOL_WINDOW: the everyday
 * core set plus the discovery meta-tools themselves. */
static const char *g_core_window[] = {
    "execute_bash", "read_file", "write_file", "edit_file", "list_dir",
    "web_search", "browser", "memory", "todo", "code_search",
    "search_tools", "describe_tools", NULL
};

cJSON *tools_schema_for_request(void) {
    if (!g_registry_booted) tools_registry_boot();
    const char *mode = getenv("ALPHA_TOOLS_MODE");
    if (!mode || !mode[0]) mode = "auto";
    int window = 32;
    const char *w = getenv("ALPHA_TOOL_WINDOW");
    if (w && atoi(w) > 0) window = atoi(w);
    if (strcmp(mode, "full") == 0) return tools_schema();
    if (strcmp(mode, "search") != 0 && g_nentries <= window) return tools_schema();

    int ncore = (int)(sizeof(g_core_window) / sizeof(g_core_window[0])) - 1;
    const char **names = malloc((size_t)(ncore + g_nactivated) * sizeof(*names));
    if (!names) return tools_schema();
    int n = 0;
    for (int i = 0; i < ncore; i++)
        if (tools_find(g_core_window[i])) names[n++] = g_core_window[i];
    for (int i = 0; i < g_nactivated; i++) {
        int seen = 0;
        for (int j = 0; j < n; j++)
            if (strcmp(names[j], g_activated[i]) == 0) { seen = 1; break; }
        if (!seen) names[n++] = g_activated[i];
    }
    cJSON *out = tools_schema_window(names, n);
    free(names);
    return out;
}

/* --- BM25-lite tool search ----------------------------------------------------
 * One document per tool: name (3x) + aliases (3x) + category (2x) +
 * description (1x), tokenized lowercase on non-alphanumeric runs. Scoring is
 * BM25 with document-frequency saturation (k1=1.5, b=0.75); df/idf are computed
 * per query rather than cached, so registration never invalidates an index. */

/* Append lowercase alnum tokens of `text` to the entry, each at weight `w`. */
static void tool_index_add(tool_entry_t *e, const char *text, double w) {
    if (!text) return;
    char tok[256];
    int tl = 0;
    for (const char *p = text; ; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c)) {
            if (tl < (int)sizeof(tok) - 1) tok[tl++] = (char)tolower(c);
        } else {
            if (tl) {
                tok[tl] = 0;
                char *cp = malloc((size_t)tl + 1);
                char **nt = realloc(e->toks, (size_t)(e->ntok + 1) * sizeof(*nt));
                double *nw = realloc(e->tokw, (size_t)(e->ntok + 1) * sizeof(*nw));
                if (cp && nt && nw) {
                    memcpy(cp, tok, (size_t)tl + 1);
                    e->toks = nt;
                    e->tokw = nw;
                    e->toks[e->ntok] = cp;
                    e->tokw[e->ntok] = w;
                    e->ntok++;
                    e->doclen += w;
                } else {
                    /* allocation failure: skip the token, keep the old arrays
                     * (a successful realloc of the other array is harmless —
                     * the count did not change) */
                    free(cp);
                    if (nt) e->toks = nt;
                    if (nw) e->tokw = nw;
                }
                tl = 0;
            }
            if (!c) break;
        }
    }
}

static void tool_index_build(tool_entry_t *e) {
    if (e->toks || !e->tool) return;
    const alpha_tool_t *t = e->tool;
    tool_index_add(e, t->name, 3.0);
    for (int a = 0; a < 4 && t->aliases[a]; a++)
        tool_index_add(e, t->aliases[a], 3.0);
    tool_index_add(e, t->category, 2.0);
    tool_index_add(e, t->description, 1.0);
}

static double tool_tf(const tool_entry_t *e, const char *term) {
    double tf = 0;
    for (int i = 0; i < e->ntok; i++)
        if (strcmp(e->toks[i], term) == 0) tf += e->tokw[i];
    return tf;
}

static int hit_cmp(const void *a, const void *b) {
    double d = ((const alpha_tool_hit_t *)b)->score - ((const alpha_tool_hit_t *)a)->score;
    if (d > 0) return 1;
    if (d < 0) return -1;
    return strcmp(((const alpha_tool_hit_t *)a)->tool->name,
                  ((const alpha_tool_hit_t *)b)->tool->name);
}

alpha_tool_hit_t *tools_search(const char *query, int k, int *out_n) {
    if (out_n) *out_n = 0;
    if (!query || !query[0]) return NULL;
    if (!g_registry_booted) tools_registry_boot();
    if (k <= 0) k = 8;

    /* tokenize the query; dedupe so a repeated term does not score twice */
    char qtok[16][64];
    int qn = 0;
    {
        char tok[64];
        int tl = 0;
        for (const char *p = query; ; p++) {
            unsigned char c = (unsigned char)*p;
            if (isalnum(c)) {
                if (tl < (int)sizeof(tok) - 1) tok[tl++] = (char)tolower(c);
            } else {
                if (tl) {
                    tok[tl] = 0;
                    int seen = 0;
                    for (int i = 0; i < qn; i++)
                        if (strcmp(qtok[i], tok) == 0) { seen = 1; break; }
                    if (!seen && qn < 16) {
                        snprintf(qtok[qn], sizeof(qtok[qn]), "%s", tok);
                        qn++;
                    }
                    tl = 0;
                }
                if (!c) break;
            }
        }
    }
    if (qn == 0) return NULL;

    for (int i = 0; i < g_nentries; i++) tool_index_build(&g_entries[i]);

    double avgdl = 0;
    for (int i = 0; i < g_nentries; i++) avgdl += g_entries[i].doclen;
    if (g_nentries) avgdl /= g_nentries;
    if (avgdl <= 0) avgdl = 1;

    const double k1 = 1.5, b = 0.75;
    alpha_tool_hit_t *hits = malloc((size_t)g_nentries * sizeof(*hits));
    if (!hits) return NULL;
    int nh = 0;
    for (int i = 0; i < g_nentries; i++) {
        double score = 0;
        for (int q = 0; q < qn; q++) {
            double tf = tool_tf(&g_entries[i], qtok[q]);
            if (tf <= 0) continue;
            int df = 0;
            for (int j = 0; j < g_nentries; j++)
                if (tool_tf(&g_entries[j], qtok[q]) > 0) df++;
            double idf = log(1.0 + (g_nentries - df + 0.5) / (df + 0.5));
            double dl = g_entries[i].doclen > 0 ? g_entries[i].doclen : 1;
            score += idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl / avgdl));
        }
        if (score > 0) {
            hits[nh].tool = g_entries[i].tool;
            hits[nh].score = score;
            nh++;
        }
    }
    if (nh == 0) { free(hits); return NULL; }
    qsort(hits, (size_t)nh, sizeof(*hits), hit_cmp);
    if (nh > k) nh = k;
    if (out_n) *out_n = nh;
    return hits;
}
