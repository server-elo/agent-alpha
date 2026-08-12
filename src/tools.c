#include "alpha.h"
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
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
 * so the list cannot come up empty. */
static const char *shell_path(void) {
    const char *env = getenv("ALPHA_SHELL");
    if (env && env[0] && access(env, X_OK) == 0) return env;
    static const char *candidates[] = { "/bin/zsh", "/bin/bash", "/bin/sh" };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    return "/bin/sh";
}

static sds shell_run(const char *cmd, const char *cwd) {
    if (!cmd || !cmd[0]) return sdsnew("ERROR: empty command");

    /* Write command to temp script to avoid quoting hell.
     * fdopen the mkstemp fd directly — never reopen by name (symlink race in /tmp). */
    char script[] = "/tmp/alpha-cmd-XXXXXX";
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

    char outf[] = "/tmp/alpha-out-XXXXXX";
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

<<<<<<< Updated upstream
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
 * Design ported from Hermes Agent's memory_tool.py (tools/memory_tool.py). */

#define ALPHA_MEMORY_DIR       ".alpha/memory"
#define ALPHA_MEMORY_ENTRY_SEP "\n§\n"
#define ALPHA_MEMORY_MAX_ENTRIES 64
#define ALPHA_MEMORY_CHAR_LIMIT   2200
#define ALPHA_USER_CHAR_LIMIT     1375

typedef struct {
    char *entries[ALPHA_MEMORY_MAX_ENTRIES];
    int count;
    int char_limit;
} memory_store_t;

static memory_store_t g_memory_store = { .count = 0, .char_limit = ALPHA_MEMORY_CHAR_LIMIT };
static memory_store_t g_user_store    = { .count = 0, .char_limit = ALPHA_USER_CHAR_LIMIT };
static pthread_mutex_t g_memory_lock = PTHREAD_MUTEX_INITIALIZER;

/* Resolve the memory directory, creating it if needed. Returns a static buffer
 * that is valid until the next call. */
static const char *memory_dir(void) {
    static char dir[PATH_MAX];
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

/* Parse a memory file into entries. Returns a freshly allocated array of
 * strdup'd strings; caller must free each entry and the array. */
static char **memory_parse(const char *raw, int *out_count) {
    *out_count = 0;
    if (!raw || !raw[0]) return NULL;
    /* Work on a copy so we can tokenize */
    char *copy = strdup(raw);
    if (!copy) return NULL;

    /* Count entries by finding the delimiter */
    int cap = 16;
    char **entries = malloc((size_t)cap * sizeof(char *));
    if (!entries) { free(copy); return NULL; }

    char *save = NULL;
    char *tok = strtok_r(copy, ALPHA_MEMORY_ENTRY_SEP, &save);
    while (tok) {
        /* Trim leading/trailing whitespace */
        while (*tok == ' ' || *tok == '\t' || *tok == '\n' || *tok == '\r') tok++;
        char *end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t' ||
                             end[-1] == '\n' || end[-1] == '\r')) end--;
        *end = 0;
        if (tok[0]) {
            if (*out_count >= cap) {
                cap *= 2;
                char **nb = realloc(entries, (size_t)cap * sizeof(char *));
                if (!nb) break;
                entries = nb;
            }
            entries[*out_count] = strdup(tok);
            (*out_count)++;
        }
        tok = strtok_r(NULL, ALPHA_MEMORY_ENTRY_SEP, &save);
    }
    free(copy);
    return entries;
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

    char **entries = memory_parse(buf, &store->count);
    free(buf);
    if (!entries) { store->count = 0; return 0; }

    /* Copy into the store, deduplicating */
    int parsed_count = store->count;
    int dst = 0;
    for (int i = 0; i < parsed_count && dst < ALPHA_MEMORY_MAX_ENTRIES; i++) {
        int dup = 0;
        for (int j = 0; j < dst; j++) {
            if (strcmp(store->entries[j], entries[i]) == 0) { dup = 1; break; }
        }
        if (!dup) {
            store->entries[dst++] = entries[i];
        } else {
            free(entries[i]);
        }
    }
    /* Free any remaining parsed entries beyond the cap */
    for (int i = parsed_count; i < parsed_count; i++) free(entries[i]); /* no-op safety */
    free(entries);
    store->count = dst;
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

/* Free all entries in a store. */
static void memory_free_store(memory_store_t *store) {
    for (int i = 0; i < store->count; i++) {
        free(store->entries[i]);
        store->entries[i] = NULL;
    }
    store->count = 0;
}

/* Initialize both stores from disk. Called once at startup. */
void memory_init(void) {
    pthread_mutex_lock(&g_memory_lock);
    memory_free_store(&g_memory_store);
    memory_free_store(&g_user_store);
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

    store->entries[store->count++] = strdup(content);
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

    free(store->entries[idx]);
    store->entries[idx] = strdup(new_content);
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
    free(store->entries[idx]);
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
=======
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
>>>>>>> Stashed changes
}

sds tools_run(const char *name, cJSON *args, const char *cwd) {
    if (!name) return sdsnew("ERROR: no tool name");
    if (!args) args = cJSON_CreateObject();

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
<<<<<<< Updated upstream
        if (path[0] == '/' || !cwd || !cwd[0])
            snprintf(full, sizeof(full), "%s", path);
        else
            snprintf(full, sizeof(full), "%s/%s", cwd, path);
        /* Fast binary check by extension — no I/O, just the path string.
         * Catches images, archives, executables, etc. before we try to
         * read them as text and hit the NUL-byte check (which still runs
         * as a backstop for files with no extension or unknown ones). */
        if (has_binary_extension(full))
            return sdscatprintf(sdsempty(),
                "ERROR: %s has a binary extension (%s). "
                "Use execute_bash with xxd, strings, or file instead.",
                full, strrchr(full, '.') ? strrchr(full, '.') : "unknown");
=======
        resolve_path(full, path, cwd);
>>>>>>> Stashed changes
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
        const char *new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_str"));
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
    if (strcmp(name, "memory") == 0) {
        return memory_tool_run(args);
    }
    if (strcmp(name, "working_diff") == 0 || strcmp(name, "diff") == 0) {
        const char *mode = cJSON_GetStringValue(cJSON_GetObjectItem(args, "mode"));
        return working_diff(cwd, mode);
    }
    return sdscatprintf(sdsempty(), "ERROR: unknown tool %s", name);
}

cJSON *tools_schema(void) {
    const char *json =
        "["
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
        "{\"type\":\"function\",\"function\":{\"name\":\"web_search\",\"description\":\"Search the web via DuckDuckGo HTML (no API key, no JS). Returns title, URL, and snippet for each result. Fast: one HTTP GET, ~0.5-2s.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Search query\"},\"max_results\":{\"type\":\"integer\",\"description\":\"Max results (1-20, default 10)\"}},\"required\":[\"query\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"todo\",\"description\":\"Manage task list for current session. Omit todos to read, provide todos array to create/update items. Each item: {id, content, status: pending|in_progress|completed|cancelled}. merge=true updates by id.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"todos\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"},\"status\":{\"type\":\"string\"}},\"required\":[\"id\",\"content\",\"status\"]}},\"merge\":{\"type\":\"boolean\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"memory\",\"description\":\"Persistent curated memory that survives across sessions. Two stores: 'memory' for your notes (environment facts, conventions, lessons) and 'user' for user profile (preferences, style). Entries are §-delimited. Actions: add (append), replace (substring match), remove (substring match). Omit action to read current entries. Character limits: 2200 (memory), 1375 (user).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"add\",\"replace\",\"remove\"]},\"target\":{\"type\":\"string\",\"enum\":[\"memory\",\"user\"],\"description\":\"Which store: 'memory' (default) or 'user'\"},\"content\":{\"type\":\"string\",\"description\":\"Entry content for add/replace\"},\"old_text\":{\"type\":\"string\",\"description\":\"Substring identifying the entry for replace/remove\"}},\"required\":[]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"working_diff\",\"description\":\"Collect a git diff of the working directory. Modes: 'working' (unstaged + untracked, default), 'staged' (git diff --cached), 'all' (everything since HEAD + untracked). Untracked files are shown as new-file diffs via git diff --no-index /dev/null <file>. Returns the diff as text.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"mode\":{\"type\":\"string\",\"enum\":[\"working\",\"staged\",\"all\"],\"description\":\"Diff mode: working (default), staged, or all\"}},\"required\":[]}}}"
        "]";
    return cJSON_Parse(json);
}
