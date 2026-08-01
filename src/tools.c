#include "alpha.h"
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>

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

static sds read_file_all(const char *path, size_t max_bytes) {
    FILE *f = fopen(path, "rb");
    if (!f) return sdscatprintf(sdsempty(), "ERROR open %s: %s", path, strerror(errno));
    sds out = sdsempty();
    char buf[8192];
    size_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (total + n > max_bytes) {
            out = sdscatlen(out, buf, max_bytes - total);
            out = sdscat(out, "\n… truncated");
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
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) return;
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return;
    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); return; }
    int count = (int)(len / sizeof(struct kinfo_proc));

    struct proc_fdinfo *fds = NULL;
    int fds_cap = 0;
    for (int i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 1 || pid == self || pt_has(t, pid)) continue;
        int sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (sz <= 0) continue;                  /* gone, or not ours to inspect */
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
            struct vnode_fdinfowithpath v;
            if (proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDVNODEPATHINFO,
                               &v, sizeof(v)) < (int)sizeof(v)) continue;
            if (v.pvip.vip_vi.vi_stat.vst_ino == ino) { pt_add(t, pid); break; }
        }
    }
    free(fds);
    free(procs);
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
    for (int waited = 0; waited < 600; waited++) {   /* 600 * 100ms = 60s */
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) { timed_out = 0; break; }
        if (r < 0) break;
        /* Ctrl-C must reach the command, not just the agent: without this a
         * 60s sleep still had to run to completion before the interrupt was
         * noticed. Same teardown as a timeout, since the child may have left
         * the process group. */
        if (alpha_cancel) { cancelled = 1; timed_out = 1; break; }
        usleep(100000);
        if (waited == 599) timed_out = 1;
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
        waitpid(pid, &status, 0);
    }

    sds out = read_file_all(outf, 200000);
    unlink(script);
    unlink(outf);
    if (!out || !out[0]) {
        if (out) sdsfree(out);
        out = sdsnew("(no output)");
    }
    if (cancelled)
        out = sdscat(out, "\nERROR: command interrupted by the user.");
    else if (timed_out)
        out = sdscat(out, "\nERROR: command exceeded 60s timeout — killed (process group, "
                          "plus descendants still holding this command's output file). "
                          "A process that called setsid() and closed its inherited fds "
                          "may still be running.");
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
        waitpid(pid, &status, 0);
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
        if (path[0] == '/' || !cwd || !cwd[0])
            snprintf(full, sizeof(full), "%s", path);
        else
            snprintf(full, sizeof(full), "%s/%s", cwd, path);
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
        if (path[0] == '/' || !cwd || !cwd[0])
            snprintf(full, sizeof(full), "%s", path);
        else
            snprintf(full, sizeof(full), "%s/%s", cwd, path);
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
        if (path[0] == '/' || !cwd || !cwd[0])
            snprintf(full, sizeof(full), "%s", path);
        else
            snprintf(full, sizeof(full), "%s/%s", cwd, path);
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
        char *pos = strstr(body, old_s);
        if (!pos) {
            sdsfree(body);
            return sdsnew("ERROR: old_str not found");
        }
        if (strstr(pos + strlen(old_s), old_s)) {
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
        if (!path || !path[0]) {
            if (cwd && cwd[0]) snprintf(full, sizeof(full), "%s", cwd);
            else snprintf(full, sizeof(full), ".");
        } else if (path[0] == '/' || !cwd || !cwd[0]) {
            snprintf(full, sizeof(full), "%s", path);
        } else {
            snprintf(full, sizeof(full), "%s/%s", cwd, path);
        }
        /* expand ~ */
        if (full[0] == '~') {
            const char *home = getenv("HOME");
            if (home && home[0]) {
                char exp[PATH_MAX];
                if (full[1] == '/' || full[1] == 0)
                    snprintf(exp, sizeof(exp), "%s%s", home, full + 1);
                else
                    snprintf(exp, sizeof(exp), "%s", full);
                snprintf(full, sizeof(full), "%s", exp);
            }
        }
        return list_dir(full);
    }
    if (strcmp(name, "browser") == 0 || strcmp(name, "web_browser") == 0) {
        return browser_tool_run(args);
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
        "{\"type\":\"function\",\"function\":{\"name\":\"browser\",\"description\":\"Pure-C browser. ONE sticky CDP tab. Loop: status/tabs -> open/navigate -> snapshot -> click/type/press/eval. close_others cleans junk. NEVER bash for click. Login/OAuth: snapshot+one click then stop. PROOF required.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\"},\"url\":{\"type\":\"string\"},\"selector\":{\"type\":\"string\"},\"text\":{\"type\":\"string\"},\"expression\":{\"type\":\"string\"},\"tab_id\":{\"type\":\"string\"},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"}},\"required\":[]}}}"
        "]";
    return cJSON_Parse(json);
}
