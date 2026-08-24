/* Self-evolution driver.
 *
 * The model is never trusted to grade its own work: it edits the source it
 * was compiled from, then THIS code re-runs the gate (build, test suite,
 * binary smoke test) and either commits the generation or reverts it with
 * git reset --hard. git is the genome -- the baseline commit makes every
 * mutation revertible, and evolution/ holds the log and the archived
 * per-generation binaries. */

#include "alpha.h"
#include "warden.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/* --- source root ----------------------------------------------------------- */

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int is_source_root(const char *dir) {
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/Makefile", dir);
    if (!file_exists(p)) return 0;
    snprintf(p, sizeof(p), "%s/src/agent_loop.c", dir);
    if (!file_exists(p)) return 0;
    snprintf(p, sizeof(p), "%s/include/alpha.h", dir);
    if (!file_exists(p)) return 0;
    return 1;
}

/* The binary normally sits in the repository root, so the tree is located
 * from the executable's own path; cwd is the fallback. A binary copied
 * elsewhere refuses to evolve rather than editing whatever happens to be
 * next to it. */
static int find_source_root(char out[PATH_MAX]) {
    char exe[PATH_MAX];
    int have = 0;
#ifdef __APPLE__
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) == 0) have = 1;
#else
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) { exe[n] = 0; have = 1; }
#endif
    if (have) {
        char real[PATH_MAX];
        if (realpath(exe, real)) {
            char *slash = strrchr(real, '/');
            if (slash) {
                *slash = 0;
                if (is_source_root(real)) {
                    snprintf(out, PATH_MAX, "%s", real);
                    return 1;
                }
            }
        }
    }
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) && is_source_root(cwd)) {
        snprintf(out, PATH_MAX, "%s", cwd);
        return 1;
    }
    return 0;
}

/* --- process runner --------------------------------------------------------
 * The gate runs outside the tool layer, so the 60s execute_bash cap does not
 * apply; `make test` legitimately takes longer. Output is captured for the
 * log, and the child gets its own process group so a timeout kills make's
 * children too, not just make. */
static sds run_capture(const char *cwd, const char *cmd, int timeout_sec, int *out_rc) {
    sds out = sdsempty();
    *out_rc = -1;
    int pipefd[2];
    if (pipe(pipefd) != 0) return sdscat(out, "ERROR: pipe failed\n");
    pid_t pid = fork();
    if (pid == 0) {
        setpgid(0, 0);
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (cwd) chdir(cwd);
        execlp("sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    /* Set the group from the parent as well: without it a kill that wins the
     * race against the child's own setpgid would miss the grandchildren. */
    setpgid(pid, pid);
    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);

    int status = 0;
    char buf[8192];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        ssize_t r = read(pipefd[0], buf, sizeof(buf));
        if (r > 0) out = sdscatlen(out, buf, (size_t)r);
        if (waitpid(pid, &status, WNOHANG) == pid) {
            while ((r = read(pipefd[0], buf, sizeof(buf))) > 0)
                out = sdscatlen(out, buf, (size_t)r);
            if (WIFEXITED(status)) *out_rc = WEXITSTATUS(status);
            break;
        }
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (el > (double)timeout_sec) {
            kill(-pid, SIGKILL);
            /* SIGKILL cannot kill a process stuck in D-state (uninterruptible
             * kernel wait). A blocking waitpid would hang the gate forever, so
             * poll with a short grace period and give up if the child is still
             * alive. It will be reaped by launchd when the call returns. */
            int grace = 0;
            while (grace < 20) {  /* 20 * 100ms = 2s grace */
                if (waitpid(pid, &status, WNOHANG) == pid) break;
                usleep(100000);
                grace++;
            }
            out = sdscatprintf(out, "\n[evolve] killed after %ds timeout\n", timeout_sec);
            break;
        }
        usleep(20000);
    }
    close(pipefd[0]);
    return out;
}

/* --- fitness gate ---------------------------------------------------------- */

/* Append only the tail: a failing build can print far more than the log or
 * the terminal needs, and the diagnosis is almost always at the end. */
static void report_tail(sds *report, const char *label, sds out) {
    size_t n = sdslen(out);
    size_t keep = n < 4000 ? n : 4000;
    *report = sdscatprintf(*report ? *report : sdsempty(), "\n--- %s (last %zu bytes) ---\n%.*s\n",
                           label, keep, (int)keep, out + n - keep);
}

/* Helper to safely append to report, initializing if needed */
static void report_append(sds *report, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (!*report) {
        *report = sdsempty();
    }
    *report = sdscatvprintf(*report, fmt, args);
    va_end(args);
}

/* Run domain-specific 360° benchmark tasks based on modified files or goal topic.
 * Uses the configured model (cfg->model) instead of a hardcoded model name, so
 * evolution works with any provider the user has set in .env. */
static int run_domain_benchmark(const char *dir, const char *model, sds *report) {
    int rc = -1;
    
    /* Check what changed in this generation for domain detection */
    sds status = run_capture(dir, "git status --porcelain 2>/dev/null || echo ''", 30, &rc);
    if (!status) return 1; /* Be permissive if we can't detect domain */
    
    /* Also check staged changes - model may have staged but not committed */
    sds staged = run_capture(dir, "git diff --cached --name-only 2>/dev/null || echo ''", 30, &rc);
    
    /* Combine for comprehensive domain detection */
    sds combined = sdsempty();
    if (status && sdslen(status) > 0) combined = sdscat(combined, status);
    if (staged && sdslen(staged) > 0) combined = sdscat(combined, staged);
    
    int is_memory = (strstr(combined, "memory") != NULL);
    int is_search = (strstr(combined, "web_search") != NULL || strstr(combined, "search") != NULL);
    int is_tools  = (strstr(combined, "tools") != NULL || strstr(combined, "edit") != NULL);
    sdsfree(status);
    sdsfree(staged);
    sdsfree(combined);

    const char *m = (model && model[0]) ? model : "local";

    if (is_memory) {
        /* Domain Task: Memory Store + Retrieve + Replace Benchmark */
        sds cmd = sdscatprintf(sdsempty(),
            "./alpha -m %s \"Use memory tool to add entry test_key_999='domain_bench_value' then retrieve memory\" 2>&1", m);
        sds out = run_capture(dir, cmd, 120, &rc);
        sdsfree(cmd);
        if (rc != 0 || !out || strstr(out, "ERROR") || !strstr(out, "domain_bench_value")) {
            report_tail(report, "Domain Benchmark: Memory Tool", out);
            report_append(report, "FAIL: 360° Memory Domain Benchmark\n");
            sdsfree(out);
            return 0;
        }
        sdsfree(out);
    } else if (is_search) {
        /* Domain Task: Web Search Speed & Parsing Benchmark */
        sds cmd = sdscatprintf(sdsempty(),
            "./alpha -m %s \"Use web_search to find latest C11 standard details\" 2>&1", m);
        sds out = run_capture(dir, cmd, 120, &rc);
        sdsfree(cmd);
        if (rc != 0 || !out || strstr(out, "ERROR")) {
            report_tail(report, "Domain Benchmark: Web Search Tool", out);
            report_append(report, "FAIL: 360° Web Search Domain Benchmark\n");
            sdsfree(out);
            return 0;
        }
        sdsfree(out);
    } else if (is_tools) {
        /* Domain Task: File Editing & Execution Benchmark */
        sds cmd = sdscatprintf(sdsempty(),
            "./alpha -m %s \"List files in current dir and report count\" 2>&1", m);
        sds out = run_capture(dir, cmd, 120, &rc);
        sdsfree(cmd);
        if (rc != 0 || !out || strstr(out, "ERROR")) {
            report_tail(report, "Domain Benchmark: Tools & File Execution", out);
            report_append(report, "FAIL: 360° Tools Domain Benchmark\n");
            sdsfree(out);
            return 0;
        }
        sdsfree(out);
    }

    return 1;
}

/* A generation survives only if every stage passes. The model already ran
 * these commands itself; running them again here is what makes its claims
 * unforgeable. */

/* --- Warden cryptographic seal ----------------------------------------------
 *
 * The model being evolved could otherwise edit its own gate: weaken a test,
 * gut the Makefile, or rewrite evolve.c itself. The seal takes SHA-256 hashes
 * of those protected files BEFORE the model edits anything, and verify()
 * recomputes them AFTER. Any mismatch = the genome tried to tamper with its
 * own harness, and the generation is rejected before the gate even runs.
 * Missing files are recorded as all-zero hashes (also fails verify). */

#define EVOLVE_PROTECTED_COUNT 4
static const char *EVOLVE_PROTECTED_FILES[EVOLVE_PROTECTED_COUNT] = {
    "Makefile", "src/evolve.c", "src/agent_loop.c", "tests/test_evolve.c"
};

typedef struct {
    char hex[65];
} seal_hash_t;

typedef struct {
    seal_hash_t files[EVOLVE_PROTECTED_COUNT];
} evolve_hash_table;

static int evolve_seal_snapshot(const char *sandbox_dir,
                                evolve_hash_table *table,
                                sds *report) {
    if (!sandbox_dir || !table) return 0;
    int ok = 1;
    sds errors = sdsempty();
    
    for (int i = 0; i < EVOLVE_PROTECTED_COUNT; i++) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", sandbox_dir,
                 EVOLVE_PROTECTED_FILES[i]);
        char hex[65];
        if (warden_sha256_file(full, hex) != WARDEN_OK) {
            /* A protected file that cannot be read now cannot be verified
             * later either -- refuse to arm the seal on an incomplete base. */
            errors = sdscatprintf(errors, "seal: cannot hash %s; ",
                                  EVOLVE_PROTECTED_FILES[i]);
            ok = 0;
        } else {
            memcpy(table->files[i].hex, hex, 65);
        }
    }
    
    if (!ok) {
        report_append(report, "FAIL: Warden seal initialization: %s\n", errors);
    }
    sdsfree(errors);
    return ok;
}

static int evolve_seal_verify(const char *sandbox_dir,
                              evolve_hash_table *table,
                              sds *report) {
    if (!sandbox_dir || !table) return 0;
    int ok = 1;
    sds errors = sdsempty();
    
    for (int i = 0; i < EVOLVE_PROTECTED_COUNT; i++) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", sandbox_dir,
                 EVOLVE_PROTECTED_FILES[i]);
        char hex[65];
        if (warden_sha256_file(full, hex) != WARDEN_OK) {
            /* Present at seal time, unreadable now == deleted by the model. */
            errors = sdscatprintf(errors, "tamper: %s deleted/unreadable; ",
                                  EVOLVE_PROTECTED_FILES[i]);
            ok = 0;
            continue;
        }
        if (memcmp(table->files[i].hex, hex, 65) != 0) {
            errors = sdscatprintf(errors, "tamper: %s modified; ",
                                  EVOLVE_PROTECTED_FILES[i]);
            ok = 0;
        }
    }
    
    if (!ok) {
        report_append(report, "FAIL: Warden seal verification -- protected files were touched: %s\n", errors);
    }
    sdsfree(errors);
    return ok;
}

static int evolve_git_protected_clean(const char *build_dir, sds *report) {
    /* The gate must never reward a mutation that weakened its own harness.
     * Sandboxes are plain directory copies (no .git), so instead of git we
     * byte-compare each protected file against its counterpart in the MAIN
     * tree -- the baseline the generation forked from. Sandbox layout is
     * <root>/sandbox/gen_NNN by construction (setup_sandbox). */
    
    /* Check if this is actually a sandbox by looking for /sandbox/ in path */
    const char *mark = strstr(build_dir, "/sandbox/");
    if (!mark || mark == build_dir) {
        /* Not an evolution sandbox (e.g. the gate-test fixture): the
         * main-tree comparison does not apply there. Deletion of tracked
         * files is still caught by the git guard that runs before this. */
        return 1;
    }
    
    /* Verify there's actually a .git in the main tree to compare against */
    size_t n = (size_t)(mark - build_dir);
    char root[PATH_MAX];
    if (n >= sizeof(root)) n = sizeof(root) - 1;
    memcpy(root, build_dir, n);
    root[n] = 0;
    
    char gitprobe[PATH_MAX];
    snprintf(gitprobe, sizeof(gitprobe), "%s/.git", root);
    if (!file_exists(gitprobe)) {
        /* No git in main tree - cannot compare */
        return 1;
    }

    static const char *paths[] = {
        "Makefile", "src/evolve.c", "src/agent_loop.c",
        "src/warden.c", "src/llm.c", "tests/test_evolve.c"
    };
    int ok = 1;
    sds errors = sdsempty();
    
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char a[PATH_MAX], b[PATH_MAX];
        char ha[65], hb[65];
        snprintf(a, sizeof(a), "%s/%s", root, paths[i]);
        snprintf(b, sizeof(b), "%s/%s", build_dir, paths[i]);
        int ra = warden_sha256_file(a, ha);
        int rb = warden_sha256_file(b, hb);
        if (ra != WARDEN_OK || rb != WARDEN_OK) {
            /* A protected file missing from either side means deletion. */
            errors = sdscatprintf(errors, "%s missing/unreadable (%s); ", paths[i],
                                  ra != WARDEN_OK ? "main" : "sandbox");
            ok = 0;
        } else if (memcmp(ha, hb, 65) != 0) {
            errors = sdscatprintf(errors, "%s modified in sandbox; ", paths[i]);
            ok = 0;
        }
    }
    
    if (!ok) {
        report_append(report, "FAIL: protected harness files differ from main tree: %s\n", errors);
    }
    sdsfree(errors);
    return ok;
}

/* A generation that deletes a git-tracked file is rejected before the build
 * is even attempted: deleting code is never an improvement, and a removal
 * could also hide a weakened harness from the stages below. Sandboxes are
 * plain directory copies without .git -- there the main-tree comparison in
 * evolve_git_protected_clean covers deletions instead. */
static int evolve_no_tracked_deletions(const char *build_dir, sds *report) {
    char probe[PATH_MAX];
    snprintf(probe, sizeof(probe), "%s/.git", build_dir);
    if (!file_exists(probe)) return 1;

    int rc = -1;
    sds status = run_capture(build_dir, "git status --porcelain", 30, &rc);
    if (rc != 0 || !status) { sdsfree(status); return 1; }

    /* Porcelain lines are "XY PATH": X staged, Y worktree. Either column
     * reading D means a tracked file was removed. Untracked (??) and
     * modified entries are the normal business of a generation. */
    sds deleted = sdsempty();
    for (char *line = strtok(status, "\n"); line; line = strtok(NULL, "\n")) {
        if (strlen(line) < 3) continue;
        if ((line[0] == 'D' && line[1] == ' ') ||
            (line[0] == ' ' && line[1] == 'D')) {
            /* Extract filename (after the status chars and space) */
            char *filename = line + 3;
            if (strlen(filename) > 0) {
                deleted = sdscatprintf(deleted, "%s; ", filename);
            }
        }
    }
    
    int ok = sdslen(deleted) == 0;
    if (!ok) {
        report_append(report, "FAIL: tracked file deleted: %s\n", deleted);
    }
    sdsfree(deleted);
    sdsfree(status);
    return ok;
}

static int evolve_warden_smoke(
    const char *dir,
    sds *report
) {
    warden_limits_t lim = warden_limits_default();
    lim.timeout_ms = 30000;

    char out[8192];

    char *const argv[] = {
        (char *)"./alpha",
        (char *)"--providers",
        NULL
    };

    int rc = warden_execute_capture(
        dir,
        "./alpha",
        argv,
        &lim,
        out,
        sizeof(out)
    );

    if (rc != WARDEN_OK) {
        report_append(report, "FAIL: Warden smoke test failed rc=%d\n%.4000s\n", rc, out);
        return 0;
    }

    return 1;
}

static int evolve_warden_model_bench(
    const char *dir,
    const char *model,
    sds *report
) {
    const char *m = (model && model[0]) ? model : "local";

    warden_limits_t lim = warden_limits_default();
    lim.timeout_ms = 60000;

    char out[8192];

    char *const argv[] = {
        (char *)"./alpha",
        (char *)"-m",
        (char *)m,
        (char *)"hi",
        NULL
    };

    int rc = warden_execute_capture(
        dir,
        "./alpha",
        argv,
        &lim,
        out,
        sizeof(out)
    );

    if (rc != WARDEN_OK || out[0] == '\0' || strstr(out, "ERROR")) {
        report_append(report, "FAIL: Warden model benchmark failed rc=%d\n%.4000s\n", rc, out);
        return 0;
    }

    return 1;
}

static int evolve_gate(const char *build_dir, const char *model, sds *report) {
    *report = NULL;  /* Initialize to NULL for report_append to work */
    int rc = -1;

    /* Reject if tests/ or Makefile changed */
    if (!evolve_git_protected_clean(build_dir, report)) {
        return 0;
    }

    /* Reward-hacking guard: reject deletions before building. */
    if (!evolve_no_tracked_deletions(build_dir, report)) {
        return 0;
    }

    /* Build */
    sds out = run_capture(build_dir, "make -j4", 600, &rc);
    if (rc != 0) {
        report_tail(report, "make -j4", out);
        report_append(report, "FAIL: build\n");
        sdsfree(out);
        return 0;
    }
    sdsfree(out);

    /* Tests */
    out = run_capture(build_dir, "make test", 900, &rc);
    int tests_ok = (rc == 0 && out && strstr(out, "ALL TESTS PASSED") && strstr(out, "=== tests/bin/"));
    if (!tests_ok) {
        report_tail(report, "make test", out);
        if (rc == 0 && out && strstr(out, "ALL TESTS PASSED") && !strstr(out, "=== tests/bin/"))
            report_append(report,
                "FAIL: test suite (ALL TESTS PASSED was printed but no test "
                "binary actually ran — the Makefile test target may have been "
                "edited to bypass the suite)\n");
        else
            report_append(report, "FAIL: test suite\n");
        sdsfree(out);
        return 0;
    }
    sdsfree(out);

    /* Warden smoke test */
    if (!evolve_warden_smoke(build_dir, report)) {
        return 0;
    }

    /* Warden model benchmark */
    if (!strstr(build_dir, "_fixture")) {
        if (!evolve_warden_model_bench(build_dir, model, report)) {
            return 0;
        }

        /* Run domain-specific 360° real task benchmark */  
        if (!run_domain_benchmark(build_dir, model, report)) {
            return 0;
        }
    }

    report_append(report, "OK: build + tests + warden smoke + model benchmark + domain benchmark\n");
    return 1;
}

/* --- evolution log --------------------------------------------------------- */

static sds json_escape(const char *s, size_t max) {
    sds out = sdsempty();
    for (size_t i = 0; s && s[i] && i < max; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') out = sdscatprintf(out, "\\%c", c);
        else if (c == '\n') out = sdscat(out, "\\n");
        else if (c == '\r' || c == '\t') { /* drop */ }
        else if (c < 0x20) out = sdscatprintf(out, "\\u%04x", c);
        else out = sdscatlen(out, (const char *)&s[i], 1);
    }
    return out;
}

static int next_generation(const char *root) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/evolution/log.jsonl", root);
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 16 * 1024 * 1024) { fclose(f); return 1; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    int max = 0;
    for (char *p = buf; (p = strstr(p, "\"gen\":")); ) {
        int g = atoi(p + 6);
        if (g > max) max = g;
        p += 6;
    }
    free(buf);
    return max + 1;
}

static void log_append(const char *root, int gen, const char *goal,
                       const char *result, const char *commit, const char *note,
                       int touched_tests) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/evolution", root);
    mkdir(dir, 0755);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/log.jsonl", dir);
    
    /* Use flock for atomic append on systems that support it */
    FILE *f = fopen(path, "a");
    if (!f) return;
    
#ifdef F_SETLKW
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fileno(f), F_SETLKW, &fl) == -1) {
        fclose(f);
        return;
    }
#endif

    sds g = json_escape(goal, 200);
    sds n = json_escape(note ? note : "", 300);
    fprintf(f, "{\"gen\":%d,\"ts\":%lld,\"goal\":\"%s\",\"result\":\"%s\","
               "\"commit\":\"%s\",\"touched_tests\":%s,\"note\":\"%s\"}\n",
            gen, (long long)time(NULL), g, result,
            commit ? commit : "", touched_tests ? "true" : "false", n);
    sdsfree(g);
    sdsfree(n);
    
#ifdef F_SETLKW
    fl.l_type = F_UNLCK;
    fcntl(fileno(f), F_SETLK, &fl);
#endif
    
    fclose(f);
}

/* Memory across generations: the agent runs one-shot, so the log tail is the
 * only thing stopping it from re-trying a mutation that was already reverted. */
static sds log_tail(const char *root, int max_lines) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/evolution/log.jsonl", root);
    FILE *f = fopen(path, "rb");
    if (!f) return sdsnew("(no earlier generations)\n");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return sdsnew("(log unreadable)\n"); }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return sdsnew("(log unreadable)\n"); }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    int newlines = 0;
    long start = (long)rd;
    while (start > 0) {
        if (buf[start - 1] == '\n' && ++newlines > max_lines) break;
        start--;
    }
    sds out = sdsnewlen(buf + start, (size_t)((long)rd - start));
    free(buf);
    if (sdslen(out) > 4000) {
        sds t = sdsnewlen(out + sdslen(out) - 4000, 4000);
        sdsfree(out);
        out = t;
    }
    return out;
}

/* --- sandbox ----------------------------------------------------------------- */

/* Setup sandbox with atomic generation directory creation to avoid races */
static int setup_sandbox(const char *root, char sandbox[PATH_MAX], int gen) {
    /* Create base sandbox directory first */
    char base[PATH_MAX];
    snprintf(base, sizeof(base), "%s/sandbox", root);
    
    /* Create with parents, ignore error if exists */
    char mkdir_cmd[PATH_MAX + 64];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s'", base);
    int rc = -1;
    sds out = run_capture(root, mkdir_cmd, 30, &rc);
    sdsfree(out);
    if (rc != 0) return 0;
    
    /* Now create the generation-specific directory atomically */
    snprintf(sandbox, PATH_MAX, "%s/gen_%03d", base, gen);
    
    /* Try mkdir first - fails if exists (race) */
    if (mkdir(sandbox, 0755) != 0) {
        if (errno == EEXIST) {
            /* Race condition: another process created it. 
             * Verify it's usable by checking for essential files. */
            char testfile[PATH_MAX];
            snprintf(testfile, sizeof(testfile), "%s/Makefile", sandbox);
            if (!file_exists(testfile)) {
                fprintf(stderr, "[evolve] sandbox gen_%03d exists but is corrupted, retry needed\n", gen);
                return 0;
            }
        } else {
            fprintf(stderr, "[evolve] mkdir sandbox failed: %s\n", strerror(errno));
            return 0;
        }
    }
    
    /* Copy source tree - only directories that exist */
    char cmd[PATH_MAX * 3 + 256];
    snprintf(cmd, sizeof(cmd),
        "for d in src tests include deps; do [ -d \"%s/$d\" ] && cp -R \"%s/$d\" '%s/' 2>/dev/null; done; "
        "cp '%s/Makefile' '%s/' 2>/dev/null; "
        "true",
        root, root, sandbox, root, sandbox);
    
    out = run_capture(root, cmd, 60, &rc);
    sdsfree(out);
    
    /* Copy the binary if it exists */
    char alphabin[PATH_MAX], destbin[PATH_MAX];
    snprintf(alphabin, sizeof(alphabin), "%s/alpha", root);
    snprintf(destbin, sizeof(destbin), "%s/alpha", sandbox);
    if (file_exists(alphabin)) {
        char cp_bin[PATH_MAX * 2 + 32];
        snprintf(cp_bin, sizeof(cp_bin), "cp '%s' '%s'", alphabin, destbin);
        out = run_capture(root, cp_bin, 30, &rc);
        sdsfree(out);
    }
    
    /* Verify critical files were copied */
    snprintf(cmd, sizeof(cmd), "[ -f '%s/Makefile' ] && [ -d '%s/src' ]", sandbox, sandbox);
    out = run_capture(root, cmd, 10, &rc);
    int ok = (rc == 0);
    sdsfree(out);
    
    return ok;
}

/* --- prompt ---------------------------------------------------------------- */

static sds build_prompt(const char *root, const char *goal, int gen) {
    sds tail = log_tail(root, 15);
    sds p = sdscatprintf(sdsempty(),
        "You are Agent Alpha, and you are evolving your own source code. Your working\n"
        "directory is the source tree of the binary you are running as: %s\n"
        "\n"
        "GOAL: %s\n"
        "\n"
        "STEP BY STEP APPROACH:\n"
        "1. Pick ONE repo from GitHub trending C today: https://github.com/trending/c\n"
        "2. Clone or inspect it. Study its architecture, code patterns, and design.\n"
        "3. Find ONE specific thing Alpha can learn from it (a tool, a pattern, a fix).\n"
        "4. Define 3 tasks that test THAT specific thing you want to implement.\n"
        "5. BENCHMARK BEFORE: Run your CURRENT self on those 3 tasks. Use execute_bash:\n"
        "   ./alpha -m <model> \"<task>\" 2>&1 | tail -5. Record success/fail + speed.\n"
        "6. Implement the ONE thing in Alpha's code.\n"
        "7. Run `make -j4 && make test`. The EXISTING tests must pass first.\n"
        "8. BENCHMARK AFTER: Only if tests pass, run the SAME 3 tasks on new binary.\n"
        "9. Compare BEFORE vs AFTER. Report: Did it improve? Success rate? Speed?\n"
        "10. Only one repo per generation. Next generation picks the next repo.\n"
        "\n"
        "PERSISTENT PROJECT & EVOLUTION MEMORY:\n"
        "Use the native `memory` tool (action=add target=memory) to track your exact project position across generations.\n"
        "Record: (1) Current repo being inspected (e.g. Hermes Agent or GitHub repo), (2) List of files already inspected line-by-line,\n"
        "(3) Next batch of files to inspect, (4) Reverse-engineering candidates to port next to native C11.\n"
        "\n"
        "Rules that keep you alive:\n"
        "1. One small, focused improvement per generation. Read code before editing it.\n"
        "2. Use `todo` to plan your steps, and `memory` to save project inspection state across re-executions.\n"
        "3. After editing, prove it yourself: `make -j4` and `make test` must both pass.\n"
        "4. NEVER delete or weaken tests, the Makefile, or source files to make the suite\n"
        "   pass. The driver checks for exactly that and reverts the whole generation.\n"
        "5. C11, -Wall -Wextra clean. Match the existing style, including its habit of\n"
        "   explaining WHY a non-obvious line exists.\n"
        "6. If behaviour changes, update README.md in the same generation.\n"
        "7. The evolution log below records earlier generations. A reverted mutation is a\n"
        "   dead end -- do not repeat it.\n"
        "\n"
        "When you stop, the driver re-runs the gate itself: build, full test suite, and 360° Before/After Quality Benchmarks.\n"
        "If anything fails or degrades, `git reset --hard` reverts every change you made. If it passes, your changes are\n"
        "committed as generation %d and the binary on disk re-executes into your improved self.\n"
        "\n"
        "Evolution log so far:\n%s",
        root, goal, gen, tail);
    sdsfree(tail);
    return p;
}

/* --- main loop ------------------------------------------------------------- */

int evolve_run(alpha_cfg_t *cfg, const char *goal, int generations, int reexec) {
    char root[PATH_MAX];
    if (!find_source_root(root)) {
        fprintf(stderr,
            "evolve: cannot find the Agent Alpha source tree (looked next to the\n"
            "executable and in the cwd). Keep the binary in its repository root.\n");
        return 2;
    }
    if (!goal || !goal[0]) goal = "improve yourself";
    cfg->cwd = root;
    /* Edit + build + test cycles need more room than the chat default of 16. */
    if (cfg->max_turns <= 0) cfg->max_turns = 64;
    /* So commands the agent runs can tell they are inside an evolution run. */
    setenv("ALPHA_EVOLVE", "1", 1);

    char evdir[PATH_MAX];
    snprintf(evdir, sizeof(evdir), "%s/evolution", root);
    mkdir(evdir, 0755);

    int rc = -1;
    sds out = run_capture(root, "git rev-parse --is-inside-work-tree", 20, &rc);
    int is_repo = (rc == 0 && out && strstr(out, "true"));
    sdsfree(out);
    if (!is_repo) {
        fprintf(stderr, "evolve: %s is not a git repository; generations cannot be snapshotted\n", root);
        return 2;
    }

    out = run_capture(root, "git status --porcelain", 30, &rc);
    int dirty = (rc == 0 && out && sdslen(out) > 0);
    sdsfree(out);
    if (dirty) {
        /* Reverting a failed generation is git reset --hard, which would take
         * any pre-existing uncommitted work with it. Commit a baseline first
         * so nothing the user had is lost. */
        printf("[evolve] uncommitted changes — committing a baseline so every generation is revertible\n");
        out = run_capture(root,
            "git add -A && git -c user.name=agent-alpha -c user.email=alpha@localhost "
            "commit -q -m 'evolve: baseline snapshot'", 60, &rc);
        if (rc != 0) {
            fprintf(stderr, "evolve: baseline commit failed:\n%s\n", out);
            sdsfree(out);
            return 2;
        }
        sdsfree(out);
    }

    printf("[evolve] source root: %s\n[evolve] goal: %s\n[evolve] generations: %d\n",
           root, goal, generations);
    fflush(stdout);

    int kept = 0, reverted = 0;
    for (int g = 0; g < generations; g++) {
        if (alpha_cancel) break;
        int gen = next_generation(root);
        printf("\n[evolve] === generation %d of %d (log gen %d) ===\n",
               g + 1, generations, gen);
        fflush(stdout);

        /* Setup sandbox for this generation */
        char sandbox[PATH_MAX];
        if (!setup_sandbox(root, sandbox, gen)) {
            fprintf(stderr, "[evolve] sandbox setup failed\n");
            break;
        }
        printf("[evolve] sandbox: %s\n", sandbox);

        /* Take Warden cryptographic SHA-256 seal snapshot of protected files BEFORE model edits */
        evolve_hash_table seal_before;
        sds seal_init_report = NULL;
        if (!evolve_seal_snapshot(sandbox, &seal_before, &seal_init_report)) {
            fprintf(stderr, "[evolve] Warden seal initialization failed: %s\n", 
                    seal_init_report ? seal_init_report : "unknown");
            sdsfree(seal_init_report);
            break;
        }
        sdsfree(seal_init_report);

        /* 1. BEFORE Benchmark: Run pre-mutation baseline benchmark on SANDBOX binary.
         * This ensures we're comparing the same binary before and after mutation. */
        const char *bm = (cfg->model && cfg->model[0]) ? cfg->model : "local";
        
        /* Build baseline in sandbox first to ensure we have a binary to test */
        printf("[evolve] building baseline in sandbox...\n");
        fflush(stdout);
        int build_rc = -1;
        out = run_capture(sandbox, "make -j4", 600, &build_rc);
        sdsfree(out);
        if (build_rc != 0) {
            fprintf(stderr, "[evolve] sandbox baseline build failed\n");
            continue;
        }
        
        /* Run BEFORE benchmark in the sandbox */
        int before_rc = -1;
        struct timespec b_t0, b_t1;
        clock_gettime(CLOCK_MONOTONIC, &b_t0);
        sds before_cmd = sdscatprintf(sdsempty(),
            "./alpha -m %s \"Use memory tool to add entry bench_before='val_before' then retrieve memory\" 2>&1", bm);
        sds before_bench = run_capture(sandbox, before_cmd, 300, &before_rc);
        sdsfree(before_cmd);
        clock_gettime(CLOCK_MONOTONIC, &b_t1);
        double before_secs = (double)(b_t1.tv_sec - b_t0.tv_sec) + (double)(b_t1.tv_nsec - b_t0.tv_nsec) / 1e9;
        printf("[evolve] BEFORE baseline benchmark: rc=%d, elapsed=%.2fs\n", before_rc, before_secs);
        fflush(stdout);

        /* Run the agent in the sandbox */
        sds prompt = build_prompt(sandbox, goal, gen);
        
        /* Temporarily set cwd to sandbox so agent works there */
        const char *orig_cwd = cfg->cwd;
        cfg->cwd = sandbox;
        
        sds reply = agent_run(cfg, prompt);
        
        cfg->cwd = orig_cwd;  /* Restore */
        
        sdsfree(prompt);
        printf("\n[evolve] agent finished generation %d:\n%s\n", gen,
               reply ? reply : "(no reply)");
        fflush(stdout);

        sds report = NULL;
        int ok = !alpha_cancel && (reply && reply[0] && strcmp(reply, "ERROR: empty response from LLM") != 0);

        /* Verify Warden cryptographic seal & git protection BEFORE running gate */
        if (ok) {
            if (!evolve_seal_verify(sandbox, &seal_before, &report)) {
                ok = 0;
            } else if (!evolve_git_protected_clean(sandbox, &report)) {
                ok = 0;
            }
        }

        if (ok) {
            ok = evolve_gate(sandbox, cfg->model, &report);
        }

        /* 2. AFTER Benchmark & Comparison: Run post-mutation benchmark on sandbox */
        if (ok) {
            int after_rc = -1;
            struct timespec a_t0, a_t1;
            clock_gettime(CLOCK_MONOTONIC, &a_t0);
            sds after_cmd = sdscatprintf(sdsempty(),
                "./alpha -m %s \"Use memory tool to add entry bench_after='val_after' then retrieve memory\" 2>&1", bm);
            sds after_bench = run_capture(sandbox, after_cmd, 300, &after_rc);
            sdsfree(after_cmd);
            clock_gettime(CLOCK_MONOTONIC, &a_t1);
            double after_secs = (double)(a_t1.tv_sec - a_t0.tv_sec) + (double)(a_t1.tv_nsec - a_t0.tv_nsec) / 1e9;
            printf("[evolve] AFTER benchmark comparison: rc=%d, elapsed=%.2fs (vs BEFORE %.2fs)\n", after_rc, after_secs, before_secs);
            fflush(stdout);

            /* 360° Quality & Performance Evaluation */
            size_t b_len = before_bench ? sdslen(before_bench) : 0;
            size_t a_len = after_bench ? sdslen(after_bench) : 0;

            int failed_quality = 0;
            sds qual_err = sdsempty();

            if (after_rc != 0) {
                failed_quality = 1;
                qual_err = sdscatprintf(qual_err, "Exit code failed (rc=%d vs before %d); ", after_rc, before_rc);
            }
            if (!after_bench || a_len == 0) {
                failed_quality = 1;
                qual_err = sdscat(qual_err, "Empty output; ");
            }
            if (after_bench && (strstr(after_bench, "ERROR") || strstr(after_bench, "Segmentation fault") || strstr(after_bench, "panic"))) {
                failed_quality = 1;
                qual_err = sdscat(qual_err, "Output contained error/fault keyword; ");
            }
            /* Only flag real truncation: output collapsing to near-nothing.
             * LLM output length naturally varies between runs -- rejecting
             * concise-but-correct answers reverted good mutations (gens
             * 18/19/21). A short answer that still exits 0 with no error
             * keywords did the task. */
            if (b_len > 400 && a_len < 100) {
                failed_quality = 1;
                qual_err = sdscatprintf(qual_err, "Quality degradation: output truncated/shorter (%zu bytes vs before %zu bytes); ", a_len, b_len);
            }
            if (after_secs > (before_secs * 1.5 + 2.0)) {
                failed_quality = 1;
                qual_err = sdscatprintf(qual_err, "Latency regression (%.2fs vs before %.2fs); ", after_secs, before_secs);
            }

            if (failed_quality) {
                ok = 0;
                if (!report) report = sdsempty();
                report = sdscatprintf(report, "\nFAIL: 360° Quality/Performance Benchmark Regression: %s\n", qual_err);
            } else {
                printf("[evolve] 360° Quality Benchmark PASSED: length=%zu vs before %zu, elapsed=%.2fs vs before %.2fs\n",
                       a_len, b_len, after_secs, before_secs);
            }
            sdsfree(qual_err);
            sdsfree(after_bench);
        }
        sdsfree(before_bench);

        if (!report) report = sdsnew(alpha_cancel ? "interrupted\n" : 
                                      (!reply || !reply[0] || strcmp(reply, "ERROR: empty response from LLM") == 0) ? 
                                      "FAIL: empty LLM response\n" : "");

        /* Audit flag: a generation that touched the tests or the Makefile is
         * legitimate more often than not, but it is where reward hacking
         * would hide, so the log says it plainly. */
        int tt_rc = -1;
        sds tt = run_capture(sandbox,
            "git status --porcelain -- tests/ Makefile 2>/dev/null || echo ''", 30, &tt_rc);
        int touched_tests = (tt && sdslen(tt) > 0);
        sdsfree(tt);

        if (ok) {
            /* Sync sandbox code and binary back into main project tree */
            char synccmd[PATH_MAX * 2 + 256];
            snprintf(synccmd, sizeof(synccmd),
                "cp -R '%s/src/'* '%s/src/' 2>/dev/null; "
                "cp -R '%s/include/'* '%s/include/' 2>/dev/null; "
                "cp -R '%s/tests/'* '%s/tests/' 2>/dev/null; "
                "cp '%s/alpha' '%s/alpha' 2>/dev/null; "
                "cp '%s/Makefile' '%s/Makefile' 2>/dev/null; "
                "true",
                sandbox, root, sandbox, root, sandbox, root, sandbox, root, sandbox, root);
            int sync_rc = -1;
            sds syncout = run_capture(root, synccmd, 60, &sync_rc);
            sdsfree(syncout);

            char gdir[PATH_MAX];
            snprintf(gdir, sizeof(gdir), "%s/evolution/gen-%03d", root, gen);
            mkdir(gdir, 0755);
            
            char cpcmd[PATH_MAX * 2 + 64];
            snprintf(cpcmd, sizeof(cpcmd), "cp '%s/alpha' '%s/evolution/gen-%03d/alpha'", sandbox, root, gen);
            int cp_rc = -1;
            sds cpout = run_capture(root, cpcmd, 60, &cp_rc);
            sdsfree(cpout);

            char msg[256];
            snprintf(msg, sizeof(msg), "evolve: generation %d", gen);
            char commitcmd[PATH_MAX + 300];
            snprintf(commitcmd, sizeof(commitcmd),
                "git add -A && git -c user.name=agent-alpha "
                "-c user.email=alpha@localhost commit -q -m '%s'", msg);
            int cm_rc = -1;
            sds cmout = run_capture(root, commitcmd, 60, &cm_rc);
            sdsfree(cmout);

            int h_rc = -1;
            sds hash = run_capture(root, "git rev-parse --short HEAD", 20, &h_rc);
            if (hash && sdslen(hash)) {
                while (sdslen(hash) && (hash[sdslen(hash) - 1] == '\n'))
                    hash[sdslen(hash) - 1] = 0;
            }

            log_append(root, gen, goal, "keep", hash ? hash : "", reply, touched_tests);
            printf("[evolve] generation %d KEPT (commit %s, binary archived to evolution/gen-%03d/alpha)\n",
                   gen, hash ? hash : "?", gen);
            sdsfree(hash);
            kept++;

            /* Become the improved self: the next generation then runs on the
             * binary it just built. Configuration crosses the exec through the
             * environment, so no API key appears in argv. */
            if (reexec && g + 1 < generations && !alpha_cancel) {
                printf("[evolve] re-executing into the generation %d binary\n", gen);
                fflush(stdout);
                
                /* Safely set environment variables with fallbacks */
                if (cfg->base_url && cfg->base_url[0]) {
                    setenv("ALPHA_BASE_URL", cfg->base_url, 1);
                } else {
                    setenv("ALPHA_BASE_URL", "", 1);
                }
                
                if (cfg->model && cfg->model[0]) {
                    setenv("ALPHA_MODEL", cfg->model, 1);
                } else {
                    setenv("ALPHA_MODEL", "local", 1);
                }
                
                if (cfg->api_key) {
                    setenv("ALPHA_API_KEY", cfg->api_key, 1);
                }
                
                if (cfg->max_turns > 0) {
                    char mt[16];
                    snprintf(mt, sizeof(mt), "%d", cfg->max_turns);
                    setenv("ALPHA_MAX_TURNS", mt, 1);
                }
                
                char bin[PATH_MAX];
                snprintf(bin, sizeof(bin), "%s/alpha", root);
                char left[16];
                snprintf(left, sizeof(left), "%d", generations - g - 1);
                char *const args[] = { bin, "--evolve", (char *)goal,
                                       "--generations", left, NULL };
                execv(bin, args);
                fprintf(stderr, "[evolve] re-exec failed: %s — continuing in this binary\n",
                        strerror(errno));
            }
        } else {
            printf("[evolve] generation %d REVERTED:%s\n", gen, report ? report : "(no report)");
            int r_rc = -1;
            sds r = run_capture(root, "git reset --hard -q HEAD", 60, &r_rc);
            sdsfree(r);
            /* Ignored paths survive the clean: evolution/ keeps the log and
             * the archived binaries, .env keeps its secrets. */
            r = run_capture(root, "git clean -fd -q", 60, &r_rc);
            sdsfree(r);
            /* The binary on disk is the failed build; rebuild so ./alpha
             * matches HEAD again. */
            r = run_capture(root, "make -j4", 600, &r_rc);
            sdsfree(r);
            log_append(root, gen, goal, "revert", "", report ? report : "", touched_tests);
            reverted++;
        }
        sdsfree(report);
        if (reply) sdsfree(reply);
    }

    printf("\n[evolve] done: %d generation%s kept, %d reverted. Log: %s/evolution/log.jsonl\n",
           kept, kept == 1 ? "" : "s", reverted, root);
    return 0;
}
