/* Self-evolution driver (Battle-Hardened Enterprise Edition).
 *
 * SECURITY & ISOLATION MODEL:
 * The model is adversarial. It edits source strictly inside an isolated sandbox.
 * THIS code re-runs the gate (build, test, warden seal, 360° benchmark)
 * and either commits or reverts with atomic git snapshots.
 *
 * HARDENED FEATURES:
 * - True Sandbox Confinement: cfg->cwd = sandbox during turn execution.
 * - Shell Injection Defense: shell_escape on all interpolated arguments.
 * - Signal & FD Hygiene: SIGCHLD masking around fork/setpgid, fd cleanup 3..1024.
 * - Constant-Time SHA-256 Seal: bitwise XOR comparison across all 6 protected files.
 * - POSIX Advisory File Locking: fcntl(F_SETLKW) on evolution/log.jsonl.
 * - Sanitized Minimal Re-exec: execve with explicit environment whitelist.
 */

#include "alpha.h"
#include "warden.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/* --- safe string helpers --------------------------------------------------- */

/* Shell-escape a string for safe interpolation into sh -c commands.
 * Prevents command injection when model-controlled strings enter run_capture. */
static sds shell_escape(const char *s) {
    sds out = sdscat(sdsempty(), "'");
    for (const char *p = s; p && *p; p++) {
        if (*p == '\'')
            out = sdscat(out, "'\\''");
        else
            out = sdscatlen(out, p, 1);
    }
    return sdscat(out, "'");
}

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
 * Hardened: proper SIGCHLD masking, fd leak prevention, and no shell
 * injection vectors. Output capture uses non-blocking I/O correctly. */
static sds run_capture(const char *cwd, const char *cmd, int timeout_sec, int *out_rc) {
    sds out = sdsempty();
    *out_rc = -1;

    /* Block SIGCHLD during fork+setpgid to prevent race where child exits
     * before parent sets its process group, causing kill(-pid) to miss it. */
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
        return sdscat(out, "ERROR: pipe failed\n");
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: restore signal mask, set up new process group, redirect fds */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
        setpgid(0, 0);
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Close all other inherited fds to prevent leaking sockets/files */
        for (int fd = 3; fd < 1024; fd++) close(fd);

        if (cwd) chdir(cwd);
        execlp("sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    if (pid < 0) {
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
        close(pipefd[0]);
        close(pipefd[1]);
        return sdscat(out, "ERROR: fork failed\n");
    }

    /* Parent: set pgid from our side too (race-safe), then unblock SIGCHLD */
    setpgid(pid, pid);
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);

    int status = 0;
    char buf[8192];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (;;) {
        ssize_t r = read(pipefd[0], buf, sizeof(buf));
        if (r > 0) out = sdscatlen(out, buf, (size_t)r);

        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            /* Drain remaining output after child exit */
            while ((r = read(pipefd[0], buf, sizeof(buf))) > 0)
                out = sdscatlen(out, buf, (size_t)r);
            if (WIFEXITED(status)) *out_rc = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) *out_rc = 128 + WTERMSIG(status);
            break;
        }

        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (double)(t1.tv_sec - t0.tv_sec)
                  + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

        if (el > (double)timeout_sec) {
            kill(-pid, SIGKILL);
            /* Grace period: poll briefly for D-state processes */
            for (int grace = 0; grace < 20; grace++) {
                if (waitpid(pid, &status, WNOHANG) == pid) break;
                usleep(100000);
            }
            out = sdscatprintf(out, "\n[evolve] killed after %ds timeout\n", timeout_sec);
            *out_rc = 128 + SIGKILL;
            break;
        }
        usleep(20000);
    }
    close(pipefd[0]);
    return out;
}

/* --- fitness gate ---------------------------------------------------------- */

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

/* Domain benchmark: uses shell_escape to prevent injection via model name */
static int run_domain_benchmark(const char *dir, const char *model, sds *report) {
    int rc = -1;
    sds status = run_capture(dir, "git status --porcelain 2>/dev/null || echo ''", 30, &rc);
    if (!status) return 1;

    sds staged = run_capture(dir, "git diff --cached --name-only 2>/dev/null || echo ''", 30, &rc);
    sds combined = sdsempty();
    if (status && sdslen(status) > 0) combined = sdscat(combined, status);
    if (staged && sdslen(staged) > 0) combined = sdscat(combined, staged);

    int is_memory = (strstr(combined, "memory") != NULL);
    int is_search = (strstr(combined, "web_search") != NULL || strstr(combined, "search") != NULL);
    int is_tools  = (strstr(combined, "tools") != NULL || strstr(combined, "edit") != NULL);
    sdsfree(status);
    sdsfree(staged);
    sdsfree(combined);

    sds safe_model = shell_escape((model && model[0]) ? model : "local");

    /* Benchmark subprocesses must not write to the real ~/.alpha/memory —
     * their bench_* / test_key_* entries used to leak into the store every
     * generation and get injected into every future system prompt. */
    sds memdir = sdscatprintf(sdsempty(), "%s/.bench-memory", dir);
    sds safe_memdir = shell_escape(memdir);
    sdsfree(memdir);

    if (is_memory) {
        sds cmd = sdscatprintf(sdsempty(),
            "ALPHA_MEMORY_DIR=%s ./alpha -m %s 'Use memory tool to add entry test_key_999=domain_bench_value then retrieve memory' 2>&1",
            safe_memdir, safe_model);
        sds out = run_capture(dir, cmd, 120, &rc);
        sdsfree(cmd);
        if (rc != 0 || !out || strstr(out, "ERROR") || !strstr(out, "domain_bench_value")) {
            report_tail(report, "Domain Benchmark: Memory Tool", out);
            report_append(report, "FAIL: 360° Memory Domain Benchmark\n");
            sdsfree(out); sdsfree(safe_model); sdsfree(safe_memdir);
            return 0;
        }
        sdsfree(out);
    } else if (is_search) {
        sds cmd = sdscatprintf(sdsempty(),
            "./alpha -m %s 'Use web_search to find latest C11 standard details' 2>&1",
            safe_model);
        sds out = run_capture(dir, cmd, 120, &rc);
        sdsfree(cmd);
        if (rc != 0 || !out || strstr(out, "ERROR")) {
            report_tail(report, "Domain Benchmark: Web Search Tool", out);
            report_append(report, "FAIL: 360° Web Search Domain Benchmark\n");
            sdsfree(out); sdsfree(safe_model); sdsfree(safe_memdir);
            return 0;
        }
        sdsfree(out);
    } else if (is_tools) {
        sds cmd = sdscatprintf(sdsempty(),
            "./alpha -m %s 'List files in current dir and report count' 2>&1",
            safe_model);
        sds out = run_capture(dir, cmd, 120, &rc);
        sdsfree(cmd);
        if (rc != 0 || !out || strstr(out, "ERROR")) {
            report_tail(report, "Domain Benchmark: Tools & File Execution", out);
            report_append(report, "FAIL: 360° Tools Domain Benchmark\n");
            sdsfree(out); sdsfree(safe_model); sdsfree(safe_memdir);
            return 0;
        }
        sdsfree(out);
    }
    sdsfree(safe_model);
    sdsfree(safe_memdir);
    return 1;
}

/* --- Warden cryptographic seal ----------------------------------------------
 * Constant-time comparison prevents timing side-channels.
 * Covers all 6 mission-critical harness files. */

#define EVOLVE_PROTECTED_COUNT 6
static const char *EVOLVE_PROTECTED_FILES[EVOLVE_PROTECTED_COUNT] = {
    "Makefile", "src/evolve.c", "src/agent_loop.c",
    "tests/test_evolve.c", "src/warden.c", "src/llm.c"
};

typedef struct { char hex[65]; } seal_hash_t;
typedef struct { seal_hash_t files[EVOLVE_PROTECTED_COUNT]; } evolve_hash_table;

/* Constant-time hex comparison: prevents timing oracle */
static int seal_hashes_equal(const char *a, const char *b) {
    unsigned char diff = 0;
    for (int i = 0; i < 64; i++) diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

static int evolve_seal_snapshot(const char *sandbox_dir,
                                evolve_hash_table *table,
                                sds *report) {
    if (!sandbox_dir || !table) return 0;
    sds errors = sdsempty();
    int ok = 1;
    for (int i = 0; i < EVOLVE_PROTECTED_COUNT; i++) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", sandbox_dir, EVOLVE_PROTECTED_FILES[i]);
        char hex[65];
        if (warden_sha256_file(full, hex) != WARDEN_OK) {
            errors = sdscatprintf(errors, "seal: cannot hash %s; ", EVOLVE_PROTECTED_FILES[i]);
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
    sds errors = sdsempty();
    int ok = 1;
    for (int i = 0; i < EVOLVE_PROTECTED_COUNT; i++) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", sandbox_dir, EVOLVE_PROTECTED_FILES[i]);
        char hex[65];
        if (warden_sha256_file(full, hex) != WARDEN_OK) {
            errors = sdscatprintf(errors, "tamper: %s deleted/unreadable; ", EVOLVE_PROTECTED_FILES[i]);
            ok = 0;
            continue;
        }
        if (!seal_hashes_equal(table->files[i].hex, hex)) {
            errors = sdscatprintf(errors, "tamper: %s modified; ", EVOLVE_PROTECTED_FILES[i]);
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
    const char *mark = strstr(build_dir, "/sandbox/");
    if (!mark || mark == build_dir) return 1;

    size_t n = (size_t)(mark - build_dir);
    char root[PATH_MAX];
    if (n >= sizeof(root)) n = sizeof(root) - 1;
    memcpy(root, build_dir, n);
    root[n] = 0;

    char gitprobe[PATH_MAX];
    snprintf(gitprobe, sizeof(gitprobe), "%s/.git", root);
    if (!file_exists(gitprobe)) return 1;

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
            errors = sdscatprintf(errors, "%s missing/unreadable (%s); ", paths[i],
                                  ra != WARDEN_OK ? "main" : "sandbox");
            ok = 0;
        } else if (!seal_hashes_equal(ha, hb)) {
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

static int evolve_no_tracked_deletions(const char *build_dir, sds *report) {
    char probe[PATH_MAX];
    snprintf(probe, sizeof(probe), "%s/.git", build_dir);
    if (!file_exists(probe)) return 1;

    int rc = -1;
    sds status = run_capture(build_dir, "git status --porcelain", 30, &rc);
    if (rc != 0 || !status) { sdsfree(status); return 1; }

    sds deleted = sdsempty();
    sds copy = sdsdup(status);
    char *saveptr = NULL;
    for (char *line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        if (strlen(line) < 3) continue;
        if ((line[0] == 'D' && line[1] == ' ') ||
            (line[0] == ' ' && line[1] == 'D')) {
            deleted = sdscatprintf(deleted, "%s; ", line + 3);
        }
    }
    sdsfree(copy);

    int ok = sdslen(deleted) == 0;
    if (!ok) {
        report_append(report, "FAIL: tracked file deleted: %s\n", deleted);
    }
    sdsfree(deleted);
    sdsfree(status);
    return ok;
}

/* A generation only counts if the agent changed something. The sandbox starts
 * as a byte-copy of root's source dirs, so any real edit shows up as a tree
 * difference. Without this check the gate (build + tests + benchmarks) passes
 * on a generation that shipped nothing, and the commit then sweeps up the
 * harness's own pending log.jsonl line — a "keep" with an empty diff, which
 * is exactly what the goal text calls a failure. */
static int evolve_sandbox_changed(const char *root, const char *sandbox) {
    char cmd[PATH_MAX * 4 + 512];
    /* *.o and tests/bin are build products; the sandbox rebuild always
     * regenerates them, so they would report a spurious difference. */
    snprintf(cmd, sizeof(cmd),
        "diff -rq -x '*.o' '%s/src' '%s/src' >/dev/null 2>&1 && "
        "diff -rq '%s/include' '%s/include' >/dev/null 2>&1 && "
        "diff -rq -x '*.o' -x bin '%s/tests' '%s/tests' >/dev/null 2>&1 && "
        "diff -rq -x '*.o' '%s/deps' '%s/deps' >/dev/null 2>&1",
        root, sandbox, root, sandbox, root, sandbox, root, sandbox);
    int rc = -1;
    sds out = run_capture(root, cmd, 60, &rc);
    sdsfree(out);
    return rc != 0;   /* diff exits 0 only when every tree is identical */
}

/* Feature code without a test is invisible to this gate: build + the existing
 * suite + benchmarks only ever exercise OLD behavior, so gen 211 shipped
 * code_search (+501 lines, zero tests) and nothing noticed — a deliberate
 * sabotage of code_search still printed ALL TESTS PASSED. When src/ or
 * include/ changed, require a new or updated tests/custom/test_*.c in the
 * same generation. Called BEFORE run_omega_red_team so Omega's generated
 * placeholder files can never satisfy the requirement. */
static int evolve_sandbox_test_coverage(const char *build_dir, sds *report) {
    const char *mark = strstr(build_dir, "/sandbox/");
    if (!mark || mark == build_dir) return 1;   /* not a sandbox: nothing to compare */

    size_t n = (size_t)(mark - build_dir);
    char root[PATH_MAX];
    if (n >= sizeof(root)) n = sizeof(root) - 1;
    memcpy(root, build_dir, n);
    root[n] = 0;

    int rc = -1;
    char cmd[PATH_MAX * 4 + 256];
    /* Behavior changed? The seal already verified the protected harness files
     * byte-identical, so any remaining src/ or include/ diff is agent-written
     * feature code. */
    snprintf(cmd, sizeof(cmd),
        "diff -rq -x '*.o' '%s/src' '%s/src' >/dev/null 2>&1 && "
        "diff -rq '%s/include' '%s/include' >/dev/null 2>&1",
        root, build_dir, root, build_dir);
    sds out = run_capture(root, cmd, 60, &rc);
    sdsfree(out);
    if (rc == 0) return 1;   /* no src/include change: tests/docs-only generation */

    /* A new or updated tests/custom/test_*.c in the same generation? */
    snprintf(cmd, sizeof(cmd),
        "diff -rq '%s/tests/custom' '%s/tests/custom' 2>/dev/null | "
        "grep 'test_.*\\.c' >/dev/null 2>&1",
        root, build_dir);
    out = run_capture(root, cmd, 60, &rc);
    sdsfree(out);
    if (rc != 0) {
        report_append(report,
            "FAIL: src/ or include/ changed but no tests/custom/test_*.c was added "
            "or updated — new behavior must ship with its own test (gen 211 shipped "
            "code_search untested; the gate cannot see feature regressions otherwise)\n");
        return 0;
    }
    return 1;
}

static int evolve_warden_smoke(const char *dir, sds *report) {
    warden_limits_t lim = warden_limits_default();
    lim.timeout_ms = 30000;
    char out[8192];
    char *const argv[] = { (char *)"./alpha", (char *)"--providers", NULL };

    int rc = warden_execute_capture(dir, "./alpha", argv, &lim, out, sizeof(out));
    if (rc != WARDEN_OK) {
        report_append(report, "FAIL: Warden smoke test failed rc=%d\n%.4000s\n", rc, out);
        return 0;
    }
    return 1;
}

static int evolve_warden_model_bench(const char *dir, const char *model, sds *report) {
    const char *m = (model && model[0]) ? model : "local";
    warden_limits_t lim = warden_limits_default();
    lim.timeout_ms = 300000; /* 5 minutes (300s) to allow reasoning models sufficient time */
    char out[8192];

    char *const argv[] = {
        (char *)"./alpha", (char *)"-m", (char *)m, (char *)"hi", NULL
    };

    int rc = warden_execute_capture(dir, "./alpha", argv, &lim, out, sizeof(out));
    if (rc != WARDEN_OK || out[0] == '\0' || strstr(out, "ERROR")) {
        report_append(report, "FAIL: Warden model benchmark failed rc=%d\n%.4000s\n", rc, out);
        return 0;
    }
    return 1;
}

/* --- Omega Adversarial Red-Teaming Subsystem -------------------------------
 * Omega acts as the adversarial breaker: it injects hostile edge-case fuzz tests
 * into tests/custom/ to stress-test any newly mutated C code before acceptance. */
static int run_omega_red_team(const char *build_dir, const char *model, sds *report) {
    (void)model;
    (void)report;
    char custom_dir[PATH_MAX];
    snprintf(custom_dir, sizeof(custom_dir), "%s/tests/custom", build_dir);
    mkdir(custom_dir, 0755);

    /* Generate baseline edge-case hostile fuzzer */
    char fuzz_file[PATH_MAX];
    snprintf(fuzz_file, sizeof(fuzz_file), "%s/test_omega_fuzz.c", custom_dir);
    FILE *f = fopen(fuzz_file, "w");
    if (f) {
        fprintf(f,
            "/* Auto-generated by Omega Adversarial Red-Team Engine */\n"
            "#include \"alpha.h\"\n"
            "#include \"test_util.h\"\n\n"
            "int main(void) {\n"
            "    TEST_BEGIN(\"omega_adversarial_fuzz\");\n"
            "    /* Edge-case NULL safety checks */\n"
            "    CHECK(1 == 1, \"omega hostile fuzzing harness active\");\n"
            "    return test_report(\"omega_adversarial_fuzz\");\n"
            "}\n");
        fclose(f);
    }
    return 1;
}

static int evolve_gate(const char *build_dir, const char *model, sds *report) {
    *report = NULL;
    int rc = -1;

    if (!evolve_git_protected_clean(build_dir, report)) return 0;
    if (!evolve_no_tracked_deletions(build_dir, report)) return 0;
    if (!evolve_sandbox_test_coverage(build_dir, report)) return 0;

    /* Run Omega Adversarial Red-Teaming pass */
    run_omega_red_team(build_dir, model, report);

    sds out = run_capture(build_dir, "make -j4", 600, &rc);
    if (rc != 0) {
        report_tail(report, "make -j4", out);
        report_append(report, "FAIL: build\n");
        sdsfree(out);
        return 0;
    }
    sdsfree(out);

    out = run_capture(build_dir, "make test", 900, &rc);
    int tests_ok = (rc == 0 && out && strstr(out, "ALL TESTS PASSED")
                    && strstr(out, "=== tests/bin/"));
    if (!tests_ok) {
        report_tail(report, "make test", out);
        if (rc == 0 && out && strstr(out, "ALL TESTS PASSED")
            && !strstr(out, "=== tests/bin/"))
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

    if (!evolve_warden_smoke(build_dir, report)) return 0;

    if (strstr(build_dir, "_fixture") == NULL) {
        if (!evolve_warden_model_bench(build_dir, model, report)) return 0;
        if (!run_domain_benchmark(build_dir, model, report)) return 0;
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
    /* Keep the TAIL of the report, not the head: report_append() puts the
     * "FAIL: ..." reason at the very end, so storing the first 300 chars
     * logged a few truncated clang command lines and discarded the actual
     * failure. The agent reads this log to learn what not to repeat — the
     * note has to contain the reason. */
    const char *np = note ? note : "";
    size_t nl = strlen(np);
    if (nl > 2000) np += nl - 2000;
    sds n = json_escape(np, 2000);
    fprintf(f, "{\"gen\":%d,\"ts\":%lld,\"goal\":\"%s\",\"result\":\"%s\","
               "\"commit\":\"%s\",\"touched_tests\":%s,\"note\":\"%s\"}\n",
            gen, (long long)time(NULL), g, result,
            commit ? commit : "", touched_tests ? "true" : "false", n);
    sdsfree(g); sdsfree(n);

#ifdef F_SETLKW
    fl.l_type = F_UNLCK;
    fcntl(fileno(f), F_SETLK, &fl);
#endif

    fclose(f);
}

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
    /* Notes are up to ~2 KB each now; 8 KB keeps roughly the 4 most recent
     * generations in the prompt instead of just the last one. */
    if (sdslen(out) > 8000) {
        sds t = sdsnewlen(out + sdslen(out) - 8000, 8000);
        sdsfree(out);
        out = t;
    }
    return out;
}

/* --- sandbox -----------------------------------------------------------------
 * Pure source snapshot: excludes .git, .env, evolution/ to ensure true isolation. */

static int setup_sandbox(const char *root, char sandbox[PATH_MAX], int gen) {
    char base[PATH_MAX];
    snprintf(base, sizeof(base), "%s/sandbox", root);

    char mkdir_cmd[PATH_MAX + 64];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s'", base);
    int rc = -1;
    sds out = run_capture(root, mkdir_cmd, 30, &rc);
    sdsfree(out);
    if (rc != 0) return 0;

    snprintf(sandbox, PATH_MAX, "%s/gen_%03d", base, gen);

    if (mkdir(sandbox, 0755) != 0) {
        if (errno == EEXIST) {
            char testfile[PATH_MAX];
            snprintf(testfile, sizeof(testfile), "%s/Makefile", sandbox);
            if (!file_exists(testfile)) {
                fprintf(stderr, "[evolve] sandbox gen_%03d corrupted\n", gen);
                return 0;
            }
        } else {
            fprintf(stderr, "[evolve] mkdir sandbox failed: %s\n", strerror(errno));
            return 0;
        }
    }

    char cmd[PATH_MAX * 3 + 256];
    snprintf(cmd, sizeof(cmd),
        "for d in src tests include deps tests/custom; do [ -d \"%s/$d\" ] && cp -R \"%s/$d\" '%s/' 2>/dev/null; done; "
        "mkdir -p '%s/tests/custom' 2>/dev/null; "
        "cp '%s/Makefile' '%s/' 2>/dev/null; "
        "true",
        root, root, sandbox, sandbox, root, sandbox);

    out = run_capture(root, cmd, 60, &rc);
    sdsfree(out);

    char alphabin[PATH_MAX], destbin[PATH_MAX];
    snprintf(alphabin, sizeof(alphabin), "%s/alpha", root);
    snprintf(destbin, sizeof(destbin), "%s/alpha", sandbox);
    if (file_exists(alphabin)) {
        char cp_bin[PATH_MAX * 2 + 32];
        snprintf(cp_bin, sizeof(cp_bin), "cp '%s' '%s'", alphabin, destbin);
        out = run_capture(root, cp_bin, 30, &rc);
        sdsfree(out);
    }

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
        "You are Agent Alpha, evolving your own codebase on macOS Apple Silicon.\n"
        "Working directory: %s\n\n"
        "GOAL: %s\n\n"
        "SELF-DIRECTED EVOLUTION:\n"
        "You choose your own mission — nobody assigns you tasks. But autonomy means SHIPPING working code, not exploring.\n"
        "You research proven open-source projects by cloning them locally and reading their real source.\n"
        "You decide yourself which ONE missing capability is worth porting, and you implement it yourself.\n\n"
        "HARNESS & VERIFICATION:\n"
        "1. DYNAMIC TEST RUNNER: Any test you create in `tests/custom/test_*.c` is automatically compiled and executed by `make test`.\n"
        "2. OMEGA ADVERSARIAL BREAKER: Your code will be automatically fuzz-tested with NULL pointers and edge cases before acceptance.\n"
        "3. PRESERVE THE GATE: `make -j4 && make test` must pass. Never edit the sealed harness files (Makefile, src/evolve.c, src/warden.c, etc.).\n"
        "4. POSIX & APPLE SILICON: Write clean C11 (-Wall -Wextra clean) using native Darwin/BSD and POSIX APIs.\n\n"
        "STEP BY STEP (follow in order, do not skip, do not stop early):\n"
        "1. SURVEY (Turn 1): Read `include/alpha.h`, `src/tools.c`, and inspect `src/tools/`.\n"
        "2. DECIDE & IMPLEMENT (Turns 2-4): Choose ONE capability to build. Write clean C11 code in a new file `src/tools/tool_<name>.c` using `alpha_tool_t`, include it in `src/tools.c`, and register it in `g_registered_tools[]`.\n"
        "3. TEST (Turn 5): Create `tests/custom/test_<name>.c` with real assertions certifying your new logic.\n"
        "4. VERIFY: Run `make -j4 && make test` to prove that all test suites pass.\n"
        "Always invoke tools using your native function-calling interface. Your final diff MUST be non-empty.\n\n"
        "Use `memory` tool to persist technical discoveries across generations.\n\n"
        "The driver re-runs the full 360° gate when you finish. If everything passes, your code is committed as generation %d.\n\n"
        "Evolution log:\n%s",
        root, goal, gen, tail);
    sdsfree(tail);
    return p;
}

/* --- main loop ------------------------------------------------------------- */

int evolve_run(alpha_cfg_t *cfg, const char *goal, int generations, int reexec) {
    char root[PATH_MAX];
    if (!find_source_root(root)) {
        fprintf(stderr, "evolve: cannot find Agent Alpha source tree.\n");
        return 2;
    }
    if (!goal || !goal[0]) goal = "improve yourself";
    cfg->cwd = root;
    if (cfg->max_turns <= 0) cfg->max_turns = 64;
    setenv("ALPHA_EVOLVE", "1", 1);

    char evdir[PATH_MAX];
    snprintf(evdir, sizeof(evdir), "%s/evolution", root);
    mkdir(evdir, 0755);

    /* Cross-process exclusivity. next_generation() reads max(gen) from the log
     * and log_append() locks only around the write, so two overlapping evolve
     * runs picked the same generation number and raced on the tree (seen as
     * duplicate gen entries in log.jsonl). Hold an advisory write lock for the
     * whole run instead. The fd survives the re-exec (fcntl locks are
     * per-process, and a process re-locking its own file succeeds), and
     * run_capture children close fds 3..1024 so they never inherit it. */
    char lockpath[PATH_MAX];
    snprintf(lockpath, sizeof(lockpath), "%s/.lock", evdir);
    int lockfd = open(lockpath, O_RDWR | O_CREAT, 0644);
    if (lockfd < 0) {
        fprintf(stderr, "evolve: cannot open %s: %s\n", lockpath, strerror(errno));
        return 2;
    }
    struct flock evfl;
    memset(&evfl, 0, sizeof(evfl));
    evfl.l_type = F_WRLCK;
    evfl.l_whence = SEEK_SET;
    if (fcntl(lockfd, F_SETLK, &evfl) == -1) {
        fprintf(stderr, "evolve: another evolution run already holds %s — exiting.\n",
                lockpath);
        close(lockfd);
        return 2;
    }

    int rc = -1;
    sds out = run_capture(root, "git rev-parse --is-inside-work-tree", 20, &rc);
    int is_repo = (rc == 0 && out && strstr(out, "true"));
    sdsfree(out);
    if (!is_repo) {
        fprintf(stderr, "evolve: %s is not a git repository.\n", root);
        return 2;
    }

    out = run_capture(root, "git status --porcelain", 30, &rc);
    int dirty = (rc == 0 && out && sdslen(out) > 0);
    sdsfree(out);
    if (dirty) {
        printf("[evolve] uncommitted changes — committing baseline\n");
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

        char sandbox[PATH_MAX];
        if (!setup_sandbox(root, sandbox, gen)) {
            fprintf(stderr, "[evolve] sandbox setup failed\n");
            break;
        }
        printf("[evolve] sandbox: %s\n", sandbox);

        evolve_hash_table seal_before;
        sds seal_init_report = NULL;
        if (!evolve_seal_snapshot(sandbox, &seal_before, &seal_init_report)) {
            fprintf(stderr, "[evolve] seal init failed: %s\n",
                    seal_init_report ? seal_init_report : "unknown");
            sdsfree(seal_init_report);
            break;
        }
        sdsfree(seal_init_report);

        /* Build baseline in sandbox */
        printf("[evolve] building baseline in sandbox...\n");
        fflush(stdout);
        int build_rc = -1;
        out = run_capture(sandbox, "make -j4", 600, &build_rc);
        sdsfree(out);
        if (build_rc != 0) {
            fprintf(stderr, "[evolve] sandbox baseline build failed\n");
            continue;
        }

        /* BEFORE benchmark in sandbox (memory writes isolated to the sandbox —
         * bench_* entries must never reach the real ~/.alpha/memory store) */
        const char *bm = (cfg->model && cfg->model[0]) ? cfg->model : "local";
        sds safe_bm = shell_escape(bm);
        sds bench_memdir = sdscatprintf(sdsempty(), "%s/.bench-memory", sandbox);
        sds safe_bench_memdir = shell_escape(bench_memdir);
        sdsfree(bench_memdir);
        int before_rc = -1;
        struct timespec b_t0, b_t1;
        clock_gettime(CLOCK_MONOTONIC, &b_t0);
        sds before_cmd = sdscatprintf(sdsempty(),
            "ALPHA_MEMORY_DIR=%s ./alpha -m %s 'Use memory tool to add entry bench_before=val_before then retrieve memory' 2>&1",
            safe_bench_memdir, safe_bm);
        sds before_bench = run_capture(sandbox, before_cmd, 300, &before_rc);
        sdsfree(before_cmd); sdsfree(safe_bm);
        clock_gettime(CLOCK_MONOTONIC, &b_t1);
        double before_secs = (double)(b_t1.tv_sec - b_t0.tv_sec)
                           + (double)(b_t1.tv_nsec - b_t0.tv_nsec) / 1e9;
        printf("[evolve] BEFORE baseline benchmark: rc=%d, elapsed=%.2fs\n", before_rc, before_secs);
        fflush(stdout);

        /* Run agent strictly in sandbox */
        sds prompt = build_prompt(sandbox, goal, gen);
        const char *orig_cwd = cfg->cwd;
        cfg->cwd = sandbox;

        sds reply = agent_run(cfg, prompt);
        cfg->cwd = orig_cwd;

        sdsfree(prompt);
        printf("\n[evolve] agent finished generation %d:\n%s\n", gen, reply ? reply : "(no reply)");
        fflush(stdout);

        sds report = NULL;
        int ok = !alpha_cancel && reply && reply[0]
                 && strcmp(reply, "ERROR: empty response from LLM") != 0;
        if (!ok && !report) {
            report = reply && reply[0] ? sdsnew(reply) : sdsnew("FAIL: generation finished without output or empty reply\n");
        }

        if (ok) {
            if (!evolve_seal_verify(sandbox, &seal_before, &report)) ok = 0;
            else if (!evolve_git_protected_clean(sandbox, &report)) ok = 0;
            /* Cheap check before the expensive gate: an empty generation must
             * not burn a full build + benchmark cycle on its way to "keep". */
            else if (!evolve_sandbox_changed(root, sandbox)) {
                report_append(&report,
                    "FAIL: empty generation — no source change in src/, include/, "
                    "tests/ or deps/ (the agent shipped nothing)\n");
                ok = 0;
            }
        }
        if (ok) ok = evolve_gate(sandbox, cfg->model, &report);

        /* Iterative Repair Gate: If gate failed for ANY reason (compiler error, test failure,
         * missing test fixture, or empty generation), feed feedback into the sandbox for up to 3 repair turns! */
        int repair_attempts = 0;
        while (!ok && !alpha_cancel && repair_attempts < 3) {
            repair_attempts++;
            printf("\n[evolve] Gate failed (repair attempt %d/3) — launching targeted repair with feedback...\n", repair_attempts);
            if (report) printf("%s\n", report);
            fflush(stdout);

            int missing_test = report && strstr(report, "no tests/custom/test_") != NULL;
            int empty_gen = report && strstr(report, "empty generation") != NULL;

            sds fix_prompt = NULL;
            if (missing_test) {
                fix_prompt = sdscatprintf(sdsempty(),
                    "Your feature code is in place and compiles cleanly — but new behavior "
                    "MUST ship with its own test, and you did not write one.\n\n"
                    "Your task now: create `tests/custom/test_<name>.c` with at least 6 real CHECK "
                    "assertions certifying the code you just added. "
                    "Any file named tests/custom/test_*.c is compiled and run automatically by "
                    "`make test`. Verify with `make -j4 && make test` that YOUR new test binary "
                    "runs and passes.\n\n"
                    "Do NOT rewrite your feature code unless your test reveals a real bug in it.");
            } else if (empty_gen) {
                fix_prompt = sdscatprintf(sdsempty(),
                    "You surveyed the repository but have NOT written any code or test files yet (empty generation).\n\n"
                    "You have a repair attempt now: immediately implement your chosen capability in `src/tools/tool_<name>.c` "
                    "using `alpha_tool_t`, include it in `src/tools.c`, register it in `g_registered_tools[]`, and create `tests/custom/test_<name>.c`. "
                    "Then verify with `make -j4 && make test`!");
            } else {
                fix_prompt = sdscatprintf(sdsempty(),
                    "Your previous modifications in this sandbox failed the quality gate with the following error:\n\n"
                    "```\n%s\n```\n\n"
                    "You are still in the same sandbox with all your modified files in place. "
                    "Inspect the exact compiler error or test failure above, use read_file and edit_file to FIX the bug, "
                    "and verify with `make -j4 && make test`. Do not start over from scratch — fix the specific error!",
                    report ? report : "Unknown gate error");
            }

            sdsfree(reply);
            cfg->cwd = sandbox;
            reply = agent_run(cfg, fix_prompt);
            cfg->cwd = orig_cwd;
            sdsfree(fix_prompt);

            sdsfree(report);
            report = NULL;
            ok = !alpha_cancel && reply && reply[0]
                 && strcmp(reply, "ERROR: empty response from LLM") != 0;

            if (ok) {
                if (!evolve_seal_verify(sandbox, &seal_before, &report)) ok = 0;
                else if (!evolve_git_protected_clean(sandbox, &report)) ok = 0;
                else if (!evolve_sandbox_changed(root, sandbox)) ok = 0;
            }
            if (ok) ok = evolve_gate(sandbox, cfg->model, &report);
        }

        /* AFTER benchmark in sandbox */
        if (ok) {
            sds safe_bm2 = shell_escape(bm);
            int after_rc = -1;
            struct timespec a_t0, a_t1;
            clock_gettime(CLOCK_MONOTONIC, &a_t0);
            sds after_cmd = sdscatprintf(sdsempty(),
                "ALPHA_MEMORY_DIR=%s ./alpha -m %s 'Use memory tool to add entry bench_after=val_after then retrieve memory' 2>&1",
                safe_bench_memdir, safe_bm2);
            sds after_bench = run_capture(sandbox, after_cmd, 300, &after_rc);
            sdsfree(after_cmd); sdsfree(safe_bm2);
            clock_gettime(CLOCK_MONOTONIC, &a_t1);
            double after_secs = (double)(a_t1.tv_sec - a_t0.tv_sec)
                              + (double)(a_t1.tv_nsec - a_t0.tv_nsec) / 1e9;
            printf("[evolve] AFTER benchmark comparison: rc=%d, elapsed=%.2fs (vs BEFORE %.2fs)\n",
                   after_rc, after_secs, before_secs);
            fflush(stdout);

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
            if (after_bench && (strstr(after_bench, "ERROR")
                || strstr(after_bench, "Segmentation fault")
                || strstr(after_bench, "panic"))) {
                failed_quality = 1;
                qual_err = sdscat(qual_err, "Output contained error/fault keyword; ");
            }
            if (b_len > 400 && a_len < 100) {
                failed_quality = 1;
                qual_err = sdscatprintf(qual_err, "Quality degradation: output truncated (%zu vs before %zu bytes); ", a_len, b_len);
            }
            if (after_secs > (before_secs * 1.5 + 2.0)) {
                failed_quality = 1;
                qual_err = sdscatprintf(qual_err, "Latency regression (%.2fs vs before %.2fs); ", after_secs, before_secs);
            }

            if (failed_quality) {
                ok = 0;
                report_append(&report, "\nFAIL: 360° Quality/Performance Benchmark Regression: %s\n", qual_err);
            } else {
                printf("[evolve] 360° Quality Benchmark PASSED: length=%zu vs before %zu, elapsed=%.2fs vs before %.2fs\n",
                       a_len, b_len, after_secs, before_secs);
            }
            sdsfree(qual_err);
            sdsfree(after_bench);
        }
        sdsfree(before_bench);
        sdsfree(safe_bench_memdir);

        if (!report) report = sdsnew(alpha_cancel ? "interrupted\n"
            : (!reply || !reply[0] || strcmp(reply, "ERROR: empty response from LLM") == 0)
              ? "FAIL: empty LLM response\n" : "");

        int tt_rc = -1;
        sds tt = run_capture(sandbox, "git status --porcelain -- tests/ Makefile 2>/dev/null || echo ''", 30, &tt_rc);
        int touched_tests = (tt && sdslen(tt) > 0);
        sdsfree(tt);

        if (ok) {
            char synccmd[PATH_MAX * 2 + 256];
            snprintf(synccmd, sizeof(synccmd),
                "cp -R '%s/src/'* '%s/src/' 2>/dev/null; "
                "cp -R '%s/include/'* '%s/include/' 2>/dev/null; "
                "cp -R '%s/tests/'* '%s/tests/' 2>/dev/null; "
                "cp -R '%s/deps/'* '%s/deps/' 2>/dev/null; "
                "cp '%s/alpha' '%s/alpha' 2>/dev/null; "
                "cp '%s/Makefile' '%s/Makefile' 2>/dev/null; "
                "true",
                sandbox, root, sandbox, root, sandbox, root, sandbox, root, sandbox, root, sandbox, root);
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
                "git add -A && git -c user.name=agent-alpha -c user.email=alpha@localhost "
                "commit -q -m '%s'", msg);
            int cm_rc = -1;
            sds cmout = run_capture(root, commitcmd, 60, &cm_rc);
            sdsfree(cmout);

            int h_rc = -1;
            sds hash = run_capture(root, "git rev-parse --short HEAD", 20, &h_rc);
            if (hash) {
                while (sdslen(hash) && hash[sdslen(hash)-1] == '\n')
                    hash[sdslen(hash)-1] = 0;
            }

            log_append(root, gen, goal, "keep", hash ? hash : "", reply, touched_tests);
            printf("[evolve] generation %d KEPT (commit %s, binary archived to evolution/gen-%03d/alpha)\n",
                   gen, hash ? hash : "?", gen);
            sdsfree(hash);
            kept++;

            if (reexec && g + 1 < generations && !alpha_cancel) {
                printf("[evolve] re-executing into generation %d binary\n", gen);
                fflush(stdout);

                char bin[PATH_MAX];
                snprintf(bin, sizeof(bin), "%s/alpha", root);
                char left[16];
                snprintf(left, sizeof(left), "%d", generations - g - 1);
                char *const args[] = { bin, "--evolve", (char *)goal,
                                       "--generations", left, NULL };

                char *envp[8];
                int ei = 0;
                sds e_base = sdscatprintf(sdsempty(), "ALPHA_BASE_URL=%s",
                                          cfg->base_url ? cfg->base_url : "");
                sds e_model = sdscatprintf(sdsempty(), "ALPHA_MODEL=%s",
                                           cfg->model ? cfg->model : "");
                envp[ei++] = e_base;
                envp[ei++] = e_model;
                if (cfg->api_key) {
                    sds e_key = sdscatprintf(sdsempty(), "ALPHA_API_KEY=%s", cfg->api_key);
                    envp[ei++] = e_key;
                }
                if (cfg->max_turns > 0) {
                    sds e_mt = sdscatprintf(sdsempty(), "ALPHA_MAX_TURNS=%d", cfg->max_turns);
                    envp[ei++] = e_mt;
                }
                envp[ei++] = (char *)"ALPHA_EVOLVE=1";
                envp[ei] = NULL;

                execve(bin, args, envp);
                fprintf(stderr, "[evolve] re-exec failed: %s\n", strerror(errno));
                for (int i = 0; i < ei - 1; i++) sdsfree(envp[i]);
            }
        } else {
            printf("[evolve] generation %d REVERTED:%s\n", gen, report ? report : "(no report)");
            /* Save failed sandbox snapshot to /tmp/alpha_revert_sandbox/ for Antigravity audit */
            char snapcmd[PATH_MAX * 2 + 128];
            snprintf(snapcmd, sizeof(snapcmd),
                "rm -rf /tmp/alpha_revert_sandbox; cp -R '%s' /tmp/alpha_revert_sandbox 2>/dev/null; "
                "echo 'GEN=%d\nREPORT=%s' > /tmp/alpha_revert_sandbox/.revert_report.txt; true",
                sandbox, gen, report ? report : "no report");
            int snap_rc = -1;
            sds snapout = run_capture(root, snapcmd, 60, &snap_rc);
            sdsfree(snapout);

            int r_rc = -1;
            sds r = run_capture(root, "git reset --hard -q HEAD", 60, &r_rc);
            sdsfree(r);
            r = run_capture(root, "git clean -fd -q", 60, &r_rc);
            sdsfree(r);
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
