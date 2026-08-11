/* Self-evolution driver.
 *
 * The model is never trusted to grade its own work: it edits the source it
 * was compiled from, then THIS code re-runs the gate (build, test suite,
 * binary smoke test) and either commits the generation or reverts it with
 * git reset --hard. git is the genome -- the baseline commit makes every
 * mutation revertible, and evolution/ holds the log and the archived
 * per-generation binaries. */

#include "alpha.h"
#include <fcntl.h>
#include <stdint.h>
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
    *report = sdscatprintf(*report, "\n--- %s (last %zu bytes) ---\n%.*s\n",
                           label, keep, (int)keep, out + n - keep);
}

/* A generation survives only if every stage passes. The model already ran
 * these commands itself; running them again here is what makes its claims
 * unforgeable. */
static int evolve_gate(const char *root, sds *report) {
    *report = sdsempty();
    int rc = -1;

    /* Reward-hacking guard: a generation that deletes source or test files
     * to make the suite pass is reverted, whatever the suite then says. */
    sds status = run_capture(root, "git status --porcelain", 30, &rc);
    if (rc == 0) {
        char *save = NULL;
        for (char *line = strtok_r(status, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            if (line[0] == 'D' || line[1] == 'D') {
                *report = sdscatprintf(*report,
                    "FAIL: tracked file deleted: %s\n", line + 3);
                sdsfree(status);
                return 0;
            }
        }
    }
    sdsfree(status);

    sds out = run_capture(root, "make -j4", 600, &rc);
    if (rc != 0) {
        report_tail(report, "make -j4", out);
        *report = sdscat(*report, "FAIL: build\n");
        sdsfree(out);
        return 0;
    }
    sdsfree(out);

    /* The string, not just the exit code: a Makefile whose test target was
     * edited to exit 0 without running anything must not pass. */
    out = run_capture(root, "make test", 900, &rc);
    /* "ALL TESTS PASSED" alone is not enough: a generation that edits the
     * Makefile test target to just echo that string and exit 0 would pass
     * every check here. The run-tests recipe prints "=== tests/bin/name ==="
     * for each binary it actually executes, so require at least one such
     * line as proof that the recipe ran rather than being bypassed. */
    int tests_ok = (rc == 0 && out
                    && strstr(out, "ALL TESTS PASSED")
                    && strstr(out, "=== tests/bin/"));
    if (!tests_ok) {
        report_tail(report, "make test", out);
        if (rc == 0 && out && strstr(out, "ALL TESTS PASSED")
            && !strstr(out, "=== tests/bin/"))
            *report = sdscat(*report,
                "FAIL: test suite (ALL TESTS PASSED was printed but no test "
                "binary actually ran — the Makefile test target may have been "
                "edited to bypass the suite)\n");
        else
            *report = sdscat(*report, "FAIL: test suite\n");
        sdsfree(out);
        return 0;
    }
    sdsfree(out);

    /* The suite cannot cover its own startup path; a binary that wedges or
     * crashes before answering --providers was observed passing make test. */
    out = run_capture(root, "./alpha --providers", 30, &rc);
    sdsfree(out);
    if (rc != 0) {
        *report = sdscat(*report, "FAIL: new binary smoke test\n");
        return 0;
    }

    *report = sdscat(*report, "OK: build + tests + smoke\n");
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
    sds g = json_escape(goal, 200);
    sds n = json_escape(note, 300);
    fprintf(f, "{\"gen\":%d,\"ts\":%lld,\"goal\":\"%s\",\"result\":\"%s\","
               "\"commit\":\"%s\",\"touched_tests\":%s,\"note\":\"%s\"}\n",
            gen, (long long)time(NULL), g, result,
            commit ? commit : "", touched_tests ? "true" : "false", n);
    sdsfree(g);
    sdsfree(n);
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

/* --- prompt ---------------------------------------------------------------- */

static sds build_prompt(const char *root, const char *goal, int gen) {
    sds tail = log_tail(root, 12);
    sds p = sdscatprintf(sdsempty(),
        "You are Agent Alpha, and you are evolving your own source code. Your working\n"
        "directory is the source tree of the binary you are running as: %s\n"
        "\n"
        "GOAL: %s\n"
        "\n"
        "Rules that keep you alive:\n"
        "1. One small, focused improvement per generation. Read code before editing it.\n"
        "2. After editing, prove it yourself: `make -j4` and `make test` must both pass.\n"
        "3. NEVER delete or weaken tests, the Makefile, or source files to make the suite\n"
        "   pass. The driver checks for exactly that and reverts the whole generation.\n"
        "4. C11, -Wall -Wextra clean. Match the existing style, including its habit of\n"
        "   explaining WHY a non-obvious line exists.\n"
        "5. If behaviour changes, update README.md in the same generation.\n"
        "6. The evolution log below records earlier generations. A reverted mutation is a\n"
        "   dead end -- do not repeat it.\n"
        "\n"
        "When you stop, the driver re-runs the gate itself: build, full test suite, and a\n"
        "smoke test of the new binary. If anything fails, `git reset --hard` reverts every\n"
        "change you made and the failure is logged. If it passes, your changes are\n"
        "committed as generation %d and the binary on disk becomes your improved self.\n"
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

        sds prompt = build_prompt(root, goal, gen);
        sds reply = agent_run(cfg, prompt);
        sdsfree(prompt);
        printf("\n[evolve] agent finished generation %d:\n%s\n", gen,
               reply ? reply : "(no reply)");
        fflush(stdout);

        sds report = NULL;
        int ok = !alpha_cancel && (reply && reply[0] && strcmp(reply, "ERROR: empty response from LLM") != 0) && evolve_gate(root, &report);
        if (!report) report = sdsnew(alpha_cancel ? "interrupted\n" : (!reply || !reply[0] || strcmp(reply, "ERROR: empty response from LLM") == 0) ? "FAIL: empty LLM response\n" : "");

        /* Audit flag: a generation that touched the tests or the Makefile is
         * legitimate more often than not, but it is where reward hacking
         * would hide, so the log says it plainly. */
        int tt_rc = -1;
        sds tt = run_capture(root,
            "git status --porcelain -- tests/ Makefile", 30, &tt_rc);
        int touched_tests = (tt_rc == 0 && tt && sdslen(tt) > 0);
        sdsfree(tt);

        if (ok) {
            char gdir[PATH_MAX];
            snprintf(gdir, sizeof(gdir), "%s/evolution/gen-%03d", root, gen);
            mkdir(gdir, 0755);
            char cpcmd[PATH_MAX + 64];
            snprintf(cpcmd, sizeof(cpcmd), "cp alpha 'evolution/gen-%03d/alpha'", gen);
            int cp_rc = -1;
            sds cpout = run_capture(root, cpcmd, 60, &cp_rc);
            sdsfree(cpout);

            char msg[256];
            snprintf(msg, sizeof(msg), "evolve: generation %d", gen);
            char commitcmd[300];
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

            log_append(root, gen, goal, "keep", hash, reply, touched_tests);
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
                setenv("ALPHA_BASE_URL", cfg->base_url ? cfg->base_url : "", 1);
                setenv("ALPHA_MODEL", cfg->model ? cfg->model : "", 1);
                if (cfg->api_key) setenv("ALPHA_API_KEY", cfg->api_key, 1);
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
            printf("[evolve] generation %d REVERTED:%s\n", gen, report);
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
            log_append(root, gen, goal, "revert", "", report, touched_tests);
            reverted++;
        }
        sdsfree(report);
        if (reply) sdsfree(reply);
    }

    printf("\n[evolve] done: %d generation%s kept, %d reverted. Log: %s/evolution/log.jsonl\n",
           kept, kept == 1 ? "" : "s", reverted, root);
    return 0;
}
