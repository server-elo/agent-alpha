#include "test_util.h"
#include "../src/evolve.c"

/* Fixture: the smallest tree the gate will accept — a Makefile whose test
 * target prints the magic string, an executable `alpha` that ignores
 * --providers, and a git repo so the deletion guard has something to check. */
#define FIX "/tmp/alpha_evolve_fixture"

static void write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(body, 1, strlen(body), f);
    fclose(f);
}

static int fixture_make(void) {
    system("rm -rf " FIX);
    if (mkdir(FIX, 0755) != 0) return 0;
    /* The gate now requires both "ALL TESTS PASSED" and "=== tests/bin/"
     * so a generation cannot bypass the suite by editing the Makefile test
     * target to just echo the magic string and exit 0. */
    write_file(FIX "/Makefile",
        "all:\n"
        "\t@echo build ok\n"
        "test:\n"
        "\t@echo === tests/bin/test_fake ===\n"
        "\t@echo running checks\n"
        "\t@echo ALL TESTS PASSED\n");
    write_file(FIX "/alpha", "#!/bin/sh\nexit 0\n");
    chmod(FIX "/alpha", 0755);
    int rc = system("cd " FIX " && git init -q && git add -A && "
                    "git -c user.name=t -c user.email=t@t commit -qm init");
    return rc == 0;
}

int main(void) {
    TEST_BEGIN("test_evolve");

    /* --- json_escape --- */
    sds e = json_escape("a\"b\\c\nd", 100);
    CHECK(e && strcmp(e, "a\\\"b\\\\c\\nd") == 0, "json_escape quotes/backslash/newline");
    sdsfree(e);
    e = json_escape("abcdefghij", 4);
    CHECK(e && strcmp(e, "abcd") == 0, "json_escape truncates at max");
    sdsfree(e);

    /* --- source root detection --- */
    CHECK(is_source_root(".") == 1, "repository root is a source root");
    system("rm -rf /tmp/alpha_evolve_empty && mkdir -p /tmp/alpha_evolve_empty");
    CHECK(is_source_root("/tmp/alpha_evolve_empty") == 0, "empty dir is not a source root");
    char root[PATH_MAX], cwd[PATH_MAX];
    /* The test binary lives in tests/bin, so detection must fall through to
     * the cwd -- make runs the suite from the repository root. */
    CHECK(find_source_root(root) == 1, "find_source_root succeeds from repo root");
    CHECK(getcwd(cwd, sizeof(cwd)) && strcmp(root, cwd) == 0,
          "find_source_root resolves to the cwd");

    /* --- generation counter / log --- */
    system("rm -rf /tmp/alpha_evolve_log && mkdir -p /tmp/alpha_evolve_log");
    CHECK_EQ_INT(next_generation("/tmp/alpha_evolve_log"), 1, "first generation is 1");
    log_append("/tmp/alpha_evolve_log", 1, "goal \"one\"", "keep", "abc1234", "note one", 0);
    log_append("/tmp/alpha_evolve_log", 3, "goal two", "revert", "", "note\ntwo", 1);
    CHECK_EQ_INT(next_generation("/tmp/alpha_evolve_log"), 4, "next generation is max+1");
    sds tail = log_tail("/tmp/alpha_evolve_log", 12);
    CHECK(tail && strstr(tail, "\"gen\":1") && strstr(tail, "\"gen\":3"),
          "log_tail returns both generations");
    CHECK(tail && strstr(tail, "goal \\\"one\\\"") && strstr(tail, "note\\ntwo"),
          "log lines are valid JSON-escaped");
    sdsfree(tail);

    /* --- run_capture --- */
    int rc = -1;
    sds out = run_capture(NULL, "echo hello && exit 3", 10, &rc);
    CHECK_EQ_INT(rc, 3, "run_capture returns the exit code");
    CHECK(out && strstr(out, "hello"), "run_capture captures stdout");
    sdsfree(out);
    out = run_capture(NULL, "sleep 30", 1, &rc);
    CHECK(rc != 0 && out && strstr(out, "timeout"), "run_capture kills on timeout");
    sdsfree(out);

    /* --- the gate, against a throwaway fixture --- */
    CHECK(fixture_make(), "fixture created");
    sds report = NULL;
    CHECK(evolve_gate(FIX, NULL, &report) == 1, "gate passes a healthy fixture");
    CHECK(report && strstr(report, "OK"), "gate report says OK");
    sdsfree(report);

    /* Weaken the test target: exit 0 without the magic string must fail even
     * though make itself succeeds. The "=== tests/bin/" line is still present
     * so the gate knows the recipe actually ran. */
    write_file(FIX "/Makefile",
        "all:\n"
        "\t@echo build ok\n"
        "test:\n"
        "\t@echo === tests/bin/test_fake ===\n"
        "\t@echo nothing ran\n");
    report = NULL;
    CHECK(evolve_gate(FIX, NULL, &report) == 0, "gate fails without ALL TESTS PASSED");
    CHECK(report && strstr(report, "FAIL: test suite"), "gate report names the suite");
    sdsfree(report);

    /* A Makefile that prints "ALL TESTS PASSED" but never ran a test binary
     * (no "=== tests/bin/" line) must fail: this is the exact bypass the new
     * check is designed to catch. */
    system("cd " FIX " && git checkout -q -- .");
    write_file(FIX "/Makefile",
        "all:\n"
        "\t@echo build ok\n"
        "test:\n"
        "\t@echo ALL TESTS PASSED\n");
    report = NULL;
    CHECK(evolve_gate(FIX, NULL, &report) == 0,
          "gate fails when ALL TESTS PASSED is printed but no test binary ran");
    CHECK(report && strstr(report, "bypass"),
          "gate report names the bypass attempt");
    sdsfree(report);

    /* Restore, then delete a tracked file: the reward-hacking guard must fire
     * before the build is even attempted. */
    system("cd " FIX " && git checkout -q -- .");
    unlink(FIX "/Makefile");
    report = NULL;
    CHECK(evolve_gate(FIX, NULL, &report) == 0, "gate fails when a tracked file is deleted");
    CHECK(report && strstr(report, "FAIL: tracked file deleted"),
          "gate report names the deletion");
    sdsfree(report);

    /* --- empty-generation check ---------------------------------------------
     * The sandbox starts as a byte-copy of root's source dirs. A generation
     * whose sandbox matches root exactly shipped nothing, however convincing
     * the transcript sounds — and the harness must not call that a "keep". */
    system("rm -rf /tmp/alpha_chg_root /tmp/alpha_chg_sbx && "
           "mkdir -p /tmp/alpha_chg_root/src /tmp/alpha_chg_root/include "
           "/tmp/alpha_chg_root/tests /tmp/alpha_chg_root/deps");
    write_file("/tmp/alpha_chg_root/src/a.c", "int a;\n");
    write_file("/tmp/alpha_chg_root/include/a.h", "#pragma once\n");
    system("cp -R /tmp/alpha_chg_root/src /tmp/alpha_chg_root/include "
           "/tmp/alpha_chg_root/tests /tmp/alpha_chg_root/deps /tmp/alpha_chg_sbx 2>/dev/null || "
           "(mkdir -p /tmp/alpha_chg_sbx && cp -R /tmp/alpha_chg_root/src /tmp/alpha_chg_root/include "
           "/tmp/alpha_chg_root/tests /tmp/alpha_chg_root/deps /tmp/alpha_chg_sbx/)");
    CHECK(evolve_sandbox_changed("/tmp/alpha_chg_root", "/tmp/alpha_chg_sbx") == 0,
          "identical trees mean an empty generation");
    /* Build products appear in the sandbox on every run and must not count. */
    write_file("/tmp/alpha_chg_sbx/src/a.o", "fake object\n");
    CHECK(evolve_sandbox_changed("/tmp/alpha_chg_root", "/tmp/alpha_chg_sbx") == 0,
          "rebuilt .o files alone do not count as a change");
    write_file("/tmp/alpha_chg_sbx/src/b.c", "int b;\n");
    CHECK(evolve_sandbox_changed("/tmp/alpha_chg_root", "/tmp/alpha_chg_sbx") == 1,
          "a new source file is a real change");
    unlink("/tmp/alpha_chg_sbx/src/b.c");
    write_file("/tmp/alpha_chg_sbx/include/a.h", "#pragma once\n/* touched */\n");
    CHECK(evolve_sandbox_changed("/tmp/alpha_chg_root", "/tmp/alpha_chg_sbx") == 1,
          "an edited header is a real change");
    system("rm -rf /tmp/alpha_chg_root /tmp/alpha_chg_sbx");

    system("rm -rf " FIX " /tmp/alpha_evolve_log /tmp/alpha_evolve_empty");
    return test_report("test_evolve");
}
