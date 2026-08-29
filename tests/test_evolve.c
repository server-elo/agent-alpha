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

    /* --- test-coverage gate: feature code must bring a test -----------------
     * Gen 211 shipped code_search (+501 lines) with zero tests and the gate
     * passed it — the suite only ever exercises OLD behavior. The coverage
     * check must reject src/ changes unaccompanied by a tests/custom/test_*.c
     * and accept them once a test exists. The sandbox path must contain
     * "/sandbox/" for the check to engage, mirroring production. */
    system("rm -rf /tmp/alpha_cov_root && "
           "mkdir -p /tmp/alpha_cov_root/src /tmp/alpha_cov_root/include "
           "/tmp/alpha_cov_root/tests/custom /tmp/alpha_cov_root/sandbox/gen_t");
    write_file("/tmp/alpha_cov_root/src/a.c", "int a;\n");
    write_file("/tmp/alpha_cov_root/include/a.h", "#pragma once\n");
    system("cp -R /tmp/alpha_cov_root/src /tmp/alpha_cov_root/include "
           "/tmp/alpha_cov_root/tests /tmp/alpha_cov_root/sandbox/gen_t/");
    report = NULL;
    CHECK(evolve_sandbox_test_coverage("/tmp/alpha_cov_root/sandbox/gen_t", &report) == 1,
          "unchanged trees need no new test");
    sdsfree(report);
    write_file("/tmp/alpha_cov_root/sandbox/gen_t/src/b.c", "int b;\n");
    report = NULL;
    CHECK(evolve_sandbox_test_coverage("/tmp/alpha_cov_root/sandbox/gen_t", &report) == 0,
          "src change without a test is rejected");
    CHECK(report && strstr(report, "no tests/custom/test_") != NULL,
          "report names the missing test");
    sdsfree(report);
    write_file("/tmp/alpha_cov_root/sandbox/gen_t/tests/custom/test_b.c", "int t;\n");
    report = NULL;
    CHECK(evolve_sandbox_test_coverage("/tmp/alpha_cov_root/sandbox/gen_t", &report) == 1,
          "src change with a new custom test is accepted");
    sdsfree(report);
    system("rm -rf /tmp/alpha_cov_root");

    /* --- seal: dynamic protected list ---------------------------------------
     * SEALED = Makefile, src/evolve.c, src/warden.c + every pre-existing
     * tests/*.c and tests/custom/*.c. src/agent_loop.c and src/llm.c are now
     * editable; NEW test files are allowed because they are not snapshotted. */
    system("rm -rf /tmp/alpha_seal_root && mkdir -p /tmp/alpha_seal_root/src "
           "/tmp/alpha_seal_root/tests/custom /tmp/alpha_seal_root/sandbox/gen_s/src "
           "/tmp/alpha_seal_root/sandbox/gen_s/tests/custom");
    write_file("/tmp/alpha_seal_root/Makefile", "all:\n\t@true\n");
    write_file("/tmp/alpha_seal_root/src/evolve.c", "/* evolve */\n");
    write_file("/tmp/alpha_seal_root/src/warden.c", "/* warden */\n");
    write_file("/tmp/alpha_seal_root/src/agent_loop.c", "/* loop */\n");
    write_file("/tmp/alpha_seal_root/src/llm.c", "/* llm */\n");
    write_file("/tmp/alpha_seal_root/tests/test_evolve.c", "/* te */\n");
    write_file("/tmp/alpha_seal_root/tests/custom/test_old.c", "/* old */\n");
    system("cp /tmp/alpha_seal_root/Makefile /tmp/alpha_seal_root/sandbox/gen_s/ && "
           "cp /tmp/alpha_seal_root/src/*.c /tmp/alpha_seal_root/sandbox/gen_s/src/ && "
           "cp /tmp/alpha_seal_root/tests/test_evolve.c /tmp/alpha_seal_root/sandbox/gen_s/tests/ && "
           "cp /tmp/alpha_seal_root/tests/custom/test_old.c /tmp/alpha_seal_root/sandbox/gen_s/tests/custom/ && "
           "cd /tmp/alpha_seal_root && git init -q");

    evolve_hash_table seal;
    report = NULL;
    CHECK(evolve_seal_snapshot("/tmp/alpha_seal_root/sandbox/gen_s", &seal, &report) == 1,
          "seal snapshot succeeds on a clean sandbox");
    sdsfree(report);
    CHECK_EQ_INT(seal.count, 5, "seal covers 3 harness files + every pre-existing test file");
    int has_agent_loop = 0, has_llm = 0, has_test_old = 0, has_test_evolve = 0;
    for (int i = 0; i < seal.count; i++) {
        if (strcmp(seal.entries[i].relpath, "src/agent_loop.c") == 0) has_agent_loop = 1;
        if (strcmp(seal.entries[i].relpath, "src/llm.c") == 0) has_llm = 1;
        if (strcmp(seal.entries[i].relpath, "tests/custom/test_old.c") == 0) has_test_old = 1;
        if (strcmp(seal.entries[i].relpath, "tests/test_evolve.c") == 0) has_test_evolve = 1;
    }
    CHECK(!has_agent_loop && !has_llm, "src/agent_loop.c and src/llm.c are no longer sealed");
    CHECK(has_test_old && has_test_evolve, "pre-existing test files are sealed");

    report = NULL;
    CHECK(evolve_seal_verify("/tmp/alpha_seal_root/sandbox/gen_s", &seal, &report) == 1,
          "seal verify passes on an untouched sandbox");
    sdsfree(report);

    /* (b) Editing formerly-protected source files must NOT trip the seal. */
    write_file("/tmp/alpha_seal_root/sandbox/gen_s/src/agent_loop.c", "/* improved */\n");
    write_file("/tmp/alpha_seal_root/sandbox/gen_s/src/llm.c", "/* improved */\n");
    report = NULL;
    CHECK(evolve_seal_verify("/tmp/alpha_seal_root/sandbox/gen_s", &seal, &report) == 1,
          "editing src/agent_loop.c and src/llm.c does not trip the seal");
    sdsfree(report);

    /* (c) Adding a NEW test file must NOT trip the seal. */
    write_file("/tmp/alpha_seal_root/sandbox/gen_s/tests/custom/test_new.c", "/* new */\n");
    report = NULL;
    CHECK(evolve_seal_verify("/tmp/alpha_seal_root/sandbox/gen_s", &seal, &report) == 1,
          "adding a new test file does not trip the seal");
    sdsfree(report);

    /* The gate-level check shares the same dynamic list: agent_loop/llm edits
     * and a new test file must pass it. */
    report = NULL;
    CHECK(evolve_git_protected_clean("/tmp/alpha_seal_root/sandbox/gen_s", &report) == 1,
          "gate accepts agent_loop/llm edits plus a new test file");
    sdsfree(report);

    /* (a) Modifying an EXISTING test file must fail the seal and the gate. */
    write_file("/tmp/alpha_seal_root/sandbox/gen_s/tests/custom/test_old.c", "/* tampered */\n");
    report = NULL;
    CHECK(evolve_seal_verify("/tmp/alpha_seal_root/sandbox/gen_s", &seal, &report) == 0,
          "editing a pre-existing test file trips the seal");
    CHECK(report && strstr(report, "tests/custom/test_old.c"),
          "seal report names the tampered test file");
    sdsfree(report);
    report = NULL;
    CHECK(evolve_git_protected_clean("/tmp/alpha_seal_root/sandbox/gen_s", &report) == 0,
          "gate rejects a tampered pre-existing test file");
    CHECK(report && strstr(report, "tests/custom/test_old.c"),
          "gate report names the tampered test file");
    sdsfree(report);
    system("rm -rf /tmp/alpha_seal_root");

    system("rm -rf " FIX " /tmp/alpha_evolve_log /tmp/alpha_evolve_empty");
    return test_report("test_evolve");
}
