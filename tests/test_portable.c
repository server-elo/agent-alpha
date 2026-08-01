/* The Linux half of src/tools.c, exercised on whatever host runs the suite.
 *
 * src/tools.c used Darwin-only APIs (libproc, KERN_PROC_ALL) with no
 * alternative, so the published repository did not compile on Linux at all
 * while its README claimed "a C compiler and libcurl, no other dependencies".
 * Compiling the /proc branch proves only that it parses; these tests run it,
 * against a synthetic /proc built in a temp directory. */
#define ALPHA_FORCE_PT_PROC 1
#define ALPHA_PROC_ROOT "/tmp/alpha_proc_fixture"
#include "../src/tools.c"
#include "test_util.h"

#define FIXTURE ALPHA_PROC_ROOT

static void fixture_reset(void) {
    system("rm -rf " FIXTURE);
    mkdir_p(FIXTURE);
}

/* One synthetic process: /proc/<pid>/stat in the kernel's field order. */
static void fixture_proc(int pid, const char *comm, int ppid, int pgid) {
    char dir[PATH_MAX], path[PATH_MAX];
    snprintf(dir, sizeof(dir), FIXTURE "/%d", pid);
    mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/stat", dir);
    FILE *f = fopen(path, "w");
    if (!f) return;
    /* pid comm state ppid pgrp ... — only the first five fields are read. */
    fprintf(f, "%d (%s) S %d %d 0 0 -1 4194304 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
            pid, comm, ppid, pgid);
    fclose(f);
}

/* An fd entry: a real symlink, so stat() resolves to the target's inode
 * exactly as it does under a real /proc. */
static void fixture_fd(int pid, int fd, const char *target) {
    char dir[PATH_MAX], link[PATH_MAX];
    snprintf(dir, sizeof(dir), FIXTURE "/%d/fd", pid);
    mkdir_p(dir);
    snprintf(link, sizeof(link), "%s/%d", dir, fd);
    unlink(link);
    if (symlink(target, link) != 0) perror("symlink");
}

/* --- /proc/<pid>/stat parsing ---------------------------------------------
 * Field 2 is the executable name in parentheses and may itself contain spaces
 * and ')'. Tokenising from the left shifts every later field, so a process
 * named "evil) 1 1" would report an attacker-chosen ppid and pgid. */
static void test_stat_parse(void) {
    TEST_BEGIN("proc_stat_ids: ppid/pgid survive a hostile process name");
    fixture_reset();

    fixture_proc(100, "bash", 7, 42);
    pid_t ppid = 0, pgid = 0;
    CHECK(proc_stat_ids(100, &ppid, &pgid), "plain name parses");
    CHECK_EQ_INT(ppid, 7, "ppid read correctly");
    CHECK_EQ_INT(pgid, 42, "pgid read correctly");

    fixture_proc(101, "my prog", 8, 43);
    ppid = pgid = 0;
    CHECK(proc_stat_ids(101, &ppid, &pgid), "name with a space parses");
    CHECK_EQ_INT(ppid, 8, "space in comm does not shift ppid");

    fixture_proc(102, "evil) 1 1", 9, 44);
    ppid = pgid = 0;
    CHECK(proc_stat_ids(102, &ppid, &pgid), "name with ')' parses");
    CHECK_EQ_INT(ppid, 9, "embedded ')' does not forge ppid");
    CHECK_EQ_INT(pgid, 44, "embedded ')' does not forge pgid");

    CHECK(!proc_stat_ids(999, &ppid, &pgid), "absent pid reports failure");
}

/* --- descendant discovery by ancestry -------------------------------------
 * The walk repeats until a pass adds nothing, because /proc is read in
 * directory order and a grandchild may be visited before its parent is known.
 *
 * Two chains are built deliberately: one whose pids ascend with depth and one
 * whose pids descend. Whichever way readdir happens to order the directory,
 * one of them is visited child-first and cannot be resolved in a single pass.
 * With one chain only, this test passed against a single-pass sabotage purely
 * because the fixture's numbering happened to match the scan order. */
static void test_sample_ancestry(void) {
    TEST_BEGIN("pt_sample: the whole tree is found, and nothing else");
    fixture_reset();

    /* ascending: root < child < grandchild */
    fixture_proc(200, "root_a",  1,   200);
    fixture_proc(210, "child_a", 200, 210);   /* own pgid: only ppid links it */
    fixture_proc(220, "grand_a", 210, 220);

    /* descending: root > child > grandchild */
    fixture_proc(299, "root_d",  1,   299);
    fixture_proc(290, "child_d", 299, 290);
    fixture_proc(280, "grand_d", 290, 280);

    /* linked by process group alone, having setsid'd away from its parent */
    fixture_proc(230, "bygroup", 1,   200);

    fixture_proc(300, "other",   1,   300);   /* unrelated */

    proctrack_t t = { .n = 0 };
    pt_sample(&t, 200);
    CHECK(pt_has(&t, 200), "root is tracked");
    CHECK(pt_has(&t, 210), "child is tracked");
    CHECK(pt_has(&t, 220), "grandchild is tracked (ascending pids)");
    CHECK(pt_has(&t, 230), "process-group member is tracked");
    CHECK(!pt_has(&t, 300), "an unrelated process is NOT tracked");
    CHECK(!pt_has(&t, 299), "the other tree is NOT tracked");
    CHECK_EQ_INT(t.n, 4, "exactly the first tree, no more");

    proctrack_t d = { .n = 0 };
    pt_sample(&d, 299);
    CHECK(pt_has(&d, 299), "root is tracked (descending pids)");
    CHECK(pt_has(&d, 290), "child is tracked (descending pids)");
    CHECK(pt_has(&d, 280), "grandchild is tracked (descending pids)");
    CHECK(!pt_has(&d, 200), "the other tree is NOT tracked");
    CHECK_EQ_INT(d.n, 3, "exactly the second tree, no more");
}

/* --- descendant discovery by inherited fd ---------------------------------
 * The point of the fd scan is the process that shed its ancestry: it has
 * reparented to init and left the group, so only the output file it still
 * holds open identifies it. */
static void test_sample_fd(void) {
    TEST_BEGIN("pt_sample_fd: a detached process is found by the file it holds");
    fixture_reset();

    const char *outf = "/tmp/alpha_portable_out";
    const char *decoy = "/tmp/alpha_portable_decoy";
    FILE *f = fopen(outf, "w");   CHECK(f != NULL, "output fixture created");
    if (f) fclose(f);
    f = fopen(decoy, "w");        CHECK(f != NULL, "decoy fixture created");
    if (f) fclose(f);

    struct stat st;
    CHECK(stat(outf, &st) == 0, "output inode readable");
    uint64_t ino = (uint64_t)st.st_ino;

    fixture_proc(400, "detached", 1, 400);    /* no ancestry link at all */
    fixture_fd(400, 1, outf);
    fixture_proc(401, "innocent", 1, 401);
    fixture_fd(401, 1, decoy);
    fixture_proc(402, "nofds",    1, 402);

    proctrack_t t = { .n = 0 };
    pt_sample(&t, 999);                       /* ancestry finds nothing */
    CHECK_EQ_INT(t.n, 0, "ancestry alone cannot see a detached process");

    pt_sample_fd(&t, ino, 402);
    CHECK(pt_has(&t, 400), "detached process found by inherited fd");
    CHECK(!pt_has(&t, 401), "a process holding a different file is not touched");
    CHECK_EQ_INT(t.n, 1, "only the holder is tracked");

    /* Never kill the caller: it holds the same file by definition. */
    proctrack_t self = { .n = 0 };
    pt_sample_fd(&self, ino, 400);
    CHECK(!pt_has(&self, 400), "the calling pid excludes itself");

    unlink(outf);
    unlink(decoy);
}

/* --- shell selection -------------------------------------------------------
 * /bin/zsh was hardcoded. It is the macOS default and absent from most Linux
 * installs, where exec'ing it made every command fail with 127. */
static void test_shell_path(void) {
    TEST_BEGIN("shell_path: an executable shell is always chosen");

    unsetenv("ALPHA_SHELL");
    const char *sh = shell_path();
    CHECK(sh && sh[0] == '/', "an absolute path is returned");
    CHECK(access(sh, X_OK) == 0, "the chosen shell is executable");

    setenv("ALPHA_SHELL", "/bin/sh", 1);
    CHECK(strcmp(shell_path(), "/bin/sh") == 0, "ALPHA_SHELL is honoured");

    /* A bad override must fall back rather than exec something nonexistent
     * and leave every command exiting 127. */
    setenv("ALPHA_SHELL", "/nonexistent/shell", 1);
    const char *fb = shell_path();
    CHECK(access(fb, X_OK) == 0, "unusable ALPHA_SHELL falls back to a real shell");
    unsetenv("ALPHA_SHELL");
}

/* --- commands actually run through the selected shell ---------------------- */
static void test_shell_run_works(void) {
    TEST_BEGIN("shell_run: works with the portable shell and process tracking");
    sds r = shell_run("echo portable_ok", "/tmp");
    CHECK(strstr(r, "portable_ok") != NULL, "command output is captured");
    CHECK(strstr(r, "__ALPHA_EXIT:0") != NULL, "exit status is reported");
    sdsfree(r);
}

/* --- macOS-only guards must not fire elsewhere -----------------------------
 * On Linux ~/Desktop is an ordinary directory; refusing it would be a bug. */
static void test_desktop_guard_is_macos_only(void) {
    TEST_BEGIN("path_is_hang_prone: no File Provider outside macOS");
    CHECK(!path_is_hang_prone("/home/user/Desktop"), "Desktop is a normal directory here");
    CHECK(!path_is_hang_prone("/tmp"), "ordinary paths still allowed");
}

int main(void) {
    test_stat_parse();
    test_sample_ancestry();
    test_sample_fd();
    test_shell_path();
    test_shell_run_works();
    test_desktop_guard_is_macos_only();
    system("rm -rf " FIXTURE);
    return test_report("portable");
}
