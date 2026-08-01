/* Regressions for src/tools.c: shell-free mkdir, process-group cleanup,
 * descendant tracking, and the edit_file size guard. */
#include "../src/tools.c"
#include "test_util.h"

/* --- mkdir_p must never hand a path to a shell ------------------------------
 * write_file used to build "mkdir -p \"%s\"" and call system(), so a path
 * containing $(...) or backticks executed. */
static void test_mkdir_no_shell(void) {
    TEST_BEGIN("mkdir_p: shell metacharacters are literal, not executed");

    const char *canaries[] = {
        "/tmp/alpha_t/q$(touch /tmp/alpha_pwned_1)w",
        "/tmp/alpha_t/`touch /tmp/alpha_pwned_2`z",
        "/tmp/alpha_t/x;touch /tmp/alpha_pwned_3;y",
        NULL
    };
    const char *marks[] = {
        "/tmp/alpha_pwned_1", "/tmp/alpha_pwned_2", "/tmp/alpha_pwned_3", NULL
    };
    for (int i = 0; marks[i]; i++) unlink(marks[i]);

    struct stat st;
    for (int i = 0; canaries[i]; i++) {
        CHECK_EQ_INT(mkdir_p(canaries[i]), 0, "mkdir_p succeeds");
        CHECK(stat(canaries[i], &st) == 0, "directory created with the literal name");
    }
    for (int i = 0; marks[i]; i++)
        CHECK(stat(marks[i], &st) != 0, "no command was executed");

    /* idempotent, and failure is reported rather than ignored */
    CHECK_EQ_INT(mkdir_p("/tmp/alpha_t/a/b/c"), 0, "nested create");
    CHECK_EQ_INT(mkdir_p("/tmp/alpha_t/a/b/c"), 0, "re-create is idempotent");
    CHECK(mkdir_p("/etc/alpha_should_fail") != 0, "unwritable path returns an error");
}

/* Testing mkdir_p alone is not enough: the injection lived in its CALLER, so a
 * regression that puts system() back into write_file_all must fail here too. */
static void test_write_file_no_shell(void) {
    TEST_BEGIN("write_file: a path with shell syntax is never executed");

    const char *mark = "/tmp/alpha_pwned_write";
    const char *path = "/tmp/alpha_t/w$(touch /tmp/alpha_pwned_write)x/note.txt";

    /* A shell would expand $(...) while creating the parent, so the canary is
     * the only reliable signal -- the write itself fails either way. */
    unlink(mark);
    system("rm -rf /tmp/alpha_t");

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "content", "hello");
    sds r = tools_run("write_file", a, "/tmp");
    cJSON_Delete(a);
    sdsfree(r);

    struct stat st;
    int executed = (stat(mark, &st) == 0);
    if (executed) unlink(mark);
    CHECK(!executed, "the embedded command did not run");
    CHECK(stat(path, &st) == 0, "the file was written under the literal path");
}

/* --- pt_add bookkeeping ---------------------------------------------------- */
static void test_proctrack(void) {
    TEST_BEGIN("proctrack: membership is exact and bounded");
    proctrack_t t = { .n = 0 };
    pt_add(&t, 42);
    pt_add(&t, 99999);
    pt_add(&t, 1);                    /* pid 1 is never tracked */
    CHECK(pt_has(&t, 42), "tracked pid is found");
    CHECK(pt_has(&t, 99999), "second tracked pid is found");
    CHECK(!pt_has(&t, 1), "pid 1 is ignored");
    CHECK(!pt_has(&t, 777), "untracked pid is not found");
    CHECK_EQ_INT(t.n, 2, "only real entries counted");

    pt_add(&t, 42);
    CHECK_EQ_INT(t.n, 2, "duplicate add does not grow the table");

    /* A pid outside the bitmap could never be marked seen, so it would be
     * re-appended on every pass and fill the array. */
    pt_add(&t, ALPHA_PID_BITS + 5);
    CHECK_EQ_INT(t.n, 2, "out-of-range pid is rejected, not re-added forever");

    proctrack_t o = { .n = 0 };
    for (int i = 2; i < ALPHA_MAX_TRACKED + 50; i++) pt_add(&o, i);
    CHECK_EQ_INT(o.n, ALPHA_MAX_TRACKED, "table is capped");
}

/* --- the 60s cap must kill the whole tree ----------------------------------
 * kill(-pgid) alone is not enough: a grandchild that calls setsid() leaves the
 * group and used to survive every time. */
static void test_timeout_kills_descendants(void) {
    TEST_BEGIN("shell_run: a daemonizing grandchild does not outlive the timeout");

    unlink("/tmp/alpha_daemon_pid");
    /* perl, because macOS has no setsid(1). The child detaches, then sleeps
     * well past the cap; shell_run must still reap it. */
    sds r = shell_run(
        "perl -e 'use POSIX; fork and exit; POSIX::setsid(); "
        "open(F,\">>\",\"/tmp/alpha_daemon_pid\"); print F \"$$\\n\"; close F; "
        "sleep 900' &\nsleep 900",
        "/tmp");
    sdsfree(r);

    FILE *f = fopen("/tmp/alpha_daemon_pid", "r");
    CHECK(f != NULL, "the grandchild really did start and detach");
    if (!f) return;
    int pid = 0;
    int got = (fscanf(f, "%d", &pid) == 1);
    fclose(f);
    unlink("/tmp/alpha_daemon_pid");
    CHECK(got && pid > 1, "captured the detached pid");
    if (got && pid > 1) {
        /* The kill is asynchronous: allow the signal to be delivered before
         * concluding it escaped, otherwise this races and fails at random. */
        int alive = 1;
        for (int i = 0; i < 40 && alive; i++) {
            if (kill(pid, 0) != 0) { alive = 0; break; }
            usleep(50000);
        }
        if (alive) kill(pid, SIGKILL);
        CHECK(!alive, "detached grandchild was killed with the tree");
    }
}

static void test_timeout_reports(void) {
    TEST_BEGIN("shell_run: a timeout is reported, not silently truncated");
    sds r = shell_run("sleep 900", "/tmp");
    CHECK(strstr(r, "timeout") != NULL, "result mentions the timeout");
    sdsfree(r);
}

/* --- edit_file must refuse files it cannot read whole ---------------------- */
static void test_edit_size_guard(void) {
    TEST_BEGIN("edit_file: refuses oversized files instead of truncating them");

    mkdir_p("/tmp/alpha_t");
    const char *path = "/tmp/alpha_t/big.txt";
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "fixture created");
    if (!f) return;
    char buf[65536];
    memset(buf, 'A', sizeof(buf));
    size_t written = 0;
    while (written < ALPHA_EDIT_MAX_BYTES + 200000) {
        fwrite(buf, 1, sizeof(buf), f);
        written += sizeof(buf);
    }
    fputs("NEEDLE", f);
    fclose(f);

    struct stat before;
    stat(path, &before);

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "NEEDLE");
    cJSON_AddStringToObject(a, "new_str", "X");
    sds r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);

    CHECK(strncmp(r, "ERROR", 5) == 0, "edit is refused");
    CHECK(strstr(r, "truncate") != NULL, "reason explains the risk");
    sdsfree(r);

    struct stat after;
    stat(path, &after);
    CHECK_EQ_INT(after.st_size, before.st_size, "file is byte-for-byte unchanged");
    unlink(path);
}

/* --- a truncated read must disclose the size of the gap --------------------
 * read_file caps at 250000 bytes and appended a bare "… truncated". Nothing
 * said how much was missing, so a 4 MB log and a 260 KB one looked identical
 * and the model answered about the whole file from the first 6% of it.
 * Measured through tools_run, on a file whose tail is uniquely identifiable. */
static void test_read_truncation_is_quantified(void) {
    TEST_BEGIN("read_file: truncation states how many bytes were not read");

    mkdir_p("/tmp/alpha_t");
    const char *path = "/tmp/alpha_t/big.txt";
    const size_t cap = 250000;          /* read_file's cap */
    const size_t extra = 130000;

    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "fixture created");
    if (!f) return;
    char buf[8192];
    memset(buf, 'A', sizeof(buf));
    size_t written = 0;
    while (written < cap + extra) {
        fwrite(buf, 1, sizeof(buf), f);
        written += sizeof(buf);
    }
    fputs("UNIQUE_TAIL_MARKER", f);
    fclose(f);

    struct stat st;
    stat(path, &st);
    long long total = (long long)st.st_size;

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    sds r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);

    /* The tail is genuinely absent -- otherwise there is nothing to disclose. */
    CHECK(strstr(r, "UNIQUE_TAIL_MARKER") == NULL, "the tail really is missing");
    CHECK(strstr(r, "TRUNCATED") != NULL, "the result says it was truncated");

    /* The exact number of unread bytes must appear, not merely the word.
     * Building the expected string here (rather than trusting a substring
     * like "bytes") is what makes a silently wrong count fail. */
    char want_missing[64], want_total[64];
    snprintf(want_missing, sizeof(want_missing), "%lld NOT read", total - (long long)cap);
    snprintf(want_total, sizeof(want_total), "%zu of %lld bytes shown", cap, total);
    CHECK(strstr(r, want_missing) != NULL, "the count of unread bytes is exact");
    CHECK(strstr(r, want_total) != NULL, "the shown/total figures are exact");
    sdsfree(r);

    /* A file under the cap must not be labelled truncated. */
    const char *small = "/tmp/alpha_t/small.txt";
    f = fopen(small, "wb");
    if (f) { fputs("short file\n", f); fclose(f); }
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", small);
    r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strstr(r, "TRUNCATED") == NULL, "a small file is not labelled truncated");
    CHECK(strcmp(r, "short file\n") == 0, "and is returned verbatim");
    sdsfree(r);

    unlink(path);
    unlink(small);
}

/* --- a NUL byte must not silently swallow the rest of the data --------------
 * Tool results are serialised with cJSON_CreateString, which stops at the
 * first NUL. read_file returned a 31-byte sds of which the model saw 6, and
 * edit_file rebuilt the file with strstr/strlen and rewrote those 31 bytes as
 * 3 -- reporting "OK wrote". Both measured against the real tools, not a
 * re-implementation. */
static void test_nul_bytes(void) {
    TEST_BEGIN("binary content is refused, not silently truncated");

    mkdir_p("/tmp/alpha_t");
    const char *path = "/tmp/alpha_t/bin.dat";
    /* 31 bytes: text, two NULs, then a tail that must survive. */
    const char payload[] = "HEADER\0\0BINARYTAIL_KEEPME_1234\n";
    const size_t plen = sizeof(payload) - 1;

    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "fixture created");
    if (!f) return;
    fwrite(payload, 1, plen, f);
    fclose(f);

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    sds r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "read_file refuses a binary file");
    CHECK(strstr(r, "binary") != NULL, "the reason names the cause");
    /* The point of the refusal is what the MODEL ends up seeing: an sds can
     * hold NULs, the JSON string it becomes cannot. */
    cJSON *s = cJSON_CreateString(r);
    CHECK_EQ_INT((int)strlen(cJSON_GetStringValue(s)), (int)sdslen(r),
                 "nothing is lost when the result is serialised");
    cJSON_Delete(s);
    sdsfree(r);

    struct stat before;
    stat(path, &before);
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "HEADER");
    cJSON_AddStringToObject(a, "new_str", "HDR");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "edit_file refuses it too");
    sdsfree(r);

    struct stat after;
    stat(path, &after);
    CHECK_EQ_INT((int)after.st_size, (int)before.st_size,
                 "the file is NOT rewritten short");
    /* Size alone would pass if the bytes were shuffled. */
    f = fopen(path, "rb");
    char back[64] = { 0 };
    size_t got = f ? fread(back, 1, sizeof(back), f) : 0;
    if (f) fclose(f);
    CHECK_EQ_INT((int)got, (int)plen, "every byte is still there");
    CHECK(got == plen && memcmp(back, payload, plen) == 0, "byte-for-byte identical");

    /* A command may legitimately emit binary: that is substituted, not
     * refused, but the tail must still reach the model. */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "command", "printf 'A\\000B_TAIL_VISIBLE\\n'");
    r = tools_run("execute_bash", a, "/tmp");
    cJSON_Delete(a);
    s = cJSON_CreateString(r);
    const char *seen = cJSON_GetStringValue(s);
    CHECK(strstr(seen, "B_TAIL_VISIBLE") != NULL,
          "output after a NUL still reaches the model");
    CHECK(strstr(seen, "NUL byte") != NULL, "the substitution is disclosed");
    cJSON_Delete(s);
    sdsfree(r);

    unlink(path);
}

/* --- malformed tool input must not crash ---------------------------------- */
static void test_bad_input(void) {
    TEST_BEGIN("tools_run: malformed arguments are rejected cleanly");
    cJSON *empty = cJSON_CreateObject();

    sds r1 = tools_run(NULL, empty, "/tmp");
    CHECK(strncmp(r1, "ERROR", 5) == 0, "NULL tool name");
    sdsfree(r1);

    sds r2 = tools_run("read_file", empty, "/tmp");
    CHECK(strncmp(r2, "ERROR", 5) == 0, "missing path argument");
    sdsfree(r2);

    cJSON *wrong = cJSON_CreateObject();
    cJSON_AddNumberToObject(wrong, "path", 42);
    sds r3 = tools_run("read_file", wrong, "/tmp");
    CHECK(strncmp(r3, "ERROR", 5) == 0, "path of the wrong type");
    sdsfree(r3);
    cJSON_Delete(wrong);

    sds r4 = tools_run("no_such_tool", empty, "/tmp");
    CHECK(strncmp(r4, "ERROR", 5) == 0, "unknown tool name");
    sdsfree(r4);

    cJSON_Delete(empty);
}

/* --- Desktop/iCloud paths hang opendir on this host ----------------------- */
static void test_hang_prone_paths(void) {
    TEST_BEGIN("list_dir: known-hanging paths fail closed");
    CHECK(path_is_hang_prone("/Users/x/Desktop"), "Desktop is refused");
    CHECK(path_is_hang_prone("/Users/x/Library/Mobile Documents"), "iCloud is refused");
    CHECK(!path_is_hang_prone("/tmp"), "ordinary paths are allowed");
}

int main(void) {
    test_mkdir_no_shell();
    test_write_file_no_shell();
    test_proctrack();
    test_timeout_kills_descendants();
    test_timeout_reports();
    test_edit_size_guard();
    test_read_truncation_is_quantified();
    test_nul_bytes();
    test_bad_input();
    test_hang_prone_paths();
    system("rm -rf /tmp/alpha_t");
    return test_report("tools");
}
