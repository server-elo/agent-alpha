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

/* --- edge cases: read_file on a directory, nonexistent path ---------------- */
static void test_read_file_edge_cases(void) {
    TEST_BEGIN("read_file: edge cases are handled cleanly");

    mkdir_p("/tmp/alpha_t/subdir");

    /* read_file on a directory */
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/subdir");
    sds r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "reading a directory is refused");
    sdsfree(r);

    /* read_file on a nonexistent path */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/no_such_file.txt");
    r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "nonexistent file is refused");
    sdsfree(r);

    /* read_file with a relative path resolved against cwd */
    FILE *f = fopen("/tmp/alpha_t/rel.txt", "w");
    if (f) { fputs("relative works\n", f); fclose(f); }
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "rel.txt");
    r = tools_run("read_file", a, "/tmp/alpha_t");
    cJSON_Delete(a);
    CHECK(strcmp(r, "relative works\n") == 0, "relative path resolved against cwd");
    sdsfree(r);
}

/* --- edge cases: write_file to read-only location, empty content ----------- */
static void test_write_file_edge_cases(void) {
    TEST_BEGIN("write_file: edge cases are handled cleanly");

    /* write to a path whose parent is a file, not a directory */
    FILE *f = fopen("/tmp/alpha_t/notadir", "w");
    if (f) { fputs("blocker\n", f); fclose(f); }
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/notadir/sub/file.txt");
    cJSON_AddStringToObject(a, "content", "should fail");
    sds r = tools_run("write_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "write into a file-as-directory fails");
    sdsfree(r);

    /* write empty content */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/empty.txt");
    cJSON_AddStringToObject(a, "content", "");
    r = tools_run("write_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "empty file is written");
    CHECK(strstr(r, "0 bytes") != NULL, "reports zero bytes");
    sdsfree(r);

    struct stat st;
    CHECK(stat("/tmp/alpha_t/empty.txt", &st) == 0 && st.st_size == 0,
          "file is genuinely empty on disk");
}

/* --- edge cases: edit_file with empty old_str, match at start/end ---------- */
static void test_edit_file_edge_cases(void) {
    TEST_BEGIN("edit_file: edge cases are handled cleanly");

    /* edit with empty old_str */
    const char *path = "/tmp/alpha_t/edit_edge.txt";
    FILE *f = fopen(path, "w");
    if (f) { fputs("hello world\n", f); fclose(f); }
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "");
    cJSON_AddStringToObject(a, "new_str", "X");
    sds r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    /* An empty old_str matches at position 0, but strstr(pos+1, "") also
     * matches at position 1, so it should be rejected as non-unique. */
    CHECK(strncmp(r, "ERROR", 5) == 0, "empty old_str is rejected");
    sdsfree(r);

    /* edit with old_str at the very start of the file */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "hello");
    cJSON_AddStringToObject(a, "new_str", "hi");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "edit at start of file succeeds");
    sdsfree(r);

    /* verify the edit */
    sds body = read_file_all(path, 4096);
    CHECK(strcmp(body, "hi world\n") == 0, "file content is correct after edit");
    sdsfree(body);

    /* edit with old_str at the very end of the file */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "world\n");
    cJSON_AddStringToObject(a, "new_str", "earth\n");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "edit at end of file succeeds");
    sdsfree(r);

    body = read_file_all(path, 4096);
    CHECK(strcmp(body, "hi earth\n") == 0, "file content is correct after end-edit");
    sdsfree(body);

    /* edit with old_str not found */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "nonexistent");
    cJSON_AddStringToObject(a, "new_str", "X");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "missing old_str is reported");
    CHECK(strstr(r, "not found") != NULL, "reason says not found");
    sdsfree(r);
}

/* --- edge cases: list_dir on a file, nonexistent path ---------------------- */
static void test_list_dir_edge_cases(void) {
    TEST_BEGIN("list_dir: edge cases are handled cleanly");

    /* list_dir on a file */
    FILE *f = fopen("/tmp/alpha_t/just_a_file.txt", "w");
    if (f) { fputs("data\n", f); fclose(f); }
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/just_a_file.txt");
    sds r = tools_run("list_dir", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "listing a file is refused");
    sdsfree(r);

    /* list_dir on a nonexistent path */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/no_such_dir");
    r = tools_run("list_dir", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "nonexistent directory is refused");
    sdsfree(r);

    /* list_dir with no path argument (uses cwd) */
    a = cJSON_CreateObject();
    r = tools_run("list_dir", a, "/tmp/alpha_t");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) != 0, "list_dir with no path succeeds");
    sdsfree(r);
}

/* --- edge cases: shell_run with NULL cwd, failing command ------------------ */
static void test_shell_run_edge_cases(void) {
    TEST_BEGIN("shell_run: edge cases are handled cleanly");

    /* NULL cwd — should still run */
    sds r = shell_run("echo ok", NULL);
    CHECK(strstr(r, "ok") != NULL, "command runs with NULL cwd");
    sdsfree(r);

    /* command that fails (non-zero exit) */
    r = shell_run("exit 42", "/tmp");
    CHECK(strstr(r, "__ALPHA_EXIT:42") != NULL, "exit code is reported");
    sdsfree(r);

    /* empty command */
    r = shell_run("", "/tmp");
    CHECK(strncmp(r, "ERROR", 5) == 0, "empty command is refused");
    sdsfree(r);

    /* NULL command */
    r = shell_run(NULL, "/tmp");
    CHECK(strncmp(r, "ERROR", 5) == 0, "NULL command is refused");
    sdsfree(r);
}

/* --- fast timeout: prove the override works -------------------------------- */
static void test_fast_timeout(void) {
    TEST_BEGIN("shell_run: fast timeout override works");
    /* With ALPHA_SHELL_TIMEOUT_MS=2000, this must finish in ~2s, not 60s. */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sds r = shell_run("sleep 900", "/tmp");
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (double)(t1.tv_sec - t0.tv_sec) +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    CHECK(strstr(r, "timeout") != NULL, "result mentions the timeout");
    CHECK(strstr(r, "2000ms") != NULL, "timeout value matches the override");
    CHECK(elapsed < 5.0, "timeout fires quickly (under 5s, not 60s)");
    sdsfree(r);
}

/* --- overlapping occurrences: the gen-6 fix must not regress ----------------
 * strstr(pos + strlen(old_s), old_s) used to skip past the entire first match,
 * so overlapping occurrences like "aba" in "ababa" were missed and the edit
 * silently picked the wrong one. The fix uses strstr(pos + 1, old_s). */
static void test_edit_overlapping(void) {
    TEST_BEGIN("edit_file: overlapping occurrences are detected as non-unique");

    mkdir_p("/tmp/alpha_t");

    /* "aba" appears twice in "ababa" with overlap: positions 0 and 2.
     * The old code (pos + strlen) would only find position 0 and report
     * it unique, then replace the wrong occurrence. */
    const char *path = "/tmp/alpha_t/overlap.txt";
    FILE *f = fopen(path, "w");
    CHECK(f != NULL, "fixture created");
    if (!f) return;
    fputs("ababa\n", f);
    fclose(f);

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "aba");
    cJSON_AddStringToObject(a, "new_str", "X");
    sds r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "overlapping 'aba' in 'ababa' is rejected");
    CHECK(strstr(r, "not unique") != NULL, "reason says not unique");
    sdsfree(r);

    /* "aa" appears twice in "aaa" with overlap: positions 0 and 1.
     * Same class of bug, different length relationship. */
    path = "/tmp/alpha_t/overlap2.txt";
    f = fopen(path, "w");
    if (f) { fputs("aaa\n", f); fclose(f); }
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "aa");
    cJSON_AddStringToObject(a, "new_str", "b");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "overlapping 'aa' in 'aaa' is rejected");
    CHECK(strstr(r, "not unique") != NULL, "reason says not unique");
    sdsfree(r);

    /* A genuinely unique string must still succeed — the fix must not
     * break the normal case. */
    path = "/tmp/alpha_t/overlap3.txt";
    f = fopen(path, "w");
    if (f) { fputs("hello world\n", f); fclose(f); }
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "hello");
    cJSON_AddStringToObject(a, "new_str", "hi");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "unique string still works after the fix");
    sdsfree(r);
}

/* --- edit_file: new_str contains old_str (self-replacement) -----------------
 * Replacing "a" with "aa" must not loop or corrupt. The uniqueness check runs
 * before any edit, so this is safe — but it must still produce the right result. */
static void test_edit_self_containing(void) {
    TEST_BEGIN("edit_file: new_str containing old_str works correctly");

    mkdir_p("/tmp/alpha_t");
    const char *path = "/tmp/alpha_t/selfcont.txt";

    /* Replace "a" with "aa" — new_str contains old_str */
    FILE *f = fopen(path, "w");
    CHECK(f != NULL, "fixture created");
    if (!f) return;
    fputs("abc\n", f);
    fclose(f);

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "a");
    cJSON_AddStringToObject(a, "new_str", "aa");
    sds r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "self-containing replacement succeeds");
    sdsfree(r);

    sds body = read_file_all(path, 4096);
    CHECK(strcmp(body, "aabc\n") == 0, "only the first 'a' was replaced");
    sdsfree(body);

    /* Replace "bc" with "abc" — new_str contains old_str, at end of file */
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "old_str", "bc");
    cJSON_AddStringToObject(a, "new_str", "abc");
    r = tools_run("edit_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "end-of-file self-containing replacement succeeds");
    sdsfree(r);

    body = read_file_all(path, 4096);
    CHECK(strcmp(body, "aaabc\n") == 0, "replacement is correct");
    sdsfree(body);
}

/* --- tools_run: NULL args are tolerated, not dereferenced ------------------ */
static void test_tools_null_args(void) {
    TEST_BEGIN("tools_run: NULL args are handled gracefully");

    /* read_file with NULL args — must not crash */
    sds r = tools_run("read_file", NULL, "/tmp");
    CHECK(strncmp(r, "ERROR", 5) == 0, "NULL args with read_file is rejected cleanly");
    sdsfree(r);

    /* write_file with NULL args */
    r = tools_run("write_file", NULL, "/tmp");
    CHECK(strncmp(r, "ERROR", 5) == 0, "NULL args with write_file is rejected cleanly");
    sdsfree(r);

    /* edit_file with NULL args */
    r = tools_run("edit_file", NULL, "/tmp");
    CHECK(strncmp(r, "ERROR", 5) == 0, "NULL args with edit_file is rejected cleanly");
    sdsfree(r);

    /* execute_bash with NULL args */
    r = tools_run("execute_bash", NULL, "/tmp");
    CHECK(strncmp(r, "ERROR", 5) == 0, "NULL args with execute_bash is rejected cleanly");
    sdsfree(r);

    /* list_dir with NULL args (should use cwd) */
    r = tools_run("list_dir", NULL, "/tmp/alpha_t");
    CHECK(strncmp(r, "ERROR", 5) != 0, "NULL args with list_dir succeeds (uses cwd)");
    sdsfree(r);
}

/* --- shell_run: nonexistent cwd is reported, not silently ignored ----------
 * The cd guard runs "cd <dir> || exit 90", so when cd fails the script exits
 * before printing __ALPHA_EXIT. The command never runs, and the exit code
 * (captured by the shell that ran the script) is 90. */
static void test_shell_bad_cwd(void) {
    TEST_BEGIN("shell_run: nonexistent cwd is reported cleanly");

    sds r = shell_run("echo hello", "/tmp/alpha_t/no_such_dir_xyz");
    /* The command must not have run — "hello" must be absent */
    CHECK(strstr(r, "hello") == NULL,
          "command did not execute with a bad cwd");
    /* The cd failure should be visible in the output */
    CHECK(strstr(r, "cd") != NULL || strstr(r, "No such") != NULL ||
          strstr(r, "not found") != NULL || strstr(r, "ERROR") != NULL,
          "cd failure is surfaced in the output");
    sdsfree(r);

    /* A valid cwd must still work */
    r = shell_run("echo ok", "/tmp");
    CHECK(strstr(r, "ok") != NULL, "valid cwd still works");
    CHECK(strstr(r, "__ALPHA_EXIT:0") != NULL, "exit 0 with valid cwd");
    sdsfree(r);
}

/* --- read_file: symlinks are followed, not rejected ------------------------ */
static void test_read_symlink(void) {
    TEST_BEGIN("read_file: symlinks are followed correctly");

    mkdir_p("/tmp/alpha_t");
    const char *target = "/tmp/alpha_t/symlink_target.txt";
    const char *link   = "/tmp/alpha_t/symlink.txt";

    FILE *f = fopen(target, "w");
    CHECK(f != NULL, "target created");
    if (!f) return;
    fputs("symlink content\n", f);
    fclose(f);

    unlink(link);
    int rc = symlink(target, link);
    CHECK(rc == 0, "symlink created");

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", link);
    sds r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strcmp(r, "symlink content\n") == 0, "symlink is followed and read");
    sdsfree(r);

    /* A dangling symlink must still report a clear error */
    unlink(target);
    a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", link);
    r = tools_run("read_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "dangling symlink is reported as an error");
    sdsfree(r);

    unlink(link);
}

/* --- write_file: long content is written whole, not truncated -------------- */
static void test_write_long_content(void) {
    TEST_BEGIN("write_file: long content is written correctly");

    mkdir_p("/tmp/alpha_t");
    const char *path = "/tmp/alpha_t/long.txt";

    /* Build a 100 KB payload with a unique tail */
    sds payload = sdsempty();
    for (int i = 0; i < 10000; i++)
        payload = sdscatprintf(payload, "line %d: abcdefghijklmnopqrstuvwxyz\n", i);
    payload = sdscat(payload, "UNIQUE_LONG_TAIL\n");
    size_t plen = sdslen(payload);

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", path);
    cJSON_AddStringToObject(a, "content", payload);
    sds r = tools_run("write_file", a, "/tmp");
    cJSON_Delete(a);
    CHECK(strncmp(r, "OK", 2) == 0, "long write succeeds");

    /* Verify the reported byte count matches */
    char want[64];
    snprintf(want, sizeof(want), "%zu bytes", plen);
    CHECK(strstr(r, want) != NULL, "reported byte count is correct");
    sdsfree(r);

    /* Verify the file on disk */
    sds body = read_file_all(path, plen + 100);
    CHECK(sdslen(body) == plen, "file on disk has the exact length");
    CHECK(strstr(body, "UNIQUE_LONG_TAIL") != NULL, "tail is intact");
    sdsfree(body);
    sdsfree(payload);
    unlink(path);
}

/* --- list_dir: many entries are all listed, sorted ------------------------- */
static void test_list_many_entries(void) {
    TEST_BEGIN("list_dir: many entries are listed and sorted");

    mkdir_p("/tmp/alpha_t/many");
    /* Create 100 files with unsorted names */
    for (int i = 0; i < 100; i++) {
        char name[64];
        snprintf(name, sizeof(name), "/tmp/alpha_t/many/file_%03d.txt", (i * 17) % 100);
        FILE *f = fopen(name, "w");
        if (f) fclose(f);
    }

    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "path", "/tmp/alpha_t/many");
    sds r = tools_run("list_dir", a, "/tmp");
    cJSON_Delete(a);

    /* Should not be an error */
    CHECK(strncmp(r, "ERROR", 5) != 0, "listing many entries succeeds");

    /* Count the file lines */
    int count = 0;
    for (const char *p = r; *p; p++) {
        if (*p == '\n') count++;
    }
    CHECK(count >= 100, "all 100 entries are listed");

    /* Verify sorting: extract names and check order */
    const char *prev = NULL;
    const char *line_start = r;
    for (const char *p = r; *p; p++) {
        if (*p != '\n') continue;
        /* Find the name after "file " prefix */
        const char *name = strstr(line_start, "file ");
        if (name) {
            name += 5; /* skip "file " */
            if (prev && strcasecmp(prev, name) > 0) {
                CHECK(0, "entries are not sorted");
                break;
            }
            prev = name;
        }
        line_start = p + 1;
    }
    /* If we got here without failing, sorting is correct */
    if (prev) CHECK(1, "entries are sorted");

    sdsfree(r);
    system("rm -rf /tmp/alpha_t/many");
}

/* --- shell_run: long output is captured whole ------------------------------ */
static void test_shell_long_output(void) {
    TEST_BEGIN("shell_run: long output is captured without truncation");

    /* Generate ~50 KB of output — well under the 200 KB read cap */
    sds r = shell_run(
        "i=0; while [ $i -lt 2000 ]; do echo \"line $i: abcdefghijklmnop\"; i=$((i+1)); done; "
        "echo UNIQUE_LONG_TAIL_MARKER",
        "/tmp");
    CHECK(strstr(r, "UNIQUE_LONG_TAIL_MARKER") != NULL,
          "tail of long output is present");
    CHECK(strstr(r, "__ALPHA_EXIT:0") != NULL, "exit code is reported");
    sdsfree(r);
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
    test_read_file_edge_cases();
    test_write_file_edge_cases();
    test_edit_file_edge_cases();
    test_list_dir_edge_cases();
    test_shell_run_edge_cases();
    test_fast_timeout();
    test_edit_overlapping();
    test_edit_self_containing();
    test_tools_null_args();
    test_shell_bad_cwd();
    test_read_symlink();
    test_write_long_content();
    test_list_many_entries();
    test_shell_long_output();
    system("rm -rf /tmp/alpha_t");
    return test_report("tools");
}
