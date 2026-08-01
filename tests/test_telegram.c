/* Regressions for src/telegram.c: UTF-8 safe chunking, fast-lane routing,
 * per-chat cwd isolation under threads, and work-queue ordering.
 *
 * telegram_run() is not called here -- no network is required. */
/* Capture what tg_send would transmit, so the REAL chunking path is tested
 * rather than a copy of its logic reimplemented in the test. */
#include "../deps/sds.h"
static char *sent_bodies[64];
static int sent_count;
static sds test_record_send(const char *token, const char *body);
#define ALPHA_TG_SEND_HOOK(tok, body) test_record_send((tok), (body))

#include "../src/telegram.c"

static sds test_record_send(const char *token, const char *body) {
    (void)token;
    if (sent_count < 64) sent_bodies[sent_count++] = strdup(body);
    return sdsnew("{\"ok\":true}");
}
#include "test_util.h"

/* --- Telegram rejects a message that is not valid UTF-8 -------------------
 * Splitting at a fixed 3500 bytes lands mid-sequence, so the API returned
 * 400 "strings must be encoded in UTF-8" and the chunk vanished silently. */
static int chunk_is_valid_utf8(const char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        int seq = c < 0x80 ? 1
                : (c & 0xE0) == 0xC0 ? 2
                : (c & 0xF0) == 0xE0 ? 3
                : (c & 0xF8) == 0xF0 ? 4 : -1;
        if (seq < 0 || i + (size_t)seq > n) return 0;
        i += (size_t)seq;
    }
    return 1;
}

/* Extract the "text" field from a captured sendMessage body and verify the
 * bytes Telegram would actually receive are valid UTF-8. */
static int body_text_is_valid_utf8(const char *body) {
    const char *p = strstr(body, "\"text\":\"");
    if (!p) return 0;
    p += 8;
    const char *end = body + strlen(body);
    while (end > p && *end != '"') end--;
    return chunk_is_valid_utf8(p, (size_t)(end - p));
}

static void check_split(const char *label, const char *unit) {
    for (int i = 0; i < sent_count; i++) free(sent_bodies[i]);
    sent_count = 0;

    sds text = sdsempty();
    while (sdslen(text) < 9000) text = sdscat(text, unit);
    tg_send("test-token", 1, text);      /* the real function under test */

    CHECK(sent_count > 1, label);
    int bad = 0;
    for (int i = 0; i < sent_count; i++)
        if (!body_text_is_valid_utf8(sent_bodies[i])) bad++;
    CHECK_EQ_INT(bad, 0, "every transmitted chunk is valid UTF-8");
    sdsfree(text);
}

static void test_utf8_chunking(void) {
    TEST_BEGIN("utf8_safe_len: long replies never split inside a character");
    check_split("ascii splits into several chunks", "a");
    check_split("2-byte (umlaut) splits", "\xc3\xbc");
    check_split("3-byte (euro sign) splits", "\xe2\x82\xac");
    check_split("4-byte (emoji) splits", "\xf0\x9f\x98\x80");

    /* the reported German/box-drawing case that was being dropped */
    check_split("mixed german + em-dash text splits", "Gr\xc3\xbc\xc3\x9f" "e \xe2\x80\x94 ");
}

/* --- control characters that carry meaning must survive -------------------
 * Every byte below 0x20 except \n and \r was dropped, so a tab vanished from
 * the wire. A Makefile arrived as "missing separator" and indented code lost
 * its structure, with no error anywhere to explain it. */
static const char *body_text(const char *body) {
    const char *p = strstr(body, "\"text\":\"");
    return p ? p + 8 : NULL;
}

static void test_tab_is_preserved(void) {
    TEST_BEGIN("tg_send: tabs are escaped, not silently dropped");
    for (int i = 0; i < sent_count; i++) free(sent_bodies[i]);
    sent_count = 0;

    tg_send("test-token", 1, "all:\n\tgcc -o x x.c\n");
    CHECK_EQ_INT(sent_count, 1, "one message sent");
    if (sent_count != 1) return;

    const char *t = body_text(sent_bodies[0]);
    CHECK(t != NULL, "body has a text field");
    if (!t) return;
    CHECK(strstr(t, "\\t") != NULL, "the tab is transmitted as \\t");
    CHECK(strstr(t, "\\n\\tgcc") != NULL, "it stays attached to the recipe line");
    /* A raw tab byte would make the JSON invalid, so it must be the escape. */
    CHECK(strchr(t, '\t') == NULL, "no raw tab byte in the JSON string");

    /* The genuinely unprintable ones are still removed. */
    for (int i = 0; i < sent_count; i++) free(sent_bodies[i]);
    sent_count = 0;
    tg_send("test-token", 1, "a\x01\x02\x1f" "b");
    const char *u = sent_count ? body_text(sent_bodies[0]) : NULL;
    CHECK(u != NULL && strstr(u, "ab") != NULL, "other control bytes are still stripped");
}

/* --- the reserved lane must not be taken by long jobs ---------------------
 * Classifying by message length routed "Go" -- which can start an hour-long
 * build -- into the lane meant to keep the bot responsive. */
static void test_fast_lane_routing(void) {
    TEST_BEGIN("job_is_quick: only tool-free chatter takes the reserved lane");
    CHECK(job_is_quick("ping"), "ping is quick");
    CHECK(job_is_quick("hi"), "hi is quick");
    CHECK(job_is_quick("Hallo!"), "case and punctuation are handled");
    CHECK(job_is_quick("status"), "status is quick");
    CHECK(job_is_quick("danke"), "german thanks is quick");

    CHECK(!job_is_quick("Go"), "Go can start a long build: NOT quick");
    CHECK(!job_is_quick("continue"), "continue is not quick");
    CHECK(!job_is_quick("build the whole OS"), "short but expensive: not quick");
    CHECK(!job_is_quick("rewrite the kernel"), "short but expensive: not quick");
    CHECK(!job_is_quick("What is 2+2?"), "anything unrecognised is not quick");
    CHECK(!job_is_quick(""), "empty is not quick");
    CHECK(!job_is_quick("ping\nand build everything"), "multiline is not quick");
}

/* --- per-chat cwd is read by workers and written by the poll thread -------- */
#define RACE_THREADS 4
#define RACE_ITERS   4000
static int race_mismatches;

static void *race_worker(void *arg) {
    long base = (long)arg * 1000;
    for (int i = 0; i < RACE_ITERS; i++) {
        long long id = base + (i % 50);
        char want[64];
        snprintf(want, sizeof(want), "/p/%lld", id);
        chat_cwd_set(id, want);
        char got[PATH_MAX];
        if (chat_cwd_get_copy(id, got, sizeof(got)) && strcmp(got, want) != 0)
            __sync_fetch_and_add(&race_mismatches, 1);
    }
    return NULL;
}

static void test_chat_cwd_thread_safety(void) {
    TEST_BEGIN("chat_cwd: concurrent access returns the right directory");
    race_mismatches = 0;
    pthread_t th[RACE_THREADS];
    for (long i = 1; i <= RACE_THREADS; i++)
        pthread_create(&th[i - 1], NULL, race_worker, (void *)i);
    for (int i = 0; i < RACE_THREADS; i++) pthread_join(th[i], NULL);
    CHECK_EQ_INT(race_mismatches, 0, "no thread ever read another chat's cwd");

    /* isolation: one chat's /cwd must not move another's */
    chat_cwd_set(9001, "/tmp");
    chat_cwd_set(9002, "/etc");
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX];
    CHECK(chat_cwd_get_copy(9001, a, sizeof(a)) && strcmp(a, "/tmp") == 0,
          "chat A keeps its own cwd");
    CHECK(chat_cwd_get_copy(9002, b, sizeof(b)) && strcmp(b, "/etc") == 0,
          "chat B keeps its own cwd");
    CHECK(!chat_cwd_get_copy(9999, c, sizeof(c)),
          "an unknown chat falls back to the global default");
}

/* --- queue: different chats run in parallel, one chat stays serialized ----- */
static void test_queue_semantics(void) {
    TEST_BEGIN("work queue: parallel across chats, ordered within a chat");
    queue_t q;
    memset(&q, 0, sizeof(q));
    pthread_mutex_init(&q.lock, NULL);
    pthread_cond_init(&q.cv, NULL);

    q_push(&q, 100, "first from A");
    q_push(&q, 100, "second from A");
    q_push(&q, 200, "only from B");
    q_push(&q, 100, "third from A");

    job_t *j1 = q_take_ready(&q, 0);
    CHECK(j1 && j1->chat_id == 100, "first job is A's oldest");
    q_mark_busy(&q, j1->chat_id);

    job_t *j2 = q_take_ready(&q, 0);
    CHECK(j2 && j2->chat_id == 200, "B is not blocked behind A");
    q_mark_busy(&q, j2->chat_id);

    job_t *j3 = q_take_ready(&q, 0);
    CHECK(j3 == NULL, "A's next message waits while A is running");

    q_clear_busy(&q, 100);
    job_t *j4 = q_take_ready(&q, 0);
    CHECK(j4 && strcmp(j4->text, "second from A") == 0,
          "A resumes in FIFO order");

    /* the reserved lane skips expensive work */
    queue_t r;
    memset(&r, 0, sizeof(r));
    pthread_mutex_init(&r.lock, NULL);
    pthread_cond_init(&r.cv, NULL);
    q_push(&r, 1, "Go");
    q_push(&r, 2, "ping");
    job_t *fast = q_take_ready(&r, 1);
    CHECK(fast && strcmp(fast->text, "ping") == 0,
          "fast lane picks ping and skips Go");
}

static void test_queue_overflow(void) {
    TEST_BEGIN("work queue: overflow is refused rather than growing forever");
    queue_t q;
    memset(&q, 0, sizeof(q));
    pthread_mutex_init(&q.lock, NULL);
    pthread_cond_init(&q.cv, NULL);
    int accepted = 0;
    for (int i = 0; i < ALPHA_QUEUE_MAX + 20; i++)
        if (q_push(&q, 1, "x")) accepted++;
    CHECK_EQ_INT(accepted, ALPHA_QUEUE_MAX, "queue caps at its limit");
}

/* --- allowlist ------------------------------------------------------------- */
static void test_allowlist(void) {
    TEST_BEGIN("allowed: only permitted chats are served");
    CHECK(allowed("123456789", 123456789LL), "listed chat is allowed");
    CHECK(!allowed("123456789", 999LL), "unlisted chat is rejected");
    CHECK(allowed("*", 999LL), "wildcard allows any chat");
    CHECK(allowed("1,2,3", 2LL), "comma-separated list works");
    CHECK(!allowed("1,2,3", 4LL), "absent id in a list is rejected");
}

static const char *alpha_argv0 = "";

/* --- voice ----------------------------------------------------------------- */
/* The transcriber used to be located relative to the CURRENT DIRECTORY, so
 * voice notes worked only when the bot was launched from the repo and failed
 * everywhere else. Assert the path is a property of the binary instead: it
 * must not move when the cwd does. */
static void test_transcriber_path_is_independent_of_cwd(void) {
    TEST_BEGIN("voice: the transcriber is found regardless of cwd");

    char saved[PATH_MAX];
    CHECK(getcwd(saved, sizeof(saved)) != NULL, "cwd readable");

    /* ALPHA_ROOT short-circuits the lookup, so leaving the developer's own
     * value in the environment would make this pass without ever exercising
     * the fallback that voice notes actually rely on. */
    char *had_root = getenv("ALPHA_ROOT");
    char saved_root[PATH_MAX];
    saved_root[0] = 0;
    if (had_root) snprintf(saved_root, sizeof(saved_root), "%s", had_root);
    unsetenv("ALPHA_ROOT");

    /* Resolve fresh at each cwd -- calling the cached accessor would compare
     * one stored string against itself and pass no matter what. */
    char from_repo[PATH_MAX], from_root[PATH_MAX], from_tmp[PATH_MAX];
    alpha_resolve_install_root(from_repo, sizeof(from_repo));

    CHECK(chdir("/") == 0, "moved to an unrelated cwd");
    alpha_resolve_install_root(from_root, sizeof(from_root));

    CHECK(chdir("/tmp") == 0, "moved again");
    alpha_resolve_install_root(from_tmp, sizeof(from_tmp));

    CHECK(chdir(saved) == 0, "cwd restored");

    CHECK(strcmp(from_root, from_repo) == 0, "install root unchanged by chdir");
    CHECK(strcmp(from_tmp, from_repo) == 0, "still unchanged from a second cwd");

    /* Guard against agreeing on a uniformly wrong answer: compare against an
     * independently obtained value -- argv[0] via the OS, rather than the
     * executable-path call the function itself uses. (This binary lives in
     * tests/bin, so its root is tests/bin, not the repo.) */
    CHECK(from_repo[0] == '/', "resolved root is absolute, not cwd-relative");
    char expect[PATH_MAX];
    if (realpath(alpha_argv0, expect)) {
        char *slash = strrchr(expect, '/');
        if (slash) *slash = 0;
        CHECK(strcmp(from_repo, expect) == 0,
              "resolved root is the directory holding this binary");
    }

    /* ALPHA_ROOT must still win when it is set. */
    setenv("ALPHA_ROOT", "/nonexistent-root", 1);
    char forced[PATH_MAX];
    alpha_resolve_install_root(forced, sizeof(forced));
    CHECK(strcmp(forced, "/nonexistent-root") == 0, "ALPHA_ROOT overrides the default");

    if (saved_root[0]) setenv("ALPHA_ROOT", saved_root, 1);
    else unsetenv("ALPHA_ROOT");
}

/* A transcriber that never finishes must not block the caller forever.
 *
 * This ran on the poll thread with a bare blocking waitpid and no guard in the
 * script either, so one wedged Whisper stopped every chat until the bot was
 * restarted. The wait must also cover the READS: a stuck child blocks the
 * parent in read() and waitpid is never reached. */
static void test_transcriber_timeout(void) {
    TEST_BEGIN("voice: a wedged transcriber is killed, not waited on forever");

    /* alpha_install_root() caches on first use (workers read it concurrently,
     * so a re-resolving static buffer would race). Setting ALPHA_ROOT here
     * would therefore be ignored, and an earlier draft of this test silently
     * probed a stale path. Plant the fake transcriber at the real resolved
     * root instead. */
    char scripts[PATH_MAX], script[PATH_MAX];
    snprintf(scripts, sizeof(scripts), "%s/scripts", alpha_install_root());
    int made_scripts = (mkdir(scripts, 0700) == 0);
    CHECK(made_scripts || errno == EEXIST, "scripts dir available");
    snprintf(script, sizeof(script), "%s/alpha-transcribe.py", scripts);

    /* Sleeps far past the timeout and never writes anything. */
    FILE *f = fopen(script, "w");
    CHECK(f != NULL, "wedged transcriber written");
    if (f) {
        fputs("#!/usr/bin/env python3\nimport time\ntime.sleep(600)\n", f);
        fclose(f);
    }

    time_t t0 = time(NULL);
    sds out = voice_transcribe("/dev/null");
    long elapsed_ms = (long)(time(NULL) - t0) * 1000;

    CHECK(out == NULL, "a wedged transcriber yields no transcript");
    /* The real bug was unbounded: assert it returned near the deadline rather
     * than merely 'eventually'. */
    CHECK(elapsed_ms < ALPHA_VOICE_TIMEOUT_MS * 3,
          "returned close to the deadline instead of hanging");
    if (out) sdsfree(out);

    /* Large stderr must not deadlock. Draining stdout to EOF first meant a
     * child filling the 64 KB stderr pipe buffer blocked writing, never closed
     * stdout, and hung the parent (measured: fine at 60000 bytes, hung at
     * 70000). Well past one buffer here, and it must still succeed. */
    f = fopen(script, "w");
    CHECK(f != NULL, "stderr-flooding transcriber written");
    if (f) {
        fputs("#!/usr/bin/env python3\n"
              "import sys\n"
              "sys.stderr.write('E' * 300000)\n"
              "sys.stderr.flush()\n"
              "print('flood ok')\n", f);
        fclose(f);
    }
    sds flood = voice_transcribe("/dev/null");
    CHECK(flood != NULL, "a transcriber writing 300 KB of stderr still succeeds");
    if (flood) {
        CHECK(strcmp(flood, "flood ok") == 0, "its stdout is intact");
        sdsfree(flood);
    }

    unlink(script);
    if (made_scripts) rmdir(scripts);
}

/* An oversized voice note must be refused mid-download.
 *
 * Telegram allows 20 MB, and transcribing that costs minutes of CPU on the
 * poll thread. CURLOPT_MAXFILESIZE only rejects up front when the server
 * declares a Content-Length, so the limit is enforced on received bytes too:
 * returning short from the write callback aborts the transfer. */
static void test_voice_download_size_cap(void) {
    TEST_BEGIN("voice: an oversized download is aborted, not written whole");

    char path[] = "/tmp/alpha_vc_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "temp sink created");
    FILE *f = fdopen(fd, "wb");
    CHECK(f != NULL, "sink opened");
    if (!f) return;

    voice_sink_t sink = { .f = f, .written = 0 };
    const size_t chunk = 64 * 1024;
    char *buf = malloc(chunk);
    CHECK(buf != NULL, "chunk buffer");
    if (!buf) { fclose(f); unlink(path); return; }
    memset(buf, 'A', chunk);

    /* Feed well past the cap and find where it refuses. */
    size_t offered = 0;
    int aborted = 0;
    for (int i = 0; i < (int)(ALPHA_VOICE_MAX_BYTES / chunk) + 64; i++) {
        size_t r = voice_write(buf, 1, chunk, &sink);
        offered += chunk;
        if (r != chunk) { aborted = 1; break; }
    }
    CHECK(aborted, "the write callback eventually refuses");
    CHECK(sink.written <= (size_t)ALPHA_VOICE_MAX_BYTES,
          "never writes more than the cap");
    CHECK(offered > (size_t)ALPHA_VOICE_MAX_BYTES,
          "the test really did offer more than the cap");

    fclose(f);
    struct stat st;
    CHECK(stat(path, &st) == 0 && st.st_size <= (off_t)ALPHA_VOICE_MAX_BYTES,
          "the file on disk is within the cap");
    free(buf);
    unlink(path);
}

/* Sessions must be written where the code says they are.
 *
 * The directory was created with system("mkdir -p sessions"), relative to the
 * cwd, while the paths were built from the install root. Whenever the two
 * differed, every session_save silently failed to open its file and the chat
 * had no memory -- with no error anywhere. */
static void test_session_dir_matches_session_path(void) {
    TEST_BEGIN("session: the directory is created where the paths point");

    char elsewhere[] = "/tmp/alpha_cwd_XXXXXX";
    CHECK(mkdtemp(elsewhere) != NULL, "unrelated cwd created");

    char saved_cwd[PATH_MAX];
    CHECK(getcwd(saved_cwd, sizeof(saved_cwd)) != NULL, "cwd readable");

    /* Move away from the install root so the two genuinely disagree -- exactly
     * the ALPHA_CWD case that lost every session. */
    CHECK(chdir(elsewhere) == 0, "moved to an unrelated cwd");

    /* Call the SAME functions telegram_run uses -- not a copy of their logic,
     * which would keep passing if telegram_run started composing its own path
     * again. */
    char sess_dir[PATH_MAX];
    session_dir(sess_dir, sizeof(sess_dir));
    struct stat pre;
    int existed = (stat(sess_dir, &pre) == 0);
    CHECK(session_dir_ensure() == 0, "session dir created at the install root");
    CHECK(stat(sess_dir, &pre) == 0, "and it really exists on disk");
    int made = !existed;

    char spath[PATH_MAX];
    session_path_for_chat(spath, sizeof(spath), 4242);
    FILE *f = fopen(spath, "w");
    CHECK(f != NULL, "a session file can actually be opened for writing");
    if (f) { fputs("{}", f); fclose(f); }

    /* The path must be anchored to the install root, not the cwd. */
    CHECK(strncmp(spath, alpha_install_root(), strlen(alpha_install_root())) == 0,
          "session path is under the install root");
    CHECK(strncmp(spath, elsewhere, strlen(elsewhere)) != 0,
          "session path is not under the cwd");

    /* And nothing may be created beside the cwd. */
    char stray[PATH_MAX];
    snprintf(stray, sizeof(stray), "%s/sessions", elsewhere);
    struct stat st;
    CHECK(stat(stray, &st) != 0, "no stray sessions dir beside the cwd");

    CHECK(chdir(saved_cwd) == 0, "cwd restored");
    unlink(spath);
    if (made) rmdir(sess_dir);
    rmdir(elsewhere);
}

/* main.c must not seed ALPHA_ROOT from the cwd: it short-circuits the install
 * root lookup, making that resolution dead code in the real binary. */
static void test_main_does_not_pin_root_to_cwd(void) {
    TEST_BEGIN("main: ALPHA_ROOT is not seeded from getcwd()");
    FILE *f = fopen("src/main.c", "rb");
    if (!f) f = fopen("../src/main.c", "rb");
    if (!f) f = fopen("../../src/main.c", "rb");
    CHECK(f != NULL, "main.c is readable");
    if (!f) return;
    sds body = sdsempty();
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) body = sdscatlen(body, buf, n);
    fclose(f);
    /* Look for an actual setenv of ALPHA_ROOT outside a comment. */
    int found = 0;
    const char *p = body;
    while ((p = strstr(p, "setenv(\"ALPHA_ROOT\"")) != NULL) { found = 1; p++; }
    CHECK(!found, "main.c does not setenv ALPHA_ROOT");
    sdsfree(body);
}

/* Two pollers on one bot token silently lose messages: Telegram gives each
 * update to whoever asked first. The guard must live in the binary, since
 * `./alpha --telegram` bypasses the launcher's pidfile entirely. */
static void test_only_one_poller_may_hold_the_lock(void) {
    TEST_BEGIN("telegram: a second poller cannot acquire the lock");

    CHECK(session_dir_ensure() == 0, "session dir available");

    int first = telegram_lock_acquire();
    CHECK(first >= 0, "first poller acquires the lock");

    /* flock is per open-file-description, so a fresh open() contends exactly
     * as a separate process would -- verified against the kernel, not assumed. */
    int second = telegram_lock_acquire();
    CHECK_EQ_INT(second, -1, "second poller is refused while the first holds it");
    if (second >= 0) close(second);

    /* The lock file must be beside the state two pollers would corrupt. */
    char dir[PATH_MAX], lockpath[PATH_MAX];
    session_dir(dir, sizeof(dir));
    snprintf(lockpath, sizeof(lockpath), "%s/telegram.lock", dir);
    struct stat st;
    CHECK(stat(lockpath, &st) == 0, "lock file lives in the session dir");

    /* It records the holder, so a refusal says who is in the way. */
    char buf[64] = "";
    FILE *lf = fopen(lockpath, "rb");
    if (lf) { size_t n = fread(buf, 1, sizeof(buf) - 1, lf); buf[n] = 0; fclose(lf); }
    char want[64];
    snprintf(want, sizeof(want), "pid=%ld", (long)getpid());
    CHECK(strcmp(buf, want) == 0, "lock records the holding pid");

    /* Releasing must let the next poller in -- a lock that never frees would
     * brick every restart, which is worse than the bug it prevents. */
    close(first);
    int third = telegram_lock_acquire();
    CHECK(third >= 0, "lock is reacquirable once the holder exits");
    if (third >= 0) close(third);
    unlink(lockpath);

    /* A correct lock nobody calls is not a guard. telegram_run cannot be
     * invoked here (it polls forever), so assert the wiring in the source --
     * otherwise deleting the call site leaves this whole test green. */
    FILE *src = fopen("src/telegram.c", "rb");
    if (!src) src = fopen("../src/telegram.c", "rb");
    if (!src) src = fopen("../../src/telegram.c", "rb");
    CHECK(src != NULL, "telegram.c is readable");
    if (!src) return;
    sds body = sdsempty();
    char rb[4096];
    size_t rn;
    while ((rn = fread(rb, 1, sizeof(rb), src)) > 0) body = sdscatlen(body, rb, rn);
    fclose(src);
    const char *run = strstr(body, "int telegram_run(");
    CHECK(run != NULL, "telegram_run found");
    if (run) {
        const char *loop = strstr(run, "for (;;)");
        CHECK(loop != NULL, "its poll loop found");
        const char *call = strstr(run, "telegram_lock_acquire()");
        CHECK(call != NULL && loop != NULL && call < loop,
              "telegram_run acquires the lock before it starts polling");
    }
    sdsfree(body);
}

/* The log is written by redirecting stderr and was never truncated: it grew
 * unbounded, ~95% of it "poll ok". Rotation must bound it without losing the
 * fd the launcher redirected, and must not fire on a terminal. */
static void test_log_rotates_when_large(void) {
    TEST_BEGIN("log: an oversized log is rotated, and writing continues");

    char dir[PATH_MAX], path[PATH_MAX], old[PATH_MAX];
    session_dir(dir, sizeof(dir));
    snprintf(path, sizeof(path), "%s/rot_test.log", dir);
    snprintf(old, sizeof(old), "%s.1", path);
    unlink(path); unlink(old);

    int saved = dup(fileno(stderr));
    CHECK(saved >= 0, "stderr saved");

    /* Under threshold: must be left completely alone. */
    FILE *f = fopen(path, "w");
    if (f) { fputs("small\n", f); fclose(f); }
    CHECK(freopen(path, "a", stderr) != NULL, "stderr redirected to the log");
    log_rotate_if_large();
    struct stat st;
    int rotated_small = (stat(old, &st) == 0);

    /* Over threshold: rotate. Write past the cap through stderr itself, the
     * way the real process does, rather than out of band. */
    char pad[4096];
    memset(pad, 'x', sizeof(pad) - 1);
    pad[sizeof(pad) - 1] = '\n';
    for (long i = 0; i <= ALPHA_LOG_MAX_BYTES / (long)sizeof(pad); i++)
        fwrite(pad, 1, sizeof(pad), stderr);
    fflush(stderr);

    long long before = 0;
    if (stat(path, &st) == 0) before = (long long)st.st_size;

    log_rotate_if_large();
    /* A line written AFTER rotation must land in the new file: if the fd were
     * still on the renamed inode, the log would silently stop growing. */
    fprintf(stderr, "POSTROTATE_MARKER\n");
    fflush(stderr);

    long long after = 0, kept = 0;
    int have_new = (stat(path, &st) == 0);
    if (have_new) after = (long long)st.st_size;
    int have_old = (stat(old, &st) == 0);
    if (have_old) kept = (long long)st.st_size;

    /* Restore before any CHECK, so failures are still reportable. */
    dup2(saved, fileno(stderr));
    close(saved);
    clearerr(stderr);

    CHECK(!rotated_small, "a log under the cap is not rotated");
    CHECK(before >= ALPHA_LOG_MAX_BYTES, "log really exceeded the cap");
    CHECK(have_old, "previous generation kept as .1");
    CHECK(kept >= ALPHA_LOG_MAX_BYTES, "the .1 file holds the old content");
    CHECK(have_new, "a fresh log exists after rotation");
    CHECK(after < before, "the live log shrank");

    char buf[256] = "";
    FILE *nf = fopen(path, "rb");
    if (nf) { size_t n = fread(buf, 1, sizeof(buf) - 1, nf); buf[n] = 0; fclose(nf); }
    CHECK(strstr(buf, "POSTROTATE_MARKER") != NULL,
          "writes after rotation reach the new file");

    unlink(path); unlink(old);
}

/* Rotation keys off stderr being a regular file; on a terminal or pipe there
 * is nothing to rotate and F_GETPATH would be meaningless. */
static void test_log_rotation_ignores_non_files(void) {
    TEST_BEGIN("log: rotation is a no-op when stderr is a pipe");

    int fds[2];
    CHECK(pipe(fds) == 0, "pipe created");
    /* Non-blocking: if a broken rotation reopened stderr onto a file, nothing
     * is ever written here and a blocking read would hang the whole suite
     * instead of failing it (observed while sabotage-testing). */
    fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK);
    int saved = dup(fileno(stderr));
    CHECK(dup2(fds[1], fileno(stderr)) >= 0, "stderr points at the pipe");

    log_rotate_if_large();   /* must not crash, rename, or freopen */

    /* stderr must still be the pipe afterwards. A rotation that reopened it
     * onto a file here would send every later diagnostic somewhere invisible,
     * so read the write back rather than merely asserting we did not crash. */
    fprintf(stderr, "PIPE_STILL_LIVE\n");
    fflush(stderr);
    char buf[64] = "";
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    if (n > 0) buf[n] = 0;

    dup2(saved, fileno(stderr));
    close(saved); close(fds[0]); close(fds[1]);
    clearerr(stderr);
    CHECK(strstr(buf, "PIPE_STILL_LIVE") != NULL,
          "stderr is untouched when it is not a regular file");
}

/* Concurrent voice notes must not collide on one temp path. */
static void test_voice_downloads_do_not_share_a_path(void) {
    TEST_BEGIN("voice: concurrent downloads get distinct temp files");
    char a[PATH_MAX], b[PATH_MAX];
    voice_tmp_path(a, sizeof(a));
    voice_tmp_path(b, sizeof(b));
    CHECK(strcmp(a, b) != 0, "two in-flight notes do not share one file");
}

int main(int argc, char **argv) {
    if (argc > 0) alpha_argv0 = argv[0];

    /* Tests that plant a fake transcriber or write session files must never do
     * so in the real install: ALPHA_ROOT is commonly exported (the launcher and
     * .env both set it), and an earlier version of this suite resolved to the
     * repo and deleted scripts/alpha-transcribe.py on cleanup, silently
     * breaking voice notes. Pin a private sandbox before anything calls
     * alpha_install_root(), whose result is cached from first use.
     * test_transcriber_path_is_independent_of_cwd is unaffected: it clears
     * ALPHA_ROOT itself and calls the uncached resolver. */
    char sandbox[] = "/tmp/alpha_test_root_XXXXXX";
    if (!mkdtemp(sandbox)) { perror("mkdtemp"); return 2; }
    setenv("ALPHA_ROOT", sandbox, 1);

    test_utf8_chunking();
    test_tab_is_preserved();
    test_fast_lane_routing();
    test_chat_cwd_thread_safety();
    test_queue_semantics();
    test_queue_overflow();
    test_allowlist();
    test_transcriber_path_is_independent_of_cwd();
    test_transcriber_timeout();
    test_voice_download_size_cap();
    test_session_dir_matches_session_path();
    test_main_does_not_pin_root_to_cwd();
    test_only_one_poller_may_hold_the_lock();
    test_log_rotates_when_large();
    test_log_rotation_ignores_non_files();
    test_voice_downloads_do_not_share_a_path();

    /* The sandbox must have absorbed the writes, and the real install must be
     * untouched -- assert it rather than trusting it. */
    char probe[PATH_MAX];
    struct stat st;
    snprintf(probe, sizeof(probe), "%s/scripts/alpha-transcribe.py", sandbox);
    CHECK(stat(probe, &st) != 0, "sandbox transcriber cleaned up");
    rmdir(sandbox);

    return test_report("telegram");
}
