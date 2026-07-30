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
    CHECK(allowed("5433551381", 5433551381LL), "listed chat is allowed");
    CHECK(!allowed("5433551381", 999LL), "unlisted chat is rejected");
    CHECK(allowed("*", 999LL), "wildcard allows any chat");
    CHECK(allowed("1,2,3", 2LL), "comma-separated list works");
    CHECK(!allowed("1,2,3", 4LL), "absent id in a list is rejected");
}

int main(void) {
    test_utf8_chunking();
    test_fast_lane_routing();
    test_chat_cwd_thread_safety();
    test_queue_semantics();
    test_queue_overflow();
    test_allowlist();
    return test_report("telegram");
}
