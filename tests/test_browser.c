/* The CDP WebSocket client in src/browser.c.
 *
 * 923 lines drove a real browser with no test at all, and it silently returned
 * corrupt data in two ways: a fragmented message (FIN=0 plus continuation
 * frames, which Chrome is free to send for any large snapshot) had only its
 * first fragment returned, and a payload cut short by the socket timeout was
 * returned truncated. Both parse as garbage in the caller, so the agent acted
 * on half a page and reported success.
 *
 * These tests speak the wire protocol against the shipped function: a small
 * server thread frames replies by hand, so the exact byte layout under test is
 * the one Chrome would send. */
#include "../src/browser.c"
#include "test_util.h"

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* --- a hand-rolled WebSocket server ---------------------------------------
 * The handshake accept-key is not verified by the client under test, so the
 * server can return a constant one. Everything after the handshake is real
 * RFC 6455 framing. */

typedef enum {
    S_ONE_FRAME,        /* a single FIN text frame */
    S_FRAGMENTED,       /* text(FIN=0) + continuation(FIN=0) + continuation(FIN=1) */
    S_TRUNCATED,        /* header promises N bytes, server sends fewer and stalls */
    S_PING_MID,         /* a ping interleaved between two fragments */
    S_EVENT_FIRST,      /* an unrelated id, then the requested one */
    S_CLOSE_ONLY,       /* a close frame and nothing else */
    S_HUGE,             /* one frame above ALPHA_WS_MAX_FRAME */
    S_EVENT_THEN_CUT    /* an unrelated event, then a truncated reply */
} scenario_t;

typedef struct {
    int port;
    scenario_t scenario;
    int ready;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} server_t;

static void send_frame(int c, int opcode, int fin, const char *body, size_t n) {
    unsigned char h[10];
    size_t hn = 0;
    h[0] = (unsigned char)((fin ? 0x80 : 0x00) | opcode);
    if (n < 126) { h[1] = (unsigned char)n; hn = 2; }
    else if (n <= 0xffff) {
        h[1] = 126;
        h[2] = (unsigned char)((n >> 8) & 0xff);
        h[3] = (unsigned char)(n & 0xff);
        hn = 4;
    } else {
        h[1] = 127;
        for (int i = 0; i < 8; i++) h[2 + i] = (unsigned char)((n >> ((7 - i) * 8)) & 0xff);
        hn = 10;
    }
    if (send(c, h, hn, 0) < 0) return;
    if (n) { if (send(c, body, n, 0) < 0) return; }
}

/* Header claims `claim` bytes but only `actual` are sent; then the server
 * sleeps past the client's receive timeout without closing. A close would be
 * detected as EOF, so this is the case that used to yield a partial result. */
static void send_truncated(int c, const char *body, size_t claim, size_t actual) {
    unsigned char h[4];
    h[0] = 0x81;
    h[1] = 126;
    h[2] = (unsigned char)((claim >> 8) & 0xff);
    h[3] = (unsigned char)(claim & 0xff);
    if (send(c, h, 4, 0) < 0) return;
    if (send(c, body, actual, 0) < 0) return;
    sleep(9);
}

static void *server_thread(void *ud) {
    server_t *s = ud;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    bind(srv, (struct sockaddr *)&a, sizeof(a));
    listen(srv, 4);
    socklen_t al = sizeof(a);
    getsockname(srv, (struct sockaddr *)&a, &al);

    pthread_mutex_lock(&s->mu);
    s->port = ntohs(a.sin_port);
    s->ready = 1;
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->mu);

    int c = accept(srv, NULL, NULL);
    if (c < 0) { close(srv); return NULL; }

    char buf[8192];
    ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(c); close(srv); return NULL; }
    const char *ok =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    if (send(c, ok, strlen(ok), 0) < 0) { close(c); close(srv); return NULL; }
    recv(c, buf, sizeof(buf), 0);          /* the client's masked request frame */

    char reply[512];
    snprintf(reply, sizeof(reply), "{\"id\":1,\"result\":{\"value\":\"%s\"}}",
             "abcdefghijklmnopqrstuvwxyz0123456789");
    size_t rn = strlen(reply);

    switch (s->scenario) {
    case S_ONE_FRAME:
        send_frame(c, 0x1, 1, reply, rn);
        break;
    case S_FRAGMENTED: {
        size_t a1 = rn / 3, a2 = rn / 3;
        send_frame(c, 0x1, 0, reply, a1);
        send_frame(c, 0x0, 0, reply + a1, a2);
        send_frame(c, 0x0, 1, reply + a1 + a2, rn - a1 - a2);
        break;
    }
    case S_TRUNCATED:
        send_truncated(c, reply, 400, rn / 2);
        break;
    case S_PING_MID: {
        /* A ping BETWEEN fragments, which is exactly what RFC 6455 permits and
         * what breaks a reader that treats every frame as data: the ping's
         * bytes get spliced into the middle of the JSON. A ping merely sent
         * first is recoverable by accident, so it proved nothing. */
        size_t a1 = rn / 2;
        send_frame(c, 0x1, 0, reply, a1);
        send_frame(c, 0x9, 1, "hb", 2);
        send_frame(c, 0x0, 1, reply + a1, rn - a1);
        break;
    }
    case S_EVENT_FIRST: {
        const char *ev = "{\"method\":\"Page.loadEventFired\",\"params\":{}}";
        send_frame(c, 0x1, 1, ev, strlen(ev));
        send_frame(c, 0x1, 1, reply, rn);
        break;
    }
    case S_CLOSE_ONLY:
        send_frame(c, 0x8, 1, "", 0);
        break;
    case S_HUGE: {
        /* Header only, advertising an absurd length. Without a cap the client
         * tries to malloc it and then blocks reading bytes that never come, so
         * the observable symptom is a hang -- which is why this scenario also
         * has to be timed, not just checked for an error string. */
        size_t big = (size_t)ALPHA_WS_MAX_FRAME + 1024;
        unsigned char h[10];
        h[0] = 0x81; h[1] = 127;
        for (int i = 0; i < 8; i++) h[2 + i] = (unsigned char)((big >> ((7 - i) * 8)) & 0xff);
        if (send(c, h, 10, 0) < 0) break;
        sleep(9);                            /* outlast the client's recv timeout */
        break;
    }
    case S_EVENT_THEN_CUT: {
        /* The reply the caller asked for never arrives intact, but an
         * unrelated event did. Returning that event instead of the error hands
         * back a well-formed JSON object that is not the answer -- the exact
         * confusion the error path exists to prevent. */
        const char *ev = "{\"method\":\"Page.loadEventFired\",\"params\":{}}";
        send_frame(c, 0x1, 1, ev, strlen(ev));
        send_truncated(c, reply, 400, rn / 2);
        break;
    }
    }

    sleep(1);
    close(c);
    close(srv);
    return NULL;
}

/* Seconds the client itself spent, excluding the server thread's teardown --
 * a timing check that included the join measured the fixture, not the code. */
static double last_call_secs;

/* Run one scenario and return whatever the shipped client produced. */
static sds run_scenario(scenario_t sc) {
    server_t s;
    memset(&s, 0, sizeof(s));
    s.scenario = sc;
    pthread_mutex_init(&s.mu, NULL);
    pthread_cond_init(&s.cv, NULL);

    pthread_t th;
    pthread_create(&th, NULL, server_thread, &s);

    pthread_mutex_lock(&s.mu);
    while (!s.ready) pthread_cond_wait(&s.cv, &s.mu);
    int port = s.port;
    pthread_mutex_unlock(&s.mu);

    char url[128];
    snprintf(url, sizeof(url), "ws://127.0.0.1:%d/devtools/page/TEST", port);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sds r = cdp_ws_call_id(url, "{\"id\":1,\"method\":\"Runtime.evaluate\"}", 1);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    last_call_secs = (double)(t1.tv_sec - t0.tv_sec) +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    pthread_join(th, NULL);
    pthread_mutex_destroy(&s.mu);
    pthread_cond_destroy(&s.cv);
    return r;
}

/* The value the server puts in every well-formed reply. */
#define EXPECT_VALUE "abcdefghijklmnopqrstuvwxyz0123456789"

static int is_complete_reply(const char *r) {
    cJSON *j = cJSON_Parse(r);
    if (!j) return 0;
    cJSON *res = cJSON_GetObjectItem(j, "result");
    cJSON *val = res ? cJSON_GetObjectItem(res, "value") : NULL;
    int ok = cJSON_IsString(val) && strcmp(val->valuestring, EXPECT_VALUE) == 0;
    cJSON_Delete(j);
    return ok;
}

static void test_single_frame(void) {
    TEST_BEGIN("ws: an ordinary single-frame reply is returned intact");
    sds r = run_scenario(S_ONE_FRAME);
    CHECK(is_complete_reply(r), "reply parses and carries the full value");
    sdsfree(r);
}

/* The first of the two silent-corruption bugs. */
static void test_fragmented_message_is_reassembled(void) {
    TEST_BEGIN("ws: a fragmented message is joined, not cut at the first frame");
    sds r = run_scenario(S_FRAGMENTED);
    /* Parsing is the real assertion: the old code returned frame 1 alone,
     * which is a prefix of valid JSON and fails here. */
    CHECK(is_complete_reply(r), "all three fragments are present and parse as JSON");
    CHECK(strstr(r, EXPECT_VALUE) != NULL, "the payload is byte-for-byte complete");
    sdsfree(r);
}

/* The second: a short read must be an error, never a result. */
static void test_truncated_payload_is_an_error(void) {
    TEST_BEGIN("ws: a payload cut short is reported, not returned half-formed");
    sds r = run_scenario(S_TRUNCATED);
    CHECK(strncmp(r, "ERROR", 5) == 0, "the caller is told it failed");
    CHECK(!is_complete_reply(r), "no partial message is passed off as a reply");
    sdsfree(r);
}

static void test_control_frames_are_skipped(void) {
    TEST_BEGIN("ws: a ping between fragments is not spliced into the message");
    sds r = run_scenario(S_PING_MID);
    CHECK(is_complete_reply(r), "the two fragments join without the ping's bytes");
    CHECK(strstr(r, "hb") == NULL, "no control payload leaks into the result");
    sdsfree(r);
}

static void test_unrelated_event_is_skipped(void) {
    TEST_BEGIN("ws: an unsolicited event is skipped in favour of the matching id");
    sds r = run_scenario(S_EVENT_FIRST);
    CHECK(is_complete_reply(r), "the reply with the requested id wins");
    CHECK(strstr(r, "loadEventFired") == NULL, "the event is not what gets returned");
    sdsfree(r);
}

static void test_close_frame_ends_cleanly(void) {
    TEST_BEGIN("ws: a close frame ends the read with an error, not a hang");
    sds r = run_scenario(S_CLOSE_ONLY);
    CHECK(strncmp(r, "ERROR", 5) == 0, "closing without replying is an error");
    sdsfree(r);
}

static void test_oversized_frame_is_refused(void) {
    TEST_BEGIN("ws: an absurd advertised length is refused before allocating");
    sds r = run_scenario(S_HUGE);
    double took = last_call_secs;
    CHECK(strncmp(r, "ERROR", 5) == 0, "the cap fires instead of allocating it");
    /* Checking only for "ERROR" passed with the cap removed: the client
     * eventually errored anyway, after blocking for the full socket timeout on
     * bytes that were never coming. The cap's actual job is to refuse
     * immediately, so the check has to be about time. */
    CHECK(took < 3.0, "it is refused at once, not after a timeout");
    CHECK(strstr(r, "too large") != NULL, "the reason names the size, not a timeout");
    sdsfree(r);
}

static void test_error_beats_a_stale_partial(void) {
    TEST_BEGIN("ws: a failure is not masked by an earlier unrelated message");
    sds r = run_scenario(S_EVENT_THEN_CUT);
    CHECK(strncmp(r, "ERROR", 5) == 0, "the truncation is reported");
    CHECK(strstr(r, "loadEventFired") == NULL,
          "the unrelated event is not returned in place of the answer");
    sdsfree(r);
}

/* --- the ws:// URL parser -------------------------------------------------
 * Chrome hands back this URL; a bad parse means connecting to the wrong host
 * or port, so the failure modes must be explicit. */
static void test_bad_ws_urls(void) {
    TEST_BEGIN("ws: malformed debugger URLs are rejected with a reason");
    sds a = cdp_ws_call_id("http://127.0.0.1:1/x", "{}", 1);
    CHECK(strncmp(a, "ERROR", 5) == 0, "a non-ws scheme is refused");
    sdsfree(a);

    sds b = cdp_ws_call_id("ws://127.0.0.1:1", "{}", 1);
    CHECK(strncmp(b, "ERROR", 5) == 0, "a URL with no path is refused");
    sdsfree(b);

    sds c = cdp_ws_call_id(NULL, "{}", 1);
    CHECK(strncmp(c, "ERROR", 5) == 0, "NULL is refused rather than dereferenced");
    sdsfree(c);
}

/* --- the JSON layer above the socket -------------------------------------- */
static void test_eval_value_extraction(void) {
    TEST_BEGIN("eval: the value is unwrapped, and an exception is surfaced");

    sds ok = sdsnew("{\"result\":{\"result\":{\"type\":\"string\",\"value\":\"hello\"}}}");
    sds v1 = json_get_eval_value(ok);
    CHECK(strcmp(v1, "hello") == 0, "a string value is unwrapped");
    sdsfree(v1); sdsfree(ok);

    sds num = sdsnew("{\"result\":{\"result\":{\"type\":\"number\",\"value\":42}}}");
    sds v2 = json_get_eval_value(num);
    CHECK(strcmp(v2, "42") == 0, "a number survives as its literal");
    sdsfree(v2); sdsfree(num);

    /* A thrown exception used to be indistinguishable from an empty result. */
    sds ex = sdsnew("{\"result\":{\"exceptionDetails\":{\"text\":\"Uncaught\"}}}");
    sds v3 = json_get_eval_value(ex);
    CHECK(strstr(v3, "EXCEPTION") != NULL, "an exception is labelled, not returned empty");
    sdsfree(v3); sdsfree(ex);

    sds junk = sdsnew("not json at all");
    sds v4 = json_get_eval_value(junk);
    CHECK(strcmp(v4, "not json at all") == 0, "unparseable input is passed through verbatim");
    sdsfree(v4); sdsfree(junk);
}

/* --- js_escape guards the injected expressions ----------------------------
 * click/type interpolate user text into a single-quoted JS literal, so an
 * unescaped quote would end the string and run whatever follows. */
static void test_js_escape(void) {
    TEST_BEGIN("js_escape: quotes and control characters cannot break out");

    sds q = js_escape("it's");
    CHECK(strcmp(q, "it\\'s") == 0, "a single quote is escaped");
    sdsfree(q);

    sds b = js_escape("a\\b");
    CHECK(strcmp(b, "a\\\\b") == 0, "a backslash is escaped");
    sdsfree(b);

    sds n = js_escape("a\nb");
    CHECK(strcmp(n, "a\\nb") == 0, "a newline cannot terminate the literal");
    sdsfree(n);

    /* The real property: every quote in the output is preceded by a backslash.
     * Searching for the substring "');" is not that -- it matches inside the
     * correctly escaped "\');" too, and this check failed against working code
     * until it was stated as the invariant rather than a spelling of it. */
    sds inj = js_escape("');alert(1);('");
    int bare = 0;
    for (size_t i = 0; i < sdslen(inj); i++)
        if (inj[i] == '\'' && (i == 0 || inj[i - 1] != '\\')) bare = 1;
    CHECK(!bare, "an injection attempt leaves no unescaped quote");
    sdsfree(inj);

    sds e = js_escape(NULL);
    CHECK(sdslen(e) == 0, "NULL yields an empty string, not a crash");
    sdsfree(e);
}

/* --- url_encode_query ----------------------------------------------------- */
static void test_url_encode(void) {
    TEST_BEGIN("url_encode_query: spaces and quotes are percent-encoded");
    sds a = url_encode_query("https://x.test/a b");
    CHECK(strstr(a, "%20") != NULL, "a space is encoded");
    sdsfree(a);

    sds b = url_encode_query("https://x.test/\"q\"");
    CHECK(strstr(b, "%22") != NULL, "a double quote is encoded");
    sdsfree(b);

    sds c = url_encode_query("https://x.test/a?b=1&c=2");
    CHECK(strcmp(c, "https://x.test/a?b=1&c=2") == 0, "an ordinary query is unchanged");
    sdsfree(c);
}

/* --- normalize_url -------------------------------------------------------- */
static void test_normalize_url(void) {
    TEST_BEGIN("normalize_url: a bare host gets a scheme, an absolute URL does not");
    char buf[PATH_MAX];
    CHECK(strcmp(normalize_url("example.test", buf, sizeof(buf)), "https://example.test") == 0,
          "a bare host becomes https");
    CHECK(strcmp(normalize_url("http://example.test", buf, sizeof(buf)), "http://example.test") == 0,
          "an explicit http URL is left alone");
    CHECK(normalize_url("", buf, sizeof(buf)) == NULL, "an empty URL is rejected");
    CHECK(normalize_url(NULL, buf, sizeof(buf)) == NULL, "NULL is rejected");
}

/* --- the tool entry point rejects nonsense -------------------------------- */
static void test_unknown_action(void) {
    TEST_BEGIN("browser_tool_run: an unknown action names the valid ones");
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "action", "teleport");
    sds r = browser_tool_run(a);
    CHECK(strncmp(r, "ERROR", 5) == 0, "the action is refused");
    CHECK(strstr(r, "snapshot") != NULL, "the error lists what is available");
    sdsfree(r);
    cJSON_Delete(a);
}

int main(void) {
    test_single_frame();
    test_fragmented_message_is_reassembled();
    test_truncated_payload_is_an_error();
    test_control_frames_are_skipped();
    test_unrelated_event_is_skipped();
    test_close_frame_ends_cleanly();
    test_oversized_frame_is_refused();
    test_error_beats_a_stale_partial();
    test_bad_ws_urls();
    test_eval_value_extraction();
    test_js_escape();
    test_url_encode();
    test_normalize_url();
    test_unknown_action();
    return test_report("browser");
}
