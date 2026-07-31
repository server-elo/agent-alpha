/* Regressions for src/agent_loop.c: session durability, observation pruning,
 * live-context bounding, and the tool-output note budget. */
#include "../src/agent_loop.c"
#include "test_util.h"

#define SESS "/tmp/alpha_sess_test.json"

static size_t msgs_bytes(cJSON *a) {
    size_t t = 0;
    int n = cJSON_GetArraySize(a);
    for (int i = 0; i < n; i++) {
        const char *c = cJSON_GetStringValue(
            cJSON_GetObjectItem(cJSON_GetArrayItem(a, i), "content"));
        if (c) t += strlen(c);
    }
    return t;
}

static sds repeat(char c, size_t n) {
    sds s = sdsempty();
    for (size_t i = 0; i < n; i++) s = sdscatlen(s, &c, 1);
    return s;
}

/* --- a damaged session must not be destroyed by the next save -------------- */
static void test_corrupt_history_is_preserved(void) {
    TEST_BEGIN("session_load: unreadable history is kept, not overwritten");
    unlink(SESS);
    unlink(SESS ".corrupt");

    cJSON *h = cJSON_CreateArray();
    for (int i = 0; i < 5; i++) messages_add_text(h, "user", "irreplaceable turn");
    session_save(SESS, h);
    cJSON_Delete(h);

    /* simulate a torn or damaged file */
    FILE *f = fopen(SESS, "w");
    fputs("[{\"role\":\"us", f);
    fclose(f);

    cJSON *l = session_load(SESS);
    CHECK_EQ_INT(cJSON_GetArraySize(l), 0, "damaged history loads as empty");
    struct stat st;
    CHECK(stat(SESS ".corrupt", &st) == 0, "damaged file is preserved for recovery");

    /* the next save must not clobber the preserved copy */
    messages_add_text(l, "user", "new turn");
    session_save(SESS, l);
    CHECK(stat(SESS ".corrupt", &st) == 0, "preserved copy survives the next save");
    cJSON_Delete(l);

    unlink(SESS);
    unlink(SESS ".corrupt");
}

/* --- writes are atomic ----------------------------------------------------- */
static void test_atomic_save(void) {
    TEST_BEGIN("session_save: a stale temp file cannot corrupt real history");
    unlink(SESS);
    cJSON *h = cJSON_CreateArray();
    for (int i = 0; i < 5; i++) messages_add_text(h, "user", "history entry");
    session_save(SESS, h);
    cJSON_Delete(h);

    FILE *f = fopen(SESS ".tmp", "w");
    fputs("[{\"role\":\"us", f);
    fclose(f);

    cJSON *l = session_load(SESS);
    CHECK_EQ_INT(cJSON_GetArraySize(l), 5, "real history is intact");
    cJSON_Delete(l);
    unlink(SESS ".tmp");
    unlink(SESS);

    /* The rename must be conditional on the write having fully succeeded.
     * Point the save at an unwritable directory: the temp file cannot be
     * written, so nothing may be renamed into place and no partial file or
     * stray .tmp may be left behind. */
    const char *bad = "/tmp/alpha_ro_dir/sess.json";
    system("rm -rf /tmp/alpha_ro_dir; mkdir -p /tmp/alpha_ro_dir; chmod 500 /tmp/alpha_ro_dir");
    cJSON *h2 = cJSON_CreateArray();
    messages_add_text(h2, "user", "should not be persisted");
    session_save(bad, h2);
    cJSON_Delete(h2);
    struct stat st;
    CHECK(stat(bad, &st) != 0, "no file created when the write cannot succeed");
    CHECK(stat("/tmp/alpha_ro_dir/sess.json.tmp", &st) != 0,
          "no stray temp file left behind");
    system("chmod 700 /tmp/alpha_ro_dir; rm -rf /tmp/alpha_ro_dir");
}

/* --- stale tool observations must not accumulate forever ------------------- */
static void test_observation_pruning(void) {
    TEST_BEGIN("session_save: old tool observations are pruned, conversation is not");
    unlink(SESS);
    cJSON *h = cJSON_CreateArray();
    sds blob = repeat('x', 9000);
    for (int r = 0; r < 10; r++) {
        char u[64];
        snprintf(u, sizeof(u), "USERTURN%d", r);
        messages_add_text(h, "user", u);
        sds o = sdscatprintf(sdsempty(),
            "[tool observations from my last turn]\n%s", blob);
        messages_add_text(h, "assistant", o);
        sdsfree(o);
        messages_add_text(h, "assistant", "short summary");
    }
    size_t before = msgs_bytes(h);
    session_save(SESS, h);
    size_t after = msgs_bytes(h);

    CHECK(after < before, "history shrank");
    int obs = 0, n = cJSON_GetArraySize(h);
    for (int i = 0; i < n; i++)
        if (is_observation(cJSON_GetArrayItem(h, i))) obs++;
    CHECK_EQ_INT(obs, ALPHA_KEEP_OBSERVATIONS, "only recent observations kept");

    int users = 0;
    for (int r = 0; r < 10; r++) {
        char u[64];
        snprintf(u, sizeof(u), "USERTURN%d", r);
        for (int i = 0; i < n; i++) {
            const char *c = cJSON_GetStringValue(
                cJSON_GetObjectItem(cJSON_GetArrayItem(h, i), "content"));
            if (c && strstr(c, u)) { users++; break; }
        }
    }
    CHECK_EQ_INT(users, 10, "every user turn survived pruning");

    sdsfree(blob);
    cJSON_Delete(h);
    unlink(SESS);
}

/* --- the in-flight array is resent on every call, so it must stay bounded -- */
static void test_live_context_is_bounded(void) {
    TEST_BEGIN("trim_live_messages: per-call size stays flat across a long request");
    cJSON *m = cJSON_CreateArray();
    messages_add_text(m, "system", "system prompt");
    sds toolout = repeat('x', 200000);
    sds reply = repeat('y', 64000);

    size_t first = 0, last = 0;
    for (int turn = 0; turn < 40; turn++) {
        trim_live_messages(m);
        size_t sz = msgs_bytes(m);
        if (turn == 9) first = sz;
        if (turn == 39) last = sz;

        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "role", "assistant");
        cJSON_AddStringToObject(a, "content", reply);
        cJSON_AddItemToArray(m, a);
        cJSON *t = cJSON_CreateObject();
        cJSON_AddStringToObject(t, "role", "tool");
        cJSON_AddStringToObject(t, "tool_call_id", "c1");
        cJSON_AddStringToObject(t, "content", toolout);
        cJSON_AddItemToArray(m, t);
    }
    /* trim_live_messages deliberately leaves the newest few messages alone, so
     * the steady state sits above the budget by roughly that tail. What must
     * hold is that it is BOUNDED: measured ~0.8 MB flat, versus ~10 MB and
     * still climbing when the trim is removed. */
    CHECK(last < 2000000, "context stays bounded");
    CHECK(last < first + first / 4, "size is flat, not linear in turn count");

    /* the newest tool result must never be abridged */
    int n = cJSON_GetArraySize(m);
    const char *newest = cJSON_GetStringValue(
        cJSON_GetObjectItem(cJSON_GetArrayItem(m, n - 1), "content"));
    CHECK(newest && strlen(newest) > 100000, "most recent tool output is intact");

    sdsfree(toolout);
    sdsfree(reply);
    cJSON_Delete(m);
}

/* --- the budget must track what is actually sent, not just "content" -------
 * A write_file call carries the whole file body in
 * tool_calls[].function.arguments and leaves content null. Counting content
 * alone reported 433 bytes for a 4 MB request, so the trim never fired and the
 * call died on the 300s curl cap.
 *
 * Ground truth here is cJSON_PrintUnformatted -- the same serialization llm.c
 * puts on the wire -- so this cannot pass by agreeing with a broken counter. */
static size_t wire_bytes(cJSON *m) {
    char *s = cJSON_PrintUnformatted(m);
    size_t n = s ? strlen(s) : 0;
    free(s);
    return n;
}

static void test_trim_counts_tool_call_arguments(void) {
    TEST_BEGIN("trim_live_messages: bulk hidden in tool_call arguments is counted and trimmed");
    cJSON *m = cJSON_CreateArray();
    messages_add_text(m, "system", "sys");
    /* Each payload must exceed the budget on its own. With smaller ones the
     * walk runs out of work before it reaches the newest message, and the
     * "most recent call is spared" check below would pass for an accidental
     * reason rather than because the tail is protected. */
    sds big = repeat('x', ALPHA_LIVE_MAX_BYTES + 100000);

    for (int i = 0; i < 20; i++) {
        char id[32];
        snprintf(id, sizeof(id), "call_%d", i);
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "role", "assistant");
        cJSON_AddNullToObject(a, "content");     /* as claude sends a pure tool call */
        cJSON *tcs = cJSON_CreateArray();
        cJSON *tc = cJSON_CreateObject();
        cJSON_AddStringToObject(tc, "id", id);
        cJSON *fn = cJSON_CreateObject();
        cJSON_AddStringToObject(fn, "name", "write_file");
        sds args = sdscatprintf(sdsempty(), "{\"path\":\"/tmp/f\",\"content\":\"%s\"}", big);
        cJSON_AddStringToObject(fn, "arguments", args);
        sdsfree(args);
        cJSON_AddItemToObject(tc, "function", fn);
        cJSON_AddItemToArray(tcs, tc);
        cJSON_AddItemToObject(a, "tool_calls", tcs);
        cJSON_AddItemToArray(m, a);

        cJSON *tr = cJSON_CreateObject();
        cJSON_AddStringToObject(tr, "role", "tool");
        cJSON_AddStringToObject(tr, "tool_call_id", id);
        cJSON_AddStringToObject(tr, "content", "OK wrote 200000 bytes");
        cJSON_AddItemToArray(m, tr);
    }

    size_t wire_before = wire_bytes(m);
    CHECK(wire_before > 3000000, "fixture really is oversized on the wire");
    CHECK(strlen(big) > (size_t)ALPHA_LIVE_MAX_BYTES,
          "one payload alone exceeds the budget, so the walk cannot stop early");
    /* The estimate must be close to the truth -- not merely nonzero. */
    size_t est = messages_bytes(m);
    CHECK(est > wire_before - wire_before / 10,
          "estimate accounts for argument payloads, not just content");

    trim_live_messages(m);
    size_t wire_after = wire_bytes(m);
    /* The floor is the protected tail, not the budget: the newest few messages
     * are never abridged, so with payloads this large the steady state sits
     * above ALPHA_LIVE_MAX_BYTES by roughly that tail. What must hold is that
     * the bulk is gone. */
    CHECK(wire_after < wire_before / 3, "oversized arguments are actually dropped");
    CHECK(wire_after < 3000000, "what remains is bounded by the protected tail");

    /* Pairing and JSON validity must survive. */
    int calls = 0, results = 0, n = cJSON_GetArraySize(m);
    for (int i = 0; i < n; i++) {
        cJSON *x = cJSON_GetArrayItem(m, i);
        cJSON *tcs = cJSON_GetObjectItem(x, "tool_calls");
        if (cJSON_IsArray(tcs)) {
            calls++;
            cJSON *tc = cJSON_GetArrayItem(tcs, 0);
            cJSON *fn = cJSON_GetObjectItem(tc, "function");
            CHECK(cJSON_GetStringValue(cJSON_GetObjectItem(fn, "name")) != NULL,
                  "tool name is preserved for pairing");
            const char *a = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "arguments"));
            CHECK(a != NULL, "arguments field still exists");
            cJSON *parsed = cJSON_Parse(a);
            CHECK(parsed != NULL, "stubbed arguments are still valid JSON");
            cJSON_Delete(parsed);
        }
        if (cJSON_GetObjectItem(x, "tool_call_id")) results++;
    }
    CHECK_EQ_INT(calls, 20, "all tool_calls still present");
    CHECK_EQ_INT(calls, results, "pairing is intact");

    /* The newest call must not be abridged -- it is the one in flight. */
    cJSON *newest = cJSON_GetArrayItem(m, cJSON_GetArraySize(m) - 2);
    cJSON *ntcs = cJSON_GetObjectItem(newest, "tool_calls");
    if (cJSON_IsArray(ntcs)) {
        const char *a = cJSON_GetStringValue(cJSON_GetObjectItem(
            cJSON_GetObjectItem(cJSON_GetArrayItem(ntcs, 0), "function"), "arguments"));
        CHECK(a && strlen(a) > 100000, "the most recent call keeps its arguments");
    }

    sdsfree(big);
    cJSON_Delete(m);
}

/* --- trimming must never orphan a tool_call_id ----------------------------
 * Anthropic-backed models reject a request where a tool_use has no matching
 * tool_result, so messages are abridged in place and never removed. */
static void test_trim_keeps_tool_pairing(void) {
    TEST_BEGIN("trim_live_messages: every tool_call keeps its tool_result");
    cJSON *m = cJSON_CreateArray();
    messages_add_text(m, "system", "sys");
    sds big = repeat('z', 300000);
    for (int t = 0; t < 10; t++) {
        char id[32];
        snprintf(id, sizeof(id), "call_%d", t);
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "role", "assistant");
        cJSON_AddStringToObject(a, "content", big);
        cJSON *tcs = cJSON_CreateArray();
        cJSON *tc = cJSON_CreateObject();
        cJSON_AddStringToObject(tc, "id", id);
        cJSON_AddItemToArray(tcs, tc);
        cJSON_AddItemToObject(a, "tool_calls", tcs);
        cJSON_AddItemToArray(m, a);

        cJSON *tm = cJSON_CreateObject();
        cJSON_AddStringToObject(tm, "role", "tool");
        cJSON_AddStringToObject(tm, "tool_call_id", id);
        cJSON_AddStringToObject(tm, "content", big);
        cJSON_AddItemToArray(m, tm);
    }
    trim_live_messages(m);

    int calls = 0, results = 0, n = cJSON_GetArraySize(m);
    for (int i = 0; i < n; i++) {
        cJSON *x = cJSON_GetArrayItem(m, i);
        if (cJSON_GetObjectItem(x, "tool_calls")) calls++;
        if (cJSON_GetObjectItem(x, "tool_call_id")) results++;
    }
    CHECK_EQ_INT(calls, 10, "all tool_calls still present");
    CHECK_EQ_INT(results, 10, "all tool_results still present");
    CHECK_EQ_INT(calls, results, "pairing is intact");

    sdsfree(big);
    cJSON_Delete(m);
}

/* --- note budget: truncation keeps both ends and announces itself ---------- */
static void test_note_budget(void) {
    TEST_BEGIN("notes_append: large output keeps head and tail, and says what was lost");
    sds notes = sdsempty();
    sds body = sdsempty();
    body = sdscat(body, "HEAD_MARKER ");
    sds filler = repeat('x', ALPHA_NOTE_PER_TOOL * 3);
    body = sdscatsds(body, filler);
    body = sdscat(body, " TAIL_MARKER_EXIT_0");
    notes_append(&notes, "execute_bash", body);

    CHECK(strstr(notes, "HEAD_MARKER") != NULL, "head is kept");
    CHECK(strstr(notes, "TAIL_MARKER_EXIT_0") != NULL, "tail is kept (exit status lives there)");
    CHECK(strstr(notes, "NOT retained") != NULL, "the gap is declared, not hidden");

    /* total budget is enforced, and the warning appears exactly once */
    sds n2 = sdsempty();
    sds chunk = repeat('y', 5000);
    for (int i = 0; i < 200; i++) notes_append(&n2, "t", chunk);
    CHECK(sdslen(n2) < (size_t)ALPHA_NOTE_TOTAL * 2, "total note budget is bounded");
    int count = 0;
    const char *p = n2;
    while ((p = strstr(p, "NOTE BUDGET EXHAUSTED")) != NULL) { count++; p++; }
    CHECK_EQ_INT(count, 1, "budget warning is emitted once, not per turn");

    sdsfree(chunk);
    sdsfree(n2);
    sdsfree(filler);
    sdsfree(body);
    sdsfree(notes);
}

/* --- history is capped by bytes, not just message count ------------------- */
static void test_history_byte_cap(void) {
    TEST_BEGIN("session_save: history is bounded in bytes");
    unlink(SESS);
    cJSON *h = cJSON_CreateArray();
    sds chunk = repeat('z', 20000);
    for (int i = 0; i < 200; i++) messages_add_text(h, "assistant", chunk);
    session_save(SESS, h);
    CHECK(msgs_bytes(h) <= ALPHA_HISTORY_MAX_BYTES, "byte cap enforced");
    CHECK(cJSON_GetArraySize(h) <= ALPHA_HISTORY_MAX_MSGS, "message cap enforced");
    CHECK(cJSON_GetArraySize(h) > 0, "history is not wiped entirely");
    sdsfree(chunk);
    cJSON_Delete(h);
    unlink(SESS);
}

/* Guard against the helpers being correct but no longer called.
 * Two sabotages -- deleting the trim_live_messages() call in run_tool_loop, and
 * making the session rename unconditional -- passed every behavioural test
 * because those tests exercise the helpers directly. Assert the wiring too. */
static int file_contains(const char *path, const char *needle) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    static char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

static void test_wiring(void) {
    TEST_BEGIN("wiring: the guards are actually invoked, not merely present");
    CHECK(file_contains("src/agent_loop.c", "trim_live_messages(messages);"),
          "run_tool_loop trims the live context every turn");
    CHECK(file_contains("src/agent_loop.c", "prune_observations(history);"),
          "session_save prunes stale observations");
    CHECK(file_contains("src/agent_loop.c", "if (ok) rename(tmp, path);"),
          "the session rename is conditional on a fully successful write");
    CHECK(file_contains("src/tools.c", "pt_kill_all(&track);"),
          "the timeout kills tracked descendants, not just the group");
    CHECK(file_contains("src/llm.c", "finish_reason"),
          "truncated replies are detected");
}

/* A tool result cut at a fixed byte offset used to split a multi-byte
 * character; the broken bytes reached the session file, which then failed to
 * parse as UTF-8 and took the entire conversation with it. */
static int valid_utf8(const char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        int seq = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2
                : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : -1;
        if (seq < 0 || i + (size_t)seq > n) return 0;
        i += (size_t)seq;
    }
    return 1;
}

/* Tool output is not guaranteed to be UTF-8 at all: a binary blob, or a test
 * printing raw control bytes, produced a session file that would not parse and
 * cost the whole conversation. Truncating on a boundary does not help when the
 * input was never valid. */
static void test_notes_sanitize_invalid_utf8(void) {
    TEST_BEGIN("notes_append: invalid input bytes never reach the session");
    const char *cases[] = {
        "before\xcc after",                 /* lone continuation byte */
        "\xff\xfe binary junk",
        "trunc\xe2\x82",                    /* sequence cut short */
        "\xed\xa0\x80 surrogate",
        NULL
    };
    for (int i = 0; cases[i]; i++) {
        sds notes = sdsempty();
        notes_append(&notes, "execute_bash", cases[i]);
        CHECK(valid_utf8(notes, sdslen(notes)), "note is valid UTF-8");
        sdsfree(notes);
    }
    /* and the same for output large enough to hit the truncating branch */
    sds big = sdsempty();
    while (sdslen(big) < (size_t)ALPHA_NOTE_PER_TOOL * 3)
        big = sdscat(big, "ok\xcc\xff");
    sds notes = sdsempty();
    notes_append(&notes, "execute_bash", big);
    CHECK(valid_utf8(notes, sdslen(notes)), "large invalid output is sanitised too");
    sdsfree(notes);
    sdsfree(big);
}

static void test_notes_never_split_utf8(void) {
    TEST_BEGIN("notes_append: truncation never splits a multi-byte character");
    /* Multi-byte fillers at every width, so head and tail cuts land mid-char. */
    const char *units[] = { "\xc3\xbc", "\xe2\x80\xa6", "\xf0\x9f\x98\x80", NULL };
    for (int u = 0; units[u]; u++) {
        for (int pad = 0; pad < 4; pad++) {
            sds body = sdsempty();
            for (int i = 0; i < pad; i++) body = sdscat(body, "a");
            while (sdslen(body) < (size_t)ALPHA_NOTE_PER_TOOL * 3)
                body = sdscat(body, units[u]);
            sds notes = sdsempty();
            notes_append(&notes, "execute_bash", body);
            CHECK(valid_utf8(notes, sdslen(notes)),
                  "note stays valid UTF-8 after truncation");
            sdsfree(notes);
            sdsfree(body);
        }
    }
}

int main(void) {
    test_wiring();
    test_notes_never_split_utf8();
    test_notes_sanitize_invalid_utf8();
    test_corrupt_history_is_preserved();
    test_atomic_save();
    test_observation_pruning();
    test_live_context_is_bounded();
    test_trim_counts_tool_call_arguments();
    test_trim_keeps_tool_pairing();
    test_note_budget();
    test_history_byte_cap();
    return test_report("session");
}
