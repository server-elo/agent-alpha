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

int main(void) {
    test_wiring();
    test_corrupt_history_is_preserved();
    test_atomic_save();
    test_observation_pruning();
    test_live_context_is_bounded();
    test_trim_keeps_tool_pairing();
    test_note_budget();
    test_history_byte_cap();
    return test_report("session");
}
