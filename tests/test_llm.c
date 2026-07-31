/* Regressions for the SSE stream parser in src/llm.c.
 *
 * No network: the parser is fed bytes directly, which is the point -- the real
 * failure mode is a chunk boundary landing somewhere awkward, and only a
 * byte-level test can place one there deliberately. */
#include "../src/llm.c"
#include "test_util.h"

/* Feed a whole SSE transcript in fixed-size pieces, so the parser is exercised
 * at every boundary rather than the convenient ones a live server happens to
 * produce. */
static void feed_in_chunks(stream_state_t *st, const char *sse, size_t chunk) {
    size_t len = strlen(sse);
    for (size_t i = 0; i < len; i += chunk) {
        size_t n = len - i;
        if (n > chunk) n = chunk;
        stream_feed(st, sse + i, n);
    }
}

static const char *SSE_TEXT =
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"},\"finish_reason\":null}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world\"},\"finish_reason\":null}]}\n\n"
    "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
    "data: [DONE]\n\n";

/* --- the whole reason for streaming: a reply must survive any chunking ----- */
static void test_content_is_independent_of_chunk_boundaries(void) {
    TEST_BEGIN("stream: text is reassembled whatever the chunk size");

    /* 1 byte at a time is the adversarial case: every JSON string, every
     * newline and every "data: " prefix is split. */
    for (size_t chunk = 1; chunk <= 64; chunk++) {
        stream_state_t st;
        stream_state_init(&st);
        feed_in_chunks(&st, SSE_TEXT, chunk);
        int ok = (strcmp(st.content, "Hello world") == 0)
              && st.done
              && strcmp(st.finish_reason, "stop") == 0;
        if (!ok) {
            printf("  (chunk=%zu content=%s done=%d finish=%s)\n",
                   chunk, st.content, st.done, st.finish_reason);
            CHECK(0, "reassembled identically at every chunk size");
            stream_state_free(&st);
            return;
        }
        stream_state_free(&st);
    }
    CHECK(1, "reassembled identically at every chunk size");

    /* And in one piece, the way a fast localhost proxy usually delivers it. */
    stream_state_t st;
    stream_state_init(&st);
    stream_feed(&st, SSE_TEXT, strlen(SSE_TEXT));
    CHECK(strcmp(st.content, "Hello world") == 0, "single-chunk delivery agrees");
    CHECK(st.done == 1, "[DONE] observed");
    stream_state_free(&st);
}

/* A chunk boundary inside a multi-byte character must not corrupt it. The old
 * non-streaming path never had to care; this one does. */
static void test_utf8_survives_a_split_character(void) {
    TEST_BEGIN("stream: a UTF-8 character split across chunks stays intact");
    /* "grün — ✓" : 2-, 3- and 3-byte sequences. */
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"content\":\"gr\xc3\xbcn \xe2\x80\x94 \xe2\x9c\x93\"}}]}\n"
        "data: [DONE]\n";
    for (size_t chunk = 1; chunk <= 8; chunk++) {
        stream_state_t st;
        stream_state_init(&st);
        feed_in_chunks(&st, sse, chunk);
        if (strcmp(st.content, "gr\xc3\xbcn \xe2\x80\x94 \xe2\x9c\x93") != 0) {
            printf("  (chunk=%zu got %s)\n", chunk, st.content);
            CHECK(0, "multi-byte characters reassembled exactly");
            stream_state_free(&st);
            return;
        }
        stream_state_free(&st);
    }
    CHECK(1, "multi-byte characters reassembled exactly");
}

/* --- tool calls ------------------------------------------------------------
 * The proxy sends each call in one chunk today, but the OpenAI streaming format
 * allows `arguments` to be split. Relying on the current behaviour would break
 * silently against any other backend, so fragments must accumulate. */
static void test_tool_call_arguments_accumulate(void) {
    TEST_BEGIN("stream: tool arguments split across deltas are concatenated");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_a\",\"function\":{\"name\":\"write_file\",\"arguments\":\"{\\\"path\\\":\"}}]}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"\\\"/tmp/x\\\",\"}}]}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"\\\"content\\\":\\\"hi\\\"}\"}}]}}]}\n"
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n"
        "data: [DONE]\n";
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 3);

    CHECK_EQ_INT(st.ntc, 1, "the three deltas are one call, not three");
    CHECK(strcmp(st.tcs[0].name, "write_file") == 0, "name from the first delta is kept");
    CHECK(strcmp(st.tcs[0].id, "call_a") == 0, "id from the first delta is kept");
    CHECK(strcmp(st.tcs[0].args, "{\"path\":\"/tmp/x\",\"content\":\"hi\"}") == 0,
          "arguments reassembled in order");

    /* The rebuilt message must be what the agent loop expects, and the
     * arguments must parse -- a half-assembled fragment would be dispatched as
     * an empty argument object and the tool would run on nothing. */
    cJSON *msg = stream_build_message(&st);
    cJSON *tcs = cJSON_GetObjectItem(msg, "tool_calls");
    CHECK(cJSON_IsArray(tcs) && cJSON_GetArraySize(tcs) == 1, "message carries one tool_call");
    cJSON *fn = cJSON_GetObjectItem(cJSON_GetArrayItem(tcs, 0), "function");
    const char *a = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "arguments"));
    cJSON *parsed = cJSON_Parse(a);
    CHECK(parsed != NULL, "assembled arguments are valid JSON");
    const char *p = parsed ? cJSON_GetStringValue(cJSON_GetObjectItem(parsed, "path")) : NULL;
    CHECK(p && strcmp(p, "/tmp/x") == 0, "and carry the real argument value");
    if (parsed) cJSON_Delete(parsed);
    cJSON_Delete(msg);
    stream_state_free(&st);
}

/* Parallel calls arrive interleaved and their `index` is not an array slot
 * (this proxy emits 1-based). Keying on it as a position would drop or
 * overwrite calls. */
static void test_parallel_tool_calls_are_kept_separate(void) {
    TEST_BEGIN("stream: interleaved parallel tool calls stay distinct");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"a\",\"function\":{\"name\":\"execute_bash\",\"arguments\":\"{\\\"command\\\":\\\"echo \"}}]}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":3,\"id\":\"c\",\"function\":{\"name\":\"list_dir\",\"arguments\":\"{}\"}}]}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"a\\\"}\"}}]}}]}\n"
        "data: [DONE]\n";
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 7);

    CHECK_EQ_INT(st.ntc, 2, "two distinct calls");
    CHECK(strcmp(st.tcs[0].name, "execute_bash") == 0, "first call identified");
    CHECK(strcmp(st.tcs[0].args, "{\"command\":\"echo a\"}") == 0,
          "its arguments completed by the later delta, not the interleaved one");
    CHECK(strcmp(st.tcs[1].name, "list_dir") == 0, "second call identified");
    CHECK(strcmp(st.tcs[1].args, "{}") == 0, "second call arguments untouched");
    stream_state_free(&st);
}

/* A call whose name never arrived cannot be dispatched: running it as "?" would
 * hand the model a result for a tool it never asked for. */
static void test_nameless_tool_call_is_dropped(void) {
    TEST_BEGIN("stream: a tool call with no name is not fabricated into one");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"content\":\"text\"}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"{}\"}}]}}]}\n"
        "data: [DONE]\n";
    stream_state_t st;
    stream_state_init(&st);
    stream_feed(&st, sse, strlen(sse));
    cJSON *msg = stream_build_message(&st);
    CHECK(cJSON_GetObjectItem(msg, "tool_calls") == NULL,
          "no tool_calls array is emitted for a nameless call");
    const char *c = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "content"));
    CHECK(c && strcmp(c, "text") == 0, "the text of the same turn is still delivered");
    cJSON_Delete(msg);
    stream_state_free(&st);
}

/* --- robustness ----------------------------------------------------------- */
static void test_malformed_chunk_does_not_abort_the_stream(void) {
    TEST_BEGIN("stream: one unparseable chunk does not discard the reply");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"content\":\"before \"}}]}\n"
        "data: {this is not json\n"
        ": a comment line\n"
        "\n"
        "event: ping\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"after\"}}]}\n"
        "data: [DONE]\n";
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 5);
    CHECK(strcmp(st.content, "before after") == 0,
          "text on both sides of the bad chunk survives");
    CHECK(st.done == 1, "stream still completes");
    stream_state_free(&st);
}

/* A truncated stream is the case that used to cost the whole turn. The parser
 * must hand back what it has rather than nothing. */
static void test_truncated_stream_keeps_partial_content(void) {
    TEST_BEGIN("stream: an interrupted stream retains what already arrived");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial answer\"}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"cut";   /* dies mid-JSON */
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 4);
    CHECK(strcmp(st.content, "partial answer") == 0,
          "the completed part is available");
    CHECK(st.done == 0, "and it is known to be incomplete");
    CHECK(sdslen(st.pending) > 0, "the torn tail is held, not emitted");
    stream_state_free(&st);
}

static void test_crlf_and_no_space_after_data(void) {
    TEST_BEGIN("stream: CRLF line endings and \"data:\" without a space");
    const char *sse =
        "data:{\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\r\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"y\"}}]}\r\n"
        "data: [DONE]\r\n";
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 6);
    CHECK(strcmp(st.content, "xy") == 0, "both variants parsed");
    CHECK(st.done == 1, "[DONE] recognised with CRLF");
    stream_state_free(&st);
}

/* More tool calls than the fixed table holds must be reported, not silently
 * truncated into a turn that looks complete. */
static void test_tool_call_overflow_is_flagged(void) {
    TEST_BEGIN("stream: exceeding the tool-call table sets the overflow flag");
    stream_state_t st;
    stream_state_init(&st);
    char line[256];
    for (int i = 1; i <= ALPHA_STREAM_MAX_TOOLCALLS + 5; i++) {
        snprintf(line, sizeof(line),
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":%d,\"id\":\"i%d\","
            "\"function\":{\"name\":\"list_dir\",\"arguments\":\"{}\"}}]}}]}\n", i, i);
        stream_feed(&st, line, strlen(line));
    }
    CHECK_EQ_INT(st.ntc, ALPHA_STREAM_MAX_TOOLCALLS, "table filled to its limit");
    CHECK(st.overflow == 1, "overflow reported rather than passing silently");
    stream_state_free(&st);
}

/* The empty-content-but-tool-calls turn is the normal shape of a tool-using
 * reply; it must not be mistaken for an empty response. */
static void test_tool_only_turn_builds_a_valid_message(void) {
    TEST_BEGIN("stream: a tool-only turn yields content=null plus tool_calls");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"z\","
        "\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"/etc/hosts\\\"}\"}}]}}]}\n"
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n"
        "data: [DONE]\n";
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 11);
    CHECK_EQ_INT(sdslen(st.content), 0, "no text in this turn");
    CHECK_EQ_INT(st.ntc, 1, "but a tool call is present");

    cJSON *msg = stream_build_message(&st);
    CHECK(cJSON_IsNull(cJSON_GetObjectItem(msg, "content")),
          "content is null, as the API expects");
    const char *role = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "role"));
    CHECK(role && strcmp(role, "assistant") == 0, "role is assistant");
    cJSON *tcs = cJSON_GetObjectItem(msg, "tool_calls");
    CHECK(cJSON_IsArray(tcs) && cJSON_GetArraySize(tcs) == 1, "one tool_call emitted");
    cJSON *tc0 = cJSON_GetArrayItem(tcs, 0);
    const char *ty = cJSON_GetStringValue(cJSON_GetObjectItem(tc0, "type"));
    CHECK(ty && strcmp(ty, "function") == 0, "type is function");
    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(tc0, "id"));
    CHECK(id && strcmp(id, "z") == 0, "id preserved for tool_result pairing");
    cJSON_Delete(msg);
    stream_state_free(&st);
}

/* The request must actually ask for a stream -- everything above tests the
 * parser, which would pass even if the flag were never sent. */
static void test_request_body_enables_streaming(void) {
    TEST_BEGIN("stream: both request paths set stream:true");
    FILE *f = fopen("src/llm.c", "rb");
    CHECK(f != NULL, "llm.c readable");
    if (!f) return;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    /* Count rather than locate: with only "is there one after the first?" a
     * missing flag on the tools path was reported as the no-tools path
     * failing, which would send the next reader to the wrong branch. */
    int flags = 0;
    for (const char *p = buf; (p = strstr(p, "\\\"stream\\\":true")) != NULL; p++) flags++;
    CHECK_EQ_INT(flags, 2, "both request bodies (tools and no-tools) ask for streaming");
    /* A leftover total timeout would reintroduce the cliff streaming removes. */
    CHECK(strstr(buf, "CURLOPT_TIMEOUT,") == NULL,
          "no fixed total timeout remains on the LLM request");
    CHECK(strstr(buf, "CURLOPT_LOW_SPEED_TIME") != NULL,
          "a stall timeout is used instead");
}

int main(void) {
    test_content_is_independent_of_chunk_boundaries();
    test_utf8_survives_a_split_character();
    test_tool_call_arguments_accumulate();
    test_parallel_tool_calls_are_kept_separate();
    test_nameless_tool_call_is_dropped();
    test_malformed_chunk_does_not_abort_the_stream();
    test_truncated_stream_keeps_partial_content();
    test_crlf_and_no_space_after_data();
    test_tool_call_overflow_is_flagged();
    test_tool_only_turn_builds_a_valid_message();
    test_request_body_enables_streaming();
    return test_report("llm");
}
