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

/* --- the request that is actually sent -------------------------------------
 *
 * Everything above tests the parser, which would pass even if the request were
 * never sent correctly. These build the real body from a config and read it
 * back as JSON, rather than grepping the source for a literal -- that only
 * proved a string existed somewhere in the file, and it went stale as soon as
 * the flag became configurable. */
static cJSON *build_body_json(const alpha_cfg_t *cfg, int with_tools) {
    cJSON *msgs = cJSON_CreateArray();
    cJSON *m = cJSON_CreateObject();
    cJSON_AddStringToObject(m, "role", "user");
    cJSON_AddStringToObject(m, "content", "hi");
    cJSON_AddItemToArray(msgs, m);
    sds body = build_request_body(cfg, msgs, with_tools);
    cJSON *parsed = cJSON_Parse(body);
    sdsfree(body);
    cJSON_Delete(msgs);
    return parsed;
}

static void test_request_body_reflects_the_config(void) {
    TEST_BEGIN("request: the body carries the configured model, limits and stream flag");

    alpha_cfg_t cfg = { .model = "qwen2.5-coder:7b", .stream = 1,
                        .max_tokens = 4096, .temperature = 0.7,
                        .parallel_tools = 1 };
    for (int with_tools = 0; with_tools <= 1; with_tools++) {
        cJSON *b = build_body_json(&cfg, with_tools);
        CHECK(b != NULL, "body is valid JSON");
        if (!b) return;
        const char *mdl = cJSON_GetStringValue(cJSON_GetObjectItem(b, "model"));
        CHECK(mdl && strcmp(mdl, "qwen2.5-coder:7b") == 0, "the configured model is sent");
        CHECK(cJSON_IsTrue(cJSON_GetObjectItem(b, "stream")),
              "streaming is requested on both the tools and no-tools paths");
        cJSON *mx = cJSON_GetObjectItem(b, "max_tokens");
        CHECK(cJSON_IsNumber(mx) && mx->valueint == 4096, "max_tokens honours the config");
        cJSON_Delete(b);
    }

    /* --no-stream must reach the wire, or the option silently does nothing. */
    cfg.stream = 0;
    cJSON *b = build_body_json(&cfg, 1);
    CHECK(cJSON_IsFalse(cJSON_GetObjectItem(b, "stream")),
          "stream:false is sent when streaming is disabled");
    cJSON_Delete(b);
}

static void test_tools_are_only_sent_when_wanted(void) {
    TEST_BEGIN("request: the tool schema is sent only on the tools path");
    alpha_cfg_t cfg = { .model = "m", .stream = 1, .parallel_tools = 1 };

    cJSON *with = build_body_json(&cfg, 1);
    cJSON *tools = cJSON_GetObjectItem(with, "tools");
    CHECK(cJSON_IsArray(tools) && cJSON_GetArraySize(tools) > 0, "tools present with_tools=1");
    CHECK(cJSON_IsTrue(cJSON_GetObjectItem(with, "parallel_tool_calls")),
          "parallel_tool_calls requested when enabled");
    cJSON_Delete(with);

    cJSON *without = build_body_json(&cfg, 0);
    CHECK(cJSON_GetObjectItem(without, "tools") == NULL,
          "no tool schema on the summary path");
    cJSON_Delete(without);

    /* Several OpenAI-compatible servers reject unknown keys outright, so this
     * one must be absent rather than false when it is not wanted. */
    cfg.parallel_tools = 0;
    cJSON *serial = build_body_json(&cfg, 1);
    CHECK(cJSON_GetObjectItem(serial, "parallel_tool_calls") == NULL,
          "parallel_tool_calls omitted entirely when disabled, not sent as false");
    cJSON_Delete(serial);
}

/* A trailing slash on the base URL is the single most likely thing a user gets
 * wrong, and it produces a 404 that looks like a wrong model name. */
static void test_url_construction(void) {
    TEST_BEGIN("request: the endpoint URL survives however the base is written");
    const char *bases[] = {
        "http://localhost:11434/v1",
        "http://localhost:11434/v1/",
        "http://localhost:11434/v1///",
    };
    for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
        alpha_cfg_t cfg = { .base_url = bases[i] };
        sds u = build_url(&cfg);
        if (strcmp(u, "http://localhost:11434/v1/chat/completions") != 0) {
            printf("  (base=%s -> %s)\n", bases[i], u);
            CHECK(0, "trailing slashes do not produce a doubled path");
            sdsfree(u);
            return;
        }
        sdsfree(u);
    }
    CHECK(1, "trailing slashes do not produce a doubled path");

    /* An empty config must still point somewhere usable rather than at a
     * malformed URL. */
    alpha_cfg_t empty = { 0 };
    sds u = build_url(&empty);
    CHECK(strstr(u, "/chat/completions") != NULL, "a default endpoint is still well formed");
    sdsfree(u);
}

/* Streaming removed the fixed total timeout; reintroducing one would restore
 * the cliff where a long reply was destroyed at the cap. */
static void test_no_total_timeout_on_the_streaming_path(void) {
    TEST_BEGIN("request: streaming uses a stall timeout, not a total one");
    FILE *f = fopen("src/llm.c", "rb");
    if (!f) f = fopen("../src/llm.c", "rb");
    CHECK(f != NULL, "llm.c readable");
    if (!f) return;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    CHECK(strstr(buf, "CURLOPT_LOW_SPEED_TIME") != NULL,
          "a stall timeout bounds the streaming path");
    /* A total cap is legitimate ONLY on the non-streaming path, where nothing
     * arrives until generation finishes and a stall timeout cannot work. */
    const char *t = strstr(buf, "CURLOPT_TIMEOUT,");
    CHECK(t == NULL || strstr(buf, "ALPHA_LLM_NOSTREAM_SECONDS") != NULL,
          "any total timeout is the non-streaming one");
}

/* Reasoning models emit their scratchpad in a separate field; it must not be
 * concatenated into the answer, which would put raw chain-of-thought in front
 * of the user and into the saved session. */
static void test_reasoning_is_kept_out_of_the_answer(void) {
    TEST_BEGIN("stream: reasoning_content is captured separately from content");
    const char *sse =
        "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"let me think\"}}]}\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"the answer\"}}]}\n"
        "data: [DONE]\n";
    stream_state_t st;
    stream_state_init(&st);
    feed_in_chunks(&st, sse, 5);
    CHECK(strcmp(st.content, "the answer") == 0, "the answer contains only the answer");
    CHECK(strcmp(st.reasoning, "let me think") == 0, "reasoning is available separately");
    cJSON *msg = stream_build_message(&st);
    const char *c = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "content"));
    CHECK(c && strcmp(c, "the answer") == 0, "and never leaks into the saved message");
    cJSON_Delete(msg);
    stream_state_free(&st);
}

/* A non-streaming response is one JSON object with "message" where a stream has
 * "delta". Both go through the same accumulator, so this proves the shared path
 * really handles the other shape. */
static void test_non_streaming_response_is_parsed(void) {
    TEST_BEGIN("request: a non-streaming response body is parsed by the same code");
    const char *json =
        "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"hello\","
        "\"tool_calls\":[{\"index\":0,\"id\":\"t1\",\"function\":"
        "{\"name\":\"list_dir\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}";
    stream_state_t st;
    stream_state_init(&st);
    stream_handle_payload(&st, json);
    CHECK(strcmp(st.content, "hello") == 0, "content read from message, not delta");
    CHECK_EQ_INT(st.ntc, 1, "tool calls read from a non-streamed message");
    /* Guarded: with the fallback removed, ntc is 0 and tcs[0].name is NULL, so
     * an unguarded strcmp segfaults. A sabotage must FAIL the suite, not crash
     * it -- a crash reports no diagnosis and no other check gets to run. */
    CHECK(st.ntc == 1 && st.tcs[0].name && strcmp(st.tcs[0].name, "list_dir") == 0,
          "with the right tool name");
    CHECK(strcmp(st.finish_reason, "tool_calls") == 0, "finish_reason observed");
    stream_state_free(&st);
}

/* Local servers take no key, and several reject a placeholder credential
 * outright. The header must be absent, not a literal "none".
 *
 * The first version of this test grepped llm.c for the string ": none" and
 * passed only because it matched a COMMENT -- a check that would have stayed
 * green with the bug present. It builds the header now. */
static void test_auth_header_is_conditional(void) {
    TEST_BEGIN("request: no Authorization header without a real key");

    const char *no_key[] = { NULL, "", "none" };
    for (size_t i = 0; i < sizeof(no_key) / sizeof(no_key[0]); i++) {
        alpha_cfg_t cfg = { .api_key = no_key[i] };
        sds h = build_auth_header(&cfg);
        if (sdslen(h) != 0) {
            printf("  (key=%s produced '%s')\n", no_key[i] ? no_key[i] : "NULL", h);
            CHECK(0, "an absent or placeholder key sends no header");
            sdsfree(h);
            return;
        }
        sdsfree(h);
    }
    CHECK(1, "an absent or placeholder key sends no header");

    alpha_cfg_t real = { .api_key = "sk-test123" };
    sds h = build_auth_header(&real);
    CHECK(strcmp(h, "Authorization: Bearer sk-test123") == 0,
          "a real key is sent as a bearer token");
    sdsfree(h);
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
    test_request_body_reflects_the_config();
    test_tools_are_only_sent_when_wanted();
    test_url_construction();
    test_no_total_timeout_on_the_streaming_path();
    test_reasoning_is_kept_out_of_the_answer();
    test_non_streaming_response_is_parsed();
    test_auth_header_is_conditional();
    return test_report("llm");
}
