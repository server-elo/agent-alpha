#include "alpha.h"
#include <curl/curl.h>

/* --- streaming ------------------------------------------------------------
 *
 * The response used to be collected whole, under a fixed CURLOPT_TIMEOUT. That
 * makes the cap a limit on TOTAL GENERATION TIME, which the model can legally
 * exceed: measured, a reply at the 16384-token cap takes ~262s of a 300s
 * budget, so any long answer sat 12% away from being destroyed -- and when it
 * died, every token the server had already produced was discarded and the user
 * got "ERROR curl: Timeout was reached" as the entire reply.
 *
 * Streaming turns that into a STALL timeout: as long as bytes keep arriving the
 * request is healthy however long it runs, and if the connection really dies
 * mid-reply the tokens received so far are still usable. */

/* One in-progress tool call, accumulated across chunks. The OpenAI streaming
 * format permits `arguments` to be split over many deltas (this proxy happens
 * to send each call whole, but that is not guaranteed and must not be relied
 * on), so fragments are appended by index rather than overwritten. */
typedef struct {
    int used;
    int index;
    sds id;
    sds name;
    sds args;
} stream_tc_t;

#define ALPHA_STREAM_MAX_TOOLCALLS 64

typedef struct {
    sds pending;        /* bytes not yet forming a complete line */
    sds content;        /* accumulated assistant text */
    sds finish_reason;
    stream_tc_t tcs[ALPHA_STREAM_MAX_TOOLCALLS];
    int ntc;
    int done;           /* saw [DONE] */
    int overflow;       /* more tool calls than we can hold */
} stream_state_t;

static void stream_state_init(stream_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->pending = sdsempty();
    st->content = sdsempty();
    st->finish_reason = sdsempty();
}

static void stream_state_free(stream_state_t *st) {
    sdsfree(st->pending);
    sdsfree(st->content);
    sdsfree(st->finish_reason);
    for (int i = 0; i < st->ntc; i++) {
        sdsfree(st->tcs[i].id);
        sdsfree(st->tcs[i].name);
        sdsfree(st->tcs[i].args);
    }
}

/* Find the slot for a streamed tool call.
 *
 * `index` identifies the call within the turn. It is NOT an array position:
 * this proxy emits 1-based indices, and a provider may skip or reorder them.
 * So slots are matched on the index value and appended in arrival order. */
static stream_tc_t *stream_tc_slot(stream_state_t *st, int index) {
    for (int i = 0; i < st->ntc; i++)
        if (st->tcs[i].used && st->tcs[i].index == index) return &st->tcs[i];
    if (st->ntc >= ALPHA_STREAM_MAX_TOOLCALLS) { st->overflow = 1; return NULL; }
    stream_tc_t *t = &st->tcs[st->ntc++];
    t->used = 1;
    t->index = index;
    t->id = sdsempty();
    t->name = sdsempty();
    t->args = sdsempty();
    return t;
}

/* Consume one `data: {...}` payload. */
static void stream_handle_payload(stream_state_t *st, const char *payload) {
    if (strcmp(payload, "[DONE]") == 0) { st->done = 1; return; }
    cJSON *root = cJSON_Parse(payload);
    if (!root) return;   /* a malformed chunk must not abort a good stream */

    cJSON *choices = cJSON_GetObjectItem(root, "choices");
    cJSON *c0 = cJSON_GetArrayItem(choices, 0);
    if (c0) {
        const char *fr = cJSON_GetStringValue(cJSON_GetObjectItem(c0, "finish_reason"));
        if (fr) {
            sdsfree(st->finish_reason);
            st->finish_reason = sdsnew(fr);
        }
        cJSON *delta = cJSON_GetObjectItem(c0, "delta");
        if (delta) {
            const char *c = cJSON_GetStringValue(cJSON_GetObjectItem(delta, "content"));
            if (c) st->content = sdscat(st->content, c);

            cJSON *tcs = cJSON_GetObjectItem(delta, "tool_calls");
            if (cJSON_IsArray(tcs)) {
                cJSON *tc = NULL;
                cJSON_ArrayForEach(tc, tcs) {
                    cJSON *idx = cJSON_GetObjectItem(tc, "index");
                    stream_tc_t *slot = stream_tc_slot(
                        st, cJSON_IsNumber(idx) ? idx->valueint : 0);
                    if (!slot) continue;
                    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(tc, "id"));
                    if (id) { sdsfree(slot->id); slot->id = sdsnew(id); }
                    cJSON *fn = cJSON_GetObjectItem(tc, "function");
                    if (fn) {
                        const char *nm = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "name"));
                        if (nm) { sdsfree(slot->name); slot->name = sdsnew(nm); }
                        const char *a = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "arguments"));
                        if (a) slot->args = sdscat(slot->args, a);
                    }
                }
            }
        }
    }
    cJSON_Delete(root);
}

/* Feed raw socket bytes; extract complete SSE lines.
 *
 * A chunk boundary can fall anywhere, including inside a UTF-8 character or
 * mid-JSON, so incomplete data is held in `pending` until its newline arrives. */
static void stream_feed(stream_state_t *st, const char *data, size_t n) {
    st->pending = sdscatlen(st->pending, data, n);
    for (;;) {
        char *nl = strchr(st->pending, '\n');
        if (!nl) break;
        size_t linelen = (size_t)(nl - st->pending);
        sds line = sdsnewlen(st->pending, linelen);
        sdsrange(st->pending, (ssize_t)(linelen + 1), -1);
        /* tolerate CRLF */
        size_t ll = sdslen(line);
        while (ll && (line[ll - 1] == '\r' || line[ll - 1] == ' ')) line[--ll] = 0;
        sdssetlen(line, ll);
        if (ll > 6 && strncmp(line, "data: ", 6) == 0)
            stream_handle_payload(st, line + 6);
        else if (ll > 5 && strncmp(line, "data:", 5) == 0)
            stream_handle_payload(st, line + 5);
        sdsfree(line);
    }
}

static size_t stream_write_cb(char *ptr, size_t size, size_t nmemb, void *ud) {
    stream_feed((stream_state_t *)ud, ptr, size * nmemb);
    return size * nmemb;
}

/* Rebuild the non-streaming `message` object the rest of the agent expects, so
 * streaming stays entirely inside this file. */
static cJSON *stream_build_message(stream_state_t *st) {
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "role", "assistant");
    if (sdslen(st->content))
        cJSON_AddStringToObject(msg, "content", st->content);
    else
        cJSON_AddNullToObject(msg, "content");
    if (st->ntc > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < st->ntc; i++) {
            stream_tc_t *t = &st->tcs[i];
            /* A call with no name is unusable: it would be dispatched as tool
             * "?" and the model would receive a result for something it never
             * asked for. Drop it rather than fabricate one. */
            if (!t->used || !sdslen(t->name)) continue;
            cJSON *tc = cJSON_CreateObject();
            cJSON_AddStringToObject(tc, "id", sdslen(t->id) ? t->id : "call_0");
            cJSON_AddStringToObject(tc, "type", "function");
            cJSON *fn = cJSON_CreateObject();
            cJSON_AddStringToObject(fn, "name", t->name);
            cJSON_AddStringToObject(fn, "arguments", sdslen(t->args) ? t->args : "{}");
            cJSON_AddItemToObject(tc, "function", fn);
            cJSON_AddItemToArray(arr, tc);
        }
        if (cJSON_GetArraySize(arr) > 0) cJSON_AddItemToObject(msg, "tool_calls", arr);
        else cJSON_Delete(arr);
    }
    return msg;
}

sds llm_chat_ex(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message,
                int with_tools, int *out_failed) {
    if (out_message) *out_message = NULL;
    if (out_failed) *out_failed = 0;
    if (!cfg || !messages) { if (out_failed) *out_failed = 1; return sdsnew("ERROR: bad llm args"); }

    char *msgs_s = cJSON_PrintUnformatted(messages);
    sds url = sdscatprintf(sdsempty(), "%s/chat/completions",
                           cfg->base_url ? cfg->base_url : "http://127.0.0.1:8317/v1");
    sds body;
    if (with_tools) {
        cJSON *tools = tools_schema();
        char *tools_s = cJSON_PrintUnformatted(tools);
        cJSON_Delete(tools);
        body = sdscatprintf(sdsempty(),
            "{\"model\":\"%s\",\"messages\":%s,\"tools\":%s,"
            "\"tool_choice\":\"auto\",\"parallel_tool_calls\":true,"
            "\"stream\":true,"
            "\"temperature\":0.2,\"max_tokens\":16384}",
            cfg->model ? cfg->model : "claude-opus-5",
            msgs_s ? msgs_s : "[]",
            tools_s ? tools_s : "[]");
        free(tools_s);
    } else {
        /* No-tools path: only used for the [TURN LIMIT] summary, which is
         * exactly when the model has the most findings to report. 400 tokens
         * cut those answers off mid-sentence. */
        body = sdscatprintf(sdsempty(),
            "{\"model\":\"%s\",\"messages\":%s,\"stream\":true,"
            "\"temperature\":0.4,\"max_tokens\":8192}",
            cfg->model ? cfg->model : "claude-opus-5",
            msgs_s ? msgs_s : "[]");
    }
    free(msgs_s);

    CURL *curl = curl_easy_init();
    if (!curl) {
        sdsfree(url);
        sdsfree(body);
        if (out_failed) *out_failed = 1;
        return sdsnew("ERROR: curl init");
    }
    stream_state_t st;
    stream_state_init(&st);
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    sds auth = sdscatprintf(sdsempty(), "Authorization: Bearer %s",
                            (cfg->api_key && cfg->api_key[0]) ? cfg->api_key : "none");
    hdrs = curl_slist_append(hdrs, auth);
    sdsfree(auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &st);
    /* No CURLOPT_TIMEOUT: with streaming, a long reply is not a failure. What
     * must be caught is a connection that has STOPPED producing, so bound the
     * silence instead -- under ALPHA_LLM_STALL_SECONDS of throughput below one
     * byte/s aborts. A healthy generation always beats that. */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, (long)ALPHA_LLM_STALL_SECONDS);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    /* shell_run spawns threads; libcurl's default alarm/longjmp DNS timeout is
     * not safe in a threaded process. */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    sdsfree(url);
    sdsfree(body);

    if (http < 200 || http >= 300) {
        /* An error body is not SSE, so it lands in `pending` unparsed. */
        sds err = sdscatprintf(sdsempty(), "ERROR HTTP %ld: %.500s", http, st.pending);
        stream_state_free(&st);
        if (out_failed) *out_failed = 1;
        return err;
    }

    int partial = 0;
    if (rc != CURLE_OK) {
        /* Whatever arrived before the break is still real work. Discarding it
         * is what made a timeout cost the entire turn; keep it and label it. */
        if (sdslen(st.content) == 0 && st.ntc == 0) {
            sds err = sdscatprintf(sdsempty(), "ERROR curl: %s", curl_easy_strerror(rc));
            stream_state_free(&st);
            if (out_failed) *out_failed = 1;
            return err;
        }
        partial = 1;
        fprintf(stderr, "[alpha] stream interrupted (%s) after %zu bytes; keeping partial reply\n",
                curl_easy_strerror(rc), sdslen(st.content));
    }

    if (sdslen(st.content) == 0 && st.ntc == 0) {
        stream_state_free(&st);
        if (out_failed) *out_failed = 1;
        return sdsnew("ERROR: empty response from LLM");
    }

    /* finish_reason == "length" means the reply was cut off mid-sentence.
     * This was silently ignored: the truncated text became the final answer and
     * the agent then reported a plausible-but-invented reason for stopping. */
    int truncated = (strcmp(st.finish_reason, "length") == 0);

    cJSON *msg = stream_build_message(&st);
    if (out_message) *out_message = msg;
    else cJSON_Delete(msg);

    sds out = sdsnew(st.content);
    if (st.overflow)
        fprintf(stderr, "[alpha] WARNING: more than %d tool calls in one turn; extras dropped\n",
                ALPHA_STREAM_MAX_TOOLCALLS);
    if (truncated) {
        fprintf(stderr, "[alpha] WARNING: reply hit the token cap and was truncated\n");
        out = sdscat(out,
            "\n\n[TRUNCATED: this reply hit the output token limit and stops "
            "mid-thought. It is incomplete \u2014 ask me to continue.]");
    }
    if (partial)
        out = sdscat(out,
            "\n\n[INCOMPLETE: the connection to the model dropped mid-reply. "
            "This is what arrived before it stopped \u2014 ask me to continue.]");
    stream_state_free(&st);
    return out;
}

sds llm_chat(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message, int with_tools) {
    return llm_chat_ex(cfg, messages, out_message, with_tools, NULL);
}

