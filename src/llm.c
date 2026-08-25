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
    sds reasoning;      /* accumulated chain-of-thought, where a model emits it */
    sds finish_reason;
    stream_tc_t tcs[ALPHA_STREAM_MAX_TOOLCALLS];
    int ntc;
    int done;           /* saw [DONE] */
    int overflow;       /* more tool calls than we can hold */
    const alpha_events_t *ev;   /* optional live callbacks */
} stream_state_t;

static void stream_state_init(stream_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->pending = sdsempty();
    st->content = sdsempty();
    st->reasoning = sdsempty();
    st->finish_reason = sdsempty();
}

static void stream_state_free(stream_state_t *st) {
    sdsfree(st->pending);
    sdsfree(st->content);
    sdsfree(st->reasoning);
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
        /* "delta" for a stream, "message" for a single JSON response: the same
         * accumulator serves both, so the non-streaming path (needed by servers
         * that cannot stream tool calls) is not a second parser to keep in
         * step with this one. */
        cJSON *delta = cJSON_GetObjectItem(c0, "delta");
        if (!delta) delta = cJSON_GetObjectItem(c0, "message");
        if (delta) {
            const char *c = cJSON_GetStringValue(cJSON_GetObjectItem(delta, "content"));
            if (c) {
                st->content = sdscat(st->content, c);
                if (st->ev && st->ev->on_text) st->ev->on_text(st->ev->ud, c);
            }
            /* Reasoning models put their scratchpad in a separate field, under
             * two different names depending on the provider. */
            const char *r = cJSON_GetStringValue(cJSON_GetObjectItem(delta, "reasoning_content"));
            if (!r) r = cJSON_GetStringValue(cJSON_GetObjectItem(delta, "reasoning"));
            if (r) {
                st->reasoning = sdscat(st->reasoning, r);
                if (st->ev && st->ev->on_reasoning) st->ev->on_reasoning(st->ev->ud, r);
            }

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

/* Non-streaming responses arrive as one JSON object rather than SSE lines, so
 * they are buffered whole and handed to the same payload parser. */
static size_t plain_write_cb(char *ptr, size_t size, size_t nmemb, void *ud) {
    stream_state_t *st = ud;
    st->pending = sdscatlen(st->pending, ptr, size * nmemb);
    return size * nmemb;
}

/* Ctrl-C during a long generation must abort the HTTP request, not wait for
 * the stall timeout. Returning non-zero from the progress callback does that. */
static int llm_progress_cb(void *ud, curl_off_t dt, curl_off_t dn,
                           curl_off_t ut, curl_off_t un) {
    (void)ud; (void)dt; (void)dn; (void)ut; (void)un;
    return alpha_cancel ? 1 : 0;
}

/* --- salvaging tool calls emitted as text ------------------------------------
 *
 * Local fine-tunes sometimes write a tool call as markup inside the content
 * instead of using the structured tool_calls channel (observed in production:
 * "<tool_call>{...}</tool_call>", Hermes-style "<invoke name=...>", and bare
 * "[Calling tool" repetition loops). The server passes that through as plain
 * text, and the agent loop would take "I am calling the tool" as the final
 * answer -- a turn that did nothing but believed it worked.
 *
 * Well-formed markup is recovered here into real tool calls. Bare "[Calling
 * tool" loops carry no payload and cannot be recovered; the agent loop nudges
 * the model to re-issue those. Only names from tools_schema() (plus the aliases
 * tools_run accepts) are honoured, so prose merely showing an example call can
 * never fire a real tool. */
static int salvage_name_known(const char *name) {
    if (!name || !name[0]) return 0;
    static const char *alias[] = { "bash", "ls", "web_browser", "diff", NULL };
    for (int i = 0; alias[i]; i++)
        if (strcmp(name, alias[i]) == 0) return 1;
    int found = 0;
    cJSON *schema = tools_schema();
    cJSON *t = NULL;
    cJSON_ArrayForEach(t, schema) {
        const char *n = cJSON_GetStringValue(cJSON_GetObjectItem(
            cJSON_GetObjectItem(t, "function"), "name"));
        if (n && strcmp(n, name) == 0) { found = 1; break; }
    }
    cJSON_Delete(schema);
    return found;
}

/* Extract name="..." (or name='...') from a tag starting at `tag`.
 * Returns a malloc'd name (caller frees) and advances *past to just after the
 * closing quote, or NULL when the attribute is absent/malformed. */
static char *salvage_tag_name(const char *tag, const char **past) {
    const char *p = strstr(tag, "name");
    if (!p) return NULL;
    p += 4;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '=') return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"' && *p != '\'') return NULL;
    char quote = *p++;
    const char *end = strchr(p, quote);
    if (!end || end == p) return NULL;
    char *name = strndup(p, (size_t)(end - p));
    if (past) *past = end + 1;
    return name;
}

static void salvage_add_call(stream_state_t *st, const char *name, const char *args) {
    if (st->ntc >= ALPHA_STREAM_MAX_TOOLCALLS) { st->overflow = 1; return; }
    stream_tc_t *t = &st->tcs[st->ntc];
    t->used = 1;
    t->index = 1000 + st->ntc;      /* cannot collide with a streamed index */
    t->id = sdsempty();
    t->name = sdsnew(name);
    t->args = sdsnew(args && args[0] ? args : "{}");
    st->ntc++;
}

/* Scan st->content for text-markup tool calls; move each valid one into the
 * tool-call table and out of the content. Content without valid markup is left
 * byte-identical. */
static void salvage_text_tool_calls(stream_state_t *st) {
    if (st->ntc > 0 || !st->content || !st->content[0]) return;

    sds kept = sdsempty();
    const char *c = st->content;
    size_t len = sdslen(st->content);
    size_t pos = 0;
    int salvaged = 0;

    while (pos < len) {
        const char *tc = strstr(c + pos, "<tool_call>");
        const char *iv = strstr(c + pos, "<invoke");
        const char *start = NULL;
        int kind = 0;               /* 1 = <tool_call> JSON, 2 = <invoke> XML */
        if (tc && (!iv || tc < iv)) { start = tc; kind = 1; }
        else if (iv) { start = iv; kind = 2; }
        if (!start) break;

        sds name = NULL;
        sds args = NULL;
        const char *block_end = NULL;   /* one past the closing tag */

        if (kind == 1) {
            const char *body = start + strlen("<tool_call>");
            const char *close = strstr(body, "</tool_call>");
            if (!close) break;          /* truncated markup: leave the text */
            sds raw = sdsnewlen(body, (size_t)(close - body));
            cJSON *call = cJSON_Parse(raw);
            sdsfree(raw);
            if (call) {
                const char *n = cJSON_GetStringValue(cJSON_GetObjectItem(call, "name"));
                cJSON *a = cJSON_GetObjectItem(call, "arguments");
                if (!a) a = cJSON_GetObjectItem(call, "parameters");
                if (n && salvage_name_known(n)) {
                    name = sdsnew(n);
                    if (cJSON_IsString(a)) args = sdsnew(a->valuestring);
                    else if (a) {
                        char *printed = cJSON_PrintUnformatted(a);
                        args = sdsnew(printed ? printed : "{}");
                        free(printed);
                    } else args = sdsnew("{}");
                }
                cJSON_Delete(call);
            }
            block_end = close + strlen("</tool_call>");
        } else {
            const char *past = NULL;
            char *n = salvage_tag_name(start, &past);
            const char *close = strstr(start, "</invoke>");
            if (n && close && salvage_name_known(n)) {
                name = sdsnew(n);
                cJSON *params = cJSON_CreateObject();
                const char *p = past;
                while (p < close) {
                    const char *pt = strstr(p, "<parameter");
                    if (!pt || pt >= close) break;
                    const char *kpast = NULL;
                    char *k = salvage_tag_name(pt, &kpast);
                    if (!k) break;
                    const char *vstart = strchr(kpast, '>');
                    const char *vend = vstart ? strstr(vstart, "</parameter>") : NULL;
                    if (!vstart || !vend || vend > close) { free(k); break; }
                    sds v = sdsnewlen(vstart + 1, (size_t)(vend - vstart - 1));
                    cJSON_AddStringToObject(params, k, v);
                    sdsfree(v);
                    free(k);
                    p = vend + strlen("</parameter>");
                }
                char *printed = cJSON_PrintUnformatted(params);
                args = sdsnew(printed ? printed : "{}");
                free(printed);
                cJSON_Delete(params);
            }
            free(n);
            if (!close) break;          /* truncated markup: leave the text */
            block_end = close + strlen("</invoke>");
        }

        if (name) {
            salvage_add_call(st, name, args);
            salvaged++;
            /* text between the previous block and this one stays */
            kept = sdscatlen(kept, c + pos, (size_t)(start - (c + pos)));
            pos = (size_t)(block_end - c);
        } else {
            /* not a usable call: keep the opening tag as text and move on */
            kept = sdscatlen(kept, c + pos, (size_t)(start - (c + pos)) + 1);
            pos = (size_t)(start - c) + 1;
        }
        sdsfree(name);
        sdsfree(args);
    }

    if (salvaged > 0) {
        kept = sdscatlen(kept, c + pos, len - pos);
        sdsfree(st->content);
        st->content = kept;
        fprintf(stderr, "[alpha] salvaged %d tool call(s) the model wrote as text markup\n",
                salvaged);
    } else {
        sdsfree(kept);
    }
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

/* Build the endpoint URL.
 *
 * Tolerates a trailing slash: ".../v1/" + "/chat/completions" is a 404 on every
 * server, and a trailing slash is the natural way to paste a URL. */
static sds build_url(const alpha_cfg_t *cfg) {
    const char *base = (cfg->base_url && cfg->base_url[0])
                     ? cfg->base_url : "http://localhost:11434/v1";
    size_t blen = strlen(base);
    while (blen > 0 && base[blen - 1] == '/') blen--;
    return sdscatprintf(sdsempty(), "%.*s/chat/completions", (int)blen, base);
}

/* Strip or replace bytes that are not valid UTF-8. The Ark coding endpoint
 * rejects the entire request body when any byte sequence is invalid UTF-8,
 * which happens when tool output contains binary data. Operates in-place. */
static void sanitize_utf8(sds s) {
    size_t i, j = 0;
    size_t len = sdslen(s);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x7F) {
            s[j++] = s[i];                     /* 1-byte (ASCII) */
        } else if (c >= 0xC2 && c <= 0xDF && i + 1 < len &&
                   (unsigned char)s[i+1] >= 0x80 && (unsigned char)s[i+1] <= 0xBF) {
            s[j++] = s[i++];                    /* 2-byte */
            s[j++] = s[i];
        } else if (c >= 0xE0 && c <= 0xEF && i + 2 < len &&
                   (unsigned char)s[i+1] >= 0x80 && (unsigned char)s[i+1] <= 0xBF &&
                   (unsigned char)s[i+2] >= 0x80 && (unsigned char)s[i+2] <= 0xBF) {
            s[j++] = s[i++];                    /* 3-byte */
            s[j++] = s[i++];
            s[j++] = s[i];
        } else if (c >= 0xF0 && c <= 0xF4 && i + 3 < len &&
                   (unsigned char)s[i+1] >= 0x80 && (unsigned char)s[i+1] <= 0xBF &&
                   (unsigned char)s[i+2] >= 0x80 && (unsigned char)s[i+2] <= 0xBF &&
                   (unsigned char)s[i+3] >= 0x80 && (unsigned char)s[i+3] <= 0xBF) {
            s[j++] = s[i++];                    /* 4-byte */
            s[j++] = s[i++];
            s[j++] = s[i++];
            s[j++] = s[i];
        } else {
            s[j++] = '?';                        /* invalid byte -> replacement */
        }
    }
    s[j] = 0;
    sdssetlen(s, j);
}

/* Build the request body. Separate from the transport so the suite can assert
 * what is actually sent for a given config -- the previous test grepped this
 * file for a literal `"stream":true`, which proved only that the string existed
 * somewhere, and went stale the moment the flag became configurable. */
static sds build_request_body(const alpha_cfg_t *cfg, cJSON *messages, int with_tools) {
    char *msgs_raw = cJSON_PrintUnformatted(messages);
    sds msgs_s = sdsnew(msgs_raw);
    free(msgs_raw);
    sanitize_utf8(msgs_s);
    const char *model = (cfg->model && cfg->model[0]) ? cfg->model : "local";
    int max_tokens = cfg->max_tokens > 0 ? cfg->max_tokens : 32768;
    double temp = cfg->temperature > 0.0 ? cfg->temperature : 0.2;
    int stream = cfg->stream;
    sds body;
    if (with_tools) {
        cJSON *tools = tools_schema();
        char *tools_s = cJSON_PrintUnformatted(tools);
        cJSON_Delete(tools);
        /* parallel_tool_calls is rejected outright by some OpenAI-compatible
         * servers, so it is only sent when actually wanted. */
        body = sdscatprintf(sdsempty(),
            "{\"model\":\"%s\",\"messages\":%s,\"tools\":%s,"
            "\"tool_choice\":\"auto\",%s"
            "\"stream\":%s,"
            "\"temperature\":%.2f,\"max_tokens\":%d}",
            model,
            msgs_s ? msgs_s : "[]",
            tools_s ? tools_s : "[]",
            cfg->parallel_tools ? "\"parallel_tool_calls\":true," : "",
            stream ? "true" : "false",
            temp, max_tokens);
        free(tools_s);
    } else {
        /* No-tools path: used for the [TURN LIMIT] summary, which is exactly
         * when the model has the most findings to report, so it gets the same
         * token budget rather than a token afterthought. */
        body = sdscatprintf(sdsempty(),
            "{\"model\":\"%s\",\"messages\":%s,\"stream\":%s,"
            "\"temperature\":%.2f,\"max_tokens\":%d}",
            model, msgs_s ? msgs_s : "[]", stream ? "true" : "false",
            temp + 0.2, max_tokens);
    }
    sdsfree(msgs_s);
    return body;
}

/* The Authorization header, or empty when there is no key.
 *
 * Local servers take no key at all, and several reject a placeholder outright,
 * so "none" and "" must both mean "send no header" rather than being passed
 * through as a literal credential. */
static sds build_auth_header(const alpha_cfg_t *cfg) {
    const char *k = cfg->api_key;
    if (!k || !k[0] || strcmp(k, "none") == 0) return sdsempty();
    return sdscatprintf(sdsempty(), "Authorization: Bearer %s", k);
}

sds llm_chat_ex(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message,
                int with_tools, int *out_failed) {
    if (out_message) *out_message = NULL;
    if (out_failed) *out_failed = 0;
    if (!cfg || !messages) { if (out_failed) *out_failed = 1; return sdsnew("ERROR: bad llm args"); }

    sds url = build_url(cfg);
    sds body = build_request_body(cfg, messages, with_tools);
    int stream = cfg->stream;

    CURL *curl = curl_easy_init();
    if (!curl) {
        sdsfree(url);
        sdsfree(body);
        if (out_failed) *out_failed = 1;
        return sdsnew("ERROR: curl init");
    }
    stream_state_t st;
    stream_state_init(&st);
    st.ev = cfg->events;
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    sds auth = build_auth_header(cfg);
    if (sdslen(auth)) {
        hdrs = curl_slist_append(hdrs, auth);
        /* Anthropic's own endpoint uses a different header; sending both is
         * harmless everywhere else and saves a provider special case here. */
        sds xk = sdscatprintf(sdsempty(), "x-api-key: %s", cfg->api_key);
        hdrs = curl_slist_append(hdrs, xk);
        sdsfree(xk);
        hdrs = curl_slist_append(hdrs, "anthropic-version: 2023-06-01");
    }
    sdsfree(auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                     stream ? stream_write_cb : plain_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &st);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, llm_progress_cb);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    if (stream) {
        /* No CURLOPT_TIMEOUT: with streaming, a long reply is not a failure.
         * What must be caught is a connection that has STOPPED producing, so
         * bound the silence instead -- under ALPHA_LLM_STALL_SECONDS of
         * throughput below one byte/s aborts. A healthy generation beats that. */
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, (long)ALPHA_LLM_STALL_SECONDS);
    } else {
        /* Without streaming there is nothing on the wire until generation
         * finishes, so a stall timeout would abort every healthy request. Only
         * a total cap is possible here -- one reason streaming is the default. */
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)ALPHA_LLM_NOSTREAM_SECONDS);
    }
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    /* shell_run spawns threads; libcurl's default alarm/longjmp DNS timeout is
     * not safe in a threaded process. */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode rc = curl_easy_perform(curl);
    if (!stream && rc == CURLE_OK) stream_handle_payload(&st, st.pending);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    sdsfree(body);

    /* A transport failure leaves http == 0. Reporting that as "HTTP 0" hid the
     * single most common first-run problem -- nothing listening at the URL --
     * behind a status code that does not exist, so transport is judged first. */
    if (rc != CURLE_OK && http == 0) {
        const char *hint = "";
        if (rc == CURLE_COULDNT_CONNECT)
            hint = "\nNothing is listening there. Start the local server, or set "
                   "--url / ALPHA_BASE_URL to a reachable endpoint.";
        else if (rc == CURLE_COULDNT_RESOLVE_HOST)
            hint = "\nThat hostname does not resolve. Check --url / ALPHA_BASE_URL.";
        sds err = sdscatprintf(sdsempty(), "ERROR: cannot reach %s: %s%s",
                               url, curl_easy_strerror(rc), hint);
        stream_state_free(&st);
        sdsfree(url);
        if (out_failed) *out_failed = 1;
        return err;
    }
    sdsfree(url);

    if (http < 200 || http >= 300) {
        /* An error body is not SSE, so it lands in `pending` unparsed. Say what
         * it usually means: at this point the user has just typed a base URL
         * and a model name, and those are the two things that go wrong. */
        const char *hint = "";
        if (http == 401 || http == 403)
            hint = "\nThe API key was rejected. Check ALPHA_API_KEY, or the "
                   "provider's own key variable.";
        else if (http == 404)
            hint = "\nEndpoint or model not found. Check ALPHA_BASE_URL (it must "
                   "end in /v1 for most servers) and ALPHA_MODEL.";
        else if (http == 429)
            hint = "\nRate limited by the provider. Wait, or use a local model.";
        sds err = sdscatprintf(sdsempty(), "ERROR HTTP %ld: %.500s%s", http, st.pending, hint);
        stream_state_free(&st);
        if (out_failed) *out_failed = 1;
        return err;
    }

    int partial = 0;
    if (rc == CURLE_ABORTED_BY_CALLBACK) {
        /* User interrupt, not a failure: keep whatever arrived. */
        if (sdslen(st.content) == 0 && st.ntc == 0) {
            stream_state_free(&st);
            if (out_failed) *out_failed = 1;
            return sdsnew("ERROR: interrupted");
        }
        partial = 1;
    } else if (rc != CURLE_OK) {
        /* Whatever arrived before the break is still real work. Discarding it
         * is what made a timeout cost the entire turn; keep it and label it. */
        if (sdslen(st.content) == 0 && st.ntc == 0) {
            const char *hint = "";
            if (rc == CURLE_COULDNT_CONNECT)
                hint = "\nNothing is listening at that address. Start the local "
                       "server, or set ALPHA_BASE_URL to a reachable one.";
            sds err = sdscatprintf(sdsempty(), "ERROR curl: %s%s",
                                   curl_easy_strerror(rc), hint);
            stream_state_free(&st);
            if (out_failed) *out_failed = 1;
            return err;
        }
        partial = 1;
        fprintf(stderr, "[alpha] stream interrupted (%s) after %zu bytes; keeping partial reply\n",
                curl_easy_strerror(rc), sdslen(st.content));
    }

    /* If content is empty but reasoning was streamed, promote it to prevent false empty response drops */
    if (sdslen(st.content) == 0 && sdslen(st.reasoning) > 0) {
        st.content = sdscat(st.content, st.reasoning);
    }

    /* A model that wrote its tool call as text markup gets one chance to be
     * understood anyway; bare "[Calling tool" loops carry no payload and are
     * left as text for the agent loop to reject. */
    if (with_tools && st.ntc == 0 && sdslen(st.content) > 0)
        salvage_text_tool_calls(&st);

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
        out = sdscat(out, alpha_cancel
            ? "\n\n[INTERRUPTED: stopped at your request \u2014 this is what had "
              "arrived so far.]"
            : "\n\n[INCOMPLETE: the connection to the model dropped mid-reply. "
              "This is what arrived before it stopped \u2014 ask me to continue.]");
    stream_state_free(&st);
    return out;
}

sds llm_chat(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message, int with_tools) {
    return llm_chat_ex(cfg, messages, out_message, with_tools, NULL);
}

