#include "alpha.h"

/* Continuous session + tools always available (the model chooses). */
static const char *SYSTEM_PROMPT =
    " You are Agent Alpha, a premier autonomous AI coding assistant written in pure C.\n"
    " You run natively on the user's Apple Silicon Metal GPU with a FULL 256,000 token (256k) context window\n"
    " and 8-bit quantized KV caching. Use your massive context capacity to the fullest: do not limit yourself\n"
    " to small tweaks. Ingest entire modules, compare multi-file architectures, and implement complete, robust,\n"
    " production-grade features and tools in pure C.\n"
    " \n"
    " TOOLS: execute_bash, read_file, write_file, edit_file, list_dir, web_search, browser, memory.\n"
    " Call a tool before claiming any disk or web work. Never report a result you\n"
    " did not observe. If a tool fails, say so and quote the error.\n"
    " You may call several tools at once; each gets its own result.\n"
    " \n"
    " WEB SEARCH vs BROWSER:\n"
    " - ALWAYS use `web_search` first for search queries, latest news, AI models, documentation, or lookups.\n"
    "   `web_search` is 10x faster (0.5s HTTP) and returns clean title/URL/snippets.\n"
    " - ONLY use `browser` when interacting with web apps, clicking buttons, filling forms, or accessing sites that require JavaScript.\n"
    "Browser steps must still be one at a time (snapshot before click).\n"
    "\n"
    "BROWSER: one sticky CDP tab, never spam new tabs.\n"
    "1) browser action=status or tabs if unsure\n"
    "2) browser action=open url=... (reuses the sticky tab)\n"
    "3) browser action=snapshot (read buttons/inputs BEFORE clicking)\n"
    "4) browser action=click text=... OR selector=... OR x/y\n"
    "5) browser action=type / fill / press / eval as needed\n"
    "6) browser action=close_others to clean up\n"
    "Click by text only matches short button/link labels, not body text.\n"
    "Never use execute_bash to click or type in the browser.\n"
    "Login / OAuth / captcha / 2FA: do open+snapshot+one click at most, then STOP and\n"
    "tell the user the exact manual step. Do not thrash ten browser turns.\n"
    "Quote TAB_ID / RESULT / AFTER_URL from tool output as proof; never invent it.\n"
    "NEVER ask for or store passwords. If the user pastes one, refuse to use it and\n"
    "tell them to rotate it.\n"
    "\n"
    "If a path or project does not exist and the user did not ask you to create it,\n"
    "report it missing and stop. Do not scaffold something just to claim success.\n"
    "Answer recall questions from the session text; no tools needed.\n"
    "Small talk: brief. Coding: inspect, edit, then show short proof.\n";
static void messages_add_text(cJSON *messages, const char *role, const char *text) {
    cJSON *m = cJSON_CreateObject();
    cJSON_AddStringToObject(m, "role", role);
    cJSON_AddStringToObject(m, "content", text ? text : "");
    cJSON_AddItemToArray(messages, m);
}

static cJSON *session_load(const char *path) {
    if (!path || !path[0]) return cJSON_CreateArray();
    FILE *f = fopen(path, "rb");
    if (!f) return cJSON_CreateArray();
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) {
        fclose(f);
        return cJSON_CreateArray();
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return cJSON_CreateArray();
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (!arr || !cJSON_IsArray(arr)) {
        if (arr) cJSON_Delete(arr);
        /* Unreadable history was silently replaced by an empty one, and the
         * next save then overwrote the damaged file for good. Keep a copy so
         * the conversation is recoverable, and say so. */
        char keep[PATH_MAX];
        snprintf(keep, sizeof(keep), "%s.corrupt", path);
        if (rename(path, keep) == 0)
            fprintf(stderr, "[alpha] session %s was unreadable; kept a copy at %s\n",
                    path, keep);
        else
            fprintf(stderr, "[alpha] session %s was unreadable and could not be saved\n",
                    path);
        return cJSON_CreateArray();
    }
    return arr;
}

/* Trim by bytes, not just message count: tool observations are now large, so a
 * fixed message cap no longer bounds the file (or the prompt) usefully. */
#define ALPHA_HISTORY_MAX_MSGS  60
#define ALPHA_HISTORY_MAX_BYTES 1000000

static size_t history_bytes(cJSON *history) {
    size_t total = 0;
    int n = cJSON_GetArraySize(history);
    for (int i = 0; i < n; i++) {
        const char *c = cJSON_GetStringValue(
            cJSON_GetObjectItem(cJSON_GetArrayItem(history, i), "content"));
        if (c) total += strlen(c);
    }
    return total;
}

/* Tool observations are only useful for the request that produced them. Kept
 * forever they dominate the session (measured: 170 KB of a 202 KB history) and
 * are re-uploaded on EVERY llm call, so a 27-turn request resent ~5 MB and burnt
 * its wall-clock budget on reconnaissance instead of work. Keep the most recent
 * few; older ones are superseded by the assistant's own summaries. */
#define ALPHA_KEEP_OBSERVATIONS 4

static int is_observation(cJSON *m) {
    const char *c = cJSON_GetStringValue(cJSON_GetObjectItem(m, "content"));
    return c && strncmp(c, "[tool observations", 18) == 0;
}

static void prune_observations(cJSON *history) {
    int n = cJSON_GetArraySize(history);
    int total = 0;
    for (int i = 0; i < n; i++)
        if (is_observation(cJSON_GetArrayItem(history, i))) total++;
    int drop = total - ALPHA_KEEP_OBSERVATIONS;
    for (int i = 0; i < cJSON_GetArraySize(history) && drop > 0; ) {
        if (is_observation(cJSON_GetArrayItem(history, i))) {
            cJSON_DeleteItemFromArray(history, i);
            drop--;
            continue;   /* indices shifted */
        }
        i++;
    }
}

static void session_save(const char *path, cJSON *history) {
    if (!path || !path[0] || !history) return;
    prune_observations(history);
    int n = cJSON_GetArraySize(history);
    while (n > ALPHA_HISTORY_MAX_MSGS) {
        cJSON_DeleteItemFromArray(history, 0);
        n--;
    }
    while (n > 2 && history_bytes(history) > ALPHA_HISTORY_MAX_BYTES) {
        cJSON_DeleteItemFromArray(history, 0);
        n--;
    }
    char *s = cJSON_PrintUnformatted(history);
    if (!s) return;
    /* Atomic: write to a temp file in the same dir, then rename. A crash
     * mid-write used to leave truncated JSON, which session_load silently
     * discarded — the whole chat history vanished with no error. */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (f) {
        size_t len = strlen(s);
        int ok = (fwrite(s, 1, len, f) == len);
        if (ok) ok = (fputc('\n', f) != EOF);
        if (ok) ok = (fflush(f) == 0);
        if (ok) ok = (fsync(fileno(f)) == 0);
        fclose(f);
        if (ok) rename(tmp, path);
        else unlink(tmp);
    }
    free(s);
}

void agent_session_clear(const char *session_path) {
    if (!session_path || !session_path[0]) return;
    unlink(session_path);
}

/* Keep a bounded digest of what the tools actually observed, so the next turn
 * still knows it (tool-role messages are not persisted in history). */
/* Budgets for what a turn's tool output contributes to persistent memory.
 * Kept as assistant text rather than real tool-role messages on purpose: a
 * trimmed history must never separate a tool_call from its tool_result, which
 * Anthropic-backed models reject outright. */
#define ALPHA_NOTE_PER_TOOL   4000
#define ALPHA_NOTE_TOTAL    200000

/* Replace invalid UTF-8 with U+FFFD in place.
 *
 * Truncating on a character boundary is not enough: a tool can emit bytes that
 * were never valid UTF-8 at all (a binary blob, a test printing raw control
 * bytes). Those went verbatim into the session file, which then failed to parse
 * and cost the whole conversation. Sanitise at the point of storage, since that
 * is the only place every tool result passes through. */
static sds sanitize_utf8(const char *s, size_t n) {
    sds out = sdsempty();
    size_t i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        int seq = c < 0x80 ? 1
                : (c & 0xE0) == 0xC0 ? 2
                : (c & 0xF0) == 0xE0 ? 3
                : (c & 0xF8) == 0xF0 ? 4 : -1;
        int ok = (seq > 0 && i + (size_t)seq <= n);
        for (int k = 1; ok && k < seq; k++)
            if (((unsigned char)s[i + k] & 0xC0) != 0x80) ok = 0;
        if (!ok) {
            out = sdscatlen(out, "\xef\xbf\xbd", 3);   /* U+FFFD */
            i++;
            continue;
        }
        out = sdscatlen(out, s + i, (size_t)seq);
        i += (size_t)seq;
    }
    return out;
}

static void notes_append(sds *notes, const char *name, const char *result) {
    if (!notes || !*notes) return;
    /* Budget exhausted. Say so once, otherwise a long run silently stops
     * recording and the model believes it remembers work it no longer has. */
    if (sdslen(*notes) > ALPHA_NOTE_TOTAL) {
        if (!strstr(*notes, "[NOTE BUDGET EXHAUSTED]"))
            *notes = sdscat(*notes,
                "[NOTE BUDGET EXHAUSTED] Later tool output in this turn was not "
                "retained. Re-run a tool rather than recalling it from memory.\n");
        return;
    }
    /* Work on a sanitised copy so neither branch below can store bad bytes. */
    sds clean = sanitize_utf8(result ? result : "", result ? strlen(result) : 0);
    result = clean;
    size_t full = sdslen(clean);
    size_t n = full;
    if (n > ALPHA_NOTE_PER_TOOL) n = ALPHA_NOTE_PER_TOOL;
    if (full > ALPHA_NOTE_PER_TOOL) {
        /* Keep both ends: the head identifies what ran, the tail usually holds
         * the result/exit status that actually matters. */
        size_t head = (size_t)(ALPHA_NOTE_PER_TOOL * 0.7);
        size_t tail = ALPHA_NOTE_PER_TOOL - head;
        /* Cutting at a fixed byte offset splits multi-byte characters, and the
         * broken bytes were written straight into the session file -- which
         * then failed to parse as UTF-8 and cost the whole conversation.
         * Pull each cut back to a character boundary. */
        while (head > 0 && ((unsigned char)result[head] & 0xC0) == 0x80) head--;
        while (tail > 0 && ((unsigned char)result[full - tail] & 0xC0) == 0x80) tail--;
        /* Say explicitly that the middle is GONE from memory, so a later turn
         * re-reads the source instead of confidently answering from a hole. */
        *notes = sdscatprintf(*notes,
            "[%s] %.*s\n"
            "…[%zu bytes NOT retained in memory — re-run this tool if you need them; "
            "do not answer about this gap from memory]…\n%.*s\n",
            name ? name : "tool", (int)head, result,
            full - ALPHA_NOTE_PER_TOOL, (int)tail, result + full - tail);
    } else {
        *notes = sdscatprintf(*notes, "[%s] %.*s\n",
                              name ? name : "tool", (int)n, result ? result : "");
    }
    sdsfree(clean);
}

/* The in-flight message array is resent in full on every LLM call, so its size
 * drives cost quadratically across a long request (measured: 10 MB per call by
 * turn 40, 216 MB cumulative). Only session_save() was bounded; nothing capped
 * the live array. Trim the oldest tool results, which are the bulk of it and
 * are already digested into tool_notes.
 *
 * The system prompt (index 0) and the most recent exchanges are never dropped. */
#define ALPHA_LIVE_MAX_BYTES 400000

/* Size of one message as it will appear on the wire. "content" is not the only
 * field that carries bulk: an assistant turn that calls write_file puts the
 * entire file body in tool_calls[].function.arguments and leaves content null.
 * Counting content alone reported 433 bytes for a 4 MB request, so the trim
 * below never fired and the call eventually exceeded the 300s curl cap. */
static size_t message_bytes(cJSON *m) {
    size_t t = 32;                          /* role/braces envelope */
    const char *c = cJSON_GetStringValue(cJSON_GetObjectItem(m, "content"));
    if (c) t += strlen(c);
    cJSON *tcs = cJSON_GetObjectItem(m, "tool_calls");
    if (cJSON_IsArray(tcs)) {
        cJSON *tc = NULL;
        cJSON_ArrayForEach(tc, tcs) {
            cJSON *fn = cJSON_GetObjectItem(tc, "function");
            const char *a = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "arguments"));
            if (a) t += strlen(a);
            t += 64;
        }
    }
    return t;
}

static size_t messages_bytes(cJSON *messages) {
    size_t t = 0;
    int n = cJSON_GetArraySize(messages);
    for (int i = 0; i < n; i++) t += message_bytes(cJSON_GetArrayItem(messages, i));
    return t;
}

static void trim_live_messages(cJSON *messages) {
    /* Walk forward from index 1 (keep the system prompt) and replace the oldest
     * oversized tool results with a stub. A tool message must stay present so
     * its tool_call_id still pairs with the assistant turn that requested it. */
    int n = cJSON_GetArraySize(messages);
    for (int i = 1; i < n - 6 && messages_bytes(messages) > ALPHA_LIVE_MAX_BYTES; i++) {
        cJSON *m = cJSON_GetArrayItem(messages, i);
        const char *role = cJSON_GetStringValue(cJSON_GetObjectItem(m, "role"));
        if (!role) continue;
        int is_tool = (strcmp(role, "tool") == 0);
        int is_asst = (strcmp(role, "assistant") == 0);
        if (!is_tool && !is_asst) continue;
        if (message_bytes(m) < 2000) continue;

        /* An assistant turn carrying tool_calls must keep its structure; only
         * its prose is replaced, never the message itself. */
        const char *s = cJSON_GetStringValue(cJSON_GetObjectItem(m, "content"));
        if (s && strlen(s) >= 2000)
            cJSON_ReplaceItemInObject(m, "content", cJSON_CreateString(
                is_tool
                  ? "[earlier tool output dropped to stay within the context budget — "
                    "re-run the tool if you need it again]"
                  : "[earlier reply abridged to stay within the context budget]"));

        /* The arguments of an already-executed call are dead weight: its result
         * is right below it. Stub them out, but keep parseable JSON so anything
         * that re-reads the history does not choke. */
        cJSON *tcs = cJSON_GetObjectItem(m, "tool_calls");
        if (cJSON_IsArray(tcs)) {
            cJSON *tc = NULL;
            cJSON_ArrayForEach(tc, tcs) {
                cJSON *fn = cJSON_GetObjectItem(tc, "function");
                if (!fn) continue;
                const char *a = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "arguments"));
                if (!a || strlen(a) < 2000) continue;
                cJSON_ReplaceItemInObject(fn, "arguments", cJSON_CreateString(
                    "{\"note\":\"arguments dropped to stay within the context budget\"}"));
            }
        }
    }
}

static sds run_tool_loop(alpha_cfg_t *cfg, cJSON *messages, sds *tool_notes) {
    sds last = sdsempty();
    /* Turns alone do not bound a request: 40 turns x (120s LLM + 60s tool) is
     * ~2 hours, during which this worker slot is unusable. Cap wall-clock too. */
    time_t deadline = time(NULL) + ALPHA_REQUEST_MAX_SECONDS;
    int max_turns = cfg->max_turns > 0 ? cfg->max_turns : 16;
    /* Hard ceiling only as a runaway guard. It used to be 20, below the
     * default of 24 from main.c, so ALPHA_MAX_TURNS silently did nothing. */
    if (max_turns > 200) max_turns = 200;
    int browser_turns = 0;
    int transport_fails = 0;
    int fmt_nudges = 0;

    const alpha_events_t *ev = cfg->events;

    for (int turn = 0; turn < max_turns; turn++) {
        if (alpha_cancel) break;
        if (ev && ev->on_turn) ev->on_turn(ev->ud, turn, max_turns);
        if (time(NULL) >= deadline) {
            messages_add_text(messages, "user",
                "[TIME LIMIT] This request has run too long. Stop calling tools and "
                "answer now in plain text with what you already found.");
            break;
        }
        trim_live_messages(messages);
        cJSON *msg = NULL;
        int failed = 0;
        sds content = NULL;
        /* Transient provider hiccups (rate limits, 5xx, dropped connections)
         * used to burn an entire turn or evolution generation. Retry only
         * clearly-transient errors -- config errors (401/404) would fail
         * identically on every attempt and just add latency. */
        for (int attempt = 0;; attempt++) {
            sdsfree(content);   /* NULL-safe: frees the previous failed attempt */
            msg = NULL;
            content = llm_chat_ex(cfg, messages, &msg,
                                  1 /* always tools available */, &failed);
            if (!failed || attempt >= 2) break;
            int transient = strstr(content, "HTTP 429") != NULL
                         || strstr(content, "HTTP 500") != NULL
                         || strstr(content, "HTTP 502") != NULL
                         || strstr(content, "HTTP 503") != NULL
                         || strstr(content, "HTTP 504") != NULL
                         || strstr(content, "cannot reach") != NULL
                         || strstr(content, "timed out") != NULL
                         || strstr(content, "empty response") != NULL
                         || strstr(content, "server aborted generation") != NULL;
            if (!transient) break;
            int backoff = 2 * (attempt + 1);
            fprintf(stderr, "[alpha] transient LLM error, retrying in %ds...\n",
                    backoff);
            sleep(backoff);
        }
        /* Only a real transport/HTTP/parse failure aborts. A model is allowed to
         * legitimately answer with text starting "ERROR: the build failed". */
        if (failed) {
            if (msg) cJSON_Delete(msg);
            sdsfree(last);
            return content;
        }
        /* Text-mode tool-call markup ("[Calling tool", "<invoke", "<tool_call>")
         * is a failed call leaked into prose. Leaving the fragment in the
         * conversation history teaches the model to imitate it — one leak
         * becomes a repetition loop (observed in evolution: turns degrade into
         * endless "[Calling tool" after a single leak). Detect it for the nudge
         * path below, then cut the fragment so history stays clean whether or
         * not real tool calls also arrived in the same reply. */
        int fmt_fail = 0;
        if (content) {
            const char *m1 = strstr(content, "[Calling tool");
            const char *m2 = strstr(content, "<invoke");
            const char *m3 = strstr(content, "<tool_call");
            const char *cut = m1;
            if (m2 && (!cut || m2 < cut)) cut = m2;
            if (m3 && (!cut || m3 < cut)) cut = m3;
            if (cut) {
                fmt_fail = 1;
                sdssetlen(content, (size_t)(cut - content));
                if (msg) {
                    cJSON *mc = cJSON_GetObjectItem(msg, "content");
                    if (cJSON_IsString(mc) && mc->valuestring) {
                        const char *k1 = strstr(mc->valuestring, "[Calling tool");
                        const char *k2 = strstr(mc->valuestring, "<invoke");
                        const char *k3 = strstr(mc->valuestring, "<tool_call");
                        const char *kcut = k1;
                        if (k2 && (!kcut || k2 < kcut)) kcut = k2;
                        if (k3 && (!kcut || k3 < kcut)) kcut = k3;
                        if (kcut) mc->valuestring[kcut - mc->valuestring] = '\0';
                    }
                }
            }
        }
        if (msg) cJSON_AddItemToArray(messages, msg);
        else messages_add_text(messages, "assistant", content);

        cJSON *tcs = msg ? cJSON_GetObjectItem(msg, "tool_calls") : NULL;
        int ntools = cJSON_IsArray(tcs) ? cJSON_GetArraySize(tcs) : 0;
        if (ntools <= 0) {
            /* Two text-only failure modes must not be accepted as a finished
             * answer — in both, nothing was executed:
             * (a) the model wrote its call as text markup (fmt_fail above);
             * (b) the reply hit the output token cap mid-call (the "[TRUNCATED"
             *     marker llm.c appends), leaving half a call as text.
             * Say the call never ran and let it retry — bounded, so a model
             * that cannot recover still gets to end its turn. */
            int truncated = content && strstr(content, "[TRUNCATED:");
            if (fmt_nudges < 3 && (fmt_fail || truncated)) {
                fmt_nudges++;
                if (!cfg->quiet)
                    fprintf(stderr, "[alpha] %s, nudging model to retry (turn %d)\n",
                            truncated ? "reply cut off at the token cap mid-call"
                                      : "tool call emitted as text",
                            turn);
                messages_add_text(messages, "user",
                    truncated
                    ? "[FORMAT ERROR] Your reply hit the output token limit and was cut "
                      "off before the tool call completed — nothing was executed. Keep "
                      "the reasoning SHORT and re-issue the tool call now. If you are "
                      "writing a file, split it: write_file the first part, then append "
                      "the rest with execute_bash 'cat >> file' chunks of at most ~150 "
                      "lines each."
                    : "[FORMAT ERROR] Your tool call was written as plain text and was "
                      "NOT executed — no tool ran. Re-issue it now as a real tool call "
                      "using the function-calling mechanism, not as text or markup. Do "
                      "NOT draft the file contents in your reply first — put them "
                      "directly in the tool arguments, in at most ~150 lines per call.");
                sdsfree(content);
                continue;
            }
            /* In self-evolution mode (ALPHA_EVOLVE=1), an evolutionary goal requires real code diff
             * and tests. If the model emits plain text without tools and diff is still empty, do NOT
             * terminate early — nudge the model to execute its tool call immediately! */
            const char *evolve_env = getenv("ALPHA_EVOLVE");
            if (evolve_env && evolve_env[0] && fmt_nudges < 4 && turn < cfg->max_turns - 2) {
                fmt_nudges++;
                if (!cfg->quiet)
                    fprintf(stderr, "[alpha] text-only reply in evolution mode without tools, prompting model to execute tools (turn %d)\n", turn);
                messages_add_text(messages, "user",
                    "[ACTION REQUIRED] You replied with conversational text, but you have NOT modified `src/tools.c` "
                    "or created `tests/custom/test_<name>.c` yet. Evolution requires real code + test diffs. "
                    "Do NOT reply with text alone. Invoke your tool calls NOW (`write_file`, `edit_file`, or `execute_bash`)!");
                sdsfree(content);
                continue;
            }
            sdsfree(last);
            last = content;
            break;
        }
        sdsfree(content);

        /* Every tool_call MUST get its own tool result message, in order.
         * Anthropic-backed models hard-reject
         * a request where a tool_use id has no matching tool_result. */
        int curl_dead = 0;
        for (int ti = 0; ti < ntools; ti++) {
            cJSON *tc = cJSON_GetArrayItem(tcs, ti);
            cJSON *fn = cJSON_GetObjectItem(tc, "function");
            const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "name"));
            const char *args_s = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "arguments"));
            const char *tid = cJSON_GetStringValue(cJSON_GetObjectItem(tc, "id"));
            cJSON *args = args_s ? cJSON_Parse(args_s) : cJSON_CreateObject();
            if (!args) args = cJSON_CreateObject();

            if (ev && ev->on_tool_start)
                ev->on_tool_start(ev->ud, name ? name : "?", args_s);
            else if (!cfg->quiet) {
                fprintf(stderr, "[alpha] tool %s (turn %d, %d/%d)\n",
                        name ? name : "?", turn, ti + 1, ntools);
                fflush(stderr);
            }
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            sds result = tools_run(name, args, cfg->cwd);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            cJSON_Delete(args);
            if (ev && ev->on_tool_end)
                ev->on_tool_end(ev->ud, name ? name : "?", result,
                                (double)(t1.tv_sec - t0.tv_sec) +
                                (double)(t1.tv_nsec - t0.tv_nsec) / 1e9);
            notes_append(tool_notes, name, result);

            cJSON *tr = cJSON_CreateObject();
            cJSON_AddStringToObject(tr, "role", "tool");
            if (tid) cJSON_AddStringToObject(tr, "tool_call_id", tid);
            cJSON_AddStringToObject(tr, "content", result);
            cJSON_AddItemToArray(messages, tr);

            /* Stop thrashing on browser login walls / long browser chains */
            if (name && (strcmp(name, "browser") == 0 || strcmp(name, "web_browser") == 0)) {
                browser_turns++;
                int wall = result && (
                    strstr(result, "accounts.google.com") ||
                    strstr(result, "signin") ||
                    strstr(result, "oauth") ||
                    strstr(result, "captcha") ||
                    strstr(result, "2FA") ||
                    strstr(result, "challenge")
                );
                if (browser_turns >= 6 || (wall && browser_turns >= 3)) {
                    messages_add_text(messages, "user",
                        "[BROWSER STOP] Enough browser steps. Summarize PROOF so far. "
                        "If login/OAuth/captcha/2FA needs the user, say the exact manual step. "
                        "Do NOT call more tools this turn.");
                }
            }
            /* Give up only if the tool itself keeps failing to reach anything.
             * Match the start of the result, not a substring: a file whose
             * contents merely mention "ERROR curl" must not kill the session. */
            if (result && strncmp(result, "ERROR curl", 10) == 0) {
                if (++transport_fails >= 3) {
                    sdsfree(last);
                    last = sdsdup(result);
                    curl_dead = 1;
                }
            } else {
                transport_fails = 0;
            }
            sdsfree(result);
            if (alpha_cancel) break;
        }
        if (curl_dead) break;
    }
    /* Interrupted: return what was produced rather than asking the model for a
     * summary, which would ignore the interrupt and start another request. */
    if (alpha_cancel) {
        if (!last || !last[0]) {
            if (last) sdsfree(last);
            return sdsnew("[interrupted]");
        }
        return last;
    }
    /* Turn budget exhausted while the model was still calling tools: the work
     * is done but no text was ever produced. Do NOT throw it away — ask once
     * more, without tools, so the user gets the findings instead of
     * "(no response)". */
    if (!last || !last[0]) {
        messages_add_text(messages, "user",
            "[TURN LIMIT] No more tool calls are possible. Answer now in plain text "
            "using what the tools already returned above. Do not call any tool.");
        cJSON *fmsg = NULL;
        int ffailed = 0;
        sds summary = llm_chat_ex(cfg, messages, &fmsg, 0 /* no tools */, &ffailed);
        if (fmsg) cJSON_Delete(fmsg);
        if (!ffailed && summary && summary[0]) {
            if (last) sdsfree(last);
            return summary;
        }
        sdsfree(summary);
    }
    if (!last || !last[0]) {
        if (last) sdsfree(last);
        return sdsnew("(no response)");
    }
    return last;
}

sds agent_run_session(alpha_cfg_t *cfg, const char *session_path, const char *user_text) {
    if (!cfg) return sdsnew("ERROR: no cfg");
    if (!user_text || !user_text[0]) return sdsnew("ERROR: empty user text");

    char cwd_buf[PATH_MAX];
    if (!cfg->cwd || !cfg->cwd[0]) {
        if (getcwd(cwd_buf, sizeof(cwd_buf))) cfg->cwd = cwd_buf;
        else cfg->cwd = ".";
    }

    alpha_cancel = 0;
    alpha_cfg_defaults(cfg);

    cJSON *history = session_load(session_path);
    cJSON *messages = cJSON_CreateArray();
    sds sys = sdscatprintf(sdsempty(),
        "%s\n[session cwd=%s model=%s tools=always-on]",
        SYSTEM_PROMPT, cfg->cwd, cfg->model ? cfg->model : "?");

    /* Inject persistent memory into the system prompt. This is a frozen
     * snapshot loaded at session start — mid-session writes update the files
     * on disk but do NOT change this prompt, preserving the prefix cache. */
    sds mem_block = memory_format_for_prompt("memory");
    sds user_block = memory_format_for_prompt("user");
    if (sdslen(mem_block)) {
        sys = sdscat(sys, "\n");
        sys = sdscatlen(sys, mem_block, sdslen(mem_block));
    }
    if (sdslen(user_block)) {
        sys = sdscat(sys, "\n");
        sys = sdscatlen(sys, user_block, sdslen(user_block));
    }
    sdsfree(mem_block);
    sdsfree(user_block);

    messages_add_text(messages, "system", sys);
    sdsfree(sys);

    int hn = cJSON_GetArraySize(history);
    for (int i = 0; i < hn; i++) {
        cJSON *h = cJSON_GetArrayItem(history, i);
        if (!cJSON_IsObject(h)) continue;
        const char *role = cJSON_GetStringValue(cJSON_GetObjectItem(h, "role"));
        const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(h, "content"));
        if (!role || !content) continue;
        if (strcmp(role, "user") && strcmp(role, "assistant")) continue;
        messages_add_text(messages, role, content);
    }
    messages_add_text(messages, "user", user_text);

    sds tool_notes = sdsempty();
    sds reply = run_tool_loop(cfg, messages, &tool_notes);

    messages_add_text(history, "user", user_text);
    if (sdslen(tool_notes)) {
        sds note = sdscatprintf(sdsempty(),
            "[tool observations from my last turn — real output, not guesses]\n%s", tool_notes);
        messages_add_text(history, "assistant", note);
        sdsfree(note);
    }
    sdsfree(tool_notes);
    messages_add_text(history, "assistant", reply ? reply : "");
    session_save(session_path, history);

    cJSON_Delete(messages);
    cJSON_Delete(history);
    return reply;
}

sds agent_run(alpha_cfg_t *cfg, const char *user_text) {
    return agent_run_session(cfg, NULL, user_text);
}
