#include "alpha.h"
#include <curl/curl.h>

typedef struct {
    sds body;
} curl_buf_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    curl_buf_t *b = userdata;
    size_t n = size * nmemb;
    b->body = sdscatlen(b->body, ptr, n);
    return n;
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
            "{\"model\":\"%s\",\"messages\":%s,"
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
    curl_buf_t buf = { .body = sdsempty() };
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    sds auth = sdscatprintf(sdsempty(), "Authorization: Bearer %s",
                            (cfg->api_key && cfg->api_key[0]) ? cfg->api_key : "none");
    hdrs = curl_slist_append(hdrs, auth);
    sdsfree(auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    /* Raised token caps mean longer generations; 45s cut off summaries mid-call. */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, with_tools ? 300L : 240L);
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

    if (rc != CURLE_OK) {
        sds err = sdscatprintf(sdsempty(), "ERROR curl: %s", curl_easy_strerror(rc));
        sdsfree(buf.body);
        if (out_failed) *out_failed = 1;
        return err;
    }
    if (http < 200 || http >= 300) {
        sds err = sdscatprintf(sdsempty(), "ERROR HTTP %ld: %s", http, buf.body);
        sdsfree(buf.body);
        if (out_failed) *out_failed = 1;
        return err;
    }

    cJSON *root = cJSON_Parse(buf.body);
    sdsfree(buf.body);
    if (!root) { if (out_failed) *out_failed = 1; return sdsnew("ERROR: bad JSON from LLM"); }

    cJSON *choices = cJSON_GetObjectItem(root, "choices");
    cJSON *c0 = cJSON_GetArrayItem(choices, 0);
    cJSON *msg = c0 ? cJSON_GetObjectItem(c0, "message") : NULL;
    if (!msg) {
        cJSON_Delete(root);
        if (out_failed) *out_failed = 1;
        return sdsnew("ERROR: no message in LLM response");
    }

    /* finish_reason == "length" means the reply was cut off mid-sentence.
     * This was silently ignored: the truncated text became the final answer and
     * the agent then reported a plausible-but-invented reason for stopping. */
    const char *fr = cJSON_GetStringValue(cJSON_GetObjectItem(c0, "finish_reason"));
    int truncated = (fr && strcmp(fr, "length") == 0);

    /* detach message for caller */
    cJSON *dup = cJSON_Duplicate(msg, 1);
    cJSON_Delete(root);
    if (out_message) *out_message = dup;

    const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(dup, "content"));
    sds out = sdsnew(content ? content : "");
    if (truncated) {
        fprintf(stderr, "[alpha] WARNING: reply hit the token cap and was truncated\n");
        out = sdscat(out,
            "\n\n[TRUNCATED: this reply hit the output token limit and stops "
            "mid-thought. It is incomplete \u2014 ask me to continue.]");
    }
    return out;
}

sds llm_chat(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message, int with_tools) {
    return llm_chat_ex(cfg, messages, out_message, with_tools, NULL);
}

