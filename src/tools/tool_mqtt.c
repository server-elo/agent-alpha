/* tool_mqtt.c — MQTT Topic Filter Engine ported from arendst/Tasmota
 * Covers: tasmota MQTT topic handling (MQTT spec §4.7), wildcard matching,
 * topic/filter validation, and multi-filter routing. Inspired by Tasmota's
 * extensive MQTT usage (my_user_config.h PROJECT/topic, GroupTopic, rule
 * triggers) and Berry/MQTT dispatch.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>

#define MQTT_MAX_TOPIC_LEN 65535
#define MQTT_MAX_LEVELS    128
#define MQTT_MAX_FILTERS   32

/* overflow-safe: returns 1 if a+b would overflow size_t */
static int sz_add_overflow(size_t a, size_t b) {
    return a > SIZE_MAX - b;
}
/* overflow-safe bounds check for topic length */
static int topic_len_ok(size_t len, size_t extra) {
    if (sz_add_overflow(len, extra)) return 0;
    return (len + extra) <= (size_t)MQTT_MAX_TOPIC_LEN;
}

/* validate that string contains only allowed MQTT chars:
 * printable ASCII 0x20-0x7E except NUL, and no control chars.
 * For topic: '+' and '#' are forbidden. For filter: they are allowed
 * only as standalone levels.
 * Returns NULL on success, error message otherwise.
 */
static const char *validate_mqtt_chars(const char *s, int is_filter) {
    if (!s) return "NULL pointer";
    size_t len = strlen(s);
    if (len == 0) return "empty string";
    if (len > (size_t)MQTT_MAX_TOPIC_LEN) return "exceeds max topic length";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0) return "contains NUL";
        if (c < 0x20 || c > 0x7E) return "contains non-printable or non-ASCII";
        if (!is_filter && (c == '+' || c == '#')) return "topic must not contain wildcards +/#";
        if (c == 0x7F) return "contains DEL";
    }
    return NULL;
}

/* Validate filter wildcard placement per MQTT 3.1.1 §4.7.1 */
static const char *validate_filter_wildcards(const char *filter) {
    size_t len = strlen(filter);
    /* empty already rejected */
    size_t start = 0;
    int level = 0;
    int found_hash = 0;
    for (size_t i = 0; i <= len; i++) {
        int is_sep = (i == len || filter[i] == '/');
        if (!is_sep) continue;
        size_t lpos = start;
        size_t llen = i - start;
        level++;
        if (level > MQTT_MAX_LEVELS) return "too many levels";
        if (llen == 0) {
            /* empty level is allowed (e.g. "a//b" or leading/trailing slash) */
        } else if (llen == 1 && filter[lpos] == '#') {
            if (i != len) return "'#' must be last level";
            found_hash = 1;
        } else if (llen == 1 && filter[lpos] == '+') {
            /* ok */
            if (found_hash) return "'#' must be last";
        } else {
            /* multi-char level must not contain wildcards */
            for (size_t j = lpos; j < lpos + llen; j++) {
                if (filter[j] == '+' || filter[j] == '#')
                    return "wildcards must occupy entire level";
            }
        }
        start = i + 1;
    }
    (void)found_hash;
    return NULL;
}

static const char *validate_topic_str(const char *topic) {
    const char *e = validate_mqtt_chars(topic, 0);
    if (e) return e;
    /* topic must not be empty level edge? allow "/" per spec but not empty string already */
    /* MQTT spec: topic must not contain wildcards — already checked */
    /* Check levels count */
    size_t len = strlen(topic);
    int levels = 1;
    for (size_t i = 0; i < len; i++) if (topic[i] == '/') {
        if (sz_add_overflow((size_t)levels, 1)) return "too many levels";
        levels++;
    }
    if (levels > MQTT_MAX_LEVELS) return "too many levels";
    return NULL;
}

static const char *validate_filter_str(const char *filter) {
    const char *e = validate_mqtt_chars(filter, 1);
    if (e) return e;
    return validate_filter_wildcards(filter);
}

/* Split string by '/' into levels. Returns number of levels, fills out arrays.
 * Caller provides storage for pointers/lens. Does not allocate.
 * Handles empty levels and trailing slash.
 */
static int split_levels(const char *s, const char **out_ptr, size_t *out_len, int max_levels) {
    size_t len = strlen(s);
    int n = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || s[i] == '/') {
            if (n >= max_levels) return -1;
            out_ptr[n] = s + start;
            out_len[n] = i - start;
            n++;
            start = i + 1;
        }
    }
    return n;
}

static int level_eq(const char *a, size_t alen, const char *b, size_t blen) {
    if (alen != blen) return 0;
    return memcmp(a, b, alen) == 0;
}

/* MQTT filter matching per spec */
static int mqtt_match_levels(const char **t_ptr, size_t *t_len, int t_n,
                             const char **f_ptr, size_t *f_len, int f_n) {
    int ti = 0, fi = 0;
    while (fi < f_n) {
        /* '#' matches remaining topic levels (including zero levels if filter ends with /# ?) */
        if (f_len[fi] == 1 && f_ptr[fi][0] == '#') {
            return 1; /* '#' is always last, validated */
        }
        if (ti >= t_n) return 0; /* topic exhausted but filter still has non-# levels */
        if (f_len[fi] == 1 && f_ptr[fi][0] == '+') {
            /* matches any single level including empty */
            ti++; fi++;
            continue;
        }
        if (!level_eq(t_ptr[ti], t_len[ti], f_ptr[fi], f_len[fi])) return 0;
        ti++; fi++;
    }
    return ti == t_n;
}

static int mqtt_match(const char *topic, const char *filter) {
    const char *t_ptr[MQTT_MAX_LEVELS];
    size_t t_len[MQTT_MAX_LEVELS];
    const char *f_ptr[MQTT_MAX_LEVELS];
    size_t f_len[MQTT_MAX_LEVELS];
    int t_n = split_levels(topic, t_ptr, t_len, MQTT_MAX_LEVELS);
    int f_n = split_levels(filter, f_ptr, f_len, MQTT_MAX_LEVELS);
    if (t_n < 0 || f_n < 0) return 0;
    return mqtt_match_levels(t_ptr, t_len, t_n, f_ptr, f_len, f_n);
}

static sds tool_mqtt_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "match";

    /* Common numeric validation helper */
    cJSON *max_lv = cJSON_GetObjectItem(args, "max_levels");
    if (cJSON_IsNumber(max_lv)) {
        double d = max_lv->valuedouble;
        if (d < 0) return sdsnew("ERROR: max_levels must be non-negative");
        if (d > (double)MQTT_MAX_LEVELS) return sdscatprintf(sdsempty(), "ERROR: max_levels exceeds %d", MQTT_MAX_LEVELS);
        /* overflow-safe bounds subtraction check example: ensure max_levels leaves room */
        long ml = (long)d;
        if (ml < 0) return sdsnew("ERROR: max_levels negative");
        if ((size_t)ml > SIZE_MAX - 16) return sdsnew("ERROR: max_levels overflow");
    }

    if (strcmp(action, "match") == 0) {
        const char *topic = cJSON_GetStringValue(cJSON_GetObjectItem(args, "topic"));
        const char *filter = cJSON_GetStringValue(cJSON_GetObjectItem(args, "filter"));
        if (!topic) return sdsnew("ERROR: 'topic' parameter required for match");
        if (!filter) return sdsnew("ERROR: 'filter' parameter required for match");
        const char *te = validate_topic_str(topic);
        if (te) return sdscatprintf(sdsempty(), "{\"action\":\"match\",\"error\":\"invalid topic: %s\"}", te);
        const char *fe = validate_filter_str(filter);
        if (fe) return sdscatprintf(sdsempty(), "{\"action\":\"match\",\"error\":\"invalid filter: %s\"}", fe);
        int m = mqtt_match(topic, filter);
        return sdscatprintf(sdsempty(), "{\"action\":\"match\",\"topic\":\"%s\",\"filter\":\"%s\",\"match\":%s}",
            topic, filter, m ? "true" : "false");
    }

    if (strcmp(action, "validate_topic") == 0) {
        const char *topic = cJSON_GetStringValue(cJSON_GetObjectItem(args, "topic"));
        if (!topic) {
            /* also accept generic "value" param */
            topic = cJSON_GetStringValue(cJSON_GetObjectItem(args, "value"));
        }
        if (!topic) return sdsnew("ERROR: 'topic' parameter required for validate_topic");
        /* character set validation */
        size_t len = strlen(topic);
        /* overflow-safe length check */
        if (!topic_len_ok(len, 0)) return sdsnew("{\"action\":\"validate_topic\",\"valid\":false,\"error\":\"exceeds max length\"}");
        /* charset check: reject control chars */
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)topic[i];
            if (c < 0x20 || c > 0x7E) {
                return sdscatprintf(sdsempty(), "{\"action\":\"validate_topic\",\"valid\":false,\"error\":\"invalid charset at pos %zu\"}", i);
            }
        }
        const char *e = validate_topic_str(topic);
        if (e) return sdscatprintf(sdsempty(), "{\"action\":\"validate_topic\",\"valid\":false,\"error\":\"%s\"}", e);
        return sdscatprintf(sdsempty(), "{\"action\":\"validate_topic\",\"valid\":true,\"topic\":\"%s\"}", topic);
    }

    if (strcmp(action, "validate_filter") == 0) {
        const char *filter = cJSON_GetStringValue(cJSON_GetObjectItem(args, "filter"));
        if (!filter) filter = cJSON_GetStringValue(cJSON_GetObjectItem(args, "value"));
        if (!filter) return sdsnew("ERROR: 'filter' parameter required for validate_filter");
        size_t len = strlen(filter);
        if (!topic_len_ok(len, 0)) return sdsnew("{\"action\":\"validate_filter\",\"valid\":false,\"error\":\"exceeds max length\"}");
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)filter[i];
            if (c < 0x20 || c > 0x7E) {
                return sdscatprintf(sdsempty(), "{\"action\":\"validate_filter\",\"valid\":false,\"error\":\"invalid charset at pos %zu\"}", i);
            }
        }
        const char *e = validate_filter_str(filter);
        if (e) return sdscatprintf(sdsempty(), "{\"action\":\"validate_filter\",\"valid\":false,\"error\":\"%s\"}", e);
        return sdscatprintf(sdsempty(), "{\"action\":\"validate_filter\",\"valid\":true,\"filter\":\"%s\"}", filter);
    }

    if (strcmp(action, "route") == 0) {
        const char *topic = cJSON_GetStringValue(cJSON_GetObjectItem(args, "topic"));
        if (!topic) return sdsnew("ERROR: 'topic' parameter required for route");
        cJSON *filters = cJSON_GetObjectItem(args, "filters");
        if (!cJSON_IsArray(filters)) return sdsnew("ERROR: 'filters' array parameter required for route");
        const char *te = validate_topic_str(topic);
        if (te) return sdscatprintf(sdsempty(), "{\"action\":\"route\",\"error\":\"invalid topic: %s\"}", te);
        int n = cJSON_GetArraySize(filters);
        if (n < 0) return sdsnew("ERROR: invalid filters array");
        if (n > MQTT_MAX_FILTERS) return sdscatprintf(sdsempty(), "ERROR: too many filters (max %d)", MQTT_MAX_FILTERS);
        /* overflow-safe check for output buffer sizing */
        if (sz_add_overflow((size_t)n, 8)) return sdsnew("ERROR: filters count overflow");
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"route\",\"topic\":\"%s\",\"matches\":[", topic);
        int first = 1;
        int match_count = 0;
        for (int i = 0; i < n; i++) {
            cJSON *el = cJSON_GetArrayItem(filters, i);
            if (!cJSON_IsString(el)) continue;
            const char *f = el->valuestring;
            if (!f) continue;
            const char *fe = validate_filter_str(f);
            if (fe) continue; /* skip invalid filters */
            if (mqtt_match(topic, f)) {
                if (!first) out = sdscat(out, ",");
                out = sdscatprintf(out, "\"%s\"", f);
                first = 0;
                match_count++;
                if (match_count > MQTT_MAX_FILTERS) break;
            }
        }
        out = sdscatprintf(out, "],\"count\":%d}", match_count);
        return out;
    }

    if (strcmp(action, "extract") == 0) {
        const char *topic = cJSON_GetStringValue(cJSON_GetObjectItem(args, "topic"));
        const char *filter = cJSON_GetStringValue(cJSON_GetObjectItem(args, "filter"));
        if (!topic || !filter) return sdsnew("ERROR: 'topic' and 'filter' required for extract");
        const char *te = validate_topic_str(topic);
        if (te) return sdscatprintf(sdsempty(), "{\"action\":\"extract\",\"error\":\"invalid topic: %s\"}", te);
        const char *fe = validate_filter_str(filter);
        if (fe) return sdscatprintf(sdsempty(), "{\"action\":\"extract\",\"error\":\"invalid filter: %s\"}", fe);
        if (!mqtt_match(topic, filter)) {
            return sdscatprintf(sdsempty(), "{\"action\":\"extract\",\"topic\":\"%s\",\"filter\":\"%s\",\"match\":false}", topic, filter);
        }
        /* extract '+' captures and '#' remainder */
        const char *t_ptr[MQTT_MAX_LEVELS]; size_t t_len[MQTT_MAX_LEVELS];
        const char *f_ptr[MQTT_MAX_LEVELS]; size_t f_len[MQTT_MAX_LEVELS];
        int t_n = split_levels(topic, t_ptr, t_len, MQTT_MAX_LEVELS);
        int f_n = split_levels(filter, f_ptr, f_len, MQTT_MAX_LEVELS);
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"extract\",\"topic\":\"%s\",\"filter\":\"%s\",\"match\":true,\"plus\":[", topic, filter);
        int first = 1;
        int ti = 0;
        sds hash_val = sdsempty();
        for (int fi = 0; fi < f_n; fi++) {
            if (f_len[fi]==1 && f_ptr[fi][0]=='#') {
                /* remainder of topic from ti */
                for (int k = ti; k < t_n; k++) {
                    if (k > ti) hash_val = sdscat(hash_val, "/");
                    hash_val = sdscatlen(hash_val, t_ptr[k], t_len[k]);
                }
                break;
            }
            if (f_len[fi]==1 && f_ptr[fi][0]=='+') {
                if (!first) out = sdscat(out, ",");
                sds cap = sdsempty();
                if (ti < t_n) cap = sdscatlen(cap, t_ptr[ti], t_len[ti]);
                out = sdscatprintf(out, "\"%s\"", cap);
                sdsfree(cap);
                first = 0;
            }
            ti++;
        }
        out = sdscat(out, "]");
        out = sdscatprintf(out, ",\"hash\":\"%s\"}", hash_val);
        sdsfree(hash_val);
        return out;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown mqtt action '%s' (use match, validate_topic, validate_filter, route, extract)", action);
}

static const alpha_tool_t tool_mqtt = {
    .name = "mqtt_topic",
    .aliases = {"mqtt", "mqtt_match", NULL},
    .category = "iot",
    .description = "MQTT topic filter engine from arendst/Tasmota (MQTT 3.1.1 §4.7): wildcard matching (+/#), topic/filter validation, multi-filter routing, and wildcard extraction. Actions: match, validate_topic, validate_filter, route, extract.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"mqtt_topic\",\"description\":\"MQTT topic filter engine from arendst/Tasmota (MQTT 3.1.1 §4.7): wildcard matching (+/#), topic/filter validation, multi-filter routing, and wildcard extraction. Actions: match, validate_topic, validate_filter, route, extract.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"match\",\"validate_topic\",\"validate_filter\",\"route\",\"extract\"]},\"topic\":{\"type\":\"string\",\"description\":\"MQTT topic (no wildcards)\"},\"filter\":{\"type\":\"string\",\"description\":\"MQTT filter (may contain +/#)\"},\"value\":{\"type\":\"string\",\"description\":\"alias for topic/filter in validate actions\"},\"filters\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"array of filters for route\"},\"max_levels\":{\"type\":\"integer\",\"description\":\"optional max levels check (non-negative)\"}},\"required\":[]}}}",
    .run = tool_mqtt_run
};
