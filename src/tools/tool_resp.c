/* tool_resp.c — Pure-C RESP (REdis Serialization Protocol) codec
 * Actions: parse, encode
 * RESP2: simple strings (+), errors (-), integers (:), bulk strings ($),
 *        arrays (*), nulls ($-1 / *-1).
 * RESP3 adds: null (_), doubles (,), booleans (#), maps (%).
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>

#define RESP_MAX_BULK  (64 * 1024 * 1024)   /* max bulk string payload */
#define RESP_MAX_ITEMS (1 << 20)            /* max array/map element count */
#define RESP_MAX_DEPTH 64                   /* max nesting depth */

/* --- low-level helpers -------------------------------------------------- */

/* Strict long long parse of s[0..len): optional single '-', digits only,
 * no '+' sign, no whitespace, no leading-zero policy (lenient). */
static int resp_parse_ll(const char *s, size_t len, long long *out) {
    if (len == 0) return -1;
    size_t i = 0;
    if (s[0] == '-') {
        if (len == 1) return -1;
        i = 1;
    } else if (s[0] == '+') {
        return -1;
    }
    for (; i < len; i++) {
        if (!isdigit((unsigned char)s[i])) return -1;
    }
    if (len >= 32) return -1; /* surely overflows int64 */
    char buf[32];
    memcpy(buf, s, len);
    buf[len] = '\0';
    errno = 0;
    char *ep = NULL;
    long long v = strtoll(buf, &ep, 10);
    if (errno == ERANGE || !ep || *ep != '\0') return -1;
    *out = v;
    return 0;
}

/* Find first CRLF in [p, end). Returns pointer to '\r' or NULL. */
static const char *resp_find_crlf(const char *p, const char *end) {
    for (const char *q = p; q + 1 < end; q++) {
        if (q[0] == '\r' && q[1] == '\n') return q;
    }
    return NULL;
}

/* A line-based value (simple string, error, ...) must not contain a bare
 * CR or LF per the RESP spec. */
static int resp_line_clean(const char *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (p[i] == '\r' || p[i] == '\n') return 0;
    }
    return 1;
}

/* --- parser ------------------------------------------------------------- */

typedef struct {
    const char *cur;
    const char *end;
    sds err;
    int depth;
} resp_parser_t;

static cJSON *resp_parse_node(resp_parser_t *r);

static sds resp_fail(resp_parser_t *r, const char *msg) {
    if (!r->err) r->err = sdscatprintf(sdsempty(), "ERROR: %s", msg);
    return r->err;
}

/* Parse one length-prefixed line after the type byte: expects the cursor on
 * the first char of the payload line. On success the out params describe the
 * line content and the cursor moves past the CRLF. */
static int resp_read_line(resp_parser_t *r, const char **line, size_t *line_len) {
    const char *crlf = resp_find_crlf(r->cur, r->end);
    if (!crlf) { resp_fail(r, "missing CRLF terminator"); return -1; }
    *line = r->cur;
    *line_len = (size_t)(crlf - r->cur);
    r->cur = crlf + 2;
    return 0;
}

static int resp_read_count(resp_parser_t *r, long long *out, int allow_null) {
    const char *line; size_t len;
    if (resp_read_line(r, &line, &len) != 0) return -1;
    long long v;
    if (resp_parse_ll(line, len, &v) != 0) {
        resp_fail(r, "invalid integer in length/count line");
        return -1;
    }
    if (allow_null && v == -1) { *out = -1; return 0; }
    if (v < 0) { resp_fail(r, "negative length/count (only -1 allowed)"); return -1; }
    if (v > RESP_MAX_ITEMS) { resp_fail(r, "length/count exceeds limit"); return -1; }
    *out = v;
    return 0;
}

static cJSON *resp_parse_simple(resp_parser_t *r, const char *type_name) {
    const char *line; size_t len;
    if (resp_read_line(r, &line, &len) != 0) return NULL;
    if (!resp_line_clean(line, len)) {
        resp_fail(r, "bare CR/LF inside line value");
        return NULL;
    }
    cJSON *node = cJSON_CreateObject();
    cJSON_AddStringToObject(node, "type", type_name);
    char *copy = malloc(len + 1);
    if (!copy) { cJSON_Delete(node); resp_fail(r, "out of memory"); return NULL; }
    memcpy(copy, line, len);
    copy[len] = '\0';
    cJSON_AddStringToObject(node, "value", copy);
    free(copy);
    return node;
}

static cJSON *resp_parse_int(resp_parser_t *r) {
    const char *line; size_t len;
    if (resp_read_line(r, &line, &len) != 0) return NULL;
    long long v;
    if (resp_parse_ll(line, len, &v) != 0) {
        resp_fail(r, "invalid integer value");
        return NULL;
    }
    cJSON *node = cJSON_CreateObject();
    cJSON_AddStringToObject(node, "type", "int");
    cJSON_AddNumberToObject(node, "value", (double)v);
    /* raw preserves full int64 precision beyond 2^53 */
    char *raw = malloc(len + 1);
    if (!raw) { cJSON_Delete(node); resp_fail(r, "out of memory"); return NULL; }
    memcpy(raw, line, len);
    raw[len] = '\0';
    cJSON_AddStringToObject(node, "raw", raw);
    free(raw);
    return node;
}

static cJSON *resp_parse_bulk(resp_parser_t *r) {
    long long len;
    if (resp_read_count(r, &len, 1) != 0) return NULL;
    cJSON *node = cJSON_CreateObject();
    if (len == -1) {
        cJSON_AddStringToObject(node, "type", "null");
        cJSON_AddNullToObject(node, "value");
        return node;
    }
    if (len > RESP_MAX_BULK) {
        cJSON_Delete(node);
        resp_fail(r, "bulk length exceeds limit");
        return NULL;
    }
    if ((size_t)(r->end - r->cur) < (size_t)len + 2) {
        cJSON_Delete(node);
        resp_fail(r, "truncated bulk string payload");
        return NULL;
    }
    if (r->cur[len] != '\r' || r->cur[len + 1] != '\n') {
        cJSON_Delete(node);
        resp_fail(r, "bulk string payload not followed by CRLF");
        return NULL;
    }
    char *copy = malloc((size_t)len + 1);
    if (!copy) { cJSON_Delete(node); resp_fail(r, "out of memory"); return NULL; }
    memcpy(copy, r->cur, (size_t)len);
    copy[len] = '\0';
    r->cur += len + 2;
    cJSON_AddStringToObject(node, "type", "bulk");
    cJSON_AddStringToObject(node, "value", copy);
    cJSON_AddNumberToObject(node, "length", (double)len);
    free(copy);
    return node;
}

static cJSON *resp_parse_aggregate(resp_parser_t *r, const char *type_name,
                                   int is_map) {
    long long count;
    if (resp_read_count(r, &count, 1) != 0) return NULL;
    cJSON *node = cJSON_CreateObject();
    if (count == -1) {
        cJSON_AddStringToObject(node, "type", "null");
        cJSON_AddNullToObject(node, "value");
        return node;
    }
    if (is_map && count > RESP_MAX_ITEMS / 2) {
        cJSON_Delete(node);
        resp_fail(r, "map pair count exceeds limit");
        return NULL;
    }
    if (r->depth >= RESP_MAX_DEPTH) {
        cJSON_Delete(node);
        resp_fail(r, "nesting too deep");
        return NULL;
    }
    r->depth++;
    cJSON *arr = cJSON_CreateArray();
    for (long long i = 0; i < count; i++) {
        if (is_map) {
            cJSON *k = resp_parse_node(r);
            if (!k) goto fail;
            cJSON *v = resp_parse_node(r);
            if (!v) { cJSON_Delete(k); goto fail; }
            cJSON *pair = cJSON_CreateObject();
            cJSON_AddItemToObject(pair, "key", k);
            cJSON_AddItemToObject(pair, "value", v);
            cJSON_AddItemToArray(arr, pair);
        } else {
            cJSON *el = resp_parse_node(r);
            if (!el) goto fail;
            cJSON_AddItemToArray(arr, el);
        }
    }
    r->depth--;
    cJSON_AddStringToObject(node, "type", type_name);
    cJSON_AddNumberToObject(node, "count", (double)count);
    cJSON_AddItemToObject(node, "value", arr);
    return node;
fail:
    r->depth--;
    cJSON_Delete(arr);
    cJSON_Delete(node);
    return NULL;
}

static cJSON *resp_parse_double(resp_parser_t *r) {
    const char *line; size_t len;
    if (resp_read_line(r, &line, &len) != 0) return NULL;
    if (len == 0 || len >= 64) { resp_fail(r, "invalid double value"); return NULL; }
    char buf[64];
    memcpy(buf, line, len);
    buf[len] = '\0';
    double v;
    if (strcmp(buf, "inf") == 0 || strcmp(buf, "+inf") == 0) v = HUGE_VAL;
    else if (strcmp(buf, "-inf") == 0) v = -HUGE_VAL;
    else if (strcmp(buf, "nan") == 0 || strcmp(buf, "-nan") == 0) v = NAN;
    else {
        char *ep = NULL;
        errno = 0;
        v = strtod(buf, &ep);
        if (!ep || *ep != '\0' || ep == buf) {
            resp_fail(r, "invalid double value");
            return NULL;
        }
    }
    cJSON *node = cJSON_CreateObject();
    cJSON_AddStringToObject(node, "type", "double");
    cJSON_AddNumberToObject(node, "value", v);
    return node;
}

static cJSON *resp_parse_bool(resp_parser_t *r) {
    const char *line; size_t len;
    if (resp_read_line(r, &line, &len) != 0) return NULL;
    if (len != 1 || (line[0] != 't' && line[0] != 'f')) {
        resp_fail(r, "invalid boolean (expected 't' or 'f')");
        return NULL;
    }
    cJSON *node = cJSON_CreateObject();
    cJSON_AddStringToObject(node, "type", "bool");
    cJSON_AddBoolToObject(node, "value", line[0] == 't');
    return node;
}

static cJSON *resp_parse_node(resp_parser_t *r) {
    if (r->cur >= r->end) {
        resp_fail(r, "unexpected end of input");
        return NULL;
    }
    char t = *r->cur++;
    switch (t) {
        case '+': return resp_parse_simple(r, "simple");
        case '-': return resp_parse_simple(r, "error");
        case ':': return resp_parse_int(r);
        case '$': return resp_parse_bulk(r);
        case '*': return resp_parse_aggregate(r, "array", 0);
        case '%': return resp_parse_aggregate(r, "map", 1);
        case ',': return resp_parse_double(r);
        case '#': return resp_parse_bool(r);
        case '_': {
            const char *line; size_t len;
            if (resp_read_line(r, &line, &len) != 0) return NULL;
            if (len != 0) { resp_fail(r, "null type must be followed by empty line"); return NULL; }
            cJSON *node = cJSON_CreateObject();
            cJSON_AddStringToObject(node, "type", "null");
            cJSON_AddNullToObject(node, "value");
            return node;
        }
        default:
            r->cur--;
            resp_fail(r, "unknown RESP type byte");
            return NULL;
    }
}

/* --- encoder ------------------------------------------------------------ */

static sds resp_enc_node(cJSON *v, const char *otype, int resp2, sds *err,
                         int depth);

static sds resp_enc_err(sds *err, const char *msg) {
    if (err && !*err) *err = sdsnew(msg);
    return NULL;
}

/* Format a double the way RESP3 does: inf/-inf/nan, else %.17g. */
static void resp_fmt_double(double d, char buf[64]) {
    if (isnan(d)) snprintf(buf, 64, "nan");
    else if (isinf(d)) snprintf(buf, 64, d > 0 ? "inf" : "-inf");
    else snprintf(buf, 64, "%.17g", d);
}

/* Extract a strict int64 from a JSON number or numeric string. */
static int resp_value_as_ll(cJSON *v, long long *out) {
    if (cJSON_IsNumber(v)) {
        double d = v->valuedouble;
        if (d < -9223372036854775808.0 || d > 9223372036854775807.0) return -1;
        long long ll = (long long)d;
        if ((double)ll != d) return -1;
        *out = ll;
        return 0;
    }
    if (cJSON_IsString(v) && v->valuestring) {
        return resp_parse_ll(v->valuestring, strlen(v->valuestring), out);
    }
    return -1;
}

static sds resp_enc_line_type(cJSON *v, const char *prefix, const char *what,
                              sds *err) {
    if (!cJSON_IsString(v) || !v->valuestring) {
        return resp_enc_err(err, what);
    }
    const char *s = v->valuestring;
    if (!resp_line_clean(s, strlen(s))) {
        return resp_enc_err(err, "ERROR: simple/error strings cannot contain CR or LF");
    }
    return sdscatprintf(sdsempty(), "%s%s\r\n", prefix, s);
}

static sds resp_enc_node(cJSON *v, const char *otype, int resp2, sds *err,
                         int depth) {
    if (depth > RESP_MAX_DEPTH) {
        return resp_enc_err(err, "ERROR: nesting too deep");
    }

    /* Explicit type from parameter or typed-node object. */
    const char *type = otype;
    cJSON *inner = v;
    if (!type && cJSON_IsObject(v)) {
        cJSON *t = cJSON_GetObjectItem(v, "type");
        cJSON *val = cJSON_GetObjectItem(v, "value");
        if (cJSON_IsString(t) && t->valuestring &&
            (val || strcmp(t->valuestring, "null") == 0)) {
            type = t->valuestring;
            inner = val;
        }
    }

    if (type) {
        if (strcmp(type, "simple") == 0)
            return resp_enc_line_type(inner, "+", "ERROR: 'simple' requires a string value", err);
        if (strcmp(type, "error") == 0)
            return resp_enc_line_type(inner, "-", "ERROR: 'error' requires a string value", err);
        if (strcmp(type, "int") == 0 || strcmp(type, "integer") == 0) {
            long long ll;
            if (resp_value_as_ll(inner, &ll) != 0)
                return resp_enc_err(err, "ERROR: 'int' requires an integer value (number or numeric string)");
            return sdscatprintf(sdsempty(), ":%lld\r\n", ll);
        }
        if (strcmp(type, "bulk") == 0 || strcmp(type, "string") == 0) {
            if (!cJSON_IsString(inner) || !inner->valuestring)
                return resp_enc_err(err, "ERROR: 'bulk' requires a string value");
            const char *s = inner->valuestring;
            return sdscatprintf(sdsempty(), "$%zu\r\n%s\r\n", strlen(s), s);
        }
        if (strcmp(type, "null") == 0)
            return sdsnew(resp2 ? "$-1\r\n" : "_\r\n");
        if (strcmp(type, "double") == 0) {
            double d;
            if (cJSON_IsNumber(inner)) d = inner->valuedouble;
            else if (cJSON_IsString(inner) && inner->valuestring) {
                const char *s = inner->valuestring;
                if (strcmp(s, "inf") == 0 || strcmp(s, "+inf") == 0) d = HUGE_VAL;
                else if (strcmp(s, "-inf") == 0) d = -HUGE_VAL;
                else if (strcmp(s, "nan") == 0) d = NAN;
                else {
                    char *ep = NULL;
                    d = strtod(s, &ep);
                    if (!ep || *ep != '\0' || ep == s)
                        return resp_enc_err(err, "ERROR: 'double' requires a numeric value");
                }
            } else {
                return resp_enc_err(err, "ERROR: 'double' requires a numeric value");
            }
            char buf[64];
            resp_fmt_double(d, buf);
            if (resp2) return sdscatprintf(sdsempty(), "$%zu\r\n%s\r\n", strlen(buf), buf);
            return sdscatprintf(sdsempty(), ",%s\r\n", buf);
        }
        if (strcmp(type, "bool") == 0 || strcmp(type, "boolean") == 0) {
            int b;
            if (cJSON_IsBool(inner)) b = cJSON_IsTrue(inner);
            else if (cJSON_IsString(inner) && inner->valuestring &&
                     strcmp(inner->valuestring, "true") == 0) b = 1;
            else if (cJSON_IsString(inner) && inner->valuestring &&
                     strcmp(inner->valuestring, "false") == 0) b = 0;
            else return resp_enc_err(err, "ERROR: 'bool' requires true/false");
            if (resp2) return sdscatprintf(sdsempty(), ":%d\r\n", b);
            return sdscatprintf(sdsempty(), "#%c\r\n", b ? 't' : 'f');
        }
        if (strcmp(type, "array") == 0) {
            if (!cJSON_IsArray(inner))
                return resp_enc_err(err, "ERROR: 'array' requires an array value");
            int n = cJSON_GetArraySize(inner);
            sds out = sdscatprintf(sdsempty(), "*%d\r\n", n);
            cJSON *el = NULL;
            cJSON_ArrayForEach(el, inner) {
                sds part = resp_enc_node(el, NULL, resp2, err, depth + 1);
                if (!part) { sdsfree(out); return NULL; }
                out = sdscatsds(out, part);
                sdsfree(part);
            }
            return out;
        }
        if (strcmp(type, "map") == 0) {
            if (!cJSON_IsObject(inner))
                return resp_enc_err(err, "ERROR: 'map' requires an object value");
            int n = cJSON_GetArraySize(inner);
            sds out;
            if (resp2) out = sdscatprintf(sdsempty(), "*%d\r\n", n * 2);
            else out = sdscatprintf(sdsempty(), "%%%d\r\n", n);
            cJSON *el = NULL;
            cJSON_ArrayForEach(el, inner) {
                const char *k = el->string ? el->string : "";
                sds kpart = sdscatprintf(sdsempty(), "$%zu\r\n%s\r\n", strlen(k), k);
                sds vpart = resp_enc_node(el, NULL, resp2, err, depth + 1);
                if (!vpart) { sdsfree(kpart); sdsfree(out); return NULL; }
                out = sdscatsds(out, kpart);
                out = sdscatsds(out, vpart);
                sdsfree(kpart);
                sdsfree(vpart);
            }
            return out;
        }
        return resp_enc_err(err, "ERROR: unknown type (use simple/error/int/bulk/array/null/double/map/bool)");
    }

    /* Inference */
    if (cJSON_IsNull(v)) return sdsnew(resp2 ? "$-1\r\n" : "_\r\n");
    if (cJSON_IsBool(v)) {
        int b = cJSON_IsTrue(v);
        if (resp2) return sdscatprintf(sdsempty(), ":%d\r\n", b);
        return sdscatprintf(sdsempty(), "#%c\r\n", b ? 't' : 'f');
    }
    if (cJSON_IsNumber(v)) {
        long long ll;
        if (resp_value_as_ll(v, &ll) == 0)
            return sdscatprintf(sdsempty(), ":%lld\r\n", ll);
        char buf[64];
        resp_fmt_double(v->valuedouble, buf);
        if (resp2) return sdscatprintf(sdsempty(), "$%zu\r\n%s\r\n", strlen(buf), buf);
        return sdscatprintf(sdsempty(), ",%s\r\n", buf);
    }
    if (cJSON_IsString(v) && v->valuestring) {
        const char *s = v->valuestring;
        return sdscatprintf(sdsempty(), "$%zu\r\n%s\r\n", strlen(s), s);
    }
    if (cJSON_IsArray(v)) return resp_enc_node(v, "array", resp2, err, depth);
    if (cJSON_IsObject(v)) return resp_enc_node(v, "map", resp2, err, depth);
    return resp_enc_err(err, "ERROR: unsupported JSON value for encode");
}

/* --- tool entry point --------------------------------------------------- */

static const char *resp_get_data(cJSON *args) {
    const char *keys[] = {"data", "input", "text", "resp", NULL};
    for (int i = 0; keys[i]; i++) {
        const char *s = cJSON_GetStringValue(cJSON_GetObjectItem(args, keys[i]));
        if (s) return s;
    }
    return NULL;
}

static sds tool_resp_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "parse";

    if (strcmp(action, "parse") == 0 || strcmp(action, "decode") == 0) {
        const char *data = resp_get_data(args);
        if (!data) return sdsnew("ERROR: 'data' (RESP wire string) is required for parse");
        if (!data[0]) return sdsnew("ERROR: 'data' is empty");
        resp_parser_t r;
        r.cur = data;
        r.end = data + strlen(data);
        r.err = NULL;
        r.depth = 0;
        cJSON *node = resp_parse_node(&r);
        if (!node) {
            sds e = r.err ? r.err : sdsnew("ERROR: parse failed");
            return e;
        }
        long consumed = (long)(r.cur - data);
        long trailing = (long)(r.end - r.cur);
        cJSON_AddStringToObject(node, "action", "parse");
        /* RESP3-only type bytes imply resp3, else wire is resp2-compatible */
        char t0 = data[0];
        cJSON_AddStringToObject(node, "version",
            (t0 == '_' || t0 == ',' || t0 == '#' || t0 == '%') ? "resp3" : "resp2");
        cJSON_AddNumberToObject(node, "consumed", (double)consumed);
        cJSON_AddNumberToObject(node, "trailing", (double)trailing);
        char *js = cJSON_PrintUnformatted(node);
        sds res = sdsnew(js ? js : "{}");
        free(js);
        cJSON_Delete(node);
        return res;
    }

    if (strcmp(action, "encode") == 0) {
        cJSON *val = cJSON_GetObjectItem(args, "value");
        if (!val) val = cJSON_GetObjectItem(args, "data");
        if (!val) return sdsnew("ERROR: 'value' is required for encode");
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(args, "type"));
        const char *ver = cJSON_GetStringValue(cJSON_GetObjectItem(args, "version"));
        if (!ver) ver = cJSON_GetStringValue(cJSON_GetObjectItem(args, "protocol"));
        int resp2 = 0;
        if (ver && (strcmp(ver, "2") == 0 || strcmp(ver, "resp2") == 0 ||
                    strcmp(ver, "RESP2") == 0)) resp2 = 1;
        sds err = NULL;
        sds wire = resp_enc_node(val, type, resp2, &err, 0);
        if (!wire) {
            sds e = err ? err : sdsnew("ERROR: encode failed");
            return e;
        }
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "encode");
        cJSON_AddStringToObject(obj, "version", resp2 ? "resp2" : "resp3");
        cJSON_AddStringToObject(obj, "resp", wire);
        cJSON_AddNumberToObject(obj, "bytes", (double)sdslen(wire));
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js);
        cJSON_Delete(obj);
        sdsfree(wire);
        return res;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown resp action '%s' (use parse/encode)", action);
}

static const alpha_tool_t tool_resp = {
    .name = "resp",
    .aliases = {"resp_parse", "redis_proto", NULL},
    .category = "codec",
    .description = "RESP (REdis Serialization Protocol) codec, pure C, in-memory. parse: RESP2/RESP3 wire string to typed JSON tree (simple/error/int/bulk/array/null/double/map/bool) with consumed/trailing byte counts. encode: JSON value to RESP wire string (type inference or explicit type, resp2/resp3 modes). Strict validation: CRLF terminators, int64 overflow, bulk-length limits, nesting depth.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"resp\",\"description\":\"RESP (REdis Serialization Protocol) codec: parse RESP2/RESP3 wire strings, encode JSON values to RESP wire format.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"parse\",\"encode\"],\"description\":\"Operation\"},\"data\":{\"type\":\"string\",\"description\":\"RESP wire string for parse (may contain \\r\\n)\"},\"value\":{\"description\":\"JSON value for encode (string/number/bool/null/array/object or typed node {type,value})\"},\"type\":{\"type\":\"string\",\"enum\":[\"simple\",\"error\",\"int\",\"bulk\",\"array\",\"null\",\"double\",\"map\",\"bool\"],\"description\":\"Explicit RESP type for encode (otherwise inferred)\"},\"version\":{\"type\":\"string\",\"enum\":[\"resp2\",\"resp3\"],\"description\":\"Wire version for encode (default resp3)\"}}},\"required\":[\"action\"]}}",
    .run = tool_resp_run
};
