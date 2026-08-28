/* tool_intset.c — Compact sorted integer set ported from redis/src/intset.c */
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#define IST_ENC_INT16 2u
#define IST_ENC_INT32 4u
#define IST_ENC_INT64 8u
#define IST_HDR 8u
#define IST_MAX_ENTRIES (1u << 20)

static uint32_t ist_enc_for(int64_t v) {
    if (v < INT32_MIN || v > INT32_MAX) return IST_ENC_INT64;
    if (v < INT16_MIN || v > INT16_MAX) return IST_ENC_INT32;
    return IST_ENC_INT16;
}

static void ist_header(unsigned char *b, uint32_t enc, uint32_t len) {
    b[0] = (unsigned char)(enc & 0xff); b[1] = (unsigned char)((enc >> 8) & 0xff);
    b[2] = (unsigned char)((enc >> 16) & 0xff); b[3] = (unsigned char)((enc >> 24) & 0xff);
    b[4] = (unsigned char)(len & 0xff); b[5] = (unsigned char)((len >> 8) & 0xff);
    b[6] = (unsigned char)((len >> 16) & 0xff); b[7] = (unsigned char)((len >> 24) & 0xff);
}

static int ist_parse_header(const unsigned char *b, size_t n, uint32_t *enc, uint32_t *len) {
    if (n < IST_HDR) return 0;
    uint32_t e = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    uint32_t l = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
    if (e != IST_ENC_INT16 && e != IST_ENC_INT32 && e != IST_ENC_INT64) return 0;
    if (l > IST_MAX_ENTRIES) return 0;
    if ((uint64_t)l * e + IST_HDR != (uint64_t)n) return 0;
    *enc = e; *len = l;
    return 1;
}

static int64_t ist_get(const unsigned char *b, uint32_t enc, uint32_t pos) {
    const unsigned char *p = b + IST_HDR + (size_t)pos * enc;
    uint64_t u = 0;
    for (uint32_t i = 0; i < enc; i++) u |= (uint64_t)p[i] << (8u * i);
    if (enc < 8u && (u & (1ull << (8u * enc - 1))))
        u |= ~0ull << (8u * enc);
    int64_t v;
    memcpy(&v, &u, sizeof v);
    return v;
}

static void ist_put(unsigned char *b, uint32_t enc, uint32_t pos, int64_t v) {
    unsigned char *p = b + IST_HDR + (size_t)pos * enc;
    uint64_t u;
    memcpy(&u, &v, sizeof u);
    for (uint32_t i = 0; i < enc; i++) p[i] = (unsigned char)((u >> (8u * i)) & 0xffu);
}

static int ist_search(const unsigned char *b, uint32_t enc, uint32_t len,
                      int64_t v, uint32_t *pos) {
    if (len == 0) { if (pos) *pos = 0; return 0; }
    if (v > ist_get(b, enc, len - 1)) { if (pos) *pos = len; return 0; }
    if (v < ist_get(b, enc, 0)) { if (pos) *pos = 0; return 0; }
    int64_t lo = 0, hi = (int64_t)len - 1;
    while (lo <= hi) {
        int64_t mid = lo + (hi - lo) / 2;
        int64_t cur = ist_get(b, enc, (uint32_t)mid);
        if (v > cur) lo = mid + 1;
        else if (v < cur) hi = mid - 1;
        else { if (pos) *pos = (uint32_t)mid; return 1; }
    }
    if (pos) *pos = (uint32_t)lo;
    return 0;
}

static void ist_read_header_raw(const unsigned char *b, uint32_t *enc, uint32_t *len) {
    *enc = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    *len = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
}

static unsigned char *ist_add(unsigned char *buf, size_t buf_n, int64_t v, int *added) {
    uint32_t enc = 0, len = 0;
    ist_read_header_raw(buf, &enc, &len);
    (void)buf_n;
    *added = 1;
    uint32_t newenc = ist_enc_for(v);
    if (newenc > enc) {
        unsigned char *nb = realloc(buf, IST_HDR + (size_t)(len + 1) * newenc);
        if (!nb) return NULL;
        uint32_t pre = (v < 0) ? 1u : 0u;
        for (int64_t i = (int64_t)len - 1; i >= 0; i--)
            ist_put(nb, newenc, (uint32_t)i + pre, ist_get(nb, enc, (uint32_t)i));
        ist_put(nb, newenc, pre ? 0u : len, v);
        ist_header(nb, newenc, len + 1);
        return nb;
    }
    uint32_t pos;
    if (ist_search(buf, enc, len, v, &pos)) { *added = 0; return buf; }
    unsigned char *nb = realloc(buf, IST_HDR + (size_t)(len + 1) * enc);
    if (!nb) return NULL;
    if (pos < len)
        memmove(nb + IST_HDR + (size_t)(pos + 1) * enc,
                nb + IST_HDR + (size_t)pos * enc,
                (size_t)(len - pos) * enc);
    ist_put(nb, enc, pos, v);
    ist_header(nb, enc, len + 1);
    return nb;
}

static unsigned char *ist_remove(unsigned char *buf, size_t buf_n, int64_t v, int *removed) {
    *removed = 0;
    uint32_t enc = 0, len = 0;
    ist_read_header_raw(buf, &enc, &len);
    (void)buf_n;
    if (ist_enc_for(v) > enc) return buf;
    uint32_t pos;
    if (!ist_search(buf, enc, len, v, &pos)) return buf;
    if (pos < len - 1)
        memmove(buf + IST_HDR + (size_t)pos * enc,
                buf + IST_HDR + (size_t)(pos + 1) * enc,
                (size_t)(len - 1 - pos) * enc);
    *removed = 1;
    size_t new_n = IST_HDR + (size_t)(len - 1) * enc;
    if (len - 1 == 0) new_n = IST_HDR;
    unsigned char *nb = realloc(buf, new_n);
    if (!nb) return buf;
    ist_header(nb, enc, len - 1);
    return nb;
}

static unsigned char *ist_hex_decode(const char *hex, size_t *out_n) {
    size_t hl = strlen(hex);
    if (hl == 0 || hl % 2 != 0) return NULL;
    size_t n = hl / 2;
    if (n > IST_HDR + (size_t)IST_MAX_ENTRIES * IST_ENC_INT64) return NULL;
    unsigned char *buf = malloc(n);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)hex[2 * i]) || !isxdigit((unsigned char)hex[2 * i + 1])) {
            free(buf);
            return NULL;
        }
        char bs[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        buf[i] = (unsigned char)strtoul(bs, NULL, 16);
    }
    *out_n = n;
    return buf;
}

static sds ist_hex_encode(const unsigned char *b, size_t n) {
    sds out = sdsempty();
    for (size_t i = 0; i < n; i++)
        out = sdscatprintf(out, "%02x", b[i]);
    return out;
}

static int ist_arg_int(const cJSON *item, int64_t *out) {
    if (cJSON_IsString(item) && item->valuestring) {
        errno = 0;
        char *end = NULL;
        long long v = strtoll(item->valuestring, &end, 10);
        if (errno == ERANGE || end == item->valuestring || (end && *end != '\0')) return 0;
        *out = (int64_t)v;
        return 1;
    }
    if (cJSON_IsNumber(item)) {
        double d = item->valuedouble;
        if (d < -9.2e18 || d > 9.2e18) return 0;
        if ((double)(int64_t)d != d) return 0;
        *out = (int64_t)d;
        return 1;
    }
    return 0;
}

static sds tool_intset_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action) action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "op"));
    if (!action) return sdsnew("ERROR: intset requires action: create|add|remove|get|find|random|stats");
    for (const char *p = action; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_' ))
            return sdscatprintf(sdsempty(), "ERROR: invalid action '%s'", action);
    }

    if (strcmp(action, "create") == 0 || strcmp(action, "add") == 0) {
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        cJSON *vals = cJSON_GetObjectItem(args, "values");
        cJSON *val_single = cJSON_GetObjectItem(args, "value");
        if (vals && !cJSON_IsArray(vals)) return sdsnew("ERROR: values must be an array");
        if (!vals && !val_single && !data_hex) {
            if (strcmp(action, "add") == 0) return sdsnew("ERROR: add requires 'value' or 'values'");
        }
        unsigned char *buf = NULL;
        size_t cur_n = 0;
        uint32_t enc = IST_ENC_INT16, len = 0;
        if (data_hex) {
            size_t hlen = strlen(data_hex);
            if (hlen == 0 || hlen % 2 != 0) return sdsnew("ERROR: data must be even-length hex string");
            for (size_t i = 0; i < hlen; i++) if (!isxdigit((unsigned char)data_hex[i])) return sdsnew("ERROR: data contains non-hex character");
            size_t buf_n = 0;
            buf = ist_hex_decode(data_hex, &buf_n);
            if (!buf) return sdsnew("ERROR: failed to decode data hex");
            if (!ist_parse_header(buf, buf_n, &enc, &len)) { free(buf); return sdsnew("ERROR: data header invalid"); }
            cur_n = buf_n;
        } else {
            buf = malloc(IST_HDR);
            if (!buf) return sdsnew("ERROR: allocation failed");
            ist_header(buf, IST_ENC_INT16, 0);
            cur_n = IST_HDR; enc = IST_ENC_INT16; len = 0;
        }
        int total_added = 0;
        if (vals && cJSON_IsArray(vals)) {
            int n = cJSON_GetArraySize(vals);
            if ((uint64_t)len + (uint64_t)n > IST_MAX_ENTRIES) { free(buf); return sdsnew("ERROR: add would exceed max entries"); }
            for (int i = 0; i < n; i++) {
                int64_t v;
                if (!ist_arg_int(cJSON_GetArrayItem(vals, i), &v)) { free(buf); return sdsnew("ERROR: values must be integers"); }
                int added=0; unsigned char *nb = ist_add(buf, cur_n, v, &added);
                if (!nb) { free(buf); return sdsnew("ERROR: allocation failed during add"); }
                buf = nb; if (added) total_added++;
                uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
            }
        } else if (val_single) {
            int64_t v;
            if (!ist_arg_int(val_single, &v)) { free(buf); return sdsnew("ERROR: value must be integer"); }
            if (len + 1 > IST_MAX_ENTRIES) { free(buf); return sdsnew("ERROR: add would exceed max entries"); }
            int added=0; unsigned char *nb = ist_add(buf, cur_n, v, &added);
            if (!nb) { free(buf); return sdsnew("ERROR: allocation failed"); }
            buf = nb; if (added) total_added++;
            ist_read_header_raw(buf,&enc,&len); cur_n = IST_HDR + (size_t)len*enc;
        }
        sds hex = ist_hex_encode(buf, cur_n);
        const char *enc_s = enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64";
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"%s\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"added\":%d,\"values\":[", action, enc_s, len, len, total_added);
        for (uint32_t i=0;i<len;i++) {
            int64_t v = ist_get(buf, enc, i);
            out = sdscatprintf(out, "%s%lld", i?",":"", (long long)v);
        }
        out = sdscatprintf(out, "],\"data\":\"%s\"}", hex);
        sdsfree(hex); free(buf);
        return out;
    }
    if (strcmp(action, "remove") == 0) {
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        cJSON *vals = cJSON_GetObjectItem(args, "values");
        cJSON *targets = cJSON_GetObjectItem(args, "targets");
        cJSON *val_single = cJSON_GetObjectItem(args, "value");
        unsigned char *buf = NULL;
        size_t cur_n = 0;
        uint32_t enc=0, len=0;
        cJSON *remove_list = NULL;
        int use_targets = 0;
        if (data_hex) {
            size_t hlen = strlen(data_hex);
            if (hlen == 0 || hlen % 2 != 0) return sdsnew("ERROR: data must be even-length hex string");
            for (size_t i = 0; i < hlen; i++) if (!isxdigit((unsigned char)data_hex[i])) return sdsnew("ERROR: data contains non-hex character");
            size_t buf_n=0;
            buf = ist_hex_decode(data_hex, &buf_n);
            if (!buf) return sdsnew("ERROR: failed to decode data hex");
            if (!ist_parse_header(buf, buf_n, &enc, &len)) { free(buf); return sdsnew("ERROR: data header invalid"); }
            cur_n = buf_n;
            if (vals && cJSON_IsArray(vals)) remove_list = vals;
            else if (val_single) remove_list = NULL;
            else if (targets && cJSON_IsArray(targets)) remove_list = targets;
            else return sdsnew("ERROR: remove requires 'value' or 'values'");
        } else {
            if (!vals || !cJSON_IsArray(vals)) return sdsnew("ERROR: remove requires 'values' array as base set");
            buf = malloc(IST_HDR);
            if (!buf) return sdsnew("ERROR: allocation failed");
            ist_header(buf, IST_ENC_INT16, 0);
            cur_n = IST_HDR; enc = IST_ENC_INT16; len = 0;
            int nbase = cJSON_GetArraySize(vals);
            for (int i=0;i<nbase;i++) {
                int64_t v; if (!ist_arg_int(cJSON_GetArrayItem(vals,i),&v)) { free(buf); return sdsnew("ERROR: values must be integers"); }
                int added=0; unsigned char *nb = ist_add(buf, cur_n, v, &added);
                if (!nb) { free(buf); return sdsnew("ERROR: allocation failed"); }
                buf=nb; uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
            }
            if (targets && cJSON_IsArray(targets)) { remove_list = targets; use_targets=1; }
            else if (val_single) remove_list = NULL;
            else { free(buf); return sdsnew("ERROR: remove requires 'targets' array when using stateless values base"); }
        }
        sds removed_json = sdsnew("[");
        int first = 1;
        if (remove_list) {
            int n = cJSON_GetArraySize(remove_list);
            for (int i=0;i<n;i++) {
                int64_t v; if (!ist_arg_int(cJSON_GetArrayItem(remove_list,i),&v)) { free(buf); sdsfree(removed_json); return sdsnew("ERROR: values must be integers"); }
                int removed=0; unsigned char *nb = ist_remove(buf, cur_n, v, &removed);
                buf = nb;
                uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                if (cur_n==IST_HDR) { enc=IST_ENC_INT16; len=0; }
                if (!first) removed_json = sdscat(removed_json, ",");
                removed_json = sdscat(removed_json, removed ? "true" : "false");
                first = 0;
            }
        } else {
            cJSON *single = val_single ? val_single : cJSON_GetObjectItem(args, "target");
            if (!single) single = use_targets ? NULL : vals;
            int64_t v; if (!ist_arg_int(single,&v)) { free(buf); sdsfree(removed_json); return sdsnew("ERROR: value must be integer"); }
            int removed=0; unsigned char *nb = ist_remove(buf, cur_n, v, &removed);
            buf = nb;
            uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); cur_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
            removed_json = sdscat(removed_json, removed ? "true" : "false");
        }
        removed_json = sdscat(removed_json, "]");
        sds hex = ist_hex_encode(buf, cur_n);
        const char *enc_s = enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64";
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"remove\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"removed\":%s,\"data\":\"%s\",\"values\":[", enc_s, len, len, removed_json, hex);
        sdsfree(removed_json); sdsfree(hex);
        for (uint32_t i=0;i<len;i++) {
            int64_t v = ist_get(buf, enc, i);
            out = sdscatprintf(out, "%s%lld", i?",":"", (long long)v);
        }
        out = sdscatprintf(out, "]}");
        free(buf);
        return out;
    }
    {
        const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        unsigned char *buf = NULL;
        size_t buf_n = 0;
        uint32_t enc=0, len=0;
        if (data_hex) {
            size_t hlen = strlen(data_hex);
            if (hlen == 0 || hlen % 2 != 0) return sdsnew("ERROR: data must be even-length hex string");
            for (size_t i = 0; i < hlen; i++) if (!isxdigit((unsigned char)data_hex[i])) return sdsnew("ERROR: data contains non-hex character");
            buf = ist_hex_decode(data_hex, &buf_n);
            if (!buf) return sdsnew("ERROR: failed to decode data hex");
            if (!ist_parse_header(buf, buf_n, &enc, &len)) { free(buf); return sdsnew("ERROR: data header invalid"); }
        } else {
            cJSON *vals = cJSON_GetObjectItem(args, "values");
            if (!vals) {
                if (strcmp(action,"get")==0) return sdsnew("ERROR: get requires 'values' array or data");
                if (strcmp(action,"find")==0 || strcmp(action,"contains")==0) return sdsnew("ERROR: find requires 'values' array or data");
                if (strcmp(action,"random")==0 || strcmp(action,"rand")==0) return sdsnew("ERROR: random on empty intset");
            }
            if (vals && !cJSON_IsArray(vals)) return sdsnew("ERROR: values must be an array");
            buf = malloc(IST_HDR);
            if (!buf) return sdsnew("ERROR: allocation failed");
            ist_header(buf, IST_ENC_INT16, 0);
            buf_n = IST_HDR; enc = IST_ENC_INT16; len = 0;
            if (vals && cJSON_IsArray(vals)) {
                int n = cJSON_GetArraySize(vals);
                for (int i=0;i<n;i++) {
                    int64_t v; if (!ist_arg_int(cJSON_GetArrayItem(vals,i),&v)) { free(buf); return sdsnew("ERROR: values must be integers"); }
                    int added=0; unsigned char *nb = ist_add(buf, buf_n, v, &added);
                    if (!nb) { free(buf); return sdsnew("ERROR: allocation failed"); }
                    buf = nb; uint32_t ce=0, cl=0; ist_read_header_raw(buf,&ce,&cl); buf_n = IST_HDR + (size_t)cl*ce; enc=ce; len=cl;
                }
            }
        }
        if (strcmp(action, "get") == 0) {
            cJSON *idx_item = cJSON_GetObjectItem(args, "index");
            if (!cJSON_IsNumber(idx_item)) { free(buf); return sdsnew("ERROR: get requires numeric 'index'"); }
            double d = idx_item->valuedouble;
            if (d < 0) { free(buf); return sdsnew("ERROR: index must be non-negative for intset get"); }
            if ((double)(int64_t)d != d) { free(buf); return sdsnew("ERROR: index must be integral"); }
            int64_t idx = (int64_t)d;
            if ((uint64_t)idx >= (uint64_t)len) { free(buf); return sdsnew("ERROR: index out of bounds for intset get"); }
            int64_t v = ist_get(buf, enc, (uint32_t)idx);
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"get\",\"index\":%lld,\"value\":%lld,\"encoding\":\"%s\"}", (long long)idx, (long long)v, enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64");
            free(buf); return out;
        }
        if (strcmp(action, "find") == 0 || strcmp(action, "contains") == 0) {
            cJSON *val_item = cJSON_GetObjectItem(args, "value");
            if (!val_item) val_item = cJSON_GetObjectItem(args, "target");
            if (!val_item) { free(buf); return sdsnew("ERROR: find requires 'value'"); }
            int64_t v; if (!ist_arg_int(val_item,&v)) { free(buf); return sdsnew("ERROR: value must be integer"); }
            uint32_t pos=0; int found = ist_search(buf, enc, len, v, &pos);
            int64_t idx_out = found ? (int64_t)pos : -1;
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"find\",\"value\":%lld,\"found\":%s,\"index\":%lld}", (long long)v, found?"true":"false", (long long)idx_out);
            free(buf); return out;
        }
        if (strcmp(action, "random") == 0 || strcmp(action, "rand") == 0) {
            if (len == 0) { free(buf); return sdsnew("ERROR: random on empty intset"); }
            int64_t seed = 0;
            cJSON *seed_item = cJSON_GetObjectItem(args, "seed");
            if (seed_item) {
                if (!ist_arg_int(seed_item,&seed)) { free(buf); return sdsnew("ERROR: seed must be integer"); }
                if (seed < 0) { free(buf); return sdsnew("ERROR: seed must be non-negative"); }
            } else {
                seed = (int64_t)(time(NULL) ^ (intptr_t)buf);
                if (seed < 0) seed = -seed;
            }
            uint64_t x = (uint64_t)seed + 0x9e3779b97f4a7c15ULL;
            x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
            x *= 0x2545F4914F6CDD1DULL;
            uint32_t idx = (uint32_t)(x % len);
            int64_t v = ist_get(buf, enc, idx);
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"random\",\"index\":%u,\"value\":%lld}", idx, (long long)v);
            free(buf); return out;
        }
        if (strcmp(action, "stats") == 0 || strcmp(action, "info") == 0) {
            const char *enc_s = enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64";
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"stats\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"bytes\":%zu", enc_s, len, len, buf_n);
            if (len > 0) {
                int64_t mn = ist_get(buf, enc, 0);
                int64_t mx = ist_get(buf, enc, len-1);
                out = sdscatprintf(out, ",\"min\":%lld,\"max\":%lld", (long long)mn, (long long)mx);
            }
            out = sdscat(out, "}");
            free(buf); return out;
        }
        if (strcmp(action, "list") == 0 || strcmp(action, "dump") == 0) {
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"list\",\"encoding\":\"%s\",\"len\":%u,\"length\":%u,\"values\":[", enc==IST_ENC_INT16?"int16":enc==IST_ENC_INT32?"int32":"int64", len, len);
            for (uint32_t i=0;i<len;i++) {
                int64_t v = ist_get(buf, enc, i);
                out = sdscatprintf(out, "%s%lld", i?",":"", (long long)v);
                if (sdslen(out) > 8000) { out = sdscat(out, "]"); break; }
            }
            if (len <= 8000) out = sdscat(out, "]");
            out = sdscat(out, "}");
            free(buf); return out;
        }
        free(buf);
        return sdscatprintf(sdsempty(), "ERROR: unknown intset action '%s'", action);
    }
}

static const alpha_tool_t tool_intset = {
    .name = "intset",
    .aliases = {"intset_ops", NULL},
    .category = "datastruct",
    .description = "Compact sorted integer set ported from redis/src/intset.c. Auto-upgrades encoding int16→int32→int64. Serialized as 8-byte LE header + packed elements, hex-encoded. Actions: create, add, remove, get, find, random, stats, list.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"intset\",\"description\":\"Compact sorted integer set ported from redis/src/intset.c. Auto-upgrades encoding int16→int32→int64. Serialized as 8-byte LE header + packed elements, hex-encoded. Actions: create, add, remove, get, find, random, stats, list.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"create\",\"add\",\"remove\",\"get\",\"find\",\"random\",\"stats\",\"list\"],\"description\":\"Operation\"},\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded intset blob\"},\"value\":{\"type\":\"string\",\"description\":\"Single integer value\"},\"values\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Array of integer values\"},\"index\":{\"type\":\"integer\",\"description\":\"Positional index for get\"},\"seed\":{\"type\":\"integer\",\"description\":\"Seed for random\"}},\"required\":[\"action\"]}}}",
    .run = tool_intset_run
};
