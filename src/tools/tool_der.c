/* tool_der.c — Pure-C read-only ASN.1 DER structure parser
 * Actions: parse (default), valid
 * Input: hex or base64 DER blob; walks TLV triples (tag class, constructed
 * bit, tag number incl. high-tag form, length incl. long form, value
 * offset/length) and emits a JSON tree. Strict DER: indefinite lengths,
 * non-minimal length/tag encodings, truncation and overflow are rejected.
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#define DER_MAX_BYTES   (1u << 20)  /* 1 MiB decoded input cap */
#define DER_MAX_DEPTH   64          /* hard recursion cap */
#define DER_DEFAULT_DEPTH 32
#define DER_VALUE_HEX_MAX 32        /* bytes of primitive value embedded as hex */
#define DER_TAG_MAX     0xFFFFFFFFu /* high-tag-number accumulation cap */

static const char *der_class_name(int cls) {
    switch (cls) {
        case 0: return "universal";
        case 1: return "application";
        case 2: return "context-specific";
        default: return "private";
    }
}

static const char *der_tag_name(uint64_t tag) {
    switch (tag) {
        case 1:  return "BOOLEAN";
        case 2:  return "INTEGER";
        case 3:  return "BIT STRING";
        case 4:  return "OCTET STRING";
        case 5:  return "NULL";
        case 6:  return "OBJECT IDENTIFIER";
        case 7:  return "ObjectDescriptor";
        case 8:  return "EXTERNAL";
        case 9:  return "REAL";
        case 10: return "ENUMERATED";
        case 11: return "EMBEDDED PDV";
        case 12: return "UTF8String";
        case 13: return "RELATIVE-OID";
        case 16: return "SEQUENCE";
        case 17: return "SET";
        case 18: return "NumericString";
        case 19: return "PrintableString";
        case 20: return "TeletexString";
        case 21: return "VideotexString";
        case 22: return "IA5String";
        case 23: return "UTCTime";
        case 24: return "GeneralizedTime";
        case 25: return "GraphicString";
        case 26: return "VisibleString";
        case 27: return "GeneralString";
        case 28: return "UniversalString";
        case 30: return "BMPString";
        default: return NULL;
    }
}

/* ---------- input decoders ---------- */

static int der_hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex, tolerating whitespace, ':' and '-' separators. */
static int der_hex_decode(const char *s, uint8_t **out, size_t *outlen, sds *err) {
    size_t digits = 0;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p) || *p == ':' || *p == '-') continue;
        if (der_hex_nibble((unsigned char)*p) < 0) {
            *err = sdscatprintf(sdsempty(), "ERROR: invalid hex character '%c'", *p);
            return -1;
        }
        digits++;
    }
    if (digits == 0) { *err = sdsnew("ERROR: hex input is empty"); return -1; }
    if (digits & 1) { *err = sdsnew("ERROR: odd number of hex digits"); return -1; }
    if (digits / 2 > DER_MAX_BYTES) { *err = sdsnew("ERROR: input exceeds 1 MiB cap"); return -1; }
    uint8_t *buf = malloc(digits / 2);
    if (!buf) { *err = sdsnew("ERROR: out of memory"); return -1; }
    size_t i = 0;
    int hi = -1;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p) || *p == ':' || *p == '-') continue;
        int n = der_hex_nibble((unsigned char)*p);
        if (hi < 0) hi = n;
        else { buf[i++] = (uint8_t)((hi << 4) | n); hi = -1; }
    }
    *out = buf;
    *outlen = digits / 2;
    return 0;
}

static int der_b64_value(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Strict base64: whitespace ignored, padding only at the very end,
 * total length must be a multiple of 4. */
static int der_b64_decode(const char *s, uint8_t **out, size_t *outlen, sds *err) {
    size_t n = 0, pad = 0;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        if (*p == '=') {
            pad++;
            if (pad > 2) { *err = sdsnew("ERROR: too much base64 padding"); return -1; }
            /* ensure only padding (or whitespace) follows */
            for (const char *q = p + 1; *q; q++) {
                if (isspace((unsigned char)*q)) continue;
                if (*q != '=') { *err = sdsnew("ERROR: data after base64 padding"); return -1; }
            }
        } else {
            if (pad > 0) { *err = sdsnew("ERROR: data after base64 padding"); return -1; }
            if (der_b64_value((unsigned char)*p) < 0) {
                *err = sdscatprintf(sdsempty(), "ERROR: invalid base64 character '%c'", *p);
                return -1;
            }
        }
        n++;
    }
    if (n == 0) { *err = sdsnew("ERROR: base64 input is empty"); return -1; }
    if (n % 4 != 0) { *err = sdsnew("ERROR: base64 length not a multiple of 4"); return -1; }
    size_t blen = (n / 4) * 3 - pad;
    if (blen == 0) { *err = sdsnew("ERROR: base64 decodes to zero bytes"); return -1; }
    if (blen > DER_MAX_BYTES) { *err = sdsnew("ERROR: input exceeds 1 MiB cap"); return -1; }
    uint8_t *buf = malloc(blen);
    if (!buf) { *err = sdsnew("ERROR: out of memory"); return -1; }
    size_t i = 0;
    uint32_t acc = 0;
    int have = 0;
    for (const char *p = s; *p && i < blen; p++) {
        if (isspace((unsigned char)*p) || *p == '=') continue;
        acc = (acc << 6) | (uint32_t)der_b64_value((unsigned char)*p);
        have += 6;
        if (have >= 8) {
            have -= 8;
            buf[i++] = (uint8_t)((acc >> have) & 0xFF);
        }
    }
    *out = buf;
    *outlen = blen;
    return 0;
}

/* ---------- TLV parsing ---------- */

typedef struct {
    int      cls;          /* 0 universal, 1 application, 2 context, 3 private */
    int      constructed;
    uint64_t tag;
    size_t   offset;       /* offset of tag byte */
    size_t   header_len;   /* tag + length bytes */
    uint64_t length;       /* content length */
    size_t   value_off;
} der_tlv_t;

/* Parse one TLV header at *pos (content bounded by end). Advances *pos past
 * the header. Returns 0 on success, -1 with *err set on failure. */
static int der_read_tlv(const uint8_t *buf, size_t end, size_t *pos, der_tlv_t *t, sds *err) {
    size_t p = *pos;
    if (p >= end) { *err = sdsnew("ERROR: truncated: missing tag byte"); return -1; }
    t->offset = p;
    uint8_t b = buf[p++];
    t->cls = (b >> 6) & 0x03;
    t->constructed = (b & 0x20) ? 1 : 0;
    uint64_t tag = b & 0x1F;
    if (tag == 0x1F) {
        /* high-tag-number form, base-128 big-endian */
        tag = 0;
        int first = 1;
        for (;;) {
            if (p >= end) {
                *err = sdscatprintf(sdsempty(),
                    "ERROR: truncated high-tag-number at offset %lu", (unsigned long)t->offset);
                return -1;
            }
            uint8_t c = buf[p++];
            if (first && c == 0x80) {
                *err = sdscatprintf(sdsempty(),
                    "ERROR: non-minimal high-tag-number encoding at offset %lu", (unsigned long)(p - 1));
                return -1;
            }
            first = 0;
            if (tag > (DER_TAG_MAX >> 7)) {
                *err = sdscatprintf(sdsempty(),
                    "ERROR: tag number overflow at offset %lu", (unsigned long)t->offset);
                return -1;
            }
            tag = (tag << 7) | (c & 0x7F);
            if (!(c & 0x80)) break;
        }
        if (tag < 31) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: high-tag-number form used for tag %lu (< 31, non-minimal DER)",
                (unsigned long)tag);
            return -1;
        }
    }
    t->tag = tag;
    if (p >= end) {
        *err = sdscatprintf(sdsempty(),
            "ERROR: truncated: missing length byte at offset %lu", (unsigned long)p);
        return -1;
    }
    uint8_t lb = buf[p++];
    uint64_t len;
    if (lb < 0x80) {
        len = lb;
    } else {
        size_t nlen = lb & 0x7F;
        if (nlen == 0) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: indefinite length at offset %lu (not allowed in DER)", (unsigned long)(p - 1));
            return -1;
        }
        if (nlen == 0x7F) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: reserved length-of-length 0xFF at offset %lu", (unsigned long)(p - 1));
            return -1;
        }
        if (nlen > 8) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: length-of-length %lu too large at offset %lu",
                (unsigned long)nlen, (unsigned long)(p - 1));
            return -1;
        }
        if (end - p < nlen) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: truncated long-form length at offset %lu", (unsigned long)(p - 1));
            return -1;
        }
        if (buf[p] == 0x00) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: non-minimal long-form length (leading zero) at offset %lu", (unsigned long)p);
            return -1;
        }
        len = 0;
        for (size_t i = 0; i < nlen; i++) len = (len << 8) | buf[p++];
        if (len < 128) {
            *err = sdscatprintf(sdsempty(),
                "ERROR: long-form length for value %lu (< 128, non-minimal DER)",
                (unsigned long)len);
            return -1;
        }
    }
    t->header_len = p - t->offset;
    t->length = len;
    t->value_off = p;
    if (len > (uint64_t)(end - p)) {
        *err = sdscatprintf(sdsempty(),
            "ERROR: truncated content: need %llu bytes at offset %lu, only %lu remain",
            (unsigned long long)len, (unsigned long)p, (unsigned long)(end - p));
        return -1;
    }
    *pos = p;
    return 0;
}

static cJSON *der_build(const uint8_t *buf, size_t *pos, size_t end, int depth, int max_depth, sds *err) {
    der_tlv_t t;
    if (der_read_tlv(buf, end, pos, &t, err) != 0) return NULL;
    cJSON *n = cJSON_CreateObject();
    cJSON_AddNumberToObject(n, "offset", (double)t.offset);
    cJSON_AddNumberToObject(n, "header_len", (double)t.header_len);
    cJSON_AddStringToObject(n, "class", der_class_name(t.cls));
    cJSON_AddNumberToObject(n, "class_num", t.cls);
    cJSON_AddBoolToObject(n, "constructed", t.constructed);
    cJSON_AddNumberToObject(n, "tag", (double)t.tag);
    const char *tn = (t.cls == 0) ? der_tag_name(t.tag) : NULL;
    if (tn) cJSON_AddStringToObject(n, "tag_name", tn);
    else cJSON_AddNullToObject(n, "tag_name");
    cJSON_AddNumberToObject(n, "length", (double)t.length);
    cJSON_AddNumberToObject(n, "total_len", (double)(t.header_len + t.length));
    cJSON_AddNumberToObject(n, "value_offset", (double)t.value_off);
    cJSON_AddNumberToObject(n, "value_len", (double)t.length);

    size_t vend = t.value_off + (size_t)t.length;
    if (t.constructed) {
        if (depth >= max_depth) {
            cJSON_AddBoolToObject(n, "children_truncated", 1);
        } else {
            cJSON *children = cJSON_CreateArray();
            size_t cpos = t.value_off;
            while (cpos < vend) {
                cJSON *c = der_build(buf, &cpos, vend, depth + 1, max_depth, err);
                if (!c) { cJSON_Delete(children); cJSON_Delete(n); return NULL; }
                cJSON_AddItemToArray(children, c);
            }
            cJSON_AddItemToObject(n, "children", children);
        }
    } else {
        size_t show = t.length < DER_VALUE_HEX_MAX ? (size_t)t.length : DER_VALUE_HEX_MAX;
        char hexbuf[DER_VALUE_HEX_MAX * 2 + 1];
        for (size_t i = 0; i < show; i++)
            snprintf(hexbuf + i * 2, 3, "%02X", buf[t.value_off + i]);
        hexbuf[show * 2] = '\0';
        cJSON_AddStringToObject(n, "value_hex", hexbuf);
        if ((size_t)t.length > show) cJSON_AddBoolToObject(n, "value_hex_truncated", 1);
    }
    *pos = vend;
    return n;
}

/* Parse a full DER blob. On success returns the root node; *out_pos receives
 * the number of bytes consumed. */
static cJSON *der_parse(const uint8_t *buf, size_t len, int max_depth, size_t *out_pos, sds *err) {
    size_t pos = 0;
    cJSON *root = der_build(buf, &pos, len, 0, max_depth, err);
    if (!root) return NULL;
    if (pos != len) {
        cJSON_Delete(root);
        *err = sdscatprintf(sdsempty(),
            "ERROR: %lu trailing bytes after top-level TLV",
            (unsigned long)(len - pos));
        return NULL;
    }
    *out_pos = pos;
    return root;
}

/* ---------- tool entry ---------- */

static const char *der_get_input(cJSON *args) {
    const char *keys[] = {"data", "input", "der", "hex", "text", NULL};
    for (int i = 0; keys[i]; i++) {
        const char *s = cJSON_GetStringValue(cJSON_GetObjectItem(args, keys[i]));
        if (s) return s;
    }
    return NULL;
}

static sds tool_der_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "parse";

    if (strcmp(action, "parse") != 0 && strcmp(action, "decode") != 0 &&
        strcmp(action, "valid") != 0 && strcmp(action, "validate") != 0) {
        return sdscatprintf(sdsempty(),
            "ERROR: unknown der action '%s' (use parse/valid)", action);
    }
    int want_valid = (strcmp(action, "valid") == 0 || strcmp(action, "validate") == 0);

    const char *input = der_get_input(args);
    if (!input || !input[0])
        return sdsnew("ERROR: 'data' (hex or base64 DER blob) is required");

    const char *format = cJSON_GetStringValue(cJSON_GetObjectItem(args, "format"));
    if (!format || !format[0]) format = "auto";

    int max_depth = DER_DEFAULT_DEPTH;
    cJSON *md = cJSON_GetObjectItem(args, "max_depth");
    if (!md) md = cJSON_GetObjectItem(args, "depth");
    if (cJSON_IsNumber(md)) {
        double v = cJSON_GetNumberValue(md);
        if (v < 0 || v > DER_MAX_DEPTH || v != (double)(int)v)
            return sdscatprintf(sdsempty(),
                "ERROR: max_depth must be an integer in [0, %d]", DER_MAX_DEPTH);
        max_depth = (int)v;
    }

    /* resolve format */
    int use_hex;
    if (strcasecmp(format, "hex") == 0) use_hex = 1;
    else if (strcasecmp(format, "base64") == 0 || strcasecmp(format, "b64") == 0) use_hex = 0;
    else if (strcasecmp(format, "auto") == 0) {
        /* all-hex (ignoring separators) with even digit count -> hex */
        size_t digits = 0;
        int allhex = 1;
        for (const char *p = input; *p; p++) {
            if (isspace((unsigned char)*p) || *p == ':' || *p == '-') continue;
            if (der_hex_nibble((unsigned char)*p) < 0) { allhex = 0; break; }
            digits++;
        }
        use_hex = (allhex && digits > 0 && !(digits & 1));
    } else {
        return sdscatprintf(sdsempty(),
            "ERROR: unknown format '%s' (use hex/base64/auto)", format);
    }

    uint8_t *buf = NULL;
    size_t len = 0;
    sds err = NULL;
    int rc = use_hex ? der_hex_decode(input, &buf, &len, &err)
                     : der_b64_decode(input, &buf, &len, &err);
    if (rc != 0) {
        sds e = err ? err : sdsnew("ERROR: decode failed");
        return e;
    }

    size_t consumed = 0;
    cJSON *root = der_parse(buf, len, max_depth, &consumed, &err);
    free(buf);
    if (!root) {
        if (want_valid) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "action", "valid");
            cJSON_AddBoolToObject(obj, "valid", 0);
            cJSON_AddStringToObject(obj, "error", err ? err + 7 : "parse failed");
            if (err) sdsfree(err);
            char *js = cJSON_PrintUnformatted(obj);
            sds res = sdsnew(js ? js : "{}");
            free(js); cJSON_Delete(obj);
            return res;
        }
        sds e = err ? err : sdsnew("ERROR: parse failed");
        return e;
    }

    if (want_valid) {
        cJSON_Delete(root);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "valid");
        cJSON_AddBoolToObject(obj, "valid", 1);
        cJSON_AddNumberToObject(obj, "bytes", (double)consumed);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj);
        return res;
    }

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "parse");
    cJSON_AddStringToObject(obj, "format", use_hex ? "hex" : "base64");
    cJSON_AddNumberToObject(obj, "bytes", (double)consumed);
    cJSON_AddNumberToObject(obj, "max_depth", max_depth);
    cJSON_AddItemToObject(obj, "root", root);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js); cJSON_Delete(obj);
    return res;
}

static const alpha_tool_t tool_der = {
    .name = "der",
    .aliases = {"asn1", "tlv", "der_parse", NULL},
    .category = "codec",
    .description = "Read-only ASN.1 DER structure parser (pure C, in-memory): decodes hex or base64, walks TLV triples (tag class, constructed bit, tag number incl. high-tag form, length incl. long form, value offset/len) and emits a JSON tree. Strict DER: rejects indefinite lengths, non-minimal length/tag encodings, truncation, overflow and trailing bytes. Actions: parse, valid. Depth-limited recursion, primitive values embedded as hex (capped).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"der\",\"description\":\"Parse an ASN.1 DER blob (hex or base64) into a JSON TLV tree, or just validate it.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"parse\",\"valid\"],\"description\":\"parse (default) returns the TLV tree; valid returns a boolean\"},\"data\":{\"type\":\"string\",\"description\":\"DER blob as hex (whitespace/colon tolerant) or base64\"},\"format\":{\"type\":\"string\",\"enum\":[\"auto\",\"hex\",\"base64\"],\"description\":\"Input encoding (default auto)\"},\"max_depth\":{\"type\":\"integer\",\"description\":\"Constructed-node recursion depth limit, 0-64 (default 32); deeper constructed nodes are marked children_truncated\"}},\"required\":[\"data\"]}}}",
    .run = tool_der_run
};
