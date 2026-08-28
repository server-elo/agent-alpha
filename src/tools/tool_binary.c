/* tool_binary.c — Binary Inspection, Hex Wildcard Search, Boyer-Moore & Patching Tools */
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_hex_pattern_search_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
    if (!data_hex || !pattern)
        return sdsnew("ERROR: data and pattern parameters required for hex_pattern_search");

    size_t dlen = strlen(data_hex);
    uint8_t *dbuf = malloc(dlen / 2 + 1);
    size_t dcount = 0;
    for (size_t i = 0; i + 1 < dlen; i += 2) {
        char byte_str[3] = { data_hex[i], data_hex[i+1], '\0' };
        char *endptr = NULL;
        unsigned long val = strtoul(byte_str, &endptr, 16);
        if (endptr && *endptr == '\0') dbuf[dcount++] = (uint8_t)val;
    }

    typedef struct { uint8_t byte; uint8_t is_wildcard; } hex_pat_t;
    hex_pat_t pat[128];
    size_t pcount = 0;
    const char *p = pattern;
    while (*p && pcount < 128) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') {
            pat[pcount].byte = 0;
            pat[pcount].is_wildcard = 1;
            pcount++;
            p += 2;
        } else if (isxdigit(p[0]) && isxdigit(p[1])) {
            char byte_str[3] = { p[0], p[1], '\0' };
            pat[pcount].byte = (uint8_t)strtoul(byte_str, NULL, 16);
            pat[pcount].is_wildcard = 0;
            pcount++;
            p += 2;
        } else {
            p++;
        }
    }

    sds out = sdscatprintf(sdsempty(), "{\"action\":\"hex_pattern_search\",\"pattern_length\":%zu,\"matches\":[", pcount);
    int matches = 0;
    if (pcount > 0 && dcount >= pcount) {
        for (size_t i = 0; i <= dcount - pcount; i++) {
            int ok = 1;
            for (size_t j = 0; j < pcount; j++) {
                if (!pat[j].is_wildcard && dbuf[i + j] != pat[j].byte) {
                    ok = 0;
                    break;
                }
            }
            if (ok) {
                out = sdscatprintf(out, "%s%zu", matches > 0 ? "," : "", i);
                matches++;
            }
        }
    }
    out = sdscatprintf(out, "],\"total_matches\":%d}", matches);
    free(dbuf);
    return out;
}

static sds tool_binary_patch_apply_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    const char *patch_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "patch"));
    cJSON *off_item = cJSON_GetObjectItem(args, "offset");
    if (!data_hex || !patch_hex || !cJSON_IsNumber(off_item))
        return sdsnew("ERROR: data, patch, and numeric offset required for binary_patch_apply");

    if (off_item->valueint < 0)
        return sdsnew("ERROR: offset must be non-negative for binary_patch_apply");

    size_t offset = (size_t)off_item->valueint;
    size_t dlen = strlen(data_hex);
    size_t plen = strlen(patch_hex);
    if (dlen % 2 != 0 || plen % 2 != 0)
        return sdsnew("ERROR: hex data and patch length must be even numbers of characters");

    size_t dcount = dlen / 2;
    size_t pcount = plen / 2;
    if (offset > dcount || pcount > dcount - offset)
        return sdsnew("ERROR: patch bounds exceed data buffer size");

    uint8_t *dbuf = malloc(dcount);
    for (size_t i = 0; i < dcount; i++) {
        if (!isxdigit(data_hex[i*2]) || !isxdigit(data_hex[i*2+1])) {
            free(dbuf);
            return sdsnew("ERROR: invalid non-hex character in data buffer");
        }
        char byte_str[3] = { data_hex[i*2], data_hex[i*2+1], '\0' };
        dbuf[i] = (uint8_t)strtoul(byte_str, NULL, 16);
    }

    sds orig_hex = sdsempty();
    for (size_t i = 0; i < pcount; i++) {
        if (!isxdigit(patch_hex[i*2]) || !isxdigit(patch_hex[i*2+1])) {
            sdsfree(orig_hex);
            free(dbuf);
            return sdsnew("ERROR: invalid non-hex character in patch string");
        }
        char byte_str[3] = { patch_hex[i*2], patch_hex[i*2+1], '\0' };
        uint8_t pbyte = (uint8_t)strtoul(byte_str, NULL, 16);
        orig_hex = sdscatprintf(orig_hex, "%02x", dbuf[offset + i]);
        dbuf[offset + i] = pbyte;
    }

    sds patched_hex = sdsempty();
    for (size_t i = 0; i < dcount; i++) {
        patched_hex = sdscatprintf(patched_hex, "%02x", dbuf[i]);
    }

    sds out = sdscatprintf(sdsempty(),
        "{\"action\":\"binary_patch_apply\",\"offset\":%zu,\"patch_bytes\":%zu,\"original\":\"%s\",\"patched\":\"%s\"}",
        offset, pcount, orig_hex, patched_hex);
    sdsfree(orig_hex);
    sdsfree(patched_hex);
    free(dbuf);
    return out;
}

static sds tool_boyer_moore_search_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
    if (!text || !pattern)
        return sdsnew("ERROR: text and pattern required for boyer_moore_search");

    size_t n = strlen(text);
    size_t m = strlen(pattern);
    if (m == 0)
        return sdsnew("ERROR: pattern must not be empty");

    int bad_char[256];
    for (int i = 0; i < 256; i++) bad_char[i] = (int)m;
    for (size_t i = 0; i < m; i++) bad_char[(unsigned char)pattern[i]] = (int)(m - 1 - i);

    int *good_suffix = malloc(m * sizeof(int));
    int *suff = malloc(m * sizeof(int));
    for (size_t i = 0; i < m; i++) good_suffix[i] = (int)m;

    suff[m - 1] = (int)m;
    int g = (int)m - 1, f = 0;
    for (int i = (int)m - 2; i >= 0; --i) {
        if (i > g && suff[i + (int)m - 1 - f] < i - g) {
            suff[i] = suff[i + (int)m - 1 - f];
        } else {
            if (i < g) g = i;
            f = i;
            while (g >= 0 && pattern[g] == pattern[g + (int)m - 1 - f]) --g;
            suff[i] = f - g;
        }
    }

    int j = 0;
    for (int i = (int)m - 1; i >= -1; --i) {
        if (i == -1 || suff[i] == i + 1) {
            for (; j < (int)m - 1 - i; ++j) {
                if (good_suffix[j] == (int)m) good_suffix[j] = (int)m - 1 - i;
            }
        }
    }
    for (size_t i = 0; i < m - 1; ++i) {
        good_suffix[m - 1 - suff[i]] = (int)(m - 1 - i);
    }
    free(suff);

    sds out = sdscatprintf(sdsempty(), "{\"action\":\"boyer_moore_search\",\"pattern_length\":%zu,\"matches\":[", m);
    int matches = 0;
    int s = 0;
    while (s <= (int)(n - m)) {
        int k = (int)m - 1;
        while (k >= 0 && pattern[k] == text[s + k]) k--;
        if (k < 0) {
            out = sdscatprintf(out, "%s%d", matches > 0 ? "," : "", s);
            matches++;
            s += good_suffix[0];
        } else {
            int bc_shift = bad_char[(unsigned char)text[s + k]] - ((int)m - 1) + k;
            int gs_shift = good_suffix[k];
            int max_shift = gs_shift > bc_shift ? gs_shift : bc_shift;
            s += max_shift > 0 ? max_shift : 1;
        }
    }
    free(good_suffix);
    out = sdscatprintf(out, "],\"total_matches\":%d}", matches);
    return out;
}

static sds tool_multi_hex_edit_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    cJSON *changes = cJSON_GetObjectItem(args, "changes");
    if (!data_hex || !changes || !cJSON_IsArray(changes))
        return sdsnew("ERROR: data and changes array required for multi_hex_edit");

    size_t dlen = strlen(data_hex);
    if (dlen % 2 != 0)
        return sdsnew("ERROR: hex data length must be an even number of characters");

    size_t dcount = dlen / 2;
    uint8_t *dbuf = malloc(dcount);
    for (size_t i = 0; i < dcount; i++) {
        if (!isxdigit(data_hex[i*2]) || !isxdigit(data_hex[i*2+1])) {
            free(dbuf);
            return sdsnew("ERROR: invalid non-hex character in data buffer");
        }
        char byte_str[3] = { data_hex[i*2], data_hex[i*2+1], '\0' };
        dbuf[i] = (uint8_t)strtoul(byte_str, NULL, 16);
    }

    int n_changes = cJSON_GetArrayItem(changes, 0) ? cJSON_GetArraySize(changes) : 0;
    if (n_changes == 0) {
        free(dbuf);
        return sdsnew("ERROR: changes array must not be empty");
    }

    for (int c = 0; c < n_changes; c++) {
        cJSON *item = cJSON_GetArrayItem(changes, c);
        cJSON *off_item = cJSON_GetObjectItem(item, "offset");
        const char *patch_hex = cJSON_GetStringValue(cJSON_GetObjectItem(item, "patch"));
        if (!off_item || !cJSON_IsNumber(off_item) || !patch_hex) {
            free(dbuf);
            return sdsnew("ERROR: each change item must contain numeric offset and string patch");
        }
        if (off_item->valueint < 0) {
            free(dbuf);
            return sdsnew("ERROR: offset must be non-negative");
        }
        size_t off = (size_t)off_item->valueint;
        size_t plen = strlen(patch_hex);
        if (plen % 2 != 0) {
            free(dbuf);
            return sdsnew("ERROR: patch hex length must be even");
        }
        size_t pcount = plen / 2;
        if (off > dcount || pcount > dcount - off) {
            free(dbuf);
            return sdsnew("ERROR: patch bounds exceed data buffer size");
        }
        for (size_t i = 0; i < plen; i++) {
            if (!isxdigit(patch_hex[i])) {
                free(dbuf);
                return sdsnew("ERROR: invalid non-hex character in patch");
            }
        }
    }

    cJSON *rollbacks = cJSON_CreateArray();
    for (int c = 0; c < n_changes; c++) {
        cJSON *item = cJSON_GetArrayItem(changes, c);
        size_t off = (size_t)cJSON_GetObjectItem(item, "offset")->valueint;
        const char *patch_hex = cJSON_GetStringValue(cJSON_GetObjectItem(item, "patch"));
        size_t pcount = strlen(patch_hex) / 2;

        sds orig_chunk = sdsempty();
        for (size_t i = 0; i < pcount; i++) {
            char byte_str[3] = { patch_hex[i*2], patch_hex[i*2+1], '\0' };
            uint8_t pbyte = (uint8_t)strtoul(byte_str, NULL, 16);
            orig_chunk = sdscatprintf(orig_chunk, "%02x", dbuf[off + i]);
            dbuf[off + i] = pbyte;
        }
        cJSON *rb = cJSON_CreateObject();
        cJSON_AddNumberToObject(rb, "offset", (double)off);
        cJSON_AddStringToObject(rb, "original", orig_chunk);
        sdsfree(orig_chunk);
        cJSON_AddItemToArray(rollbacks, rb);
    }

    sds patched_hex = sdsempty();
    for (size_t i = 0; i < dcount; i++) {
        patched_hex = sdscatprintf(patched_hex, "%02x", dbuf[i]);
    }
    free(dbuf);

    cJSON *res_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(res_obj, "action", "multi_hex_edit");
    cJSON_AddNumberToObject(res_obj, "applied_changes", n_changes);
    cJSON_AddItemToObject(res_obj, "rollbacks", rollbacks);
    cJSON_AddStringToObject(res_obj, "patched", patched_hex);
    sdsfree(patched_hex);

    char *json_str = cJSON_PrintUnformatted(res_obj);
    cJSON_Delete(res_obj);
    sds out = sdsnew(json_str);
    free(json_str);
    return out;
}

static const alpha_tool_t tool_hex_pattern_search = {
    .name = "hex_pattern_search",
    .aliases = {NULL},
    .category = "binary",
    .description = "Scans binary buffers (hex string) for byte patterns with ?? wildcard support. Returns matching byte offsets.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"hex_pattern_search\",\"description\":\"Scans binary buffers (hex string) for byte patterns with ?? wildcard support. Returns matching byte offsets.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded binary data buffer to search\"},\"pattern\":{\"type\":\"string\",\"description\":\"Hex pattern with optional ?? wildcards (e.g. '48 89 ?? 55')\"}},\"required\":[\"data\",\"pattern\"]}}}",
    .run = tool_hex_pattern_search_run
};

static const alpha_tool_t tool_binary_patch_apply = {
    .name = "binary_patch_apply",
    .aliases = {NULL},
    .category = "binary",
    .description = "Applies hex byte patches at specific offsets in a binary buffer. Returns modified hex and original overwritten bytes for rollback.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"binary_patch_apply\",\"description\":\"Applies hex byte patches at specific offsets in a binary buffer. Returns modified hex and original overwritten bytes for rollback.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded binary data buffer\"},\"patch\":{\"type\":\"string\",\"description\":\"Hex-encoded patch bytes to write\"},\"offset\":{\"type\":\"integer\",\"description\":\"Byte offset where patch is applied\"}},\"required\":[\"data\",\"patch\",\"offset\"]}}}",
    .run = tool_binary_patch_apply_run
};

static const alpha_tool_t tool_boyer_moore_search = {
    .name = "boyer_moore_search",
    .aliases = {NULL},
    .category = "search",
    .description = "Ultra-fast Boyer-Moore exact substring search algorithm with both Bad Character and Good Suffix heuristics. Returns all match indices.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"boyer_moore_search\",\"description\":\"Ultra-fast Boyer-Moore exact substring search algorithm with both Bad Character and Good Suffix heuristics. Returns all match indices.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"Haystack text to search\"},\"pattern\":{\"type\":\"string\",\"description\":\"Needle substring to search for\"}},\"required\":[\"text\",\"pattern\"]}}}",
    .run = tool_boyer_moore_search_run
};

static const alpha_tool_t tool_multi_hex_edit = {
    .name = "multi_hex_edit",
    .aliases = {NULL},
    .category = "binary",
    .description = "Atomic Multi-Location Binary Hex Patching Engine from RevokeMsgPatcher. Applies an array of multiple offset modifications transactionally with all-or-nothing validation and structured per-patch rollback logs.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"multi_hex_edit\",\"description\":\"Atomic Multi-Location Binary Hex Patching Engine from RevokeMsgPatcher. Applies an array of multiple offset modifications transactionally with all-or-nothing validation and structured per-patch rollback logs.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"string\",\"description\":\"Original hex-encoded binary buffer\"},\"changes\":{\"type\":\"array\",\"description\":\"Array of change objects: [{'offset': 0, 'patch': '9090'}]\"}},\"required\":[\"data\",\"changes\"]}}}",
    .run = tool_multi_hex_edit_run
};
