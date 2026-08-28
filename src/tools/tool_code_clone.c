/* tool_code_clone.c — MinHash Fingerprinting & Locality-Sensitive Hashing (LSH) from DeusData/codebase-memory-mcp */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const uint32_t MH_SEEDS[64] = {
    0x9e3779b9, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f,
    0x165667b1, 0x9e3779f9, 0x7f4a7c15, 0x2545f491,
    0x4f6cdd1d, 0x738a9d01, 0x8405a0cd, 0xa0761d65,
    0x39a1d25b, 0x5b3c8471, 0x1f83d9ab, 0x4a5b6c7d,
    0x2c3d4e5f, 0x6a7b8c9d, 0x0f1e2d3c, 0x4b5a6978,
    0x8796a5b4, 0xc3d2e1f0, 0x13579bdf, 0x2468ace0,
    0xfedcba98, 0x76543210, 0x01234567, 0x89abcdef,
    0xdeadbeef, 0xcafebabe, 0xfeedface, 0x12345678,
    0x87654321, 0xabcdef01, 0x23456789, 0x6789abcd,
    0xef012345, 0x456789ab, 0xcdef0123, 0x0123cdef,
    0x89abcdef, 0x67890123, 0xef456789, 0x23cdef01,
    0xab0123cd, 0x4589ef23, 0x0167ab45, 0x89234567,
    0xcdef8901, 0x23450123, 0x67894567, 0xabcd89ab,
    0xef01cdef, 0x01230123, 0x45674567, 0x89ab89ab,
    0xcdefcdef, 0x13572468, 0x24681357, 0x35792468,
    0x468a3579, 0x579b468a, 0x68ac579b, 0x79bd68ac
};

static sds tool_code_clone_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "fingerprint";

    if (strcmp(action, "fingerprint") == 0 || strcmp(action, "encode") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!text) return sdsnew("ERROR: text or readable file path required for fingerprint");

        uint32_t fp[64];
        for (int i = 0; i < 64; i++) fp[i] = 0xFFFFFFFFU;

        size_t tlen = strlen(text);
        size_t shingle_count = 0;
        if (tlen >= 3) {
            for (size_t i = 0; i <= tlen - 3; i++) {
                uint32_t b0 = (unsigned char)text[i];
                uint32_t b1 = (unsigned char)text[i + 1];
                uint32_t b2 = (unsigned char)text[i + 2];
                uint32_t gram = (b0 << 16) | (b1 << 8) | b2;
                shingle_count++;
                for (int k = 0; k < 64; k++) {
                    uint32_t h = (gram ^ MH_SEEDS[k]) * 0x5bd1e995U;
                    h ^= h >> 15;
                    h *= 0x5bd1e995U;
                    h ^= h >> 13;
                    if (h < fp[k]) fp[k] = h;
                }
            }
        } else if (tlen > 0) {
            uint32_t gram = 0;
            for (size_t i = 0; i < tlen; i++) gram = (gram << 8) | (unsigned char)text[i];
            shingle_count = 1;
            for (int k = 0; k < 64; k++) {
                uint32_t h = (gram ^ MH_SEEDS[k]) * 0x5bd1e995U;
                h ^= h >> 15;
                h *= 0x5bd1e995U;
                h ^= h >> 13;
                fp[k] = h;
            }
        }

        char hex[513];
        for (int i = 0; i < 64; i++) snprintf(hex + i * 8, 9, "%08x", fp[i]);
        hex[512] = 0;

        sds out = sdscatprintf(sdsempty(),
            "{\"action\":\"fingerprint\",\"k\":64,\"shingles\":%zu,\"input_bytes\":%zu,\"hex\":\"%s\",\"values\":[",
            shingle_count, tlen, hex);
        for (int i = 0; i < 64; i++) out = sdscatprintf(out, "%s%u", i ? "," : "", fp[i]);
        out = sdscat(out, "]}");
        return out;
    }

    if (strcmp(action, "jaccard") == 0 || strcmp(action, "similarity") == 0 || strcmp(action, "compare") == 0) {
        cJSON *item_a = cJSON_GetObjectItem(args, "a");
        cJSON *item_b = cJSON_GetObjectItem(args, "b");
        if (!item_a || !item_b) return sdsnew("ERROR: both 'a' and 'b' parameters required");
        const char *sa = cJSON_GetStringValue(item_a);
        const char *sb = cJSON_GetStringValue(item_b);
        if (!sa || !sb) return sdsnew("ERROR: 'a' and 'b' must be strings (raw text or 512-hex fingerprint)");

        uint32_t fp_a[64], fp_b[64];
        size_t la = strlen(sa), lb = strlen(sb);

        if (la == 512) {
            for (int i = 0; i < 64; i++) {
                char buf[9] = {0}; memcpy(buf, sa + i * 8, 8);
                fp_a[i] = (uint32_t)strtoul(buf, NULL, 16);
            }
        } else {
            for (int i = 0; i < 64; i++) fp_a[i] = 0xFFFFFFFFU;
            if (la >= 3) {
                for (size_t i = 0; i <= la - 3; i++) {
                    uint32_t gram = ((unsigned char)sa[i] << 16) | ((unsigned char)sa[i+1] << 8) | (unsigned char)sa[i+2];
                    for (int k = 0; k < 64; k++) {
                        uint32_t h = (gram ^ MH_SEEDS[k]) * 0x5bd1e995U; h ^= h >> 15; h *= 0x5bd1e995U; h ^= h >> 13;
                        if (h < fp_a[k]) fp_a[k] = h;
                    }
                }
            }
        }

        if (lb == 512) {
            for (int i = 0; i < 64; i++) {
                char buf[9] = {0}; memcpy(buf, sb + i * 8, 8);
                fp_b[i] = (uint32_t)strtoul(buf, NULL, 16);
            }
        } else {
            for (int i = 0; i < 64; i++) fp_b[i] = 0xFFFFFFFFU;
            if (lb >= 3) {
                for (size_t i = 0; i <= lb - 3; i++) {
                    uint32_t gram = ((unsigned char)sb[i] << 16) | ((unsigned char)sb[i+1] << 8) | (unsigned char)sb[i+2];
                    for (int k = 0; k < 64; k++) {
                        uint32_t h = (gram ^ MH_SEEDS[k]) * 0x5bd1e995U; h ^= h >> 15; h *= 0x5bd1e995U; h ^= h >> 13;
                        if (h < fp_b[k]) fp_b[k] = h;
                    }
                }
            }
        }

        int matching = 0;
        for (int i = 0; i < 64; i++) if (fp_a[i] == fp_b[i]) matching++;
        double similarity = (double)matching / 64.0;
        int matched_bands = 0;
        for (int b = 0; b < 32; b++) {
            if (fp_a[b * 2] == fp_b[b * 2] && fp_a[b * 2 + 1] == fp_b[b * 2 + 1]) matched_bands++;
        }

        return sdscatprintf(sdsempty(),
            "{\"action\":\"jaccard\",\"similarity\":%.6f,\"matching_slots\":%d,\"total_slots\":64,\"lsh_bands_matched\":%d,\"total_bands\":32,\"is_clone\":%s}",
            similarity, matching, matched_bands, similarity >= 0.85 ? "true" : "false");
    }

    if (strcmp(action, "lsh_match") == 0 || strcmp(action, "query") == 0) {
        const char *query_text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
        if (!query_text) return sdsnew("ERROR: query text required for lsh_match");
        cJSON *corpus = cJSON_GetObjectItem(args, "corpus");
        if (!corpus || !cJSON_IsArray(corpus)) return sdsnew("ERROR: corpus array required for lsh_match");

        double threshold = 0.80;
        cJSON *t_item = cJSON_GetObjectItem(args, "threshold");
        if (cJSON_IsNumber(t_item) && t_item->valuedouble >= 0.0 && t_item->valuedouble <= 1.0)
            threshold = t_item->valuedouble;

        uint32_t q_fp[64];
        size_t qlen = strlen(query_text);
        if (qlen == 512) {
            for (int i = 0; i < 64; i++) {
                char buf[9] = {0}; memcpy(buf, query_text + i * 8, 8);
                q_fp[i] = (uint32_t)strtoul(buf, NULL, 16);
            }
        } else {
            for (int i = 0; i < 64; i++) q_fp[i] = 0xFFFFFFFFU;
            if (qlen >= 3) {
                for (size_t i = 0; i <= qlen - 3; i++) {
                    uint32_t gram = ((unsigned char)query_text[i] << 16) | ((unsigned char)query_text[i+1] << 8) | (unsigned char)query_text[i+2];
                    for (int k = 0; k < 64; k++) {
                        uint32_t h = (gram ^ MH_SEEDS[k]) * 0x5bd1e995U; h ^= h >> 15; h *= 0x5bd1e995U; h ^= h >> 13;
                        if (h < q_fp[k]) q_fp[k] = h;
                    }
                }
            }
        }

        sds out = sdscatprintf(sdsempty(), "{\"action\":\"lsh_match\",\"threshold\":%.2f,\"matches\":[", threshold);
        int n_corpus = cJSON_GetArraySize(corpus);
        int match_count = 0;
        for (int ci = 0; ci < n_corpus; ci++) {
            cJSON *elem = cJSON_GetArrayItem(corpus, ci);
            const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(elem, "id"));
            const char *ctext = cJSON_GetStringValue(cJSON_GetObjectItem(elem, "text"));
            if (!ctext) continue;

            uint32_t c_fp[64];
            size_t clen = strlen(ctext);
            if (clen == 512) {
                for (int i = 0; i < 64; i++) {
                    char buf[9] = {0}; memcpy(buf, ctext + i * 8, 8);
                    c_fp[i] = (uint32_t)strtoul(buf, NULL, 16);
                }
            } else {
                for (int i = 0; i < 64; i++) c_fp[i] = 0xFFFFFFFFU;
                if (clen >= 3) {
                    for (size_t i = 0; i <= clen - 3; i++) {
                        uint32_t gram = ((unsigned char)ctext[i] << 16) | ((unsigned char)ctext[i+1] << 8) | (unsigned char)ctext[i+2];
                        for (int k = 0; k < 64; k++) {
                            uint32_t h = (gram ^ MH_SEEDS[k]) * 0x5bd1e995U; h ^= h >> 15; h *= 0x5bd1e995U; h ^= h >> 13;
                            if (h < c_fp[k]) c_fp[k] = h;
                        }
                    }
                }
            }

            int matching = 0;
            for (int i = 0; i < 64; i++) if (q_fp[i] == c_fp[i]) matching++;
            double sim = (double)matching / 64.0;
            int matched_bands = 0;
            for (int b = 0; b < 32; b++) {
                if (q_fp[b * 2] == c_fp[b * 2] && q_fp[b * 2 + 1] == c_fp[b * 2 + 1]) matched_bands++;
            }

            if (sim >= threshold || matched_bands > 0) {
                out = sdscatprintf(out, "%s{\"id\":\"%s\",\"similarity\":%.6f,\"matching_slots\":%d,\"bands_matched\":%d}",
                    match_count ? "," : "", id ? id : "unknown", sim, matching, matched_bands);
                match_count++;
            }
        }
        out = sdscatprintf(out, "],\"total_matches\":%d}", match_count);
        return out;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown code_clone_detector action '%s'", action);
}

static const alpha_tool_t tool_code_clone = {
    .name = "code_clone_detector",
    .aliases = {"minhash_lsh", NULL},
    .category = "analysis",
    .description = "Fast MinHash Fingerprinting & Locality-Sensitive Hashing (LSH) for Code Clones & Near-Duplicate Detection from DeusData/codebase-memory-mcp. Computes K=64 MinHash vector (512-hex chars), Jaccard similarity estimation, and 32-band LSH candidate retrieval.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"code_clone_detector\",\"description\":\"Fast MinHash Fingerprinting & Locality-Sensitive Hashing (LSH) for Code Clones & Near-Duplicate Detection from DeusData/codebase-memory-mcp. Computes K=64 MinHash vector (512-hex chars), Jaccard similarity estimation, and 32-band LSH candidate retrieval.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"fingerprint\",\"jaccard\",\"lsh_match\"]},\"text\":{\"type\":\"string\",\"description\":\"Source code text to fingerprint\"},\"a\":{\"type\":\"string\",\"description\":\"First signature or text for Jaccard compare\"},\"b\":{\"type\":\"string\",\"description\":\"Second signature or text for Jaccard compare\"},\"query\":{\"type\":\"string\",\"description\":\"Query text or fingerprint for LSH search\"},\"corpus\":{\"type\":\"array\",\"description\":\"Corpus array of {id, text} items to match against\"},\"threshold\":{\"type\":\"number\",\"description\":\"Similarity threshold [0.0..1.0] (default 0.8)\"}},\"required\":[]}}}",
    .run = tool_code_clone_run
};
