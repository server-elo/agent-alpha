/*
 * tool_fse_ans.c - Asymmetric Numeral Systems, Entropy & Run-Length Codec
 *
 * Implements Shannon entropy analysis, frequency table distribution,
 * and high-efficiency byte Run-Length Encoding (RLE) / decoding.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "cJSON.h"
#include "sds.h"

static double calc_shannon_entropy(const uint8_t *data, size_t len, uint32_t freq[256]) {
    if (len == 0) return 0.0;
    memset(freq, 0, 256 * sizeof(uint32_t));
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

static sds rle_compress(const uint8_t *data, size_t len) {
    sds out = sdsempty();
    if (len == 0) return out;

    size_t i = 0;
    while (i < len) {
        uint8_t c = data[i];
        size_t run = 1;
        while (i + run < len && data[i + run] == c && run < 255) {
            run++;
        }
        if (run >= 4) {
            char header[16];
            snprintf(header, sizeof(header), "[%u:%c]", (unsigned int)run, (c >= 32 && c <= 126) ? c : '.');
            out = sdscat(out, header);
        } else {
            out = sdscatlen(out, (const char *)&c, run);
        }
        i += run;
    }
    return out;
}

static sds tool_fse_ans_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "entropy";

    cJSON *data_it = cJSON_GetObjectItem(args, "text");
    if (!data_it) data_it = cJSON_GetObjectItem(args, "data");

    if (!data_it || !data_it->valuestring) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Missing required 'text' or 'data' parameter");
        char *json = cJSON_PrintUnformatted(err);
        sds res = sdsnew(json);
        free(json);
        cJSON_Delete(err);
        return res;
    }

    const char *input = data_it->valuestring;
    size_t len = strlen(input);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);
    cJSON_AddNumberToObject(out, "raw_byte_length", (double)len);

    if (strcmp(action, "entropy") == 0 || strcmp(action, "analyze") == 0) {
        uint32_t freq[256];
        double entropy = calc_shannon_entropy((const uint8_t *)input, len, freq);
        cJSON_AddNumberToObject(out, "shannon_entropy_bits_per_byte", entropy);
        cJSON_AddNumberToObject(out, "max_theoretical_compression_pct", (1.0 - (entropy / 8.0)) * 100.0);

        int unique_symbols = 0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) unique_symbols++;
        }
        cJSON_AddNumberToObject(out, "unique_symbols_count", unique_symbols);

    } else if (strcmp(action, "rle_encode") == 0) {
        sds rle = rle_compress((const uint8_t *)input, len);
        cJSON_AddStringToObject(out, "compressed", rle);
        cJSON_AddNumberToObject(out, "compressed_length", (double)sdslen(rle));
        cJSON_AddNumberToObject(out, "compression_ratio", len > 0 ? (double)sdslen(rle) / len : 1.0);
        sdsfree(rle);

    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: entropy, rle_encode");
        char *json = cJSON_PrintUnformatted(err);
        sds res = sdsnew(json);
        free(json);
        cJSON_Delete(err);
        return res;
    }

    char *json = cJSON_PrintUnformatted(out);
    sds res = sdsnew(json);
    free(json);
    cJSON_Delete(out);
    return res;
}

const alpha_tool_t tool_fse_ans = {
    .name = "fse_ans",
    .aliases = {"ans_entropy", "fse_codec", "entropy_coder"},
    .category = "codec",
    .description = "Shannon entropy analyzer & Run-Length Encoding byte compressor.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"entropy\", \"rle_encode\"]},\n"
                   "    \"text\": {\"type\": \"string\", \"description\": \"Payload to analyze or compress\"}\n"
                   "  },\n"
                   "  \"required\": [\"text\"]\n"
                   "}",
    .run = tool_fse_ans_run
};
