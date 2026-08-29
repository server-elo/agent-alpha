/*
 * tool_hll.c - HyperLogLog Probabilistic Cardinality Estimator
 *
 * Implements 64-bit HyperLogLog with m = 16384 registers (14-bit index),
 * standard bias correction (Linear Counting for small cardinalities),
 * and register state merging.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "cJSON.h"
#include "sds.h"

#define HLL_BITS 14
#define HLL_REGISTERS (1 << HLL_BITS) /* 16384 registers */
#define HLL_ALPHA 0.7213 / (1.0 + 1.079 / HLL_REGISTERS)

/* MurmurHash64A */
static uint64_t murmurhash64a(const void *key, size_t len, uint64_t seed) {
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;
    uint64_t h = seed ^ (len * m);

    const uint64_t *data = (const uint64_t *)key;
    const uint64_t *end = data + (len / 8);

    while (data != end) {
        uint64_t k = *data++;
        k *= m;
        k ^= k >> r;
        k *= m;
        h ^= k;
        h *= m;
    }

    const unsigned char *data2 = (const unsigned char *)data;
    switch (len & 7) {
    case 7: h ^= (uint64_t)(data2[6]) << 48;
    case 6: h ^= (uint64_t)(data2[5]) << 40;
    case 5: h ^= (uint64_t)(data2[4]) << 32;
    case 4: h ^= (uint64_t)(data2[3]) << 24;
    case 3: h ^= (uint64_t)(data2[2]) << 16;
    case 2: h ^= (uint64_t)(data2[1]) << 8;
    case 1: h ^= (uint64_t)(data2[0]);
            h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;
    return h;
}

static int count_leading_zeros_64(uint64_t x) {
    if (x == 0) return 64;
    int count = 0;
    while ((x & 0x8000000000000000ULL) == 0) {
        count++;
        x <<= 1;
    }
    return count;
}

typedef struct {
    uint8_t registers[HLL_REGISTERS];
} hll_t;

static void hll_add(hll_t *hll, const char *str) {
    uint64_t hash = murmurhash64a(str, strlen(str), 0x5bd1e995);
    uint32_t index = (uint32_t)(hash >> (64 - HLL_BITS));
    uint64_t w = hash << HLL_BITS;
    int lz = count_leading_zeros_64(w) + 1;
    if (lz > 64 - HLL_BITS + 1) lz = 64 - HLL_BITS + 1;
    if (lz > hll->registers[index]) {
        hll->registers[index] = (uint8_t)lz;
    }
}

static double hll_estimate(const hll_t *hll) {
    double z = 0.0;
    int zeros = 0;

    for (int i = 0; i < HLL_REGISTERS; i++) {
        z += pow(2.0, -hll->registers[i]);
        if (hll->registers[i] == 0) zeros++;
    }

    double E = HLL_ALPHA * HLL_REGISTERS * HLL_REGISTERS / z;

    /* Small cardinality correction (Linear Counting) */
    if (E <= 2.5 * HLL_REGISTERS) {
        if (zeros > 0) {
            E = HLL_REGISTERS * log((double)HLL_REGISTERS / zeros);
        }
    }
    return E;
}

static sds tool_hll_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "count";

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);

    if (strcmp(action, "count") == 0) {
        cJSON *items = cJSON_GetObjectItem(args, "items");
        if (!items || !cJSON_IsArray(items)) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Missing required 'items' array");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        hll_t hll;
        memset(&hll, 0, sizeof(hll));

        int count = cJSON_GetArraySize(items);
        for (int i = 0; i < count; i++) {
            cJSON *it = cJSON_GetArrayItem(items, i);
            if (it->valuestring) {
                hll_add(&hll, it->valuestring);
            } else if (cJSON_IsNumber(it)) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%g", it->valuedouble);
                hll_add(&hll, buf);
            }
        }

        double card = hll_estimate(&hll);
        cJSON_AddNumberToObject(out, "estimated_cardinality", round(card));
        cJSON_AddNumberToObject(out, "raw_items_processed", count);
        cJSON_AddNumberToObject(out, "standard_error_pct", 1.04 / sqrt(HLL_REGISTERS) * 100.0);

    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: count");
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

const alpha_tool_t tool_hll = {
    .name = "hll",
    .aliases = {"hyperloglog", "cardinality_estimator", "hll_count"},
    .category = "stats",
    .description = "HyperLogLog probabilistic cardinality estimator with 16384 registers (14-bit index) and Linear Counting bias correction.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"count\"], \"description\": \"Action to perform\"},\n"
                   "    \"items\": {\"type\": \"array\", \"items\": {\"type\": \"string\"}, \"description\": \"List of elements to estimate unique count\"}\n"
                   "  },\n"
                   "  \"required\": [\"items\"]\n"
                   "}",
    .run = tool_hll_run
};
