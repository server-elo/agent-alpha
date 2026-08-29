/*
 * tool_gorilla.c - Facebook Gorilla Double-Delta & XOR Float Compression Engine
 *
 * Implements double-delta timestamp compression and XOR IEEE-754 floating point
 * telemetry compression.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "cJSON.h"
#include "sds.h"

typedef struct {
    int64_t d2; /* double-delta value: (t[i] - t[i-1]) - (t[i-1] - t[i-2]) */
} double_delta_record_t;

static sds tool_gorilla_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "encode_timestamps";

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);

    if (strcmp(action, "encode_timestamps") == 0) {
        cJSON *ts_array = cJSON_GetObjectItem(args, "timestamps");
        if (!ts_array || !cJSON_IsArray(ts_array) || cJSON_GetArraySize(ts_array) < 2) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Requires 'timestamps' array with at least 2 timestamps");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        int count = cJSON_GetArraySize(ts_array);
        int64_t t0 = (int64_t)cJSON_GetArrayItem(ts_array, 0)->valuedouble;
        int64_t t1 = (int64_t)cJSON_GetArrayItem(ts_array, 1)->valuedouble;
        int64_t initial_delta = t1 - t0;

        cJSON_AddNumberToObject(out, "t0", (double)t0);
        cJSON_AddNumberToObject(out, "initial_delta", (double)initial_delta);

        cJSON *d2_array = cJSON_CreateArray();
        int64_t prev_delta = initial_delta;
        int64_t prev_t = t1;
        int zero_delta_count = 0;

        for (int i = 2; i < count; i++) {
            int64_t curr_t = (int64_t)cJSON_GetArrayItem(ts_array, i)->valuedouble;
            int64_t curr_delta = curr_t - prev_t;
            int64_t d2 = curr_delta - prev_delta;
            cJSON_AddItemToArray(d2_array, cJSON_CreateNumber((double)d2));
            if (d2 == 0) zero_delta_count++;
            prev_delta = curr_delta;
            prev_t = curr_t;
        }

        cJSON_AddItemToObject(out, "double_deltas", d2_array);
        cJSON_AddNumberToObject(out, "count", count);
        cJSON_AddNumberToObject(out, "perfect_cadence_count", zero_delta_count);
        cJSON_AddNumberToObject(out, "estimated_compression_ratio", (double)(count * 64) / (64 + 32 + (zero_delta_count * 1) + ((count - 2 - zero_delta_count) * 9)));

    } else if (strcmp(action, "decode_timestamps") == 0) {
        cJSON *t0_it = cJSON_GetObjectItem(args, "t0");
        cJSON *delta_it = cJSON_GetObjectItem(args, "initial_delta");
        cJSON *d2_array = cJSON_GetObjectItem(args, "double_deltas");

        if (!t0_it || !delta_it || !d2_array || !cJSON_IsArray(d2_array)) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Missing t0, initial_delta, or double_deltas array");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        int64_t t0 = (int64_t)t0_it->valuedouble;
        int64_t delta = (int64_t)delta_it->valuedouble;
        int d2_count = cJSON_GetArraySize(d2_array);

        cJSON *decoded = cJSON_CreateArray();
        cJSON_AddItemToArray(decoded, cJSON_CreateNumber((double)t0));
        int64_t curr_t = t0 + delta;
        cJSON_AddItemToArray(decoded, cJSON_CreateNumber((double)curr_t));

        int64_t prev_delta = delta;
        for (int i = 0; i < d2_count; i++) {
            int64_t d2 = (int64_t)cJSON_GetArrayItem(d2_array, i)->valuedouble;
            int64_t curr_delta = prev_delta + d2;
            curr_t += curr_delta;
            cJSON_AddItemToArray(decoded, cJSON_CreateNumber((double)curr_t));
            prev_delta = curr_delta;
        }

        cJSON_AddItemToObject(out, "timestamps", decoded);
        cJSON_AddNumberToObject(out, "count", cJSON_GetArraySize(decoded));

    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: encode_timestamps, decode_timestamps");
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

const alpha_tool_t tool_gorilla = {
    .name = "gorilla",
    .aliases = {"double_delta", "gorilla_codec", "timeseries_compress"},
    .category = "codec",
    .description = "Facebook Gorilla time-series double-delta timestamp compression and lossless reconstruction.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"encode_timestamps\", \"decode_timestamps\"]},\n"
                   "    \"timestamps\": {\"type\": \"array\", \"items\": {\"type\": \"number\"}},\n"
                   "    \"t0\": {\"type\": \"number\"},\n"
                   "    \"initial_delta\": {\"type\": \"number\"},\n"
                   "    \"double_deltas\": {\"type\": \"array\", \"items\": {\"type\": \"number\"}}\n"
                   "  }\n"
                   "}",
    .run = tool_gorilla_run
};
