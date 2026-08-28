/* tool_json_query.c — Embedded JSON query, filter, project, and aggregate engine */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_json_query_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "query";

    const char *data_str = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    if (!data_str || !data_str[0])
        return sdsnew("ERROR: 'data' parameter (JSON string) required for json_query");

    cJSON *data = cJSON_Parse(data_str);
    if (!data)
        return sdscatprintf(sdsempty(), "ERROR: invalid JSON: %s", cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "parse error");

    sds result = NULL;

    if (strcmp(action, "query") == 0) {
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        if (!path || !path[0]) {
            char *s = cJSON_Print(data);
            result = sdsnew(s ? s : "{}");
            free(s);
            cJSON_Delete(data);
            return result;
        }

        cJSON *cur = data;
        char *path_copy = strdup(path);
        if (!path_copy) { cJSON_Delete(data); return sdsnew("ERROR: allocation failed"); }

        char *save = NULL;
        char *tok = strtok_r(path_copy, ".", &save);
        while (tok && cur) {
            char *end = NULL;
            long idx = strtol(tok, &end, 10);
            if (end && *end == 0 && cJSON_IsArray(cur)) {
                cur = cJSON_GetArrayItem(cur, (int)idx);
            } else {
                cur = cJSON_GetObjectItem(cur, tok);
            }
            tok = strtok_r(NULL, ".", &save);
        }
        free(path_copy);

        if (!cur) {
            cJSON_Delete(data);
            return sdscatprintf(sdsempty(), "ERROR: path '%s' not found in JSON", path);
        }

        char *val_str = cJSON_PrintUnformatted(cur);
        result = sdscatprintf(sdsempty(),
            "{\"action\":\"query\",\"path\":\"%s\",\"value\":%s}",
            path, val_str ? val_str : "null");
        free(val_str);
        cJSON_Delete(data);
        return result;
    }

    if (strcmp(action, "filter") == 0) {
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        const char *filter_key = cJSON_GetStringValue(cJSON_GetObjectItem(args, "filter_key"));
        if (!filter_key) filter_key = cJSON_GetStringValue(cJSON_GetObjectItem(args, "key"));

        cJSON *arr = data;
        if (path && path[0]) {
            cJSON *cur = data;
            char *pc = strdup(path);
            char *sv = NULL;
            char *tk = strtok_r(pc, ".", &sv);
            while (tk && cur) {
                char *ep = NULL;
                long ix = strtol(tk, &ep, 10);
                if (ep && *ep == 0 && cJSON_IsArray(cur)) cur = cJSON_GetArrayItem(cur, (int)ix);
                else cur = cJSON_GetObjectItem(cur, tk);
                tk = strtok_r(NULL, ".", &sv);
            }
            free(pc);
            arr = cur;
        }

        if (!arr || !cJSON_IsArray(arr)) {
            cJSON_Delete(data);
            return sdsnew("ERROR: filter target must be a JSON array");
        }

        double filter_min = -1e100, filter_max = 1e100;
        cJSON *fm = cJSON_GetObjectItem(args, "filter_min");
        if (cJSON_IsNumber(fm)) filter_min = fm->valuedouble;
        cJSON *fx = cJSON_GetObjectItem(args, "filter_max");
        if (cJSON_IsNumber(fx)) filter_max = fx->valuedouble;

        cJSON *out_arr = cJSON_CreateArray();
        int n = cJSON_GetArraySize(arr);
        for (int i = 0; i < n; i++) {
            cJSON *obj = cJSON_GetArrayItem(arr, i);
            if (!cJSON_IsObject(obj)) continue;
            cJSON *val_item = cJSON_GetObjectItem(obj, filter_key);
            if (!val_item || !cJSON_IsNumber(val_item)) continue;
            double v = val_item->valuedouble;
            if (v >= filter_min && v <= filter_max)
                cJSON_AddItemToArray(out_arr, cJSON_Duplicate(obj, 1));
        }

        char *s = cJSON_PrintUnformatted(out_arr);
        result = sdscatprintf(sdsempty(),
            "{\"action\":\"filter\",\"key\":\"%s\",\"min\":%.2f,\"max\":%.2f,\"matched\":%d,\"data\":%s}",
            filter_key, filter_min, filter_max, cJSON_GetArraySize(out_arr), s ? s : "[]");
        free(s);
        cJSON_Delete(out_arr);
        cJSON_Delete(data);
        return result;
    }

    if (strcmp(action, "project") == 0) {
        const char *fields_str = cJSON_GetStringValue(cJSON_GetObjectItem(args, "fields"));
        if (!fields_str || !fields_str[0]) {
            cJSON_Delete(data);
            return sdsnew("ERROR: 'fields' parameter (comma-separated) required for project");
        }

        if (!cJSON_IsArray(data)) {
            cJSON_Delete(data);
            return sdsnew("ERROR: project target must be a JSON array");
        }

        char *fields_copy = strdup(fields_str);
        if (!fields_copy) { cJSON_Delete(data); return sdsnew("ERROR: allocation failed"); }
        char *field_names[64];
        int nf = 0;
        char *sv = NULL;
        char *tk = strtok_r(fields_copy, ",", &sv);
        while (tk && nf < 64) {
            while (*tk == ' ' || *tk == '\t') tk++;
            char *end = tk + strlen(tk);
            while (end > tk && (end[-1] == ' ' || end[-1] == '\t')) end--;
            *end = 0;
            if (tk[0]) field_names[nf++] = tk;
            tk = strtok_r(NULL, ",", &sv);
        }

        cJSON *out_arr = cJSON_CreateArray();
        int n = cJSON_GetArraySize(data);
        for (int i = 0; i < n; i++) {
            cJSON *obj = cJSON_GetArrayItem(data, i);
            if (!cJSON_IsObject(obj)) continue;
            cJSON *proj = cJSON_CreateObject();
            for (int f = 0; f < nf; f++) {
                cJSON *val = cJSON_GetObjectItem(obj, field_names[f]);
                if (val) {
                    cJSON_AddItemToObject(proj, field_names[f], cJSON_Duplicate(val, 1));
                }
            }
            cJSON_AddItemToArray(out_arr, proj);
        }
        free(fields_copy);

        char *s = cJSON_PrintUnformatted(out_arr);
        result = sdscatprintf(sdsempty(),
            "{\"action\":\"project\",\"fields\":\"%s\",\"count\":%d,\"data\":%s}",
            fields_str, cJSON_GetArraySize(out_arr), s ? s : "[]");
        free(s);
        cJSON_Delete(out_arr);
        cJSON_Delete(data);
        return result;
    }

    if (strcmp(action, "aggregate") == 0) {
        const char *value_key = cJSON_GetStringValue(cJSON_GetObjectItem(args, "value_key"));
        if (!value_key) value_key = cJSON_GetStringValue(cJSON_GetObjectItem(args, "key"));
        if (!value_key || !value_key[0]) {
            cJSON_Delete(data);
            return sdsnew("ERROR: 'value_key' parameter required for aggregate");
        }

        if (!cJSON_IsArray(data)) {
            cJSON_Delete(data);
            return sdsnew("ERROR: aggregate target must be a JSON array");
        }

        int count = 0;
        double sum = 0.0, min_val = 1e100, max_val = -1e100;
        int n = cJSON_GetArraySize(data);
        for (int i = 0; i < n; i++) {
            cJSON *obj = cJSON_GetArrayItem(data, i);
            if (!cJSON_IsObject(obj)) continue;
            cJSON *val_item = cJSON_GetObjectItem(obj, value_key);
            if (!val_item || !cJSON_IsNumber(val_item)) continue;
            double v = val_item->valuedouble;
            count++;
            sum += v;
            if (v < min_val) min_val = v;
            if (v > max_val) max_val = v;
        }

        double avg = count > 0 ? sum / count : 0.0;
        result = sdscatprintf(sdsempty(),
            "{\"action\":\"aggregate\",\"key\":\"%s\",\"count\":%d,\"sum\":%.2f,\"avg\":%.2f,\"min\":%.2f,\"max\":%.2f}",
            value_key, count, sum, avg, min_val, max_val);
        cJSON_Delete(data);
        return result;
    }

    cJSON_Delete(data);
    return sdscatprintf(sdsempty(), "ERROR: unknown json_query action '%s' (use query/filter/project/aggregate)", action);
}

static const alpha_tool_t tool_json_query = {
    .name = "json_query",
    .aliases = {"jq", NULL},
    .category = "data",
    .description = "Embedded JSON query, filter, project, and aggregate engine. Supports dot-separated path navigation (including array indices), numeric-range filtering, field projection, and aggregation (count, sum, avg, min, max).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"json_query\",\"description\":\"Embedded JSON query, filter, project, and aggregate engine. Supports dot-separated path navigation (including array indices), numeric-range filtering, field projection, and aggregation (count, sum, avg, min, max).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"query\",\"filter\",\"project\",\"aggregate\"],\"description\":\"Operation to perform (default: query)\"},\"data\":{\"type\":\"string\",\"description\":\"JSON string to operate on\"},\"path\":{\"type\":\"string\",\"description\":\"Dot-separated path for query or filter base, e.g. 'users.0.name'\"},\"filter_key\":{\"type\":\"string\",\"description\":\"Object key to filter on (for action=filter)\"},\"filter_min\":{\"type\":\"number\",\"description\":\"Minimum value for numeric filter (inclusive)\"},\"filter_max\":{\"type\":\"number\",\"description\":\"Maximum value for numeric filter (inclusive)\"},\"fields\":{\"type\":\"string\",\"description\":\"Comma-separated list of fields to project (for action=project)\"},\"value_key\":{\"type\":\"string\",\"description\":\"Numeric field to aggregate over (for action=aggregate)\"}},\"required\":[\"data\"]}}}",
    .run = tool_json_query_run
};
