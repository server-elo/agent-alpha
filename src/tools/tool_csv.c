/* tool_csv.c — Pure-C CSV parser / stringifier (RFC 4180) — gen_246
 * Actions: parse, stringify
 * parse:   data=<csv text>, delimiter="," , header=bool  -> {rows: [...]} or header objects
 * stringify: data=<json array> (array of arrays or array of objects) -> {csv:"..."}
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static cJSON *csv_parse_text(const char *text, char delim, int has_header, sds *err) {
    *err = NULL;
    if (!text) {
        *err = sdsnew("ERROR: 'data' is required");
        return NULL;
    }
    size_t len = strlen(text);
    /* empty input -> empty rows */
    if (len == 0) {
        return cJSON_CreateArray();
    }
    cJSON *rows = cJSON_CreateArray();
    if (!rows) { *err = sdsnew("ERROR: allocation failed"); return NULL; }
    char *field = (char*)malloc(len + 1);
    if (!field) { cJSON_Delete(rows); *err = sdsnew("ERROR: allocation failed"); return NULL; }
    size_t fpos = 0;
    int in_q = 0;
    cJSON *cur_row = cJSON_CreateArray();
    if (!cur_row) { free(field); cJSON_Delete(rows); *err = sdsnew("ERROR: allocation failed"); return NULL; }

    for (size_t i = 0; i < len; i++) {
        char c = text[i];
        /* handle CRLF as single newline when not in quotes */
        if (!in_q && c == '\r') {
            if (i + 1 < len && text[i+1] == '\n') i++; /* consume \n */
            c = '\n';
        }
        if (in_q) {
            if (c == '"') {
                if (i + 1 < len && text[i+1] == '"') {
                    field[fpos++] = '"';
                    i++;
                } else {
                    in_q = 0;
                }
            } else {
                field[fpos++] = c;
            }
        } else {
            if (c == '"') {
                if (fpos == 0) {
                    in_q = 1;
                } else {
                    /* stray quote inside unquoted field -> treat as literal */
                    field[fpos++] = c;
                }
            } else if (c == delim) {
                field[fpos] = '\0';
                cJSON_AddItemToArray(cur_row, cJSON_CreateString(field));
                fpos = 0;
            } else if (c == '\n') {
                field[fpos] = '\0';
                cJSON_AddItemToArray(cur_row, cJSON_CreateString(field));
                fpos = 0;
                /* add row if not a trailing empty due to final newline? keep all */
                /* skip completely empty rows that are just [""] and at EOF? Keep for now but
                 * avoid adding an empty row for a blank line that is just newline with no fields?
                 * Our logic already added one field "" so row is [""] -> keep as is; caller can filter. */
                cJSON_AddItemToArray(rows, cur_row);
                cur_row = cJSON_CreateArray();
                if (!cur_row) { free(field); cJSON_Delete(rows); *err = sdsnew("ERROR: allocation failed"); return NULL; }
            } else {
                field[fpos++] = c;
            }
        }
    }
    if (in_q) {
        free(field); cJSON_Delete(cur_row); cJSON_Delete(rows);
        *err = sdsnew("ERROR: unterminated quoted field");
        return NULL;
    }
    /* flush last field/row if any pending data */
    /* Need to distinguish between input ending with newline (cur_row empty, fpos 0) vs
     * input without newline (cur_row has some fields, or fpos>0) */
    int has_pending = (fpos > 0) || (cJSON_GetArraySize(cur_row) > 0);
    /* Also handle case like "a,b," ending with delimiter -> last field is empty but not yet flushed:
     *    text = "a,b," -> loop flushed "a" and "b" on commas, fpos=0, cur_row=[a,b], has_pending true -> need to flush "" */
    /* has_pending captures that because cur_row size >0 */
    if (has_pending) {
        field[fpos] = '\0';
        cJSON_AddItemToArray(cur_row, cJSON_CreateString(field));
        cJSON_AddItemToArray(rows, cur_row);
    } else {
        cJSON_Delete(cur_row);
    }
    free(field);

    /* If has_header, convert to array of objects */
    if (has_header) {
        if (cJSON_GetArraySize(rows) == 0) {
            return rows;
        }
        cJSON *header = cJSON_GetArrayItem(rows, 0);
        int ncols = cJSON_GetArraySize(header);
        /* build header strings */
        char **cols = (char**)malloc((size_t)ncols * sizeof(char*));
        if (!cols) { cJSON_Delete(rows); *err = sdsnew("ERROR: allocation failed"); return NULL; }
        for (int i = 0; i < ncols; i++) {
            cJSON *h = cJSON_GetArrayItem(header, i);
            cols[i] = (h && cJSON_IsString(h)) ? h->valuestring : "";
        }
        cJSON *out = cJSON_CreateArray();
        int nrows = cJSON_GetArraySize(rows);
        for (int r = 1; r < nrows; r++) {
            cJSON *row = cJSON_GetArrayItem(rows, r);
            /* skip rows that are single empty field from blank lines */
            if (cJSON_GetArraySize(row) == 1) {
                cJSON *only = cJSON_GetArrayItem(row, 0);
                if (only && cJSON_IsString(only) && only->valuestring[0] == '\0') {
                    /* check if this was a blank line - skip unless it's the only data? */
                    /* But keep if header has 1 col and blank line represents empty record? skip blank lines */
                    continue;
                }
            }
            cJSON *obj = cJSON_CreateObject();
            for (int c2 = 0; c2 < ncols; c2++) {
                cJSON *val = cJSON_GetArrayItem(row, c2);
                const char *vs = "";
                if (val && cJSON_IsString(val)) vs = val->valuestring;
                cJSON_AddStringToObject(obj, cols[c2], vs);
            }
            /* if row has more columns than header, add extra as col_n */
            int rowcols = cJSON_GetArraySize(row);
            for (int c2 = ncols; c2 < rowcols; c2++) {
                cJSON *val = cJSON_GetArrayItem(row, c2);
                const char *vs = (val && cJSON_IsString(val)) ? val->valuestring : "";
                char extra[32]; snprintf(extra, sizeof(extra), "col_%d", c2);
                cJSON_AddStringToObject(obj, extra, vs);
            }
            cJSON_AddItemToArray(out, obj);
        }
        free(cols);
        cJSON_Delete(rows);
        return out;
    }
    /* For non-header mode, remove trailing blank row that comes from final newline?
     * Already handled via has_pending logic, so no extra row. But if input was "a,b\n"
     * we correctly have 1 row. If input was "a,b\n\n" we have 2 rows second is [""] - keep. */
    return rows;
}

static sds csv_escape_field(const char *f, char delim) {
    int need_quote = 0;
    for (const char *p = f; *p; p++) {
        if (*p == delim || *p == '"' || *p == '\n' || *p == '\r') { need_quote = 1; break; }
    }
    if (!need_quote) return sdsnew(f);
    sds out = sdsnew("\"");
    for (const char *p = f; *p; p++) {
        if (*p == '"') out = sdscat(out, "\"\"");
        else out = sdscatlen(out, p, 1);
    }
    out = sdscat(out, "\"");
    return out;
}

static sds tool_csv_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "parse";

    if (strcmp(action, "parse") == 0) {
        cJSON *jdata = cJSON_GetObjectItem(args, "data");
        if (!jdata) jdata = cJSON_GetObjectItem(args, "csv");
        if (!jdata) jdata = cJSON_GetObjectItem(args, "text");
        if (!jdata) return sdsnew("ERROR: 'data' string with CSV content is required for parse");
        const char *text = NULL;
        char *owned = NULL;
        if (cJSON_IsString(jdata)) {
            text = jdata->valuestring;
        } else if (cJSON_IsArray(jdata)) {
            /* already array -> wrap as rows */
            char *p = cJSON_PrintUnformatted(jdata);
            sds out = sdscatprintf(sdsempty(), "{\"action\":\"parse\",\"rows\":%s}", p ? p : "[]");
            if (p) free(p);
            return out;
        } else {
            return sdsnew("ERROR: 'data' must be a string for parse");
        }
        (void)owned;
        char delim = ',';
        cJSON *jdel = cJSON_GetObjectItem(args, "delimiter");
        if (!jdel) jdel = cJSON_GetObjectItem(args, "delim");
        if (cJSON_IsString(jdel) && jdel->valuestring[0]) delim = jdel->valuestring[0];
        int header = 0;
        cJSON *jh = cJSON_GetObjectItem(args, "header");
        if (cJSON_IsBool(jh)) header = cJSON_IsTrue(jh);
        else if (cJSON_IsNumber(jh)) header = jh->valueint != 0;
        else if (cJSON_IsString(jh)) header = (strcmp(jh->valuestring, "true")==0 || strcmp(jh->valuestring,"1")==0);

        sds err = NULL;
        cJSON *rows = csv_parse_text(text, delim, header, &err);
        if (!rows) {
            sds e = err ? err : sdsnew("ERROR: parse failed");
            return e;
        }
        char *js = cJSON_PrintUnformatted(rows);
        sds out;
        if (header) out = sdscatprintf(sdsempty(), "{\"action\":\"parse\",\"header\":true,\"rows\":%s}", js ? js : "[]");
        else out = sdscatprintf(sdsempty(), "{\"action\":\"parse\",\"rows\":%s}", js ? js : "[]");
        if (js) free(js);
        cJSON_Delete(rows);
        return out;
    }

    if (strcmp(action, "stringify") == 0) {
        cJSON *jdata = cJSON_GetObjectItem(args, "data");
        if (!jdata) jdata = cJSON_GetObjectItem(args, "rows");
        if (!jdata) return sdsnew("ERROR: 'data' array is required for stringify");
        /* if string, try to parse as JSON */
        cJSON *arr = NULL;
        int owned = 0;
        if (cJSON_IsString(jdata) && jdata->valuestring) {
            arr = cJSON_Parse(jdata->valuestring);
            if (!arr || !cJSON_IsArray(arr)) {
                if (arr) cJSON_Delete(arr);
                return sdsnew("ERROR: 'data' string is not a JSON array for stringify");
            }
            owned = 1;
        } else if (cJSON_IsArray(jdata)) {
            arr = jdata;
        } else {
            return sdsnew("ERROR: 'data' must be an array for stringify");
        }
        char delim = ',';
        cJSON *jdel = cJSON_GetObjectItem(args, "delimiter");
        if (!jdel) jdel = cJSON_GetObjectItem(args, "delim");
        if (cJSON_IsString(jdel) && jdel->valuestring[0]) delim = jdel->valuestring[0];
        int n = cJSON_GetArraySize(arr);
        if (n == 0) {
            if (owned) cJSON_Delete(arr);
            return sdsnew("{\"action\":\"stringify\",\"csv\":\"\"}");
        }
        /* detect array of objects vs array of arrays */
        cJSON *first = cJSON_GetArrayItem(arr, 0);
        int is_objects = first && cJSON_IsObject(first);
        sds csv = sdsempty();
        char delim_str[2] = {delim, '\0'};
        if (is_objects) {
            /* collect header from first object keys */
            int ncols = 0;
            /* count keys */
            cJSON *child = first->child;
            while (child) { ncols++; child = child->next; }
            char **headers = (char**)malloc((size_t)ncols * sizeof(char*));
            int idx = 0;
            child = first->child;
            while (child) { headers[idx++] = child->string ? child->string : ""; child = child->next; }
            /* header row */
            for (int i = 0; i < ncols; i++) {
                if (i) csv = sdscat(csv, delim_str);
                sds esc = csv_escape_field(headers[i], delim);
                csv = sdscat(csv, esc);
                sdsfree(esc);
            }
            csv = sdscat(csv, "\n");
            for (int r = 0; r < n; r++) {
                cJSON *obj = cJSON_GetArrayItem(arr, r);
                if (!cJSON_IsObject(obj)) continue;
                for (int c2 = 0; c2 < ncols; c2++) {
                    if (c2) csv = sdscat(csv, delim_str);
                    cJSON *v = cJSON_GetObjectItem(obj, headers[c2]);
                    const char *vs = "";
                    if (v) {
                        if (cJSON_IsString(v)) vs = v->valuestring;
                        else if (cJSON_IsNumber(v)) {
                            char nb[64]; snprintf(nb, sizeof(nb), "%g", v->valuedouble);
                            sds esc = csv_escape_field(nb, delim);
                            csv = sdscat(csv, esc); sdsfree(esc);
                            continue;
                        }
                    }
                    sds esc = csv_escape_field(vs, delim);
                    csv = sdscat(csv, esc);
                    sdsfree(esc);
                }
                if (r + 1 < n) csv = sdscat(csv, "\n");
            }
            free(headers);
        } else {
            for (int r = 0; r < n; r++) {
                cJSON *row = cJSON_GetArrayItem(arr, r);
                if (!cJSON_IsArray(row)) return sdsnew("ERROR: 'data' must be array of arrays or array of objects");
                int m = cJSON_GetArraySize(row);
                for (int c2 = 0; c2 < m; c2++) {
                    if (c2) csv = sdscat(csv, delim_str);
                    cJSON *v = cJSON_GetArrayItem(row, c2);
                    const char *vs = "";
                    char nb[64];
                    if (v) {
                        if (cJSON_IsString(v)) vs = v->valuestring;
                        else if (cJSON_IsNumber(v)) { snprintf(nb, sizeof(nb), "%g", v->valuedouble); vs = nb; }
                    }
                    sds esc = csv_escape_field(vs, delim);
                    csv = sdscat(csv, esc);
                    sdsfree(esc);
                }
                if (r + 1 < n) csv = sdscat(csv, "\n");
            }
        }
        cJSON *out = cJSON_CreateObject();
        cJSON_AddStringToObject(out, "action", "stringify");
        cJSON_AddStringToObject(out, "csv", csv);
        char *js = cJSON_PrintUnformatted(out);
        sds res = sdsnew(js ? js : "{\"action\":\"stringify\",\"csv\":\"\"}");
        if (js) free(js);
        cJSON_Delete(out);
        sdsfree(csv);
        if (owned) cJSON_Delete(arr);
        return res;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown csv action '%s' (use parse/stringify)", action);
}

static const alpha_tool_t tool_csv = {
    .name = "csv",
    .aliases = {"csv_parse", "csv_stringify", NULL},
    .category = "data",
    .description = "RFC 4180 CSV parser/stringifier: parse CSV text to JSON rows (header->objects) and stringify JSON arrays back to CSV with quoting.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"csv\",\"description\":\"RFC 4180 CSV parser/stringifier: parse CSV text to JSON rows and stringify arrays back to CSV.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"parse\",\"stringify\"],\"description\":\"Action\"},\"data\":{\"type\":\"string\",\"description\":\"CSV text for parse, or JSON array string/array for stringify\"},\"rows\":{\"type\":\"array\",\"description\":\"alias for data (array of arrays/objects) for stringify\"},\"delimiter\":{\"type\":\"string\",\"description\":\"Field delimiter single char (default ',')\"},\"header\":{\"type\":\"boolean\",\"description\":\"If true, first row is header and parse returns array of objects\"}},\"required\":[]}}}",
    .run = tool_csv_run
};
