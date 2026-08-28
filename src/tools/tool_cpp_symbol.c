/* tool_cpp_symbol.c — Fast C/C++ AST Symbol Extractor from colbymchenry/codegraph */
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_cpp_symbol_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *text_item = cJSON_GetObjectItem(args, "text");
    if (!text_item || !text_item->valuestring) {
        return sdsnew("ERROR: text parameter required for cpp_symbol_extract");
    }
    const char *text = text_item->valuestring;
    const char *p = text;
    const char *end = text + strlen(text);

    cJSON *sym_arr = cJSON_CreateArray();
    int sym_count = 0;
    int current_line = 1;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
        if (p >= end) break;

        if (*p == '\n') {
            current_line++;
            p++;
            continue;
        }

        if (p + 1 < end && p[0] == '/' && p[1] == '/') {
            while (p < end && *p != '\n') p++;
            continue;
        }

        if (p + 1 < end && p[0] == '/' && p[1] == '*') {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/')) {
                if (*p == '\n') current_line++;
                p++;
            }
            if (p + 1 < end) p += 2;
            continue;
        }

        if (*p == '#') {
            p++;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            if (p + 6 <= end && strncmp(p, "define", 6) == 0 && !isalnum(p[6])) {
                p += 6;
                while (p < end && (*p == ' ' || *p == '\t')) p++;
                const char *name_start = p;
                while (p < end && (isalnum(*p) || *p == '_')) p++;
                if (p > name_start) {
                    char macro_name[256];
                    size_t len = (size_t)(p - name_start);
                    if (len >= sizeof(macro_name)) len = sizeof(macro_name) - 1;
                    memcpy(macro_name, name_start, len);
                    macro_name[len] = '\0';

                    cJSON *item = cJSON_CreateObject();
                    cJSON_AddStringToObject(item, "kind", "macro");
                    cJSON_AddStringToObject(item, "name", macro_name);
                    cJSON_AddNumberToObject(item, "line", current_line);
                    cJSON_AddItemToArray(sym_arr, item);
                    sym_count++;
                }
            } else if (p + 7 <= end && strncmp(p, "include", 7) == 0 && !isalnum(p[7])) {
                p += 7;
                while (p < end && (*p == ' ' || *p == '\t')) p++;
                if (p < end && (*p == '<' || *p == '"')) {
                    char delim = (*p == '<') ? '>' : '"';
                    p++;
                    const char *inc_start = p;
                    while (p < end && *p != delim && *p != '\n') p++;
                    if (p < end && *p == delim) {
                        char inc_name[256];
                        size_t len = (size_t)(p - inc_start);
                        if (len >= sizeof(inc_name)) len = sizeof(inc_name) - 1;
                        memcpy(inc_name, inc_start, len);
                        inc_name[len] = '\0';

                        cJSON *item = cJSON_CreateObject();
                        cJSON_AddStringToObject(item, "kind", "include");
                        cJSON_AddStringToObject(item, "name", inc_name);
                        cJSON_AddNumberToObject(item, "line", current_line);
                        cJSON_AddItemToArray(sym_arr, item);
                        sym_count++;
                    }
                }
            }
            while (p < end && *p != '\n') p++;
            continue;
        }

        if ((p + 6 <= end && strncmp(p, "struct", 6) == 0 && !isalnum(p[6])) ||
            (p + 5 <= end && strncmp(p, "class", 5) == 0 && !isalnum(p[5])) ||
            (p + 4 <= end && strncmp(p, "enum", 4) == 0 && !isalnum(p[4]))) {
            const char *kind_str = (strncmp(p, "struct", 6) == 0) ? "struct" :
                                   (strncmp(p, "class", 5) == 0) ? "class" : "enum";
            while (p < end && isalpha(*p)) p++;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            const char *name_start = p;
            while (p < end && (isalnum(*p) || *p == '_')) p++;
            if (p > name_start) {
                char type_name[256];
                size_t len = (size_t)(p - name_start);
                if (len >= sizeof(type_name)) len = sizeof(type_name) - 1;
                memcpy(type_name, name_start, len);
                type_name[len] = '\0';

                cJSON *item = cJSON_CreateObject();
                cJSON_AddStringToObject(item, "kind", kind_str);
                cJSON_AddStringToObject(item, "name", type_name);
                cJSON_AddNumberToObject(item, "line", current_line);
                cJSON_AddItemToArray(sym_arr, item);
                sym_count++;
            }
            while (p < end && *p != ';' && *p != '{' && *p != '\n') p++;
            continue;
        }

        const char *ident_start = p;
        while (p < end && (isalnum(*p) || *p == '_' || *p == ':')) p++;
        if (p > ident_start) {
            const char *after_ident = p;
            while (after_ident < end && (*after_ident == ' ' || *after_ident == '\t')) after_ident++;
            if (after_ident < end && *after_ident == '(') {
                char full_ident[256];
                size_t len = (size_t)(p - ident_start);
                if (len >= sizeof(full_ident)) len = sizeof(full_ident) - 1;
                memcpy(full_ident, ident_start, len);
                full_ident[len] = '\0';

                char receiver[256] = {0};
                char func_name[256] = {0};
                char *colon = strstr(full_ident, "::");
                if (colon) {
                    size_t rlen = (size_t)(colon - full_ident);
                    if (rlen >= sizeof(receiver)) rlen = sizeof(receiver) - 1;
                    memcpy(receiver, full_ident, rlen);
                    receiver[rlen] = '\0';
                    strncpy(func_name, colon + 2, sizeof(func_name) - 1);
                } else {
                    strncpy(func_name, full_ident, sizeof(func_name) - 1);
                }

                if (strcmp(func_name, "if") != 0 && strcmp(func_name, "while") != 0 &&
                    strcmp(func_name, "for") != 0 && strcmp(func_name, "switch") != 0 &&
                    strcmp(func_name, "sizeof") != 0 && strcmp(func_name, "return") != 0) {
                    cJSON *item = cJSON_CreateObject();
                    cJSON_AddStringToObject(item, "kind", "function");
                    cJSON_AddStringToObject(item, "name", func_name);
                    cJSON_AddStringToObject(item, "qualified_name", full_ident);
                    if (receiver[0]) {
                        cJSON_AddStringToObject(item, "receiver", receiver);
                    }
                    cJSON_AddNumberToObject(item, "line", current_line);
                    cJSON_AddItemToArray(sym_arr, item);
                    sym_count++;
                }
                p = after_ident + 1;
                continue;
            }
        }

        p++;
    }

    cJSON *res_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(res_obj, "action", "cpp_symbol_extract");
    cJSON_AddNumberToObject(res_obj, "total_symbols", sym_count);
    cJSON_AddItemToObject(res_obj, "symbols", sym_arr);

    char *json_str = cJSON_PrintUnformatted(res_obj);
    cJSON_Delete(res_obj);
    sds out = sdsnew(json_str);
    free(json_str);
    return out;
}

static const alpha_tool_t tool_cpp_symbol = {
    .name = "cpp_symbol_extract",
    .aliases = {NULL},
    .category = "code",
    .description = "Fast C/C++ AST Symbol Extractor from colbymchenry/codegraph. Scans source code and extracts functions, qualified methods (Class::method), classes, structs, enums, macros, and include headers.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"cpp_symbol_extract\",\"description\":\"Fast C/C++ AST Symbol Extractor from colbymchenry/codegraph. Scans source code and extracts functions, qualified methods (Class::method), classes, structs, enums, macros, and include headers.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"C/C++ source code text to analyze\"}},\"required\":[\"text\"]}}}",
    .run = tool_cpp_symbol_run
};
