/* tool_mdesk.c — Fast Metadesk Lexer & Code Tokenizer from EpicGames/raddebugger */
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_mdesk_tokenize_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    if (!text)
        return sdsnew("ERROR: text parameter required for mdesk_tokenize");

    cJSON *sw_item = cJSON_GetObjectItem(args, "skip_whitespace");
    int skip_whitespace = (sw_item && cJSON_IsBool(sw_item)) ? cJSON_IsTrue(sw_item) : 1;

    size_t len = strlen(text);
    const uint8_t *p = (const uint8_t *)text;
    const uint8_t *end = p + len;

    cJSON *tok_arr = cJSON_CreateArray();
    int tok_count = 0;

    while (p < end) {
        const uint8_t *tok_start = p;
        const char *kind = "symbol";
        cJSON *flags = cJSON_CreateArray();

        /* 1. Whitespace */
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\v') {
            kind = "whitespace";
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\v')) p++;
        }
        /* 2. Newline */
        else if (*p == '\n') {
            kind = "newline";
            p++;
        }
        /* 3. Single-line comment // */
        else if (p + 1 < end && p[0] == '/' && p[1] == '/') {
            kind = "comment";
            p += 2;
            int escaped = 0;
            while (p < end) {
                if (escaped) {
                    escaped = 0;
                } else {
                    if (*p == '\n') break;
                    if (*p == '\\') escaped = 1;
                }
                p++;
            }
        }
        /* 4. Multi-line comment */
        else if (p + 1 < end && p[0] == '/' && p[1] == '*') {
            kind = "comment";
            p += 2;
            int closed = 0;
            while (p < end) {
                if (p + 1 < end && p[0] == '*' && p[1] == '/') {
                    p += 2;
                    closed = 1;
                    break;
                }
                p++;
            }
            if (!closed) {
                cJSON_AddItemToArray(flags, cJSON_CreateString("broken_comment"));
            }
        }
        /* 5. Identifiers */
        else if (isalpha(*p) || *p == '_' || *p >= 0x80) {
            kind = "identifier";
            p++;
            while (p < end && (isalnum(*p) || *p == '_' || *p >= 0x80)) p++;
        }
        /* 6. Numerics */
        else if (isdigit(*p) || (*p == '.' && p + 1 < end && isdigit(p[1]))) {
            kind = "numeric";
            p++;
            while (p < end && (isalnum(*p) || *p == '_' || *p == '.')) p++;
        }
        /* 7. Triplet string literals (""", ''', ```) */
        else if (p + 2 < end && ((p[0] == '"' && p[1] == '"' && p[2] == '"') ||
                                 (p[0] == '\'' && p[1] == '\'' && p[2] == '\'') ||
                                 (p[0] == '`' && p[1] == '`' && p[2] == '`'))) {
            uint8_t q = p[0];
            kind = "string";
            cJSON_AddItemToArray(flags, cJSON_CreateString("triplet"));
            if (q == '\'') cJSON_AddItemToArray(flags, cJSON_CreateString("single_quote"));
            else if (q == '"') cJSON_AddItemToArray(flags, cJSON_CreateString("double_quote"));
            else if (q == '`') cJSON_AddItemToArray(flags, cJSON_CreateString("tick"));
            p += 3;
            int closed = 0;
            while (p + 2 < end) {
                if (p[0] == q && p[1] == q && p[2] == q) {
                    p += 3;
                    closed = 1;
                    break;
                }
                p++;
            }
            if (!closed) {
                p = end;
                cJSON_AddItemToArray(flags, cJSON_CreateString("broken_string"));
            }
        }
        /* 8. Singlet string literals (", ', `) */
        else if (*p == '"' || *p == '\'' || *p == '`') {
            uint8_t q = *p;
            kind = "string";
            if (q == '\'') cJSON_AddItemToArray(flags, cJSON_CreateString("single_quote"));
            else if (q == '"') cJSON_AddItemToArray(flags, cJSON_CreateString("double_quote"));
            else if (q == '`') cJSON_AddItemToArray(flags, cJSON_CreateString("tick"));
            p++;
            int escaped = 0;
            int closed = 0;
            while (p < end && *p != '\n') {
                if (!escaped && *p == '\\') {
                    escaped = 1;
                } else if (!escaped && *p == q) {
                    p++;
                    closed = 1;
                    break;
                } else {
                    escaped = 0;
                }
                p++;
            }
            if (!closed) {
                cJSON_AddItemToArray(flags, cJSON_CreateString("broken_string"));
            }
        }
        /* 9. Symbols & Operators */
        else {
            kind = "symbol";
            p++;
        }

        size_t tok_len = (size_t)(p - tok_start);
        size_t tok_off = (size_t)(tok_start - (const uint8_t *)text);

        if (skip_whitespace && (strcmp(kind, "whitespace") == 0 || strcmp(kind, "newline") == 0)) {
            cJSON_Delete(flags);
            continue;
        }

        cJSON *tok_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(tok_obj, "kind", kind);
        char *tok_str = malloc(tok_len + 1);
        memcpy(tok_str, tok_start, tok_len);
        tok_str[tok_len] = '\0';
        cJSON_AddStringToObject(tok_obj, "text", tok_str);
        free(tok_str);
        cJSON_AddNumberToObject(tok_obj, "offset", (double)tok_off);
        cJSON_AddNumberToObject(tok_obj, "length", (double)tok_len);
        if (cJSON_GetArraySize(flags) > 0) {
            cJSON_AddItemToObject(tok_obj, "flags", flags);
        } else {
            cJSON_Delete(flags);
        }
        cJSON_AddItemToArray(tok_arr, tok_obj);
        tok_count++;
    }

    cJSON *res_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(res_obj, "action", "mdesk_tokenize");
    cJSON_AddNumberToObject(res_obj, "total_tokens", tok_count);
    cJSON_AddItemToObject(res_obj, "tokens", tok_arr);

    char *json_str = cJSON_PrintUnformatted(res_obj);
    cJSON_Delete(res_obj);
    sds out = sdsnew(json_str);
    free(json_str);
    return out;
}

static const alpha_tool_t tool_mdesk = {
    .name = "mdesk_tokenize",
    .aliases = {NULL},
    .category = "parsing",
    .description = "Fast Metadesk Lexer & Code Tokenizer from EpicGames/raddebugger. Scans text, C/C++ code, and DSLs into structured tokens with identifiers, numerics, strings, triplet quotes, symbols, comments, and offset spans.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"mdesk_tokenize\",\"description\":\"Fast Metadesk Lexer & Code Tokenizer from EpicGames/raddebugger. Scans text, C/C++ code, and DSLs into structured tokens with identifiers, numerics, strings, triplet quotes, symbols, comments, and offset spans.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"Source code or data text to tokenize\"},\"skip_whitespace\":{\"type\":\"boolean\",\"description\":\"Filter out whitespace and newline tokens (default true)\"}},\"required\":[\"text\"]}}}",
    .run = tool_mdesk_tokenize_run
};
