/*
 * tool_html_codec.c - HTML & XML Entity Encoder, Decoder, and Tag Stripper
 *
 * Implements W3C HTML5 named character reference decoding, decimal/hex numeric
 * entities (&#DD;, &#xHH;), entity encoding, and tag stripping.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cJSON.h"
#include "sds.h"

typedef struct {
    const char *name;
    const char *utf8;
} html_entity_map_t;

static const html_entity_map_t k_html_entities[] = {
    {"amp", "&"},
    {"lt", "<"},
    {"gt", ">"},
    {"quot", "\""},
    {"apos", "'"},
    {"nbsp", "\xC2\xA0"},
    {"copy", "\xC2\xA9"},
    {"reg", "\xC2\xAE"},
    {"trade", "\xE2\x84\xA2"},
    {"euro", "\xE2\x82\xAC"},
    {"pound", "\xC2\xA3"},
    {"yen", "\xC2\xA5"},
    {"cent", "\xC2\xA2"},
    {"deg", "\xC2\xB0"},
    {"plusmn", "\xC2\xB1"},
    {"times", "\xC3\x97"},
    {"divide", "\xC3\xB7"},
    {"sect", "\xC2\xA7"},
    {"para", "\xC2\xB6"},
    {"middot", "\xC2\xB7"},
    {"mdash", "\xE2\x80\x94"},
    {"ndash", "\xE2\x80\x93"},
    {"lsquo", "\xE2\x80\x98"},
    {"rsquo", "\xE2\x80\x99"},
    {"ldquo", "\xE2\x80\x9C"},
    {"rdquo", "\xE2\x80\x9D"},
    {"hellip", "\xE2\x80\xA6"},
    {"laquo", "\xC2\xAB"},
    {"raquo", "\xC2\xBB"},
    {"alpha", "\xCE\xB1"},
    {"beta", "\xCE\xB2"},
    {"gamma", "\xCE\xB3"},
    {"delta", "\xCE\xB4"},
    {"infin", "\xE2\x88\x9E"},
    {"ne", "\xE2\x89\xA0"},
    {"le", "\xE2\x89\xA4"},
    {"ge", "\xE2\x89\xA5"},
    {"check", "\xE2\x9C\x93"},
    {NULL, NULL}
};

static void unicode_to_utf8(unsigned int codepoint, char *out, int *out_len) {
    if (codepoint <= 0x7F) {
        out[0] = (char)codepoint;
        *out_len = 1;
    } else if (codepoint <= 0x7FF) {
        out[0] = (char)(0xC0 | ((codepoint >> 6) & 0x1F));
        out[1] = (char)(0x80 | (codepoint & 0x3F));
        *out_len = 2;
    } else if (codepoint <= 0xFFFF) {
        out[0] = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
        out[1] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
        out[2] = (char)(0x80 | (codepoint & 0x3F));
        *out_len = 3;
    } else if (codepoint <= 0x10FFFF) {
        out[0] = (char)(0xF0 | ((codepoint >> 18) & 0x07));
        out[1] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
        out[3] = (char)(0x80 | (codepoint & 0x3F));
        *out_len = 4;
    } else {
        *out_len = 0;
    }
}

static sds html_decode_entities(const char *input, int *entity_count) {
    sds res = sdsempty();
    if (!input) return res;
    int count = 0;
    size_t len = strlen(input);
    size_t i = 0;

    while (i < len) {
        if (input[i] == '&') {
            size_t semi = i + 1;
            while (semi < len && semi < i + 12 && input[semi] != ';' && input[semi] != ' ' && input[semi] != '&') {
                semi++;
            }

            int decoded = 0;
            if (semi < len && input[semi] == ';') {
                size_t ent_len = semi - (i + 1);
                char ent_name[32];
                if (ent_len < sizeof(ent_name)) {
                    memcpy(ent_name, &input[i + 1], ent_len);
                    ent_name[ent_len] = '\0';

                    if (ent_name[0] == '#') {
                        unsigned int cp = 0;
                        if (ent_name[1] == 'x' || ent_name[1] == 'X') {
                            cp = (unsigned int)strtoul(&ent_name[2], NULL, 16);
                        } else {
                            cp = (unsigned int)strtoul(&ent_name[1], NULL, 10);
                        }
                        if (cp > 0 && cp <= 0x10FFFF) {
                            char utf8[8] = {0};
                            int ulen = 0;
                            unicode_to_utf8(cp, utf8, &ulen);
                            if (ulen > 0) {
                                res = sdscatlen(res, utf8, ulen);
                                i = semi + 1;
                                decoded = 1;
                                count++;
                            }
                        }
                    } else {
                        for (int k = 0; k_html_entities[k].name != NULL; k++) {
                            if (strcmp(ent_name, k_html_entities[k].name) == 0) {
                                res = sdscat(res, k_html_entities[k].utf8);
                                i = semi + 1;
                                decoded = 1;
                                count++;
                                break;
                            }
                        }
                    }
                }
            }

            if (!decoded) {
                res = sdscatlen(res, &input[i], 1);
                i++;
            }
        } else {
            res = sdscatlen(res, &input[i], 1);
            i++;
        }
    }

    if (entity_count) *entity_count = count;
    return res;
}

static sds html_encode_entities(const char *input, int encode_all) {
    sds res = sdsempty();
    if (!input) return res;

    for (size_t i = 0; input[i] != '\0'; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c == '&') res = sdscat(res, "&amp;");
        else if (c == '<') res = sdscat(res, "&lt;");
        else if (c == '>') res = sdscat(res, "&gt;");
        else if (c == '"') res = sdscat(res, "&quot;");
        else if (c == '\'') res = sdscat(res, "&#39;");
        else if (encode_all && c > 127) {
            char buf[16];
            snprintf(buf, sizeof(buf), "&#%u;", c);
            res = sdscat(res, buf);
        } else {
            res = sdscatlen(res, (const char *)&c, 1);
        }
    }
    return res;
}

static sds html_strip_tags(const char *input, int decode_inner) {
    sds text_only = sdsempty();
    if (!input) return text_only;

    int in_tag = 0;
    int in_script_or_style = 0;
    size_t len = strlen(input);

    for (size_t i = 0; i < len; i++) {
        if (!in_tag && input[i] == '<') {
            in_tag = 1;
            if (i + 7 < len && strncasecmp(&input[i], "<script", 7) == 0) in_script_or_style = 1;
            if (i + 6 < len && strncasecmp(&input[i], "<style", 6) == 0) in_script_or_style = 1;
            if (i + 8 < len && strncasecmp(&input[i], "</script", 8) == 0) in_script_or_style = 0;
            if (i + 7 < len && strncasecmp(&input[i], "</style", 7) == 0) in_script_or_style = 0;
        } else if (in_tag && input[i] == '>') {
            in_tag = 0;
        } else if (!in_tag && !in_script_or_style) {
            text_only = sdscatlen(text_only, &input[i], 1);
        }
    }

    if (decode_inner) {
        int count = 0;
        sds decoded = html_decode_entities(text_only, &count);
        sdsfree(text_only);
        return decoded;
    }
    return text_only;
}

static sds tool_html_codec_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    cJSON *text_item = cJSON_GetObjectItem(args, "text");

    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "decode";
    const char *text = text_item && text_item->valuestring ? text_item->valuestring : NULL;

    if (!text) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Missing required 'text' parameter");
        char *json = cJSON_PrintUnformatted(err);
        sds res = sdsnew(json);
        free(json);
        cJSON_Delete(err);
        return res;
    }

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);

    if (strcmp(action, "decode") == 0 || strcmp(action, "unescape") == 0) {
        int count = 0;
        sds decoded = html_decode_entities(text, &count);
        cJSON_AddStringToObject(out, "result", decoded);
        cJSON_AddNumberToObject(out, "entities_decoded", count);
        sdsfree(decoded);
    } else if (strcmp(action, "encode") == 0 || strcmp(action, "escape") == 0) {
        cJSON *all_item = cJSON_GetObjectItem(args, "encode_all");
        int encode_all = all_item ? cJSON_IsTrue(all_item) : 0;
        sds encoded = html_encode_entities(text, encode_all);
        cJSON_AddStringToObject(out, "result", encoded);
        sdsfree(encoded);
    } else if (strcmp(action, "strip_tags") == 0 || strcmp(action, "strip") == 0) {
        cJSON *dec_item = cJSON_GetObjectItem(args, "decode_entities");
        int decode_entities = dec_item ? cJSON_IsTrue(dec_item) : 1;
        sds stripped = html_strip_tags(text, decode_entities);
        cJSON_AddStringToObject(out, "result", stripped);
        sdsfree(stripped);
    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: decode, encode, strip_tags");
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

const alpha_tool_t tool_html_codec = {
    .name = "html_codec",
    .aliases = {"html_entity_decode", "html_entities", "html_unescape"},
    .category = "codec",
    .description = "Encode, decode HTML5/XML entities (&amp;, &quot;, &#39;, &#x20AC;), and strip HTML tags safely.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"decode\", \"encode\", \"strip_tags\"], \"description\": \"Action to perform\"},\n"
                   "    \"text\": {\"type\": \"string\", \"description\": \"HTML or text content to process\"},\n"
                   "    \"encode_all\": {\"type\": \"boolean\", \"description\": \"For encode action: encode non-ASCII characters as numeric entities\"},\n"
                   "    \"decode_entities\": {\"type\": \"boolean\", \"description\": \"For strip_tags action: decode inner entities after stripping\"}\n"
                   "  },\n"
                   "  \"required\": [\"text\"]\n"
                   "}",
    .run = tool_html_codec_run
};
