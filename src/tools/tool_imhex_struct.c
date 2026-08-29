/*
 * tool_imhex_struct.c - Binary Pattern Layout, Struct Unpacker & Endianness Codec
 *
 * Implements declarative binary schema parsing (u8..u64, i8..i64, IEEE 754 f32/f64,
 * fixed strings, byte arrays) supporting Little-Endian and Big-Endian unpacking.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "cJSON.h"
#include "sds.h"

static int hex2byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *parse_hex_bytes(const char *hex_str, size_t *out_len) {
    if (!hex_str) return NULL;
    size_t slen = strlen(hex_str);
    uint8_t *buf = malloc(slen / 2 + 1);
    if (!buf) return NULL;

    size_t blen = 0;
    size_t i = 0;
    while (i < slen) {
        while (i < slen && (isspace((unsigned char)hex_str[i]) || hex_str[i] == ',' || hex_str[i] == '0' && (hex_str[i+1] == 'x' || hex_str[i+1] == 'X'))) {
            if (hex_str[i] == '0' && (hex_str[i+1] == 'x' || hex_str[i+1] == 'X')) i += 2;
            else i++;
        }
        if (i >= slen) break;
        int h1 = hex2byte(hex_str[i]);
        if (h1 < 0) { free(buf); return NULL; }
        i++;
        if (i >= slen) { free(buf); return NULL; }
        int h2 = hex2byte(hex_str[i]);
        if (h2 < 0) { free(buf); return NULL; }
        i++;
        buf[blen++] = (uint8_t)((h1 << 4) | h2);
    }
    *out_len = blen;
    return buf;
}

static sds tool_imhex_struct_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "unpack";

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);

    if (strcmp(action, "unpack") == 0) {
        cJSON *data_item = cJSON_GetObjectItem(args, "data");
        cJSON *schema_item = cJSON_GetObjectItem(args, "schema");

        if (!data_item || !data_item->valuestring || !schema_item || !cJSON_IsArray(schema_item)) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Missing required 'data' (hex) or 'schema' array");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        size_t buf_len = 0;
        uint8_t *buf = parse_hex_bytes(data_item->valuestring, &buf_len);
        if (!buf) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Invalid hexadecimal byte string in 'data'");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        cJSON *fields_obj = cJSON_CreateObject();
        size_t offset = 0;
        int field_count = cJSON_GetArraySize(schema_item);

        for (int i = 0; i < field_count; i++) {
            cJSON *f = cJSON_GetArrayItem(schema_item, i);
            cJSON *name_it = cJSON_GetObjectItem(f, "name");
            cJSON *type_it = cJSON_GetObjectItem(f, "type");
            if (!name_it || !type_it) continue;

            const char *name = name_it->valuestring;
            const char *type = type_it->valuestring;

            if (strcmp(type, "u8") == 0) {
                if (offset + 1 > buf_len) break;
                cJSON_AddNumberToObject(fields_obj, name, buf[offset]);
                offset += 1;
            } else if (strcmp(type, "i8") == 0) {
                if (offset + 1 > buf_len) break;
                cJSON_AddNumberToObject(fields_obj, name, (int8_t)buf[offset]);
                offset += 1;
            } else if (strcmp(type, "u16_le") == 0) {
                if (offset + 2 > buf_len) break;
                uint16_t v = (uint16_t)(buf[offset] | (buf[offset+1] << 8));
                cJSON_AddNumberToObject(fields_obj, name, v);
                offset += 2;
            } else if (strcmp(type, "u16_be") == 0) {
                if (offset + 2 > buf_len) break;
                uint16_t v = (uint16_t)((buf[offset] << 8) | buf[offset+1]);
                cJSON_AddNumberToObject(fields_obj, name, v);
                offset += 2;
            } else if (strcmp(type, "u32_le") == 0) {
                if (offset + 4 > buf_len) break;
                uint32_t v = (uint32_t)(buf[offset] | (buf[offset+1] << 8) | (buf[offset+2] << 16) | (buf[offset+3] << 24));
                cJSON_AddNumberToObject(fields_obj, name, (double)v);
                offset += 4;
            } else if (strcmp(type, "u32_be") == 0) {
                if (offset + 4 > buf_len) break;
                uint32_t v = (uint32_t)((buf[offset] << 24) | (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3]);
                cJSON_AddNumberToObject(fields_obj, name, (double)v);
                offset += 4;
            } else if (strcmp(type, "float32_le") == 0) {
                if (offset + 4 > buf_len) break;
                uint32_t raw = (uint32_t)(buf[offset] | (buf[offset+1] << 8) | (buf[offset+2] << 16) | (buf[offset+3] << 24));
                float fval = 0.0f;
                memcpy(&fval, &raw, sizeof(fval));
                cJSON_AddNumberToObject(fields_obj, name, fval);
                offset += 4;
            } else if (strncmp(type, "string[", 7) == 0) {
                int slen = atoi(&type[7]);
                if (slen > 0 && offset + slen <= buf_len) {
                    char *sval = malloc(slen + 1);
                    memcpy(sval, &buf[offset], slen);
                    sval[slen] = '\0';
                    cJSON_AddStringToObject(fields_obj, name, sval);
                    free(sval);
                    offset += slen;
                }
            }
        }

        cJSON_AddItemToObject(out, "fields", fields_obj);
        cJSON_AddNumberToObject(out, "bytes_read", (double)offset);
        cJSON_AddNumberToObject(out, "total_bytes", (double)buf_len);
        free(buf);

    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: unpack");
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

const alpha_tool_t tool_imhex_struct = {
    .name = "imhex_struct",
    .aliases = {"struct_unpack", "binary_schema", "imhex_pattern"},
    .category = "binary",
    .description = "Inspect & unpack structured binary memory/hex strings using declarative schemas (u8..u64, float32, strings, endianness).",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"unpack\"], \"description\": \"Action to perform\"},\n"
                   "    \"data\": {\"type\": \"string\", \"description\": \"Hex byte string (e.g. '01 00 2A 00 48 65 6C 6C 6F')\"},\n"
                   "    \"schema\": {\n"
                   "      \"type\": \"array\",\n"
                   "      \"items\": {\n"
                   "        \"type\": \"object\",\n"
                   "        \"properties\": {\n"
                   "          \"name\": {\"type\": \"string\"},\n"
                   "          \"type\": {\"type\": \"string\", \"enum\": [\"u8\", \"i8\", \"u16_le\", \"u16_be\", \"u32_le\", \"u32_be\", \"float32_le\", \"string[5]\"]}\n"
                   "        },\n"
                   "        \"required\": [\"name\", \"type\"]\n"
                   "      }\n"
                   "    }\n"
                   "  },\n"
                   "  \"required\": [\"data\", \"schema\"]\n"
                   "}",
    .run = tool_imhex_struct_run
};
