/* tool_codecs.c — RFC 4648 Base64 & Base64URL + Hex codec (pure C) */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_base64_codec_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "encode";
    const char *input = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    if (!input) input = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    if (!input) input = cJSON_GetStringValue(cJSON_GetObjectItem(args, "input"));
    if (!input) input = "";
    size_t in_len = strlen(input);

    if (strcmp(action, "encode") == 0 || strcmp(action, "encode_std") == 0) {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t out_len = ((in_len + 2) / 3) * 4;
        char *out = (char*)malloc(out_len + 1);
        if (!out) return sdsnew("ERROR: alloc failed");
        size_t oi = 0;
        for (size_t i = 0; i < in_len; i += 3) {
            uint32_t a = (unsigned char)input[i];
            uint32_t b = (i + 1 < in_len) ? (unsigned char)input[i+1] : 0;
            uint32_t c = (i + 2 < in_len) ? (unsigned char)input[i+2] : 0;
            uint32_t triple = (a << 16) | (b << 8) | c;
            out[oi++] = tbl[(triple >> 18) & 0x3F];
            out[oi++] = tbl[(triple >> 12) & 0x3F];
            out[oi++] = (i + 1 < in_len) ? tbl[(triple >> 6) & 0x3F] : '=';
            out[oi++] = (i + 2 < in_len) ? tbl[triple & 0x3F] : '=';
        }
        out[oi] = 0;
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "encode");
        cJSON_AddStringToObject(obj, "encoding", "base64_std");
        cJSON_AddNumberToObject(obj, "input_len", (double)in_len);
        cJSON_AddStringToObject(obj, "data", out);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); free(out);
        return res;
    }
    if (strcmp(action, "encode_url") == 0 || strcmp(action, "encodeurl") == 0) {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        size_t out_len = ((in_len + 2) / 3) * 4;
        char *out = (char*)malloc(out_len + 1);
        if (!out) return sdsnew("ERROR: alloc failed");
        size_t oi = 0;
        for (size_t i = 0; i < in_len; i += 3) {
            uint32_t a = (unsigned char)input[i];
            uint32_t b = (i + 1 < in_len) ? (unsigned char)input[i+1] : 0;
            uint32_t c = (i + 2 < in_len) ? (unsigned char)input[i+2] : 0;
            uint32_t triple = (a << 16) | (b << 8) | c;
            out[oi++] = tbl[(triple >> 18) & 0x3F];
            out[oi++] = tbl[(triple >> 12) & 0x3F];
            out[oi++] = (i + 1 < in_len) ? tbl[(triple >> 6) & 0x3F] : '=';
            out[oi++] = (i + 2 < in_len) ? tbl[triple & 0x3F] : '=';
        }
        out[oi] = 0;
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "encode_url");
        cJSON_AddStringToObject(obj, "encoding", "base64url");
        cJSON_AddNumberToObject(obj, "input_len", (double)in_len);
        cJSON_AddStringToObject(obj, "data", out);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); free(out);
        return res;
    }
    if (strcmp(action, "hex_encode") == 0 || strcmp(action, "hex") == 0) {
        static const char hx[] = "0123456789abcdef";
        char *out = (char*)malloc(in_len * 2 + 1);
        if (!out) return sdsnew("ERROR: alloc failed");
        for (size_t i = 0; i < in_len; i++) {
            out[i*2] = hx[((unsigned char)input[i] >> 4) & 0xF];
            out[i*2+1] = hx[(unsigned char)input[i] & 0xF];
        }
        out[in_len*2] = 0;
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "hex_encode");
        cJSON_AddNumberToObject(obj, "input_len", (double)in_len);
        cJSON_AddStringToObject(obj, "data", out);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); free(out);
        return res;
    }
    if (strcmp(action, "decode") == 0 || strcmp(action, "decode_std") == 0 ||
        strcmp(action, "decode_url") == 0 || strcmp(action, "decodeurl") == 0 ||
        strcmp(action, "hex_decode") == 0) {
        int is_hex = (strcmp(action, "hex_decode") == 0);
        int is_url = (strcmp(action, "decode_url") == 0 || strcmp(action, "decodeurl") == 0);
        if (is_hex) {
            if (in_len % 2 != 0) return sdsnew("ERROR: hex_decode requires even-length hex string");
            size_t out_len = in_len / 2;
            char *out = (char*)malloc(out_len + 1);
            if (!out) return sdsnew("ERROR: alloc failed");
            for (size_t i = 0; i < out_len; i++) {
                char hi = input[i*2], lo = input[i*2+1];
                int hv = -1, lv = -1;
                if (hi >= '0' && hi <= '9') hv = hi - '0';
                else if (hi >= 'a' && hi <= 'f') hv = hi - 'a' + 10;
                else if (hi >= 'A' && hi <= 'F') hv = hi - 'A' + 10;
                if (lo >= '0' && lo <= '9') lv = lo - '0';
                else if (lo >= 'a' && lo <= 'f') lv = lo - 'a' + 10;
                else if (lo >= 'A' && lo <= 'F') lv = lo - 'A' + 10;
                if (hv < 0 || lv < 0) { free(out); return sdscatprintf(sdsempty(), "ERROR: invalid hex char at pos %zu", i*2); }
                out[i] = (char)((hv << 4) | lv);
            }
            out[out_len] = 0;
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "action", "hex_decode");
            cJSON_AddNumberToObject(obj, "input_len", (double)in_len);
            cJSON_AddNumberToObject(obj, "output_len", (double)out_len);
            cJSON_AddStringToObject(obj, "data", out);
            char *js = cJSON_PrintUnformatted(obj);
            sds res = sdsnew(js ? js : "{}");
            free(js); cJSON_Delete(obj); free(out);
            return res;
        }
        int rev[256];
        for (int i = 0; i < 256; i++) rev[i] = -1;
        const char *tbl_std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const char *tbl_url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const char *tbl = is_url ? tbl_url : tbl_std;
        for (int i = 0; i < 64; i++) rev[(unsigned char)tbl[i]] = i;
        rev[(unsigned char)'='] = 0;
        size_t valid = 0;
        for (size_t i = 0; i < in_len; i++) {
            unsigned char c = input[i];
            if (c==' '||c=='\n'||c=='\r'||c=='\t') continue;
            if (rev[c]==-1) return sdscatprintf(sdsempty(), "ERROR: invalid base64 character '%c' at pos %zu", c, i);
            valid++;
        }
        if (valid % 4 != 0) return sdsnew("ERROR: base64 length must be multiple of 4 (after trimming whitespace)");
        size_t out_cap = (valid / 4) * 3;
        char *out = (char*)malloc(out_cap + 1);
        if (!out) return sdsnew("ERROR: alloc failed");
        size_t oi = 0;
        char *filt = (char*)malloc(valid + 1);
        size_t fi = 0;
        for (size_t i = 0; i < in_len; i++) {
            unsigned char c = input[i];
            if (c==' '||c=='\n'||c=='\r'||c=='\t') continue;
            filt[fi++] = c;
        }
        for (size_t i = 0; i < valid; i += 4) {
            int a = rev[(unsigned char)filt[i]];
            int b = rev[(unsigned char)filt[i+1]];
            int c = rev[(unsigned char)filt[i+2]];
            int d = rev[(unsigned char)filt[i+3]];
            uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
            out[oi++] = (char)((triple >> 16) & 0xFF);
            if (filt[i+2] != '=') out[oi++] = (char)((triple >> 8) & 0xFF);
            if (filt[i+3] != '=') out[oi++] = (char)(triple & 0xFF);
        }
        free(filt);
        out[oi] = 0;
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", is_url ? "decode_url" : "decode");
        cJSON_AddNumberToObject(obj, "input_len", (double)in_len);
        cJSON_AddNumberToObject(obj, "output_len", (double)oi);
        cJSON_AddStringToObject(obj, "data", out);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); free(out);
        return res;
    }
    return sdscatprintf(sdsempty(), "ERROR: unknown base64_codec action '%s' (use encode/decode/encode_url/decode_url/hex_encode/hex_decode)", action);
}

static const alpha_tool_t tool_base64_codec = {
    .name = "base64_codec",
    .aliases = {"base64", "b64", NULL},
    .category = "codec",
    .description = "RFC 4648 Base64 & Base64URL + Hex codec (pure C). Actions: encode (std), decode, encode_url, decode_url, hex_encode, hex_decode. Handles padding, whitespace-tolerant decode, and binary-safe output.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"base64_codec\",\"description\":\"RFC 4648 Base64 & Base64URL + Hex codec (pure C). Actions: encode (std), decode, encode_url, decode_url, hex_encode, hex_decode. Handles padding, whitespace-tolerant decode, and binary-safe output.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"encode\",\"decode\",\"encode_url\",\"decode_url\",\"hex_encode\",\"hex_decode\"]},\"data\":{\"type\":\"string\",\"description\":\"Input string to encode/decode\"},\"text\":{\"type\":\"string\"},\"input\":{\"type\":\"string\"}},\"required\":[]}}}",
    .run = tool_base64_codec_run
};
