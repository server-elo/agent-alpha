#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

int main(void) {
    // 1: schema contains base64_codec
    {
        TEST_BEGIN("base64_codec schema");
        cJSON *schema = tools_schema();
        CHECK(schema != NULL, "tools_schema not null");
        char *js = cJSON_PrintUnformatted(schema);
        CHECK(js != NULL && strstr(js, "base64_codec") != NULL, "schema contains base64_codec");
        CHECK(js != NULL && strstr(js, "encode") != NULL, "schema has encode action");
        free(js);
        cJSON_Delete(schema);
    }
    // 2: RFC 4648 vectors - encode
    {
        TEST_BEGIN("base64 encode rfc vectors");
        struct { const char *plain; const char *b64; } vec[] = {
            {"", ""},
            {"f", "Zg=="},
            {"fo", "Zm8="},
            {"foo", "Zm9v"},
            {"foob", "Zm9vYg=="},
            {"fooba", "Zm9vYmE="},
            {"foobar", "Zm9vYmFy"},
            {"Hello World", "SGVsbG8gV29ybGQ="},
            {"Man", "TWFu"},
            {"any carnal pleasure.", "YW55IGNhcm5hbCBwbGVhc3VyZS4="},
        };
        for (size_t i=0;i<sizeof(vec)/sizeof(vec[0]);i++) {
            cJSON *args = cJSON_CreateObject();
            cJSON_AddStringToObject(args, "action", "encode");
            cJSON_AddStringToObject(args, "data", vec[i].plain);
            sds res = tools_run("base64_codec", args, ".");
            cJSON_Delete(args);
            CHECK(res != NULL, "encode returns non-null");
            cJSON *p = cJSON_Parse(res);
            CHECK(p != NULL, "encode returns valid json");
            if (p) {
                cJSON *d = cJSON_GetObjectItem(p, "data");
                CHECK(d && cJSON_IsString(d) && strcmp(d->valuestring, vec[i].b64)==0, "encode vector matches");
                cJSON_Delete(p);
            }
            sdsfree(res);
        }
    }
    // 3: decode vectors
    {
        TEST_BEGIN("base64 decode rfc vectors");
        struct { const char *b64; const char *plain; } vec[] = {
            {"Zg==", "f"},
            {"Zm8=", "fo"},
            {"Zm9v", "foo"},
            {"Zm9vYg==", "foob"},
            {"Zm9vYmE=", "fooba"},
            {"Zm9vYmFy", "foobar"},
            {"SGVsbG8gV29ybGQ=", "Hello World"},
            {"TWFu", "Man"},
        };
        for (size_t i=0;i<sizeof(vec)/sizeof(vec[0]);i++) {
            cJSON *args = cJSON_CreateObject();
            cJSON_AddStringToObject(args, "action", "decode");
            cJSON_AddStringToObject(args, "data", vec[i].b64);
            sds res = tools_run("base64_codec", args, ".");
            cJSON_Delete(args);
            cJSON *p = cJSON_Parse(res);
            CHECK(p != NULL, "decode returns valid json");
            if (p) {
                cJSON *d = cJSON_GetObjectItem(p, "data");
                CHECK(d && cJSON_IsString(d) && strcmp(d->valuestring, vec[i].plain)==0, "decode vector matches");
                cJSON_Delete(p);
            }
            sdsfree(res);
        }
    }
    // 4: roundtrip
    {
        TEST_BEGIN("base64 roundtrip");
        const char *samples[] = {"", "a", "ab", "abc", "Hello, base64! 123", "The quick brown fox jumps over the lazy dog", "0123456789", "!@#$%^&*()_+-=[]{}|;:,.<>?"};
        for (size_t i=0;i<sizeof(samples)/sizeof(samples[0]);i++) {
            cJSON *enc_args = cJSON_CreateObject();
            cJSON_AddStringToObject(enc_args, "action", "encode");
            cJSON_AddStringToObject(enc_args, "data", samples[i]);
            sds enc_res = tools_run("base64_codec", enc_args, ".");
            cJSON_Delete(enc_args);
            cJSON *enc_p = cJSON_Parse(enc_res);
            CHECK(enc_p != NULL, "roundtrip encode valid json");
            const char *b64 = "";
            if (enc_p) { cJSON *d = cJSON_GetObjectItem(enc_p, "data"); if (d) b64 = d->valuestring; }
            char *b64_copy = b64 ? strdup(b64) : strdup("");
            if (enc_p) cJSON_Delete(enc_p);
            sdsfree(enc_res);
            cJSON *dec_args = cJSON_CreateObject();
            cJSON_AddStringToObject(dec_args, "action", "decode");
            cJSON_AddStringToObject(dec_args, "data", b64_copy);
            sds dec_res = tools_run("base64_codec", dec_args, ".");
            cJSON_Delete(dec_args);
            cJSON *dec_p = cJSON_Parse(dec_res);
            CHECK(dec_p != NULL, "roundtrip decode valid json");
            if (dec_p) {
                cJSON *d = cJSON_GetObjectItem(dec_p, "data");
                CHECK(d && cJSON_IsString(d) && strcmp(d->valuestring, samples[i])==0, "roundtrip matches original");
                cJSON_Delete(dec_p);
            }
            free(b64_copy);
            sdsfree(dec_res);
        }
    }
    // 5: base64url encode/decode
    {
        TEST_BEGIN("base64url encode/decode");
        // bytes 0xFB 0xFF 0xFE encodes to +//+ in std, -__- in url (with padding variations)
        // Use a known sample: ">>>???" -> check url variant uses -_
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "encode_url");
        cJSON_AddStringToObject(args, "data", ">>>???");
        sds res = tools_run("base64_codec", args, ".");
        cJSON_Delete(args);
        cJSON *p = cJSON_Parse(res);
        CHECK(p != NULL, "encode_url valid json");
        char *url_b64 = NULL;
        if (p) { cJSON *d=cJSON_GetObjectItem(p,"data"); if(d) url_b64=strdup(d->valuestring); cJSON_Delete(p); }
        CHECK(url_b64 != NULL && strchr(url_b64, '+')==NULL && strchr(url_b64, '/')==NULL, "encode_url uses -_ not +/");
        // decode_url should invert
        cJSON *args2 = cJSON_CreateObject();
        cJSON_AddStringToObject(args2, "action", "decode_url");
        cJSON_AddStringToObject(args2, "data", url_b64 ? url_b64 : "");
        sds res2 = tools_run("base64_codec", args2, ".");
        cJSON_Delete(args2);
        cJSON *p2 = cJSON_Parse(res2);
        CHECK(p2 != NULL, "decode_url valid json");
        if (p2) { cJSON *d=cJSON_GetObjectItem(p2,"data"); CHECK(d && strcmp(d->valuestring, ">>>???")==0, "decode_url roundtrip"); cJSON_Delete(p2); }
        sdsfree(res); sdsfree(res2); free(url_b64);
    }
    // 6: hex encode/decode
    {
        TEST_BEGIN("hex encode/decode");
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "hex_encode");
        cJSON_AddStringToObject(args, "data", "Hello");
        sds res = tools_run("base64_codec", args, ".");
        cJSON_Delete(args);
        cJSON *p = cJSON_Parse(res);
        CHECK(p != NULL, "hex_encode valid json");
        if (p) { cJSON *d=cJSON_GetObjectItem(p,"data"); CHECK(d && strcmp(d->valuestring,"48656c6c6f")==0, "hex_encode Hello -> 48656c6c6f"); cJSON_Delete(p); }
        sdsfree(res);
        cJSON *args2 = cJSON_CreateObject();
        cJSON_AddStringToObject(args2, "action", "hex_decode");
        cJSON_AddStringToObject(args2, "data", "48656c6c6f");
        sds res2 = tools_run("base64_codec", args2, ".");
        cJSON_Delete(args2);
        cJSON *p2 = cJSON_Parse(res2);
        CHECK(p2 != NULL, "hex_decode valid json");
        if (p2) { cJSON *d=cJSON_GetObjectItem(p2,"data"); CHECK(d && strcmp(d->valuestring,"Hello")==0, "hex_decode roundtrip"); cJSON_Delete(p2); }
        sdsfree(res2);
        // hex empty
        cJSON *args3 = cJSON_CreateObject();
        cJSON_AddStringToObject(args3, "action", "hex_encode");
        cJSON_AddStringToObject(args3, "data", "");
        sds res3 = tools_run("base64_codec", args3, ".");
        cJSON_Delete(args3);
        cJSON *p3=cJSON_Parse(res3);
        CHECK(p3 && strcmp(cJSON_GetObjectItem(p3,"data")->valuestring,"")==0, "hex_encode empty");
        if(p3) cJSON_Delete(p3);
        sdsfree(res3);
    }
    // 7: error handling
    {
        TEST_BEGIN("base64 error handling");
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "decode");
        cJSON_AddStringToObject(args, "data", "!!!not_b64!!!");
        sds res = tools_run("base64_codec", args, ".");
        cJSON_Delete(args);
        CHECK(res && strstr(res, "ERROR") != NULL, "decode invalid chars returns ERROR");
        sdsfree(res);
        cJSON *args2 = cJSON_CreateObject();
        cJSON_AddStringToObject(args2, "action", "hex_decode");
        cJSON_AddStringToObject(args2, "data", "abc"); // odd length
        sds res2 = tools_run("base64_codec", args2, ".");
        cJSON_Delete(args2);
        CHECK(res2 && strstr(res2, "ERROR") != NULL, "hex_decode odd length ERROR");
        sdsfree(res2);
        cJSON *args3 = cJSON_CreateObject();
        cJSON_AddStringToObject(args3, "action", "bogus_action");
        cJSON_AddStringToObject(args3, "data", "hello");
        sds res3 = tools_run("base64_codec", args3, ".");
        cJSON_Delete(args3);
        CHECK(res3 && strstr(res3, "ERROR") != NULL, "unknown action ERROR");
        sdsfree(res3);
    }
    // 8: alias names
    {
        TEST_BEGIN("base64 alias names");
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "encode");
        cJSON_AddStringToObject(args, "data", "test");
        sds r1 = tools_run("base64", args, ".");
        cJSON_Delete(args);
        cJSON *args2 = cJSON_CreateObject();
        cJSON_AddStringToObject(args2, "action", "encode");
        cJSON_AddStringToObject(args2, "data", "test");
        sds r2 = tools_run("b64", args2, ".");
        cJSON_Delete(args2);
        CHECK(r1 && r2 && strcmp(r1,r2)==0, "alias b64 same as base64_codec");
        sdsfree(r1); sdsfree(r2);
    }
    // 9: whitespace tolerance
    {
        TEST_BEGIN("base64 whitespace tolerance");
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "decode");
        cJSON_AddStringToObject(args, "data", "SGVs bG8g\nV29ybGQ=");
        sds res = tools_run("base64_codec", args, ".");
        cJSON_Delete(args);
        cJSON *p=cJSON_Parse(res);
        CHECK(p && strcmp(cJSON_GetObjectItem(p,"data")->valuestring,"Hello World")==0, "whitespace tolerant decode");
        if(p) cJSON_Delete(p);
        sdsfree(res);
    }
    return test_report("test_base64_codec");
}
