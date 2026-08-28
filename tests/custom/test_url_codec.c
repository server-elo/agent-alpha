#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static void test_url_parse_components(void) {
    TEST_BEGIN("url_codec_parser: parse RFC 3986 URL components and query map");
    const char *url_str = "https://admin:secret123@api.sub.example.com:8443/v2/items/query?q=deep%20learning&limit=50&active=true#section_results";
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "parse");
    cJSON_AddStringToObject(args, "url", url_str);

    sds res = tools_run("url_codec_parser", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned");
    cJSON *p = cJSON_Parse(res);
    CHECK(p != NULL, "valid json returned");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "action")), "parse") == 0, "action confirmed");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "scheme")), "https") == 0, "scheme is https");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "user")), "admin") == 0, "user is admin");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "pass")), "secret123") == 0, "pass is secret123");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "host")), "api.sub.example.com") == 0, "host parsed");
    CHECK_EQ_INT(cJSON_GetNumberValue(cJSON_GetObjectItem(p, "port")), 8443, "port is 8443");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "path")), "/v2/items/query") == 0, "path parsed");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "fragment")), "section_results") == 0, "fragment parsed");

    cJSON *params = cJSON_GetObjectItem(p, "params");
    CHECK(params != NULL && cJSON_IsObject(params), "params is an object");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(params, "q")), "deep learning") == 0, "q parameter URL-decoded");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(params, "limit")), "50") == 0, "limit is 50");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(params, "active")), "true") == 0, "active is true");

    if (p) cJSON_Delete(p);
    sdsfree(res);
}

static void test_url_build(void) {
    TEST_BEGIN("url_codec_parser: canonical URL build");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "build");
    cJSON_AddStringToObject(args, "scheme", "http");
    cJSON_AddStringToObject(args, "host", "localhost");
    cJSON_AddNumberToObject(args, "port", 8080);
    cJSON_AddStringToObject(args, "path", "/api/v1/health");
    cJSON_AddStringToObject(args, "query", "verbose=1");
    cJSON_AddStringToObject(args, "fragment", "ok");

    sds res = tools_run("url_codec_parser", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned");
    cJSON *p = cJSON_Parse(res);
    CHECK(p != NULL, "valid json returned");
    const char *built = cJSON_GetStringValue(cJSON_GetObjectItem(p, "url"));
    CHECK(built != NULL, "built url present");
    CHECK(strcmp(built, "http://localhost:8080/api/v1/health?verbose=1#ok") == 0, "canonical URL matches");

    if (p) cJSON_Delete(p);
    sdsfree(res);
}

static void test_percent_encode_decode(void) {
    TEST_BEGIN("url_codec_parser: RFC 3986 percent encode & decode");
    const char *raw_text = "Hello World! @#$^&* ()_+";
    cJSON *args_enc = cJSON_CreateObject();
    cJSON_AddStringToObject(args_enc, "action", "encode");
    cJSON_AddStringToObject(args_enc, "text", raw_text);

    sds res_enc = tools_run("url_codec_parser", args_enc, ".");
    cJSON_Delete(args_enc);

    cJSON *p_enc = cJSON_Parse(res_enc);
    CHECK(p_enc != NULL, "valid json returned for encode");
    const char *encoded = cJSON_GetStringValue(cJSON_GetObjectItem(p_enc, "encoded"));
    CHECK(encoded != NULL && strstr(encoded, "Hello%20World") != NULL, "encoded contains %20");

    /* Decode back */
    cJSON *args_dec = cJSON_CreateObject();
    cJSON_AddStringToObject(args_dec, "action", "decode");
    cJSON_AddStringToObject(args_dec, "text", encoded);

    sds res_dec = tools_run("url_codec_parser", args_dec, ".");
    cJSON_Delete(args_dec);

    cJSON *p_dec = cJSON_Parse(res_dec);
    CHECK(p_dec != NULL, "valid json returned for decode");
    const char *decoded = cJSON_GetStringValue(cJSON_GetObjectItem(p_dec, "decoded"));
    CHECK(decoded != NULL && strcmp(decoded, raw_text) == 0, "roundtrip decoded matches original text");

    if (p_enc) cJSON_Delete(p_enc);
    if (p_dec) cJSON_Delete(p_dec);
    sdsfree(res_enc);
    sdsfree(res_dec);
}

static void test_levenshtein_distance(void) {
    TEST_BEGIN("url_codec_parser: Levenshtein distance & similarity");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "levenshtein");
    cJSON_AddStringToObject(args, "a", "kitten");
    cJSON_AddStringToObject(args, "b", "sitting");

    sds res = tools_run("url_codec_parser", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned");
    cJSON *p = cJSON_Parse(res);
    CHECK(p != NULL, "valid json returned");
    CHECK_EQ_INT(cJSON_GetNumberValue(cJSON_GetObjectItem(p, "distance")), 3, "kitten -> sitting distance is 3");
    double sim = cJSON_GetNumberValue(cJSON_GetObjectItem(p, "similarity"));
    CHECK(sim >= 0.55 && sim <= 0.60, "similarity ratio within expected range");

    if (p) cJSON_Delete(p);
    sdsfree(res);
}

static void test_adversarial_and_schema(void) {
    TEST_BEGIN("url_codec_parser: adversarial rejection & schema registration");

    /* Missing url in parse */
    cJSON *args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(args1, "action", "parse");
    sds res1 = tools_run("url_codec_parser", args1, ".");
    cJSON_Delete(args1);
    CHECK(strstr(res1, "ERROR: url parameter required") != NULL, "missing url rejected");
    sdsfree(res1);

    /* Missing host in build */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "build");
    sds res2 = tools_run("url_codec_parser", args2, ".");
    cJSON_Delete(args2);
    CHECK(strstr(res2, "ERROR: host parameter required") != NULL, "missing host rejected");
    sdsfree(res2);

    /* Schema presence */
    cJSON *schema = tools_schema();
    CHECK(schema != NULL, "schema parsed");
    char *s = cJSON_PrintUnformatted(schema);
    CHECK(s != NULL, "schema printed");
    CHECK(strstr(s, "\"name\":\"url_codec_parser\"") != NULL, "schema contains url_codec_parser");
    free(s);
    if (schema) cJSON_Delete(schema);
}

int main(void) {
    test_url_parse_components();
    test_url_build();
    test_percent_encode_decode();
    test_levenshtein_distance();
    test_adversarial_and_schema();
    return test_report("test_url_codec");
}
