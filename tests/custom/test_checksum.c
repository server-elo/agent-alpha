#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static void test_crc32_known_vector(void) {
    TEST_BEGIN("checksum crc32 known vector 123456789");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "algorithm", "crc32");
    cJSON_AddStringToObject(args, "text", "123456789");
    sds res = tools_run("checksum", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "crc32 returns response");
    CHECK(strstr(res, "\"algorithm\":\"crc32\"") != NULL, "algorithm echoed");
    CHECK(strstr(res, "\"hex\":\"cbf43926\"") != NULL, "crc32 hex matches CBF43926");
    CHECK(strstr(res, "\"input_bytes\":9") != NULL, "input_bytes 9");
    CHECK(strstr(res, "\"value\":3421780262") != NULL, "crc32 decimal 3421780262");
    cJSON *p = cJSON_Parse(res);
    CHECK(p != NULL, "valid json");
    if (p) cJSON_Delete(p);
    sdsfree(res);
}

static void test_adler32_wikipedia(void) {
    TEST_BEGIN("checksum adler32 Wikipedia");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "algorithm", "adler32");
    cJSON_AddStringToObject(args, "text", "Wikipedia");
    sds res = tools_run("checksum", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "adler32 returns response");
    CHECK(strstr(res, "\"hex\":\"11e60398\"") != NULL, "adler32 hex 11e60398");
    CHECK(strstr(res, "\"input_bytes\":9") != NULL, "input_bytes 9");
    CHECK(strstr(res, "\"value\":300286872") != NULL, "adler32 decimal 300286872");
    sdsfree(res);
}

static void test_fnv1a64_foobar(void) {
    TEST_BEGIN("checksum fnv1a64 foobar");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "algorithm", "fnv1a64");
    cJSON_AddStringToObject(args, "text", "foobar");
    sds res = tools_run("checksum", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "fnv1a64 returns response");
    CHECK(strstr(res, "\"hex\":\"85944171f73967e8\"") != NULL, "fnv1a64 hex 85944171f73967e8");
    CHECK(strstr(res, "\"input_bytes\":6") != NULL, "input_bytes 6");
    // empty string vector
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "algorithm", "fnv1a64");
    cJSON_AddStringToObject(args2, "text", "");
    sds res2 = tools_run("checksum", args2, ".");
    cJSON_Delete(args2);
    CHECK(strstr(res2, "\"hex\":\"cbf29ce484222325\"") != NULL, "fnv1a64 empty hex cbf29ce484222325");
    sdsfree(res);
    sdsfree(res2);
}

static void test_hex_data_path(void) {
    TEST_BEGIN("checksum hex data path matches text path");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "algorithm", "crc32");
    cJSON_AddStringToObject(args, "data", "313233343536373839");
    sds res = tools_run("checksum", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "hex data crc32 returns response");
    CHECK(strstr(res, "\"hex\":\"cbf43926\"") != NULL, "hex data crc32 matches text vector");
    CHECK(strstr(res, "\"input_bytes\":9") != NULL, "hex data input_bytes 9");
    sdsfree(res);

    // adler32 via hex data for "Wikipedia" = 57696B697065646961
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "algorithm", "adler32");
    cJSON_AddStringToObject(args2, "data", "57696B697065646961");
    sds res2 = tools_run("checksum", args2, ".");
    cJSON_Delete(args2);
    CHECK(strstr(res2, "\"hex\":\"11e60398\"") != NULL, "hex data adler32 matches");
    sdsfree(res2);
}

static void test_empty_input(void) {
    TEST_BEGIN("checksum empty input vectors");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "algorithm", "crc32");
    cJSON_AddStringToObject(args, "text", "");
    sds res = tools_run("checksum", args, ".");
    cJSON_Delete(args);
    CHECK(strstr(res, "\"hex\":\"00000000\"") != NULL, "crc32 empty = 00000000");
    CHECK(strstr(res, "\"value\":0") != NULL, "crc32 empty value 0");
    sdsfree(res);

    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "algorithm", "adler32");
    cJSON_AddStringToObject(args2, "text", "");
    sds res2 = tools_run("checksum", args2, ".");
    cJSON_Delete(args2);
    CHECK(strstr(res2, "\"hex\":\"00000001\"") != NULL, "adler32 empty = 00000001");
    CHECK(strstr(res2, "\"value\":1") != NULL, "adler32 empty value 1");
    sdsfree(res2);
}

static void test_error_handling(void) {
    TEST_BEGIN("checksum error handling");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "hello");
    sds res = tools_run("checksum", args, ".");
    cJSON_Delete(args);
    CHECK(strstr(res, "ERROR: algorithm required") != NULL, "missing algorithm rejected");
    sdsfree(res);

    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "algorithm", "md5");
    cJSON_AddStringToObject(args2, "text", "hello");
    sds res2 = tools_run("checksum", args2, ".");
    cJSON_Delete(args2);
    CHECK(strstr(res2, "ERROR: unknown checksum algorithm") != NULL, "unknown algorithm rejected");
    sdsfree(res2);

    cJSON *args3 = cJSON_CreateObject();
    cJSON_AddStringToObject(args3, "algorithm", "crc32");
    cJSON_AddStringToObject(args3, "data", "abc");
    sds res3 = tools_run("checksum", args3, ".");
    cJSON_Delete(args3);
    CHECK(strstr(res3, "ERROR: hex data length must be an even") != NULL, "odd hex rejected");
    sdsfree(res3);

    cJSON *args4 = cJSON_CreateObject();
    cJSON_AddStringToObject(args4, "algorithm", "crc32");
    cJSON_AddStringToObject(args4, "data", "zz");
    sds res4 = tools_run("checksum", args4, ".");
    cJSON_Delete(args4);
    CHECK(strstr(res4, "ERROR: data contains non-hex") != NULL, "non-hex rejected");
    sdsfree(res4);

    cJSON *args5 = cJSON_CreateObject();
    cJSON_AddStringToObject(args5, "algorithm", "crc32");
    sds res5 = tools_run("checksum", args5, ".");
    cJSON_Delete(args5);
    CHECK(strstr(res5, "ERROR: data (hex) or text input required") != NULL, "missing input rejected");
    sdsfree(res5);
}

static void test_schema_contains_checksum(void) {
    TEST_BEGIN("checksum schema registration");
    cJSON *schema = tools_schema();
    CHECK(schema != NULL, "schema parsed");
    char *s = cJSON_PrintUnformatted(schema);
    CHECK(s != NULL, "schema printed");
    CHECK(strstr(s, "\"name\":\"checksum\"") != NULL, "schema contains checksum");
    CHECK(strstr(s, "crc32") != NULL, "schema mentions crc32");
    free(s);
    cJSON_Delete(schema);
}

int main(void) {
    test_crc32_known_vector();
    test_adler32_wikipedia();
    test_fnv1a64_foobar();
    test_hex_data_path();
    test_empty_input();
    test_error_handling();
    test_schema_contains_checksum();
    return test_report("test_checksum");
}
