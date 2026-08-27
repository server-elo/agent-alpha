#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_hex_pattern_exact(void) {
    TEST_BEGIN("hex_pattern_search: exact byte signature matching");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec83ec2048895c2410");
    cJSON_AddStringToObject(args, "pattern", "83 EC 20");

    sds res = tools_run("hex_pattern_search", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "hex_pattern_search returns result");
    CHECK(strstr(res, "\"total_matches\":1") != NULL, "finds exact 1 match");
    CHECK(strstr(res, "[3]") != NULL, "finds matching offset index at byte 3");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "valid json result");
    if (parsed) {
        cJSON *matches = cJSON_GetObjectItem(parsed, "matches");
        CHECK(cJSON_IsArray(matches), "matches is an array");
        CHECK_EQ_INT(cJSON_GetArraySize(matches), 1, "array size is 1");
        cJSON_Delete(parsed);
    }
}

static void test_hex_pattern_wildcard(void) {
    TEST_BEGIN("hex_pattern_search: wildcard ?? byte signature matching");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "48895c2410558bec83ec204889742418");
    cJSON_AddStringToObject(args, "pattern", "48 89 ?? 24 ??");

    sds res = tools_run("hex_pattern_search", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "hex_pattern_search wildcard returns result");
    CHECK(strstr(res, "\"total_matches\":2") != NULL, "finds both wildcard occurrences");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "valid json result");
    if (parsed) {
        cJSON *matches = cJSON_GetObjectItem(parsed, "matches");
        CHECK(cJSON_IsArray(matches), "matches is array");
        CHECK_EQ_INT(cJSON_GetArraySize(matches), 2, "finds exactly 2 occurrences");
        cJSON_Delete(parsed);
    }
}

int main(void) {
    test_hex_pattern_exact();
    test_hex_pattern_wildcard();
    return test_report("test_hex_pattern");
}
