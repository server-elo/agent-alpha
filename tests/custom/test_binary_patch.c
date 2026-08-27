#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_binary_patch_basic(void) {
    TEST_BEGIN("binary_patch_apply: basic in-memory byte substitution");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec83ec2048895c2410");
    cJSON_AddNumberToObject(args, "offset", 3);
    cJSON_AddStringToObject(args, "patch", "909090");

    sds res = tools_run("binary_patch_apply", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "binary_patch_apply returns response");
    CHECK(strstr(res, "\"action\":\"binary_patch_apply\"") != NULL, "action confirmed");
    CHECK(strstr(res, "\"original\":\"83ec20\"") != NULL, "original bytes captured for rollback");
    CHECK(strstr(res, "\"patched\":\"558bec90909048895c2410\"") != NULL, "patched string matches replacement opcodes");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "valid json returned");
    if (parsed) {
        cJSON_Delete(parsed);
    }
}

static void test_binary_patch_bounds(void) {
    TEST_BEGIN("binary_patch_apply: bounds safety check");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec");
    cJSON_AddNumberToObject(args, "offset", 2);
    cJSON_AddStringToObject(args, "patch", "90909090");

    sds res = tools_run("binary_patch_apply", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "bounds rejection response returned");
    CHECK(strstr(res, "ERROR: patch bounds exceed data buffer size") != NULL, "out of bounds patch safely refused");
    sdsfree(res);
}

static void test_binary_patch_negative_offset(void) {
    TEST_BEGIN("binary_patch_apply: negative offset rejection check");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec83ec20");
    cJSON_AddNumberToObject(args, "offset", -1);
    cJSON_AddStringToObject(args, "patch", "9090");

    sds res = tools_run("binary_patch_apply", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "negative offset response returned");
    CHECK(strstr(res, "ERROR: offset must be non-negative") != NULL, "negative offset safely rejected");
    sdsfree(res);
}

static void test_binary_patch_invalid_hex(void) {
    TEST_BEGIN("binary_patch_apply: invalid non-hex rejection check");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bZZ");
    cJSON_AddNumberToObject(args, "offset", 0);
    cJSON_AddStringToObject(args, "patch", "9090");

    sds res = tools_run("binary_patch_apply", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "invalid hex response returned");
    CHECK(strstr(res, "ERROR: invalid non-hex character") != NULL, "non-hex data safely rejected");
    sdsfree(res);
}

int main(void) {
    test_binary_patch_basic();
    test_binary_patch_bounds();
    test_binary_patch_negative_offset();
    test_binary_patch_invalid_hex();
    return test_report("test_binary_patch");
}
