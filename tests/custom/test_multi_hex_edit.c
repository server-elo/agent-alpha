#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_multi_hex_edit_basic(void) {
    TEST_BEGIN("multi_hex_edit: atomic multi-location patching with rollbacks");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec83ec2048895c2410");

    cJSON *changes = cJSON_CreateArray();
    cJSON *c1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(c1, "offset", 0);
    cJSON_AddStringToObject(c1, "patch", "9090");
    cJSON_AddItemToArray(changes, c1);

    cJSON *c2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(c2, "offset", 3);
    cJSON_AddStringToObject(c2, "patch", "cc");
    cJSON_AddItemToArray(changes, c2);

    cJSON_AddItemToObject(args, "changes", changes);

    sds res = tools_run("multi_hex_edit", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "multi_hex_edit returns response");
    CHECK(strstr(res, "\"action\":\"multi_hex_edit\"") != NULL, "action confirmed");
    CHECK(strstr(res, "\"applied_changes\":2") != NULL, "applied 2 changes");
    CHECK(strstr(res, "\"original\":\"558b\"") != NULL, "rollback 1 captured");
    CHECK(strstr(res, "\"original\":\"83\"") != NULL, "rollback 2 captured");
    CHECK(strstr(res, "\"patched\":\"9090ecccec2048895c2410\"") != NULL, "correct patched string");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "valid json returned");
    if (parsed) cJSON_Delete(parsed);
}

static void test_multi_hex_edit_adversarial_negative_offset(void) {
    TEST_BEGIN("multi_hex_edit: adversarial negative offset rejection");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec");

    cJSON *changes = cJSON_CreateArray();
    cJSON *c1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(c1, "offset", -1);
    cJSON_AddStringToObject(c1, "patch", "90");
    cJSON_AddItemToArray(changes, c1);
    cJSON_AddItemToObject(args, "changes", changes);

    sds res = tools_run("multi_hex_edit", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "negative offset error returned");
    CHECK(strstr(res, "ERROR: offset must be non-negative") != NULL, "negative offset safely rejected");
    sdsfree(res);
}

static void test_multi_hex_edit_adversarial_invalid_hex(void) {
    TEST_BEGIN("multi_hex_edit: adversarial non-hex character rejection");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bZZ");

    cJSON *changes = cJSON_CreateArray();
    cJSON *c1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(c1, "offset", 0);
    cJSON_AddStringToObject(c1, "patch", "90");
    cJSON_AddItemToArray(changes, c1);
    cJSON_AddItemToObject(args, "changes", changes);

    sds res = tools_run("multi_hex_edit", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "invalid hex error returned");
    CHECK(strstr(res, "ERROR: invalid non-hex character") != NULL, "non-hex data safely rejected");
    sdsfree(res);
}

static void test_multi_hex_edit_adversarial_bounds(void) {
    TEST_BEGIN("multi_hex_edit: adversarial out-of-bounds rejection");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "data", "558bec");

    cJSON *changes = cJSON_CreateArray();
    cJSON *c1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(c1, "offset", 2);
    cJSON_AddStringToObject(c1, "patch", "909090");
    cJSON_AddItemToArray(changes, c1);
    cJSON_AddItemToObject(args, "changes", changes);

    sds res = tools_run("multi_hex_edit", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "bounds error returned");
    CHECK(strstr(res, "ERROR: patch bounds exceed data buffer size") != NULL, "out-of-bounds safely rejected");
    sdsfree(res);
}

int main(void) {
    test_multi_hex_edit_basic();
    test_multi_hex_edit_adversarial_negative_offset();
    test_multi_hex_edit_adversarial_invalid_hex();
    test_multi_hex_edit_adversarial_bounds();
    return test_report("test_multi_hex_edit");
}
