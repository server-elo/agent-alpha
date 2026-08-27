#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_boyer_moore_basic(void) {
    TEST_BEGIN("boyer_moore_search: exact pattern matching with heuristics");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "HERE IS A SIMPLE EXAMPLE");
    cJSON_AddStringToObject(args, "pattern", "EXAMPLE");

    sds res = tools_run("boyer_moore_search", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "boyer_moore_search returns response");
    CHECK(strstr(res, "\"action\":\"boyer_moore_search\"") != NULL, "action confirmed");
    CHECK(strstr(res, "\"total_matches\":1") != NULL, "found exactly 1 match");
    CHECK(strstr(res, "\"matches\":[17]") != NULL, "correct offset index matched");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "valid json returned");
    if (parsed) cJSON_Delete(parsed);
}

static void test_boyer_moore_multiple_matches(void) {
    TEST_BEGIN("boyer_moore_search: multiple occurrences with good suffix shift");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "ABAAABCDABAAAB");
    cJSON_AddStringToObject(args, "pattern", "ABAAAB");

    sds res = tools_run("boyer_moore_search", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "multiple match response returned");
    CHECK(strstr(res, "\"total_matches\":2") != NULL, "found exactly 2 matches");
    CHECK(strstr(res, "\"matches\":[0,8]") != NULL, "correct offsets matched");
    sdsfree(res);
}

static void test_boyer_moore_adversarial_empty(void) {
    TEST_BEGIN("boyer_moore_search: empty pattern rejection");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "NON_EMPTY_TEXT");
    cJSON_AddStringToObject(args, "pattern", "");

    sds res = tools_run("boyer_moore_search", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "empty pattern error returned");
    CHECK(strstr(res, "ERROR: pattern must not be empty") != NULL, "empty pattern safely rejected");
    sdsfree(res);
}

static void test_boyer_moore_adversarial_null(void) {
    TEST_BEGIN("boyer_moore_search: missing argument safety rejection");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "SOME_TEXT");

    sds res = tools_run("boyer_moore_search", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "missing parameter error returned");
    CHECK(strstr(res, "ERROR: text and pattern required") != NULL, "missing argument safely rejected");
    sdsfree(res);
}

int main(void) {
    test_boyer_moore_basic();
    test_boyer_moore_multiple_matches();
    test_boyer_moore_adversarial_empty();
    test_boyer_moore_adversarial_null();
    return test_report("test_boyer_moore");
}
