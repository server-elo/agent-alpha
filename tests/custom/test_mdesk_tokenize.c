#include "alpha.h"
#include "test_util.h"
#include <stdbool.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_mdesk_tokenize_basic(void) {
    TEST_BEGIN("mdesk_tokenize: basic C code / DSL tokenization");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "int count = 42; // compute items\n\"hello world\" + '''docstring'''");

    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "mdesk_tokenize returns response");
    CHECK(strstr(res, "\"action\":\"mdesk_tokenize\"") != NULL, "action confirmed");
    CHECK(strstr(res, "\"kind\":\"identifier\"") != NULL, "identifier recognized");
    CHECK(strstr(res, "\"text\":\"count\"") != NULL, "identifier name recognized");
    CHECK(strstr(res, "\"kind\":\"numeric\"") != NULL, "numeric recognized");
    CHECK(strstr(res, "\"text\":\"42\"") != NULL, "numeric value recognized");
    CHECK(strstr(res, "\"kind\":\"comment\"") != NULL, "comment recognized");
    CHECK(strstr(res, "\"kind\":\"string\"") != NULL, "string recognized");
    CHECK(strstr(res, "\"flags\":[\"triplet\",\"single_quote\"]") != NULL, "triplet quote recognized");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "valid json returned");
    if (parsed) cJSON_Delete(parsed);
}

static void test_mdesk_tokenize_whitespace_mode(void) {
    TEST_BEGIN("mdesk_tokenize: preserve whitespace tokens when requested");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "a \n b");
    cJSON_AddBoolToObject(args, "skip_whitespace", false);

    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "mdesk_tokenize returns response with whitespace");
    CHECK(strstr(res, "\"kind\":\"whitespace\"") != NULL, "whitespace token preserved");
    CHECK(strstr(res, "\"kind\":\"newline\"") != NULL, "newline token preserved");
    sdsfree(res);
}

static void test_mdesk_tokenize_adversarial_broken_literals(void) {
    TEST_BEGIN("mdesk_tokenize: adversarial broken string and comment handling");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "\"unclosed string\n/* unclosed comment");

    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned on malformed input");
    CHECK(strstr(res, "broken_comment") != NULL, "broken comment flagged safely");
    CHECK(strstr(res, "broken_string") != NULL, "broken string flagged safely");
    sdsfree(res);
}

static void test_mdesk_tokenize_adversarial_missing_arg(void) {
    TEST_BEGIN("mdesk_tokenize: adversarial missing argument rejection");

    cJSON *args = cJSON_CreateObject();
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "missing text error returned");
    CHECK(strstr(res, "ERROR: text parameter required") != NULL, "missing parameter safely rejected");
    sdsfree(res);
}

int main(void) {
    test_mdesk_tokenize_basic();
    test_mdesk_tokenize_whitespace_mode();
    test_mdesk_tokenize_adversarial_broken_literals();
    test_mdesk_tokenize_adversarial_missing_arg();
    return test_report("test_mdesk_tokenize");
}
