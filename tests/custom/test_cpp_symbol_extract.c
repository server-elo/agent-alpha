#include "alpha.h"
#include "test_util.h"
#include <stdbool.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_cpp_symbol_extract_basic(void) {
    TEST_BEGIN("cpp_symbol_extract: basic functions, classes, structs, macros, includes");

    const char *code =
        "#include <stdio.h>\n"
        "#include \"alpha.h\"\n"
        "#define MAX_BUFFER 1024\n"
        "struct State {\n"
        "    int id;\n"
        "};\n"
        "class Node {\n"
        "    int value;\n"
        "};\n"
        "int compute_total(int a, int b) {\n"
        "    return a + b;\n"
        "}\n"
        "void Session::reset() {\n"
        "    // reset\n"
        "}\n";

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", code);

    sds res = tools_run("cpp_symbol_extract", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "cpp_symbol_extract returns response");
    cJSON *root = cJSON_Parse(res);
    sdsfree(res);
    CHECK(root != NULL, "valid json returned");

    cJSON *action = cJSON_GetObjectItem(root, "action");
    CHECK(action && strcmp(action->valuestring, "cpp_symbol_extract") == 0, "action confirmed");

    cJSON *syms = cJSON_GetObjectItem(root, "symbols");
    CHECK(syms && cJSON_IsArray(syms), "symbols is array");
    int count = cJSON_GetArraySize(syms);
    CHECK(count >= 6, "found all extracted symbols");

    /* Check for specific extracted entities */
    int has_include = 0;
    int has_macro = 0;
    int has_struct = 0;
    int has_class = 0;
    int has_func = 0;
    int has_qualified = 0;

    for (int i = 0; i < count; i++) {
        cJSON *s = cJSON_GetArrayItem(syms, i);
        const char *k = cJSON_GetStringValue(cJSON_GetObjectItem(s, "kind"));
        const char *n = cJSON_GetStringValue(cJSON_GetObjectItem(s, "name"));
        if (k && strcmp(k, "include") == 0 && n && strcmp(n, "stdio.h") == 0) has_include = 1;
        if (k && strcmp(k, "macro") == 0 && n && strcmp(n, "MAX_BUFFER") == 0) has_macro = 1;
        if (k && strcmp(k, "struct") == 0 && n && strcmp(n, "State") == 0) has_struct = 1;
        if (k && strcmp(k, "class") == 0 && n && strcmp(n, "Node") == 0) has_class = 1;
        if (k && strcmp(k, "function") == 0 && n && strcmp(n, "compute_total") == 0) has_func = 1;
        if (k && strcmp(k, "function") == 0 && n && strcmp(n, "reset") == 0) {
            const char *rec = cJSON_GetStringValue(cJSON_GetObjectItem(s, "receiver"));
            if (rec && strcmp(rec, "Session") == 0) has_qualified = 1;
        }
    }

    CHECK(has_include, "include stdio.h extracted");
    CHECK(has_macro, "macro MAX_BUFFER extracted");
    CHECK(has_struct, "struct State extracted");
    CHECK(has_class, "class Node extracted");
    CHECK(has_func, "free function compute_total extracted");
    CHECK(has_qualified, "qualified method Session::reset extracted with receiver");

    cJSON_Delete(root);
}

static void test_cpp_symbol_extract_adversarial_comments_and_strings(void) {
    TEST_BEGIN("cpp_symbol_extract: adversarial comments and keywords in comments");

    const char *code =
        "// #define FAKE_MACRO 1\n"
        "/* class FakeClass { int x; };\n"
        "   void fake_func(); */\n"
        "int real_func() {\n"
        "    if (true) return 1;\n"
        "    while (false) {}\n"
        "    return 0;\n"
        "}\n";

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", code);

    sds res = tools_run("cpp_symbol_extract", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned");
    cJSON *root = cJSON_Parse(res);
    sdsfree(res);
    CHECK(root != NULL, "valid json");

    cJSON *syms = cJSON_GetObjectItem(root, "symbols");
    int count = cJSON_GetArraySize(syms);

    int fake_macro = 0;
    int fake_class = 0;
    int has_real = 0;

    for (int i = 0; i < count; i++) {
        cJSON *s = cJSON_GetArrayItem(syms, i);
        const char *n = cJSON_GetStringValue(cJSON_GetObjectItem(s, "name"));
        if (n && strcmp(n, "FAKE_MACRO") == 0) fake_macro = 1;
        if (n && strcmp(n, "FakeClass") == 0) fake_class = 1;
        if (n && strcmp(n, "real_func") == 0) has_real = 1;
    }

    CHECK(!fake_macro, "commented macro ignored");
    CHECK(!fake_class, "commented class ignored");
    CHECK(has_real, "real function extracted");

    cJSON_Delete(root);
}

static void test_cpp_symbol_extract_adversarial_missing_args(void) {
    TEST_BEGIN("cpp_symbol_extract: adversarial missing argument rejection");

    cJSON *args = cJSON_CreateObject();
    sds res = tools_run("cpp_symbol_extract", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "missing parameter response returned");
    CHECK(strstr(res, "ERROR:") != NULL, "error safely returned on missing text");
    sdsfree(res);
}

int main(void) {
    test_cpp_symbol_extract_basic();
    test_cpp_symbol_extract_adversarial_comments_and_strings();
    test_cpp_symbol_extract_adversarial_missing_args();
    return test_report("test_cpp_symbol_extract");
}
