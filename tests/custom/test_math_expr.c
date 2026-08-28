#include "alpha.h"
#include "test_util.h"
#include <math.h>
#include <string.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static void test_arithmetic_precedence(void) {
    TEST_BEGIN("math_expr_eval: arithmetic and precedence");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "eval");
    cJSON_AddStringToObject(args, "expression", "2 + 3 * 4");
    sds res = tools_run("math_expr_eval", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "eval 2 + 3 * 4 returns result");
    cJSON *out = cJSON_Parse(res);
    sdsfree(res);
    CHECK(out != NULL, "eval json parseable");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(out, "action")), "eval") == 0, "action is eval");
    CHECK(cJSON_IsTrue(cJSON_GetObjectItem(out, "success")), "success is true");
    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(out, "value")), 14, "2 + 3 * 4 == 14");
    cJSON_Delete(out);
}

static void test_parentheses_and_power(void) {
    TEST_BEGIN("math_expr_eval: parentheses and power precedence");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "eval");
    cJSON_AddStringToObject(args, "expression", "(2 + 3) * 4 ^ 2");
    sds res = tools_run("math_expr_eval", args, ".");
    cJSON_Delete(args);

    cJSON *out = cJSON_Parse(res);
    sdsfree(res);
    CHECK(out != NULL, "eval json parseable");
    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(out, "value")), 80, "(2 + 3) * 4^2 == 80");
    cJSON_Delete(out);
}

static void test_scientific_functions(void) {
    TEST_BEGIN("math_expr_eval: scientific functions hypot, sqrt, abs, clamp");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "eval");
    cJSON_AddStringToObject(args, "expression", "hypot(3, 4) + sqrt(144) + abs(-10) + clamp(25, 0, 10)");
    sds res = tools_run("math_expr_eval", args, ".");
    cJSON_Delete(args);

    cJSON *out = cJSON_Parse(res);
    sdsfree(res);
    CHECK(out != NULL, "eval json parseable");
    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(out, "value")), 37, "hypot(3,4)+sqrt(144)+abs(-10)+clamp(25,0,10) == 37");
    cJSON_Delete(out);
}

static void test_constants_and_variables(void) {
    TEST_BEGIN("math_expr_eval: constants pi, e and variable bindings");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "eval");
    cJSON_AddStringToObject(args, "expression", "x^2 + 2*x*y + y^2");
    cJSON *vars = cJSON_CreateObject();
    cJSON_AddNumberToObject(vars, "x", 3.0);
    cJSON_AddNumberToObject(vars, "y", 4.0);
    cJSON_AddItemToObject(args, "variables", vars);
    sds res = tools_run("math_expr_eval", args, ".");
    cJSON_Delete(args);

    cJSON *out = cJSON_Parse(res);
    sdsfree(res);
    CHECK(out != NULL, "eval with vars parseable");
    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(out, "value")), 49, "(x + y)^2 with x=3, y=4 == 49");
    cJSON_Delete(out);
}

static void test_tokenize_and_validate(void) {
    TEST_BEGIN("math_expr_eval: tokenize and validate actions");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "tokenize");
    cJSON_AddStringToObject(args, "expression", "3.14 * (radius + 2)");
    sds res = tools_run("math_expr_eval", args, ".");
    cJSON_Delete(args);

    cJSON *out = cJSON_Parse(res);
    sdsfree(res);
    CHECK(out != NULL, "tokenize parseable");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(out, "action")), "tokenize") == 0, "action is tokenize");
    cJSON *toks = cJSON_GetObjectItem(out, "tokens");
    CHECK(toks != NULL && cJSON_IsArray(toks), "tokens array exists");
    CHECK_EQ_INT(cJSON_GetArraySize(toks), 7, "token count == 7");
    cJSON_Delete(out);

    /* Validate valid */
    cJSON *v_args = cJSON_CreateObject();
    cJSON_AddStringToObject(v_args, "action", "validate");
    cJSON_AddStringToObject(v_args, "expression", "sqrt(x) + pow(y, 2)");
    sds v_res = tools_run("math_expr_eval", v_args, ".");
    cJSON_Delete(v_args);
    cJSON *v_out = cJSON_Parse(v_res);
    sdsfree(v_res);
    CHECK(v_out != NULL, "validate parseable");
    CHECK(cJSON_IsTrue(cJSON_GetObjectItem(v_out, "valid")), "valid expression returns valid: true");
    cJSON_Delete(v_out);
}

static void test_adversarial_and_schema(void) {
    TEST_BEGIN("math_expr_eval: adversarial errors and schema verification");
    /* Div by zero */
    cJSON *args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(args1, "action", "eval");
    cJSON_AddStringToObject(args1, "expression", "10 / 0");
    sds res1 = tools_run("math_expr_eval", args1, ".");
    cJSON_Delete(args1);
    cJSON *out1 = cJSON_Parse(res1);
    sdsfree(res1);
    CHECK(out1 != NULL, "div by zero json parseable");
    CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(out1, "success")), "success is false on div by zero");
    cJSON_Delete(out1);

    /* Missing closing paren */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "eval");
    cJSON_AddStringToObject(args2, "expression", "(10 + 20 * 3");
    sds res2 = tools_run("math_expr_eval", args2, ".");
    cJSON_Delete(args2);
    cJSON *out2 = cJSON_Parse(res2);
    sdsfree(res2);
    CHECK(out2 != NULL, "missing paren json parseable");
    CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(out2, "success")), "success is false on missing paren");
    cJSON_Delete(out2);

    /* Missing expression parameter */
    cJSON *args3 = cJSON_CreateObject();
    cJSON_AddStringToObject(args3, "action", "eval");
    sds res3 = tools_run("math_expr_eval", args3, ".");
    cJSON_Delete(args3);
    CHECK(res3 != NULL && strstr(res3, "ERROR") != NULL, "missing expression returns ERROR");
    sdsfree(res3);

    /* Schema registered */
    cJSON *schema = tools_schema();
    CHECK(schema != NULL, "tools_schema non-null");
    int found = 0;
    int n = cJSON_GetArraySize(schema);
    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(schema, i);
        cJSON *fn = cJSON_GetObjectItem(item, "function");
        if (fn) {
            cJSON *name = cJSON_GetObjectItem(fn, "name");
            if (name && strcmp(name->valuestring, "math_expr_eval") == 0) {
                found = 1;
                break;
            }
        }
    }
    CHECK(found == 1, "math_expr_eval is registered in tools_schema()");
    cJSON_Delete(schema);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    test_arithmetic_precedence();
    test_parentheses_and_power();
    test_scientific_functions();
    test_constants_and_variables();
    test_tokenize_and_validate();
    test_adversarial_and_schema();
    return test_report("test_math_expr");
}
