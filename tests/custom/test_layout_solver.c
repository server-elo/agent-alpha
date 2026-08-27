#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_layout_solver_bsp(void) {
    TEST_BEGIN("layout_solver: BSP tiling partition calculations");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "bsp");
    cJSON_AddNumberToObject(args, "width", 1920);
    cJSON_AddNumberToObject(args, "height", 1080);
    cJSON_AddNumberToObject(args, "count", 4);

    sds res = tools_run("layout_solver", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "layout_solver bsp returns response");
    CHECK(strstr(res, "\"action\":\"bsp\"") != NULL, "response action is bsp");
    CHECK(strstr(res, "\"w\":1920") != NULL, "canvas width preserved");
    CHECK(strstr(res, "\"h\":1080") != NULL, "canvas height preserved");
    CHECK(strstr(res, "\"id\":1") != NULL, "first node generated");
    CHECK(strstr(res, "\"id\":4") != NULL, "fourth node generated");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "response is valid JSON");
    if (parsed) {
        cJSON *nodes = cJSON_GetObjectItem(parsed, "nodes");
        CHECK(cJSON_IsArray(nodes), "nodes is an array");
        CHECK_EQ_INT(cJSON_GetArraySize(nodes), 4, "exact node count matches");
        cJSON_Delete(parsed);
    }
}

static void test_layout_solver_bezier(void) {
    TEST_BEGIN("layout_solver: Cubic Bezier easing calculations");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "bezier");
    cJSON_AddNumberToObject(args, "t", 0.5);
    cJSON_AddNumberToObject(args, "p1x", 0.25);
    cJSON_AddNumberToObject(args, "p1y", 0.1);
    cJSON_AddNumberToObject(args, "p2x", 0.25);
    cJSON_AddNumberToObject(args, "p2y", 1.0);

    sds res = tools_run("layout_solver", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "bezier evaluation returns response");
    CHECK(strstr(res, "\"action\":\"bezier\"") != NULL, "action is bezier");
    CHECK(strstr(res, "\"t\":0.5000") != NULL, "t parameter preserved");

    cJSON *parsed = cJSON_Parse(res);
    sdsfree(res);
    CHECK(parsed != NULL, "bezier result is valid JSON");
    if (parsed) {
        cJSON *y = cJSON_GetObjectItem(parsed, "y");
        CHECK(cJSON_IsNumber(y), "y coordinate is numeric");
        CHECK(y->valuedouble > 0.0 && y->valuedouble < 1.0, "y value within normal easing range");
        cJSON_Delete(parsed);
    }
}

int main(void) {
    test_layout_solver_bsp();
    test_layout_solver_bezier();
    return test_report("test_layout_solver");
}
