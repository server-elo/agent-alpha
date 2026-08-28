#include "alpha.h"
#include "test_util.h"
#include <math.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static void test_vector3_operations(void) {
    TEST_BEGIN("geom_spatial_2d3d: 3D vector length, dot, cross, distance, lerp, angle");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "vector");
    cJSON_AddNumberToObject(args, "x1", 1.0);
    cJSON_AddNumberToObject(args, "y1", 0.0);
    cJSON_AddNumberToObject(args, "z1", 0.0);
    cJSON_AddNumberToObject(args, "x2", 0.0);
    cJSON_AddNumberToObject(args, "y2", 1.0);
    cJSON_AddNumberToObject(args, "z2", 0.0);
    cJSON_AddNumberToObject(args, "t", 0.5);

    sds res = tools_run("geom_spatial_2d3d", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned");
    cJSON *p = cJSON_Parse(res);
    CHECK(p != NULL, "valid json returned");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p, "action")), "vector") == 0, "action is vector");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(p, "len1")) == 1.0, "len1 is 1.0");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(p, "len2")) == 1.0, "len2 is 1.0");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(p, "dot")) == 0.0, "perpendicular dot product is 0.0");
    CHECK_EQ_INT((int)(cJSON_GetNumberValue(cJSON_GetObjectItem(p, "angle_deg")) + 0.5), 90, "angle is 90 degrees");

    cJSON *cross = cJSON_GetObjectItem(p, "cross");
    CHECK(cross != NULL, "cross product present");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(cross, "x")) == 0.0, "cross x is 0");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(cross, "y")) == 0.0, "cross y is 0");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(cross, "z")) == 1.0, "cross z is 1.0 (X x Y = Z)");

    cJSON *lerp = cJSON_GetObjectItem(p, "lerp");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(lerp, "x")) == 0.5, "lerp x is 0.5");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(lerp, "y")) == 0.5, "lerp y is 0.5");

    if (p) cJSON_Delete(p);
    sdsfree(res);
}

static void test_quaternion_rotations(void) {
    TEST_BEGIN("geom_spatial_2d3d: quaternion from euler and vector rotation");
    /* 90 degrees yaw (Z-axis rotation) */
    cJSON *args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(args1, "action", "quaternion");
    cJSON_AddStringToObject(args1, "op", "from_euler");
    cJSON_AddNumberToObject(args1, "yaw", 90.0);
    cJSON_AddBoolToObject(args1, "degrees", 1);

    sds res1 = tools_run("geom_spatial_2d3d", args1, ".");
    cJSON_Delete(args1);

    cJSON *p1 = cJSON_Parse(res1);
    CHECK(p1 != NULL, "valid json for quaternion from_euler");
    double qz = cJSON_GetNumberValue(cJSON_GetObjectItem(p1, "z"));
    double qw = cJSON_GetNumberValue(cJSON_GetObjectItem(p1, "w"));
    CHECK(qz > 0.70 && qz < 0.71, "qz is ~sin(45 deg) = 0.7071");
    CHECK(qw > 0.70 && qw < 0.71, "qw is ~cos(45 deg) = 0.7071");

    /* Rotate vector (1, 0, 0) by 90-degree yaw -> should become (0, 1, 0) */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "quaternion");
    cJSON_AddStringToObject(args2, "op", "rotate_vector");
    cJSON_AddNumberToObject(args2, "qx", 0.0);
    cJSON_AddNumberToObject(args2, "qy", 0.0);
    cJSON_AddNumberToObject(args2, "qz", qz);
    cJSON_AddNumberToObject(args2, "qw", qw);
    cJSON_AddNumberToObject(args2, "vx", 1.0);
    cJSON_AddNumberToObject(args2, "vy", 0.0);
    cJSON_AddNumberToObject(args2, "vz", 0.0);

    sds res2 = tools_run("geom_spatial_2d3d", args2, ".");
    cJSON_Delete(args2);

    cJSON *p2 = cJSON_Parse(res2);
    CHECK(p2 != NULL, "valid json for rotate_vector");
    double rx = cJSON_GetNumberValue(cJSON_GetObjectItem(p2, "x"));
    double ry = cJSON_GetNumberValue(cJSON_GetObjectItem(p2, "y"));
    CHECK(fabs(rx) < 1e-4, "rotated x is ~0");
    CHECK(fabs(ry - 1.0) < 1e-4, "rotated y is ~1.0");

    if (p1) cJSON_Delete(p1);
    if (p2) cJSON_Delete(p2);
    sdsfree(res1);
    sdsfree(res2);
}

static void test_collision_and_color_codec(void) {
    TEST_BEGIN("geom_spatial_2d3d: 2D collision detection and Color/HSV/Hex codec");
    /* Test 1: AABB Rect-Rect collision */
    cJSON *args_col = cJSON_CreateObject();
    cJSON_AddStringToObject(args_col, "action", "collision_2d");
    cJSON_AddStringToObject(args_col, "mode", "rect_rect");
    cJSON_AddNumberToObject(args_col, "x1", 10.0);
    cJSON_AddNumberToObject(args_col, "y1", 10.0);
    cJSON_AddNumberToObject(args_col, "w1", 50.0);
    cJSON_AddNumberToObject(args_col, "h1", 50.0);
    cJSON_AddNumberToObject(args_col, "x2", 40.0);
    cJSON_AddNumberToObject(args_col, "y2", 40.0);
    cJSON_AddNumberToObject(args_col, "w2", 30.0);
    cJSON_AddNumberToObject(args_col, "h2", 30.0);

    sds res_col = tools_run("geom_spatial_2d3d", args_col, ".");
    cJSON_Delete(args_col);

    cJSON *p_col = cJSON_Parse(res_col);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p_col, "collision")), "overlapping rectangles collide");

    /* Test 2: Color RGB to HSV and Hex */
    cJSON *args_clr = cJSON_CreateObject();
    cJSON_AddStringToObject(args_clr, "action", "color");
    cJSON_AddNumberToObject(args_clr, "r", 255);
    cJSON_AddNumberToObject(args_clr, "g", 0);
    cJSON_AddNumberToObject(args_clr, "b", 0);
    cJSON_AddNumberToObject(args_clr, "a", 255);

    sds res_clr = tools_run("geom_spatial_2d3d", args_clr, ".");
    cJSON_Delete(args_clr);

    cJSON *p_clr = cJSON_Parse(res_clr);
    CHECK(p_clr != NULL, "valid json for color");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p_clr, "hex")), "#FF0000FF") == 0, "red hex matches #FF0000FF");
    cJSON *hsv = cJSON_GetObjectItem(p_clr, "hsv");
    CHECK(hsv != NULL, "hsv object present");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(hsv, "h")) == 0.0, "red hue is 0.0");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(hsv, "s")) == 1.0, "red saturation is 1.0");

    if (p_col) cJSON_Delete(p_col);
    if (p_clr) cJSON_Delete(p_clr);
    sdsfree(res_col);
    sdsfree(res_clr);
}

static void test_penner_easing_and_schema(void) {
    TEST_BEGIN("geom_spatial_2d3d: Penner easing curves & schema registration");
    cJSON *args_ease = cJSON_CreateObject();
    cJSON_AddStringToObject(args_ease, "action", "easing");
    cJSON_AddStringToObject(args_ease, "type", "bounce_out");
    cJSON_AddNumberToObject(args_ease, "t", 1.0);

    sds res_ease = tools_run("geom_spatial_2d3d", args_ease, ".");
    cJSON_Delete(args_ease);

    cJSON *p_ease = cJSON_Parse(res_ease);
    CHECK(p_ease != NULL, "valid json for easing");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(p_ease, "value")) >= 0.999, "bounce_out(1.0) reaches 1.0");

    /* Schema presence */
    cJSON *schema = tools_schema();
    CHECK(schema != NULL, "schema parsed");
    char *s = cJSON_PrintUnformatted(schema);
    CHECK(s != NULL, "schema printed");
    CHECK(strstr(s, "\"name\":\"geom_spatial_2d3d\"") != NULL, "schema contains geom_spatial_2d3d");
    free(s);
    if (schema) cJSON_Delete(schema);
    if (p_ease) cJSON_Delete(p_ease);
    sdsfree(res_ease);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    test_vector3_operations();
    test_quaternion_rotations();
    test_collision_and_color_codec();
    test_penner_easing_and_schema();
    return test_report("test_geom_spatial");
}
