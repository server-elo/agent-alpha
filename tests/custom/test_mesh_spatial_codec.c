#include "alpha.h"
#include "test_util.h"
#include <stdbool.h>
#include <math.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static void test_mesh_spatial_codec_morton_single(void) {
    TEST_BEGIN("mesh_spatial_codec: single 3D point Morton curve encoding");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "morton");
    cJSON_AddNumberToObject(args, "x", 1);
    cJSON_AddNumberToObject(args, "y", 2);
    cJSON_AddNumberToObject(args, "z", 4);

    sds res = tools_run("mesh_spatial_codec", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "response returned");
    cJSON *root = cJSON_Parse(res);
    sdsfree(res);
    CHECK(root != NULL, "valid json returned");

    cJSON *act = cJSON_GetObjectItem(root, "action");
    CHECK(act && strcmp(act->valuestring, "morton") == 0, "action is morton");

    cJSON *code = cJSON_GetObjectItem(root, "morton_code");
    CHECK(code && cJSON_IsNumber(code), "morton_code is numeric");
    /* 1 = bit 0 -> (1 << 0) = 1
       2 = bit 1 -> (1 << (1*3 + 1)) = (1 << 4) = 16 (bit 4)
       4 = bit 2 -> (1 << (2*3 + 2)) = (1 << 8) = 256 (bit 8)
       Total = 1 + 16 + 256 = 273 (0x111) */
    double val = code->valuedouble;
    CHECK((uint64_t)val == 0x111ULL, "correct Morton interleaved bitcode");

    cJSON_Delete(root);
}

static void test_mesh_spatial_codec_batch_order(void) {
    TEST_BEGIN("mesh_spatial_codec: batch 3D points with AABB bounding box computation");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "batch_order");

    cJSON *pts = cJSON_CreateArray();
    cJSON *p1 = cJSON_CreateObject();
    cJSON_AddNumberToObject(p1, "x", 0.0);
    cJSON_AddNumberToObject(p1, "y", 0.0);
    cJSON_AddNumberToObject(p1, "z", 0.0);
    cJSON_AddItemToArray(pts, p1);

    cJSON *p2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(p2, "x", 10.0);
    cJSON_AddNumberToObject(p2, "y", 20.0);
    cJSON_AddNumberToObject(p2, "z", 30.0);
    cJSON_AddItemToArray(pts, p2);

    cJSON_AddItemToObject(args, "points", pts);

    sds res = tools_run("mesh_spatial_codec", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "batch response returned");
    cJSON *root = cJSON_Parse(res);
    sdsfree(res);
    CHECK(root != NULL, "valid json");

    cJSON *act = cJSON_GetObjectItem(root, "action");
    CHECK(act && strcmp(act->valuestring, "batch_order") == 0, "action is batch_order");

    cJSON *aabb = cJSON_GetObjectItem(root, "aabb");
    CHECK(aabb != NULL, "aabb object present");

    cJSON *min_x = cJSON_GetObjectItem(aabb, "min_x");
    cJSON *max_z = cJSON_GetObjectItem(aabb, "max_z");
    CHECK(min_x && min_x->valuedouble == 0.0, "min_x is 0.0");
    CHECK(max_z && max_z->valuedouble == 30.0, "max_z is 30.0");

    cJSON *out_pts = cJSON_GetObjectItem(root, "points");
    CHECK(out_pts && cJSON_GetArraySize(out_pts) == 2, "2 points processed");

    cJSON_Delete(root);
}

static void test_mesh_spatial_codec_half_float(void) {
    TEST_BEGIN("mesh_spatial_codec: 32-bit float to 16-bit IEEE-754 half-float quantization");

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "half_float");
    cJSON_AddNumberToObject(args, "value", 1.0);

    sds res = tools_run("mesh_spatial_codec", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "half_float response returned");
    cJSON *root = cJSON_Parse(res);
    sdsfree(res);
    CHECK(root != NULL, "valid json");

    /* 1.0f in IEEE-754 half-float is 0x3C00 (15360) */
    cJSON *half_int = cJSON_GetObjectItem(root, "half_int");
    CHECK(half_int && (uint16_t)half_int->valuedouble == 0x3C00, "1.0f converts to 0x3C00 half float");

    cJSON_Delete(root);
}

static void test_mesh_spatial_codec_adversarial_rejections(void) {
    TEST_BEGIN("mesh_spatial_codec: adversarial missing parameter and empty input rejection");

    /* 1. Missing coordinates */
    cJSON *args1 = cJSON_CreateObject();
    sds res1 = tools_run("mesh_spatial_codec", args1, ".");
    cJSON_Delete(args1);

    CHECK(res1 != NULL, "missing parameter response returned");
    CHECK(strstr(res1, "ERROR:") != NULL, "missing coordinates rejected safely");
    sdsfree(res1);

    /* 2. Empty batch array */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "batch_order");
    cJSON_AddItemToObject(args2, "points", cJSON_CreateArray());
    sds res2 = tools_run("mesh_spatial_codec", args2, ".");
    cJSON_Delete(args2);

    CHECK(res2 != NULL, "empty points response returned");
    CHECK(strstr(res2, "ERROR:") != NULL, "empty points array rejected safely");
    sdsfree(res2);
}

int main(void) {
    test_mesh_spatial_codec_morton_single();
    test_mesh_spatial_codec_batch_order();
    test_mesh_spatial_codec_half_float();
    test_mesh_spatial_codec_adversarial_rejections();
    return test_report("test_mesh_spatial_codec");
}
