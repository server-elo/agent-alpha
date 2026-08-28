/* tool_mesh_spatial.c — Fast 3D Morton Space-Filling Curve & Spatial Quantizer from zeux/meshoptimizer */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_mesh_spatial_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = "morton";
    cJSON *act_item = cJSON_GetObjectItem(args, "action");
    if (act_item && act_item->valuestring) {
        action = act_item->valuestring;
    }

    if (strcmp(action, "half_float") == 0) {
        cJSON *v_item = cJSON_GetObjectItem(args, "value");
        if (!v_item || !cJSON_IsNumber(v_item)) {
            return sdsnew("ERROR: numeric value required for half_float");
        }
        float val = (float)v_item->valuedouble;
        union { float f; uint32_t ui; } u = { val };
        uint32_t ui = u.ui;
        int s = (ui >> 16) & 0x8000;
        int em = ui & 0x7fffffff;
        int h = (em - (112 << 23) + (1 << 12)) >> 13;
        h = (em < (113 << 23)) ? 0 : h;
        h = (em >= (143 << 23)) ? 0x7c00 : h;
        h = (em > (255 << 23)) ? 0x7e00 : h;
        uint16_t half = (uint16_t)(s | h);

        cJSON *res_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(res_obj, "action", "half_float");
        cJSON_AddNumberToObject(res_obj, "input_value", val);
        cJSON_AddNumberToObject(res_obj, "half_int", half);
        char hex_buf[16];
        snprintf(hex_buf, sizeof(hex_buf), "0x%04X", half);
        cJSON_AddStringToObject(res_obj, "half_hex", hex_buf);

        char *json_str = cJSON_PrintUnformatted(res_obj);
        cJSON_Delete(res_obj);
        sds out = sdsnew(json_str);
        free(json_str);
        return out;
    }

    /* Morton 3D Coordinate Encoding */
    cJSON *points_item = cJSON_GetObjectItem(args, "points");
    if (!points_item || !cJSON_IsArray(points_item)) {
        cJSON *x_item = cJSON_GetObjectItem(args, "x");
        cJSON *y_item = cJSON_GetObjectItem(args, "y");
        cJSON *z_item = cJSON_GetObjectItem(args, "z");
        if (!x_item || !y_item || !z_item || !cJSON_IsNumber(x_item) || !cJSON_IsNumber(y_item) || !cJSON_IsNumber(z_item)) {
            return sdsnew("ERROR: either points array or x,y,z numeric coordinates required for mesh_spatial_codec");
        }
        uint32_t x = (uint32_t)(x_item->valuedouble < 0 ? 0 : x_item->valuedouble);
        uint32_t y = (uint32_t)(y_item->valuedouble < 0 ? 0 : y_item->valuedouble);
        uint32_t z = (uint32_t)(z_item->valuedouble < 0 ? 0 : z_item->valuedouble);

        uint64_t px = x & 0x000fffffULL;
        px = (px ^ (px << 32)) & 0x000f00000000ffffULL;
        px = (px ^ (px << 16)) & 0x000f0000ff0000ffULL;
        px = (px ^ (px << 8))  & 0x000f00f00f00f00fULL;
        px = (px ^ (px << 4))  & 0x00c30c30c30c30c3ULL;
        px = (px ^ (px << 2))  & 0x0249249249249249ULL;

        uint64_t py = y & 0x000fffffULL;
        py = (py ^ (py << 32)) & 0x000f00000000ffffULL;
        py = (py ^ (py << 16)) & 0x000f0000ff0000ffULL;
        py = (py ^ (py << 8))  & 0x000f00f00f00f00fULL;
        py = (py ^ (py << 4))  & 0x00c30c30c30c30c3ULL;
        py = (py ^ (py << 2))  & 0x0249249249249249ULL;

        uint64_t pz = z & 0x000fffffULL;
        pz = (pz ^ (pz << 32)) & 0x000f00000000ffffULL;
        pz = (pz ^ (pz << 16)) & 0x000f0000ff0000ffULL;
        pz = (pz ^ (pz << 8))  & 0x000f00f00f00f00fULL;
        pz = (pz ^ (pz << 4))  & 0x00c30c30c30c30c3ULL;
        pz = (pz ^ (pz << 2))  & 0x0249249249249249ULL;

        uint64_t code = px | (py << 1) | (pz << 2);

        cJSON *res_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(res_obj, "action", "morton");
        cJSON_AddNumberToObject(res_obj, "x", (double)x);
        cJSON_AddNumberToObject(res_obj, "y", (double)y);
        cJSON_AddNumberToObject(res_obj, "z", (double)z);
        cJSON_AddNumberToObject(res_obj, "morton_code", (double)code);
        char hex_code[32];
        snprintf(hex_code, sizeof(hex_code), "0x%llX", (unsigned long long)code);
        cJSON_AddStringToObject(res_obj, "morton_hex", hex_code);

        char *json_str = cJSON_PrintUnformatted(res_obj);
        cJSON_Delete(res_obj);
        sds out = sdsnew(json_str);
        free(json_str);
        return out;
    }

    int pt_count = cJSON_GetArraySize(points_item);
    if (pt_count <= 0) {
        return sdsnew("ERROR: points array cannot be empty");
    }

    float min_x = 1e30f, min_y = 1e30f, min_z = 1e30f;
    float max_x = -1e30f, max_y = -1e30f, max_z = -1e30f;

    for (int i = 0; i < pt_count; i++) {
        cJSON *pt = cJSON_GetArrayItem(points_item, i);
        cJSON *px = cJSON_GetObjectItem(pt, "x");
        cJSON *py = cJSON_GetObjectItem(pt, "y");
        cJSON *pz = cJSON_GetObjectItem(pt, "z");
        if (px && py && pz && cJSON_IsNumber(px) && cJSON_IsNumber(py) && cJSON_IsNumber(pz)) {
            float vx = (float)px->valuedouble;
            float vy = (float)py->valuedouble;
            float vz = (float)pz->valuedouble;
            if (vx < min_x) min_x = vx;
            if (vy < min_y) min_y = vy;
            if (vz < min_z) min_z = vz;
            if (vx > max_x) max_x = vx;
            if (vy > max_y) max_y = vy;
            if (vz > max_z) max_z = vz;
        }
    }

    float extent_x = max_x - min_x;
    float extent_y = max_y - min_y;
    float extent_z = max_z - min_z;
    float max_extent = extent_x > extent_y ? extent_x : extent_y;
    if (extent_z > max_extent) max_extent = extent_z;
    float scale = max_extent > 1e-6f ? (65535.0f / max_extent) : 0.0f;

    cJSON *out_pts = cJSON_CreateArray();
    for (int i = 0; i < pt_count; i++) {
        cJSON *pt = cJSON_GetArrayItem(points_item, i);
        cJSON *px = cJSON_GetObjectItem(pt, "x");
        cJSON *py = cJSON_GetObjectItem(pt, "y");
        cJSON *pz = cJSON_GetObjectItem(pt, "z");
        float vx = (px && cJSON_IsNumber(px)) ? (float)px->valuedouble : 0.0f;
        float vy = (py && cJSON_IsNumber(py)) ? (float)py->valuedouble : 0.0f;
        float vz = (pz && cJSON_IsNumber(pz)) ? (float)pz->valuedouble : 0.0f;

        uint32_t qx = (uint32_t)((vx - min_x) * scale + 0.5f);
        uint32_t qy = (uint32_t)((vy - min_y) * scale + 0.5f);
        uint32_t qz = (uint32_t)((vz - min_z) * scale + 0.5f);

        uint64_t bitx = qx & 0x000fffffULL;
        bitx = (bitx ^ (bitx << 32)) & 0x000f00000000ffffULL;
        bitx = (bitx ^ (bitx << 16)) & 0x000f0000ff0000ffULL;
        bitx = (bitx ^ (bitx << 8))  & 0x000f00f00f00f00fULL;
        bitx = (bitx ^ (bitx << 4))  & 0x00c30c30c30c30c3ULL;
        bitx = (bitx ^ (bitx << 2))  & 0x0249249249249249ULL;

        uint64_t bity = qy & 0x000fffffULL;
        bity = (bity ^ (bity << 32)) & 0x000f00000000ffffULL;
        bity = (bity ^ (bity << 16)) & 0x000f0000ff0000ffULL;
        bity = (bity ^ (bity << 8))  & 0x000f00f00f00f00fULL;
        bity = (bity ^ (bity << 4))  & 0x00c30c30c30c30c3ULL;
        bity = (bity ^ (bity << 2))  & 0x0249249249249249ULL;

        uint64_t bitz = qz & 0x000fffffULL;
        bitz = (bitz ^ (bitz << 32)) & 0x000f00000000ffffULL;
        bitz = (bitz ^ (bitz << 16)) & 0x000f0000ff0000ffULL;
        bitz = (bitz ^ (bitz << 8))  & 0x000f00f00f00f00fULL;
        bitz = (bitz ^ (bitz << 4))  & 0x00c30c30c30c30c3ULL;
        bitz = (bitz ^ (bitz << 2))  & 0x0249249249249249ULL;

        uint64_t mcode = bitx | (bity << 1) | (bitz << 2);

        cJSON *res_pt = cJSON_CreateObject();
        cJSON_AddNumberToObject(res_pt, "index", i);
        cJSON_AddNumberToObject(res_pt, "x", vx);
        cJSON_AddNumberToObject(res_pt, "y", vy);
        cJSON_AddNumberToObject(res_pt, "z", vz);
        cJSON_AddNumberToObject(res_pt, "morton_code", (double)mcode);
        cJSON_AddItemToArray(out_pts, res_pt);
    }

    cJSON *res_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(res_obj, "action", "batch_order");
    cJSON_AddNumberToObject(res_obj, "point_count", pt_count);

    cJSON *aabb = cJSON_CreateObject();
    cJSON_AddNumberToObject(aabb, "min_x", min_x);
    cJSON_AddNumberToObject(aabb, "min_y", min_y);
    cJSON_AddNumberToObject(aabb, "min_z", min_z);
    cJSON_AddNumberToObject(aabb, "max_x", max_x);
    cJSON_AddNumberToObject(aabb, "max_y", max_y);
    cJSON_AddNumberToObject(aabb, "max_z", max_z);
    cJSON_AddNumberToObject(aabb, "extent", max_extent);
    cJSON_AddItemToObject(res_obj, "aabb", aabb);
    cJSON_AddItemToObject(res_obj, "points", out_pts);

    char *json_str = cJSON_PrintUnformatted(res_obj);
    cJSON_Delete(res_obj);
    sds out = sdsnew(json_str);
    free(json_str);
    return out;
}

static const alpha_tool_t tool_mesh_spatial = {
    .name = "mesh_spatial_codec",
    .aliases = {NULL},
    .category = "spatial",
    .description = "Fast 3D Morton Space-Filling Curve & Spatial Quantizer from zeux/meshoptimizer. Actions: 'morton' (encodes 3D coordinates into 64-bit interleaved Z-order Morton spatial codes), 'batch_order' (computes AABB 3D bounding box and spatial codes for vertex arrays), 'half_float' (quantizes 32-bit floats to 16-bit IEEE-754 half floats with denormal flush and NaN preservation).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"mesh_spatial_codec\",\"description\":\"Fast 3D Morton Space-Filling Curve & Spatial Quantizer from zeux/meshoptimizer. Actions: 'morton' (encodes 3D coordinates into 64-bit interleaved Z-order Morton spatial codes), 'batch_order' (computes AABB 3D bounding box and spatial codes for vertex arrays), 'half_float' (quantizes 32-bit floats to 16-bit IEEE-754 half floats with denormal flush and NaN preservation).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"morton\",\"batch_order\",\"half_float\"]},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"z\":{\"type\":\"number\"},\"value\":{\"type\":\"number\"},\"points\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"z\":{\"type\":\"number\"}}}}},\"required\":[]}}}",
    .run = tool_mesh_spatial_run
};
