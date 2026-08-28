/* tool_layout.c — Window layout solver & Bezier curves */

static sds tool_layout_solver_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action) action = "bsp";
    if (strcmp(action, "bezier") == 0) {
        double p1x = 0.25, p1y = 0.1, p2x = 0.25, p2y = 1.0, t = 0.5;
        cJSON *item = cJSON_GetObjectItem(args, "t"); if (cJSON_IsNumber(item)) t = item->valuedouble;
        item = cJSON_GetObjectItem(args, "p1x"); if (cJSON_IsNumber(item)) p1x = item->valuedouble;
        item = cJSON_GetObjectItem(args, "p1y"); if (cJSON_IsNumber(item)) p1y = item->valuedouble;
        item = cJSON_GetObjectItem(args, "p2x"); if (cJSON_IsNumber(item)) p2x = item->valuedouble;
        item = cJSON_GetObjectItem(args, "p2y"); if (cJSON_IsNumber(item)) p2y = item->valuedouble;
        double inv = 1.0 - t;
        double y = 3.0 * inv * inv * t * p1y + 3.0 * inv * t * t * p2y + t * t * t;
        double x = 3.0 * inv * inv * t * p1x + 3.0 * inv * t * t * p2x + t * t * t;
        return sdscatprintf(sdsempty(), "{\"action\":\"bezier\",\"t\":%.4f,\"x\":%.4f,\"y\":%.4f}", t, x, y);
    }
    int width = 1920, height = 1080, count = 2;
    cJSON *item = cJSON_GetObjectItem(args, "width"); if (cJSON_IsNumber(item)) width = item->valueint;
    item = cJSON_GetObjectItem(args, "height"); if (cJSON_IsNumber(item)) height = item->valueint;
    item = cJSON_GetObjectItem(args, "count"); if (cJSON_IsNumber(item)) count = item->valueint;
    if (count <= 0) count = 1; if (count > 32) count = 32;

    sds out = sdscatprintf(sdsempty(), "{\"action\":\"bsp\",\"canvas\":{\"w\":%d,\"h\":%d},\"nodes\":[", width, height);
    int cur_x = 0, cur_y = 0, cur_w = width, cur_h = height;
    for (int i = 0; i < count; i++) {
        int node_w = cur_w, node_h = cur_h;
        if (i < count - 1) {
            if (cur_w >= cur_h) {
                node_w = cur_w / 2;
                out = sdscatprintf(out, "%s{\"id\":%d,\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d}",
                                   i > 0 ? "," : "", i + 1, cur_x, cur_y, node_w, node_h);
                cur_x += node_w; cur_w -= node_w;
            } else {
                node_h = cur_h / 2;
                out = sdscatprintf(out, "%s{\"id\":%d,\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d}",
                                   i > 0 ? "," : "", i + 1, cur_x, cur_y, node_w, node_h);
                cur_y += node_h; cur_h -= node_h;
            }
        } else {
            out = sdscatprintf(out, "%s{\"id\":%d,\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d}",
                               i > 0 ? "," : "", i + 1, cur_x, cur_y, cur_w, cur_h);
        }
    }
    out = sdscat(out, "]}");
    return out;
}

static const alpha_tool_t tool_layout_solver = {
    .name = "layout_solver",
    .aliases = {NULL},
    .category = "ui",
    .description = "Window layout solver & Bezier curve evaluator.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"layout_solver\",\"description\":\"Window layout solver & Bezier curve evaluator.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"bsp\",\"bezier\"]},\"width\":{\"type\":\"integer\"},\"height\":{\"type\":\"integer\"},\"count\":{\"type\":\"integer\"},\"t\":{\"type\":\"number\"},\"p1x\":{\"type\":\"number\"},\"p1y\":{\"type\":\"number\"},\"p2x\":{\"type\":\"number\"},\"p2y\":{\"type\":\"number\"}}}}}",
    .run = tool_layout_solver_run
};
