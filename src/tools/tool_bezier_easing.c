/*
 * tool_bezier_easing.c - Cubic Bezier Curve Solver & Newton-Raphson Easing Engine
 *
 * Implements CSS-compliant cubic-bezier(x1, y1, x2, y2) timing curve evaluation,
 * iterative root-finding, and standard animation presets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "cJSON.h"
#include "sds.h"

typedef struct {
    double x1, y1, x2, y2;
} bezier_curve_t;

static const struct {
    const char *name;
    bezier_curve_t curve;
} k_bezier_presets[] = {
    {"linear", {0.0, 0.0, 1.0, 1.0}},
    {"ease", {0.25, 0.1, 0.25, 1.0}},
    {"ease-in", {0.42, 0.0, 1.0, 1.0}},
    {"ease-out", {0.0, 0.0, 0.58, 1.0}},
    {"ease-in-out", {0.42, 0.0, 0.58, 1.0}},
    {"anticipate", {0.36, 0.0, 0.66, -0.56}},
    {"overshoot", {0.34, 1.56, 0.64, 1.0}},
    {NULL, {0, 0, 0, 0}}
};

static double calc_bezier(double t, double p1, double p2) {
    return ((1.0 - 3.0 * p2 + 3.0 * p1) * t + (3.0 * p2 - 6.0 * p1)) * t * t + (3.0 * p1) * t;
}

static double calc_bezier_derivative(double t, double p1, double p2) {
    return 3.0 * (1.0 - 3.0 * p2 + 3.0 * p1) * t * t + 2.0 * (3.0 * p2 - 6.0 * p1) * t + (3.0 * p1);
}

/* Newton-Raphson root finding to find parameter t given x */
static double solve_t_for_x(double x, double x1, double x2) {
    double t = x;
    for (int i = 0; i < 8; i++) {
        double current_x = calc_bezier(t, x1, x2) - x;
        if (fabs(current_x) < 1e-7) return t;
        double d = calc_bezier_derivative(t, x1, x2);
        if (fabs(d) < 1e-7) break;
        t -= current_x / d;
    }

    /* Bisection fallback if derivative vanishes */
    double t0 = 0.0, t1 = 1.0;
    t = x;
    while (t0 < t1) {
        double current_x = calc_bezier(t, x1, x2);
        if (fabs(current_x - x) < 1e-7) return t;
        if (x > current_x) t0 = t;
        else t1 = t;
        t = (t1 + t0) / 2.0;
    }
    return t;
}

static double eval_cubic_bezier(double x, bezier_curve_t curve) {
    if (x <= 0.0) return 0.0;
    if (x >= 1.0) return 1.0;
    double t = solve_t_for_x(x, curve.x1, curve.x2);
    return calc_bezier(t, curve.y1, curve.y2);
}

static sds tool_bezier_easing_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "eval";

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);

    bezier_curve_t curve = {0.25, 0.1, 0.25, 1.0}; // default: ease

    cJSON *preset_item = cJSON_GetObjectItem(args, "preset");
    if (preset_item && preset_item->valuestring) {
        int found = 0;
        for (int i = 0; k_bezier_presets[i].name != NULL; i++) {
            if (strcmp(preset_item->valuestring, k_bezier_presets[i].name) == 0) {
                curve = k_bezier_presets[i].curve;
                found = 1;
                break;
            }
        }
        if (!found) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Unknown preset name. Options: linear, ease, ease-in, ease-out, ease-in-out, anticipate, overshoot");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }
    } else {
        cJSON *x1_it = cJSON_GetObjectItem(args, "x1");
        cJSON *y1_it = cJSON_GetObjectItem(args, "y1");
        cJSON *x2_it = cJSON_GetObjectItem(args, "x2");
        cJSON *y2_it = cJSON_GetObjectItem(args, "y2");
        if (x1_it && y1_it && x2_it && y2_it) {
            curve.x1 = x1_it->valuedouble;
            curve.y1 = y1_it->valuedouble;
            curve.x2 = x2_it->valuedouble;
            curve.y2 = y2_it->valuedouble;
        }
    }

    if (strcmp(action, "eval") == 0) {
        cJSON *t_item = cJSON_GetObjectItem(args, "x");
        if (!t_item) t_item = cJSON_GetObjectItem(args, "t");
        double x_val = t_item ? t_item->valuedouble : 0.5;

        double y_val = eval_cubic_bezier(x_val, curve);
        cJSON_AddNumberToObject(out, "x", x_val);
        cJSON_AddNumberToObject(out, "y", y_val);

        cJSON *curve_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(curve_obj, "x1", curve.x1);
        cJSON_AddNumberToObject(curve_obj, "y1", curve.y1);
        cJSON_AddNumberToObject(curve_obj, "x2", curve.x2);
        cJSON_AddNumberToObject(curve_obj, "y2", curve.y2);
        cJSON_AddItemToObject(out, "curve", curve_obj);

    } else if (strcmp(action, "sample") == 0) {
        cJSON *samples_it = cJSON_GetObjectItem(args, "samples");
        int count = samples_it ? samples_it->valueint : 11;
        if (count < 2) count = 2;
        if (count > 100) count = 100;

        cJSON *pts = cJSON_CreateArray();
        for (int i = 0; i < count; i++) {
            double x = (double)i / (count - 1);
            double y = eval_cubic_bezier(x, curve);
            cJSON *pt = cJSON_CreateObject();
            cJSON_AddNumberToObject(pt, "x", x);
            cJSON_AddNumberToObject(pt, "y", y);
            cJSON_AddItemToArray(pts, pt);
        }
        cJSON_AddItemToObject(out, "points", pts);
        cJSON_AddNumberToObject(out, "count", count);

    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: eval, sample");
        char *json = cJSON_PrintUnformatted(err);
        sds res = sdsnew(json);
        free(json);
        cJSON_Delete(err);
        return res;
    }

    char *json = cJSON_PrintUnformatted(out);
    sds res = sdsnew(json);
    free(json);
    cJSON_Delete(out);
    return res;
}

const alpha_tool_t tool_bezier_easing = {
    .name = "bezier_easing",
    .aliases = {"cubic_bezier", "easing_solver", "spline_math"},
    .category = "math",
    .description = "Cubic Bezier curve timing & easing solver: evaluate CSS cubic-bezier curves using Newton-Raphson inversion.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"eval\", \"sample\"], \"description\": \"Action to perform\"},\n"
                   "    \"x\": {\"type\": \"number\", \"description\": \"Progress time input (0.0 to 1.0)\"},\n"
                   "    \"preset\": {\"type\": \"string\", \"enum\": [\"linear\", \"ease\", \"ease-in\", \"ease-out\", \"ease-in-out\", \"anticipate\", \"overshoot\"]},\n"
                   "    \"x1\": {\"type\": \"number\"}, \"y1\": {\"type\": \"number\"},\n"
                   "    \"x2\": {\"type\": \"number\"}, \"y2\": {\"type\": \"number\"},\n"
                   "    \"samples\": {\"type\": \"integer\", \"description\": \"Number of points for sample action\"}\n"
                   "  }\n"
                   "}",
    .run = tool_bezier_easing_run
};
