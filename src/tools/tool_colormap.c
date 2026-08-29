/* tool_colormap.c — Color engine ported from datoviz/datoviz
 * (src/scene/annotation/colormap.c, MIT licensed).
 *
 * Core algorithm preserved from datoviz: ordered stop-table sampling with
 * linear interpolation between neighbouring stops, clamped to [0,1]; LUT
 * sampling maps t over (count-1) segments and interpolates within one.
 *
 * Actions:
 *   list    — enumerate built-in colormaps with their endpoints
 *   sample  — map one scalar (or dataset with min/max normalization)
 *             to RGBA / HEX / 0-1 floats
 *   ramp    — N evenly spaced samples across a colormap (gradient array)
 *   stops   — dump the raw stop table of a built-in colormap
 *   parse   — hex (#RGB / #RRGGBB / #RRGGBBAA) or [r,g,b(,a)] → RGBA
 *   to_hex  — RGBA components → hex string
 *   custom stops: pass "stops": [{"position":0..1,"hex":"#..."}...] instead
 *   of a builtin name (count >= 2, positions strictly increasing).
 *
 * No I/O, no external deps beyond cJSON/sds. All input validated; negative
 * counts and malformed data are rejected, NaN is treated as invalid, and
 * everything is bounds-checked before interpolation. */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>

#define CM_MAX_STOPS 64
#define CM_MAX_RAMP  4096

typedef struct { double position; uint8_t rgba[4]; } cm_stop_t;

/* --- built-in stop tables (verbatim values from datoviz colormap.c) -------- */
static const cm_stop_t cm_viridis[] = {
    {0.00, {68, 1, 84, 255}},   {0.25, {59, 82, 139, 255}},
    {0.50, {33, 145, 140, 255}},{0.75, {94, 201, 98, 255}},
    {1.00, {253, 231, 37, 255}}};
static const cm_stop_t cm_magma[] = {
    {0.00, {0, 0, 4, 255}},     {0.25, {80, 18, 123, 255}},
    {0.50, {182, 54, 121, 255}},{0.75, {251, 136, 97, 255}},
    {1.00, {252, 253, 191, 255}}};
static const cm_stop_t cm_plasma[] = {
    {0.00, {13, 8, 135, 255}},  {0.25, {126, 3, 168, 255}},
    {0.50, {204, 71, 120, 255}},{0.75, {248, 149, 64, 255}},
    {1.00, {240, 249, 33, 255}}};
static const cm_stop_t cm_inferno[] = {
    {0.00, {0, 0, 4, 255}},     {0.25, {87, 16, 110, 255}},
    {0.50, {188, 55, 84, 255}}, {0.75, {249, 142, 9, 255}},
    {1.00, {252, 255, 164, 255}}};
static const cm_stop_t cm_cividis[] = {
    {0.00, {0, 32, 76, 255}},   {0.25, {59, 78, 109, 255}},
    {0.50, {124, 123, 120, 255}},{0.75, {188, 172, 103, 255}},
    {1.00, {255, 233, 69, 255}}};
static const cm_stop_t cm_turbo[] = {
    {0.00, {48, 18, 59, 255}},  {0.20, {55, 91, 178, 255}},
    {0.40, {49, 205, 207, 255}},{0.60, {135, 255, 88, 255}},
    {0.80, {255, 170, 36, 255}},{1.00, {122, 4, 3, 255}}};
static const cm_stop_t cm_gray[] = {
    {0.00, {0, 0, 0, 255}},     {1.00, {255, 255, 255, 255}}};
static const cm_stop_t cm_coolwarm[] = {
    {0.00, {59, 76, 192, 255}}, {0.50, {221, 221, 221, 255}},
    {1.00, {180, 4, 38, 255}}};

typedef struct { const char *name; const cm_stop_t *stops; uint32_t count; } cm_builtin_t;
static const cm_builtin_t cm_builtins[] = {
    {"viridis", cm_viridis, 5}, {"magma", cm_magma, 5},
    {"plasma", cm_plasma, 5},   {"inferno", cm_inferno, 5},
    {"cividis", cm_cividis, 5}, {"turbo", cm_turbo, 6},
    {"gray", cm_gray, 2},       {"grey", cm_gray, 2},
    {"coolwarm", cm_coolwarm, 3},
};

/* --- hex parsing: #RGB / #RGBA / #RRGGBB / #RRGGBBAA ------------------------ */
static int cm_hex_digit(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns 1 on success. Rejects NULL, missing '#', bad length, bad chars. */
static int cm_parse_hex(const char *hex, uint8_t out[4]) {
    if (!hex || hex[0] != '#') return 0;
    size_t n = strlen(hex + 1);
    if (n != 3 && n != 4 && n != 6 && n != 8) return 0;
    out[3] = 255;
    if (n == 3 || n == 4) {
        for (int c = 0; c < (int)(n); c++) {
            int d = cm_hex_digit((unsigned char)hex[1 + c]);
            if (d < 0) return 0;
            out[c] = (uint8_t)(d * 17);
        }
        return 1;
    }
    for (int c = 0; c < (int)(n / 2); c++) {
        int hi = cm_hex_digit((unsigned char)hex[1 + 2 * c]);
        int lo = cm_hex_digit((unsigned char)hex[2 + 2 * c]);
        if (hi < 0 || lo < 0) return 0;
        out[c] = (uint8_t)(hi * 16 + lo);
    }
    return 1;
}

/* datoviz _colormap_sample_stops: nearest stops bracketing t, lerp, clamp. */
static void cm_sample_stops(const cm_stop_t *stops, uint32_t count, double t,
                            uint8_t out[4]) {
    const cm_stop_t *lo = &stops[0];
    const cm_stop_t *hi = &stops[count - 1];
    for (uint32_t i = 1; i < count; i++) {
        if (t <= stops[i].position) {
            lo = &stops[i - 1];
            hi = &stops[i];
            break;
        }
    }
    double span = hi->position - lo->position;
    double u = span > 0.0 ? (t - lo->position) / span : 0.0;
    if (u < 0.0) u = 0.0;
    if (u > 1.0) u = 1.0;
    for (int c = 0; c < 4; c++) {
        double v = (1.0 - u) * lo->rgba[c] + u * hi->rgba[c];
        out[c] = (uint8_t)(v + 0.5);
    }
}

static void cm_rgba_to_hex(const uint8_t rgba[4], char out[10]) {
    if (rgba[3] == 255)
        snprintf(out, 10, "#%02X%02X%02X", rgba[0], rgba[1], rgba[2]);
    else
        snprintf(out, 10, "#%02X%02X%02X%02X", rgba[0], rgba[1], rgba[2], rgba[3]);
}

/* Validate + convert a cJSON stops array into a cm_stop_t table.
 * Rejects: non-arrays, <2 stops, >CM_MAX_STOPS, missing/bad position or hex,
 * positions outside [0,1], non-increasing positions. */
static int cm_build_custom_stops(cJSON *arr, cm_stop_t *out, uint32_t *out_n,
                                 sds *err) {
    if (!cJSON_IsArray(arr)) {
        *err = sdsnew("ERROR: 'stops' must be an array of {position, hex}");
        return -1;
    }
    int n = cJSON_GetArraySize(arr);
    if (n < 2) {
        *err = sdsnew("ERROR: 'stops' needs at least 2 entries");
        return -1;
    }
    if (n > CM_MAX_STOPS) {
        *err = sdscatprintf(sdsempty(), "ERROR: too many stops (%d > %d)", n, CM_MAX_STOPS);
        return -1;
    }
    double prev = -1.0;
    int i = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        cJSON *pos = cJSON_GetObjectItem(item, "position");
        const char *hex = cJSON_GetStringValue(cJSON_GetObjectItem(item, "hex"));
        if (!cJSON_IsNumber(pos) || !hex) {
            *err = sdscatprintf(sdsempty(),
                                "ERROR: stops[%d] needs numeric 'position' and 'hex' string", i);
            return -1;
        }
        double p = pos->valuedouble;
        if (isnan(p) || p < 0.0 || p > 1.0) {
            *err = sdscatprintf(sdsempty(),
                                "ERROR: stops[%d] position %g outside [0,1]", i, p);
            return -1;
        }
        if (p <= prev) {
            *err = sdscatprintf(sdsempty(),
                                "ERROR: stops[%d] position %g not greater than %g", i, p, prev);
            return -1;
        }
        if (!cm_parse_hex(hex, out[i].rgba)) {
            *err = sdscatprintf(sdsempty(),
                                "ERROR: stops[%d] invalid hex '%s'", i, hex);
            return -1;
        }
        out[i].position = p;
        prev = p;
        i++;
    }
    *out_n = (uint32_t)n;
    return 0;
}

static const cm_builtin_t *cm_find_builtin(const char *name) {
    if (!name || !name[0]) return NULL;
    for (size_t i = 0; i < sizeof(cm_builtins) / sizeof(cm_builtins[0]); i++)
        if (strcmp(name, cm_builtins[i].name) == 0) return &cm_builtins[i];
    return NULL;
}

/* Shared arg resolution: colormap name or custom stops -> table + count. */
static int cm_resolve(cJSON *args, const cm_stop_t **stops, uint32_t *count,
                      sds *err) {
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(args, "colormap"));
    if (!name || !name[0]) name = cJSON_GetStringValue(cJSON_GetObjectItem(args, "name"));
    if (name && name[0]) {
        const cm_builtin_t *b = cm_find_builtin(name);
        if (!b) {
            *err = sdscatprintf(sdsempty(), "ERROR: unknown colormap '%s'", name);
            return -1;
        }
        *stops = b->stops;
        *count = b->count;
        return 0;
    }
    /* Custom stop table supplied inline. */
    cm_stop_t *table = (cm_stop_t *)malloc(sizeof(cm_stop_t) * CM_MAX_STOPS);
    if (!table) {
        *err = sdsnew("ERROR: out of memory");
        return -1;
    }
    uint32_t n = 0;
    cJSON *arr = cJSON_GetObjectItem(args, "stops");
    if (!arr) {
        free(table);
        *err = sdsnew("ERROR: provide 'colormap' name or 'stops' array");
        return -1;
    }
    if (cm_build_custom_stops(arr, table, &n, err) != 0) {
        free(table);
        return -1;
    }
    *stops = table;
    *count = n;
    return 1; /* caller owns table */
}

/* Fetch one normalized scalar from args: "t" directly, or "value"+"min"+"max"
 * normalization (datoviz scale semantics: value maps into [min,max]). */
static int cm_get_t(cJSON *args, double *t, sds *err) {
    cJSON *jt = cJSON_GetObjectItem(args, "t");
    if (cJSON_IsNumber(jt)) {
        if (isnan(jt->valuedouble)) {
            *err = sdsnew("ERROR: 't' is NaN");
            return -1;
        }
        *t = jt->valuedouble;
        if (*t < 0.0) *t = 0.0;
        if (*t > 1.0) *t = 1.0;
        return 0;
    }
    cJSON *jv = cJSON_GetObjectItem(args, "value");
    cJSON *jmin = cJSON_GetObjectItem(args, "min");
    cJSON *jmax = cJSON_GetObjectItem(args, "max");
    if (!cJSON_IsNumber(jv) || !cJSON_IsNumber(jmin) || !cJSON_IsNumber(jmax)) {
        *err = sdsnew("ERROR: provide 't' in [0,1] or 'value'+'min'+'max'");
        return -1;
    }
    double lo = jmin->valuedouble, hi = jmax->valuedouble;
    if (isnan(lo) || isnan(hi) || hi <= lo) {
        *err = sdsnew("ERROR: 'max' must be greater than 'min' (and finite)");
        return -1;
    }
    *t = (jv->valuedouble - lo) / (hi - lo);
    if (*t < 0.0) *t = 0.0;
    if (*t > 1.0) *t = 1.0;
    return 0;
}

static sds cm_color_json(const uint8_t rgba[4]) {
    char hex[10];
    cm_rgba_to_hex(rgba, hex);
    return sdscatprintf(sdsempty(),
        "{\"hex\":\"%s\",\"r\":%d,\"g\":%d,\"b\":%d,\"a\":%d,"
        "\"rgb\":[%.6f,%.6f,%.6f]}",
        hex, rgba[0], rgba[1], rgba[2], rgba[3],
        rgba[0] / 255.0, rgba[1] / 255.0, rgba[2] / 255.0);
}

static sds tool_colormap_run(cJSON *args, const char *cwd) {
    (void)cwd;
    if (!args) return sdsnew("ERROR: no arguments");
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "sample";

    sds err = NULL;
    const cm_stop_t *stops = NULL;
    uint32_t count = 0;

    /* list: no colormap resolution needed. */
    if (strcmp(action, "list") == 0) {
        sds out = sdsnew("{\"colormaps\":[");
        size_t nb = sizeof(cm_builtins) / sizeof(cm_builtins[0]);
        for (size_t i = 0; i < nb; i++) {
            if (i > 0 && strcmp(cm_builtins[i].name, cm_builtins[i - 1].name) == 0)
                continue; /* alias (grey) listed once */
            if (i > 0) out = sdscat(out, ",");
            out = sdscatprintf(out, "{\"name\":\"%s\",\"stops\":%u,"
                                    "\"low\":\"#%02X%02X%02X\",\"high\":\"#%02X%02X%02X\"}",
                               cm_builtins[i].name, cm_builtins[i].count,
                               cm_builtins[i].stops[0].rgba[0], cm_builtins[i].stops[0].rgba[1],
                               cm_builtins[i].stops[0].rgba[2],
                               cm_builtins[i].stops[cm_builtins[i].count - 1].rgba[0],
                               cm_builtins[i].stops[cm_builtins[i].count - 1].rgba[1],
                               cm_builtins[i].stops[cm_builtins[i].count - 1].rgba[2]);
        }
        out = sdscat(out, "]}");
        return out;
    }

    /* parse: standalone hex → rgba (no colormap needed). */
    if (strcmp(action, "parse") == 0) {
        const char *hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "hex"));
        uint8_t rgba[4];
        if (!hex || !cm_parse_hex(hex, rgba)) {
            return sdscatprintf(sdsempty(), "ERROR: invalid hex color '%s' "
                                "(expected #RGB, #RGBA, #RRGGBB or #RRGGBBAA)",
                                hex ? hex : "(missing)");
        }
        sds out = cm_color_json(rgba);
        out = sdscat(out, ",\"input\":\"");
        out = sdscat(out, hex);
        out = sdscat(out, "\"}");
        return out;
    }

    /* to_hex: rgba components → hex string. */
    if (strcmp(action, "to_hex") == 0) {
        cJSON *jr = cJSON_GetObjectItem(args, "r");
        cJSON *jg = cJSON_GetObjectItem(args, "g");
        cJSON *jb = cJSON_GetObjectItem(args, "b");
        cJSON *ja = cJSON_GetObjectItem(args, "a");
        int comp[4] = {255, 255, 255, 255};
        cJSON *jc[4] = {jr, jg, jb, ja};
        for (int i = 0; i < 4; i++) {
            if (!cJSON_IsNumber(jc[i])) continue; /* a optional, others defaulted */
            double v = jc[i]->valuedouble;
            if (v != floor(v) || v < 0 || v > 255) {
                return sdscatprintf(sdsempty(),
                                    "ERROR: channel %d value %g is not an integer in [0,255]", i, v);
            }
            comp[i] = (int)v;
        }
        if (!cJSON_IsNumber(jr) || !cJSON_IsNumber(jg) || !cJSON_IsNumber(jb))
            return sdsnew("ERROR: 'r', 'g' and 'b' are required for to_hex");
        uint8_t rgba[4] = {(uint8_t)comp[0], (uint8_t)comp[1],
                           (uint8_t)comp[2], (uint8_t)comp[3]};
        char hex[10];
        cm_rgba_to_hex(rgba, hex);
        return sdscatprintf(sdsempty(), "{\"hex\":\"%s\",\"r\":%d,\"g\":%d,\"b\":%d,\"a\":%d}",
                            hex, rgba[0], rgba[1], rgba[2], rgba[3]);
    }

    /* Remaining actions need a colormap. */
    int owned = cm_resolve(args, &stops, &count, &err);
    if (owned < 0) return err;

    if (strcmp(action, "stops") == 0) {
        sds out = sdscatprintf(sdsempty(), "{\"stops\":[");
        for (uint32_t i = 0; i < count; i++) {
            if (i > 0) out = sdscat(out, ",");
            char hex[10];
            cm_rgba_to_hex(stops[i].rgba, hex);
            out = sdscatprintf(out, "{\"position\":%.4f,\"hex\":\"%s\"}",
                               stops[i].position, hex);
        }
        out = sdscat(out, "]}");
        if (owned) free((void *)stops);
        return out;
    }

    if (strcmp(action, "sample") == 0) {
        double t = 0.0;
        if (cm_get_t(args, &t, &err) != 0) {
            if (owned) free((void *)stops);
            return err;
        }
        uint8_t rgba[4];
        cm_sample_stops(stops, count, t, rgba);
        sds out = cm_color_json(rgba);
        out = sdscatprintf(out, ",\"t\":%.6f}", t);
        if (owned) free((void *)stops);
        return out;
    }

    if (strcmp(action, "ramp") == 0) {
        cJSON *jn = cJSON_GetObjectItem(args, "count");
        if (!cJSON_IsNumber(jn)) {
            if (owned) free((void *)stops);
            return sdsnew("ERROR: 'count' (integer 1..4096) required for ramp");
        }
        double nd = jn->valuedouble;
        if (nd != floor(nd) || nd < 1 || nd > CM_MAX_RAMP) {
            if (owned) free((void *)stops);
            return sdscatprintf(sdsempty(),
                                "ERROR: 'count' must be an integer in [1,%d], got %g",
                                CM_MAX_RAMP, nd);
        }
        int n = (int)nd;
        sds out = sdscatprintf(sdsempty(), "{\"count\":%d,\"colors\":[", n);
        for (int i = 0; i < n; i++) {
            double t = n == 1 ? 0.0 : (double)i / (double)(n - 1);
            uint8_t rgba[4];
            cm_sample_stops(stops, count, t, rgba);
            char hex[10];
            cm_rgba_to_hex(rgba, hex);
            if (i > 0) out = sdscat(out, ",");
            out = sdscatprintf(out, "\"%s\"", hex);
        }
        out = sdscat(out, "]}");
        if (owned) free((void *)stops);
        return out;
    }

    if (owned) free((void *)stops);
    return sdscatprintf(sdsempty(), "ERROR: unknown action '%s' "
                        "(expected list, sample, ramp, stops, parse, to_hex)", action);
}

static const alpha_tool_t tool_colormap = {
    .name = "colormap",
    .aliases = {"color", "cmap", NULL},
    .category = "codec",
    .description = "Color engine ported from datoviz: 8 matplotlib-style builtin colormaps (viridis, magma, plasma, inferno, cividis, turbo, gray, coolwarm) or custom stop tables. Map scalars to RGBA/HEX (sample, with min/max normalization), build gradients (ramp), inspect stop tables, parse/emit hex colors.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"colormap\",\"description\":\"Map scalars to colors using datoviz colormaps (sample, ramp, stops, parse, to_hex, list).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"sample\",\"ramp\",\"stops\",\"parse\",\"to_hex\",\"list\"],\"description\":\"Operation\"},\"colormap\":{\"type\":\"string\",\"description\":\"Builtin name: viridis, magma, plasma, inferno, cividis, turbo, gray/grey, coolwarm\"},\"stops\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"position\":{\"type\":\"number\"},\"hex\":{\"type\":\"string\"}}},\"description\":\"Custom stop table ({position 0..1, hex}); use instead of colormap\"},\"t\":{\"type\":\"number\",\"description\":\"Normalized scalar in [0,1]\"},\"value\":{\"type\":\"number\",\"description\":\"Raw value for min/max normalization\"},\"min\":{\"type\":\"number\"},\"max\":{\"type\":\"number\"},\"count\":{\"type\":\"integer\",\"description\":\"Number of colors for ramp (1..4096)\"},\"hex\":{\"type\":\"string\",\"description\":\"Hex color for parse (#RGB/#RRGGBB/#RRGGBBAA)\"},\"r\":{\"type\":\"integer\"},\"g\":{\"type\":\"integer\"},\"b\":{\"type\":\"integer\"},\"a\":{\"type\":\"integer\"}}}}}",
    .run = tool_colormap_run
};
