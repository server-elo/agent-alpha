/*
 * tool_colormath.c - Color Science, OKLab, CIELAB & CIEDE2000 Delta-E Engine
 *
 * Implements perceptual color conversion (sRGB, Linear RGB, CIE XYZ, CIELAB, OKLab,
 * HSL, HSV), CIEDE2000 color difference formula, and Kelvin color temperature.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include "cJSON.h"
#include "sds.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

typedef struct {
    double r, g, b; /* 0.0 - 1.0 */
} rgb_t;

typedef struct {
    double h, s, l; /* h: 0-360, s: 0-1, l: 0-1 */
} hsl_t;

typedef struct {
    double x, y, z;
} xyz_t;

typedef struct {
    double L, a, b;
} lab_t;

typedef struct {
    double L, a, b;
} oklab_t;

/* Standard Illuminant D65 reference white */
#define D65_X 0.95047
#define D65_Y 1.00000
#define D65_Z 1.08883

static double srgb_to_linear(double c) {
    if (c <= 0.04045) return c / 12.92;
    return pow((c + 0.055) / 1.055, 2.4);
}

static double linear_to_srgb(double c) {
    if (c <= 0.0031308) return c * 12.92;
    return 1.055 * pow(c, 1.0 / 2.4) - 0.055;
}

static xyz_t rgb_to_xyz(rgb_t rgb) {
    double r = srgb_to_linear(rgb.r);
    double g = srgb_to_linear(rgb.g);
    double b = srgb_to_linear(rgb.b);

    xyz_t xyz;
    xyz.x = r * 0.4124564 + g * 0.3575761 + b * 0.1804375;
    xyz.y = r * 0.2126729 + g * 0.7151522 + b * 0.0721750;
    xyz.z = r * 0.0193339 + g * 0.1191920 + b * 0.9503041;
    return xyz;
}

static double lab_f(double t) {
    double delta = 6.0 / 29.0;
    if (t > delta * delta * delta) {
        return cbrt(t);
    }
    return t / (3.0 * delta * delta) + 4.0 / 29.0;
}

static lab_t xyz_to_lab(xyz_t xyz) {
    double fx = lab_f(xyz.x / D65_X);
    double fy = lab_f(xyz.y / D65_Y);
    double fz = lab_f(xyz.z / D65_Z);

    lab_t lab;
    lab.L = 116.0 * fy - 16.0;
    lab.a = 500.0 * (fx - fy);
    lab.b = 200.0 * (fy - fz);
    return lab;
}

static oklab_t rgb_to_oklab(rgb_t rgb) {
    double r = srgb_to_linear(rgb.r);
    double g = srgb_to_linear(rgb.g);
    double b = srgb_to_linear(rgb.b);

    double l = 0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b;
    double m = 0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b;
    double s = 0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b;

    double l_ = cbrt(l);
    double m_ = cbrt(m);
    double s_ = cbrt(s);

    oklab_t ok;
    ok.L = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_;
    ok.a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_;
    ok.b = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_;
    return ok;
}

static hsl_t rgb_to_hsl(rgb_t rgb) {
    double max = fmax(rgb.r, fmax(rgb.g, rgb.b));
    double min = fmin(rgb.r, fmin(rgb.g, rgb.b));
    double delta = max - min;

    hsl_t hsl;
    hsl.l = (max + min) / 2.0;

    if (delta < 1e-6) {
        hsl.h = 0;
        hsl.s = 0;
    } else {
        hsl.s = hsl.l > 0.5 ? delta / (2.0 - max - min) : delta / (max + min);
        if (max == rgb.r) {
            hsl.h = (rgb.g - rgb.b) / delta + (rgb.g < rgb.b ? 6.0 : 0.0);
        } else if (max == rgb.g) {
            hsl.h = (rgb.b - rgb.r) / delta + 2.0;
        } else {
            hsl.h = (rgb.r - rgb.g) / delta + 4.0;
        }
        hsl.h *= 60.0;
    }
    return hsl;
}

static int parse_hex_color(const char *str, rgb_t *out) {
    if (!str) return 0;
    if (str[0] == '#') str++;
    size_t len = strlen(str);
    if (len == 6) {
        unsigned int hex = (unsigned int)strtoul(str, NULL, 16);
        out->r = ((hex >> 16) & 0xFF) / 255.0;
        out->g = ((hex >> 8) & 0xFF) / 255.0;
        out->b = (hex & 0xFF) / 255.0;
        return 1;
    } else if (len == 3) {
        char full[7] = {str[0], str[0], str[1], str[1], str[2], str[2], '\0'};
        unsigned int hex = (unsigned int)strtoul(full, NULL, 16);
        out->r = ((hex >> 16) & 0xFF) / 255.0;
        out->g = ((hex >> 8) & 0xFF) / 255.0;
        out->b = (hex & 0xFF) / 255.0;
        return 1;
    }
    return 0;
}

/* Official CIEDE2000 Color Difference Implementation */
static double ciede2000(lab_t lab1, lab_t lab2) {
    double kL = 1.0, kC = 1.0, kH = 1.0;
    double C1 = sqrt(lab1.a * lab1.a + lab1.b * lab1.b);
    double C2 = sqrt(lab2.a * lab2.a + lab2.b * lab2.b);
    double C_bar = (C1 + C2) / 2.0;

    double G = 0.5 * (1.0 - sqrt(pow(C_bar, 7) / (pow(C_bar, 7) + pow(25.0, 7))));
    double a1_prime = (1.0 + G) * lab1.a;
    double a2_prime = (1.0 + G) * lab2.a;

    double C1_prime = sqrt(a1_prime * a1_prime + lab1.b * lab1.b);
    double C2_prime = sqrt(a2_prime * a2_prime + lab2.b * lab2.b);

    double h1_prime = atan2(lab1.b, a1_prime) * 180.0 / M_PI;
    if (h1_prime < 0) h1_prime += 360.0;
    double h2_prime = atan2(lab2.b, a2_prime) * 180.0 / M_PI;
    if (h2_prime < 0) h2_prime += 360.0;

    double delta_L_prime = lab2.L - lab1.L;
    double delta_C_prime = C2_prime - C1_prime;

    double delta_h_prime = 0.0;
    if (C1_prime * C2_prime > 1e-6) {
        double diff = h2_prime - h1_prime;
        if (fabs(diff) <= 180.0) delta_h_prime = diff;
        else if (diff > 180.0) delta_h_prime = diff - 360.0;
        else delta_h_prime = diff + 360.0;
    }

    double delta_H_prime = 2.0 * sqrt(C1_prime * C2_prime) * sin((delta_h_prime * M_PI / 180.0) / 2.0);

    double L_bar_prime = (lab1.L + lab2.L) / 2.0;
    double C_bar_prime = (C1_prime + C2_prime) / 2.0;

    double h_bar_prime = 0.0;
    if (C1_prime * C2_prime > 1e-6) {
        double sum = h1_prime + h2_prime;
        if (fabs(h1_prime - h2_prime) <= 180.0) h_bar_prime = sum / 2.0;
        else if (sum < 360.0) h_bar_prime = (sum + 360.0) / 2.0;
        else h_bar_prime = (sum - 360.0) / 2.0;
    } else {
        h_bar_prime = h1_prime + h2_prime;
    }

    double T = 1.0 - 0.17 * cos((h_bar_prime - 30.0) * M_PI / 180.0)
                   + 0.24 * cos((2.0 * h_bar_prime) * M_PI / 180.0)
                   + 0.32 * cos((3.0 * h_bar_prime + 6.0) * M_PI / 180.0)
                   - 0.20 * cos((4.0 * h_bar_prime - 63.0) * M_PI / 180.0);

    double SL = 1.0 + (0.015 * pow(L_bar_prime - 50.0, 2)) / sqrt(20.0 + pow(L_bar_prime - 50.0, 2));
    double SC = 1.0 + 0.045 * C_bar_prime;
    double SH = 1.0 + 0.015 * C_bar_prime * T;

    double delta_theta = 30.0 * exp(-pow((h_bar_prime - 275.0) / 25.0, 2));
    double RC = 2.0 * sqrt(pow(C_bar_prime, 7) / (pow(C_bar_prime, 7) + pow(25.0, 7)));
    double RT = -RC * sin(2.0 * delta_theta * M_PI / 180.0);

    double dE00 = sqrt(pow(delta_L_prime / (kL * SL), 2) +
                       pow(delta_C_prime / (kC * SC), 2) +
                       pow(delta_H_prime / (kH * SH), 2) +
                       RT * (delta_C_prime / (kC * SC)) * (delta_H_prime / (kH * SH)));
    return dE00;
}

/* Kelvin to RGB approximation (Tanner Helland algorithm) */
static rgb_t kelvin_to_rgb(double temp) {
    double temp_k = temp / 100.0;
    double r, g, b;

    if (temp_k <= 66) {
        r = 255.0;
        g = 99.4708025861 * log(temp_k) - 161.1195681661;
        if (temp_k <= 19) b = 0.0;
        else b = 138.5177312231 * log(temp_k - 10) - 305.0447927307;
    } else {
        r = 329.698727446 * pow(temp_k - 60, -0.1332047592);
        g = 288.1221695283 * pow(temp_k - 60, -0.0755148492);
        b = 255.0;
    }

    rgb_t res;
    res.r = fmin(255.0, fmax(0.0, r)) / 255.0;
    res.g = fmin(255.0, fmax(0.0, g)) / 255.0;
    res.b = fmin(255.0, fmax(0.0, b)) / 255.0;
    return res;
}

static sds tool_colormath_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "convert";

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);

    if (strcmp(action, "convert") == 0) {
        cJSON *color_item = cJSON_GetObjectItem(args, "color");
        const char *color_str = color_item ? color_item->valuestring : "#38bdf8";

        rgb_t rgb = {0};
        if (!parse_hex_color(color_str, &rgb)) {
            cJSON *r_it = cJSON_GetObjectItem(args, "r");
            cJSON *g_it = cJSON_GetObjectItem(args, "g");
            cJSON *b_it = cJSON_GetObjectItem(args, "b");
            if (r_it && g_it && b_it) {
                rgb.r = r_it->valuedouble > 1.0 ? r_it->valuedouble / 255.0 : r_it->valuedouble;
                rgb.g = g_it->valuedouble > 1.0 ? g_it->valuedouble / 255.0 : g_it->valuedouble;
                rgb.b = b_it->valuedouble > 1.0 ? b_it->valuedouble / 255.0 : b_it->valuedouble;
            } else {
                cJSON_Delete(out);
                cJSON *err = cJSON_CreateObject();
                cJSON_AddStringToObject(err, "status", "error");
                cJSON_AddStringToObject(err, "error", "Invalid color hex or missing r,g,b components");
                char *json = cJSON_PrintUnformatted(err);
                sds res = sdsnew(json);
                free(json);
                cJSON_Delete(err);
                return res;
            }
        }

        char hex[16];
        snprintf(hex, sizeof(hex), "#%02X%02X%02X", (int)(rgb.r * 255 + 0.5), (int)(rgb.g * 255 + 0.5), (int)(rgb.b * 255 + 0.5));
        cJSON_AddStringToObject(out, "hex", hex);

        cJSON *rgb_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(rgb_obj, "r", (int)(rgb.r * 255 + 0.5));
        cJSON_AddNumberToObject(rgb_obj, "g", (int)(rgb.g * 255 + 0.5));
        cJSON_AddNumberToObject(rgb_obj, "b", (int)(rgb.b * 255 + 0.5));
        cJSON_AddItemToObject(out, "rgb", rgb_obj);

        hsl_t hsl = rgb_to_hsl(rgb);
        cJSON *hsl_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(hsl_obj, "h", hsl.h);
        cJSON_AddNumberToObject(hsl_obj, "s", hsl.s);
        cJSON_AddNumberToObject(hsl_obj, "l", hsl.l);
        cJSON_AddItemToObject(out, "hsl", hsl_obj);

        xyz_t xyz = rgb_to_xyz(rgb);
        cJSON *xyz_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(xyz_obj, "x", xyz.x);
        cJSON_AddNumberToObject(xyz_obj, "y", xyz.y);
        cJSON_AddNumberToObject(xyz_obj, "z", xyz.z);
        cJSON_AddItemToObject(out, "xyz", xyz_obj);

        lab_t lab = xyz_to_lab(xyz);
        cJSON *lab_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(lab_obj, "L", lab.L);
        cJSON_AddNumberToObject(lab_obj, "a", lab.a);
        cJSON_AddNumberToObject(lab_obj, "b", lab.b);
        cJSON_AddItemToObject(out, "cielab", lab_obj);

        oklab_t ok = rgb_to_oklab(rgb);
        cJSON *ok_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(ok_obj, "L", ok.L);
        cJSON_AddNumberToObject(ok_obj, "a", ok.a);
        cJSON_AddNumberToObject(ok_obj, "b", ok.b);
        cJSON_AddItemToObject(out, "oklab", ok_obj);

    } else if (strcmp(action, "delta_e") == 0) {
        cJSON *c1_item = cJSON_GetObjectItem(args, "color1");
        cJSON *c2_item = cJSON_GetObjectItem(args, "color2");
        rgb_t rgb1 = {0}, rgb2 = {0};

        if (!parse_hex_color(c1_item ? c1_item->valuestring : NULL, &rgb1) ||
            !parse_hex_color(c2_item ? c2_item->valuestring : NULL, &rgb2)) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Missing or invalid 'color1' and 'color2' hex strings");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        lab_t lab1 = xyz_to_lab(rgb_to_xyz(rgb1));
        lab_t lab2 = xyz_to_lab(rgb_to_xyz(rgb2));

        double dE00 = ciede2000(lab1, lab2);
        double dE76 = sqrt(pow(lab1.L - lab2.L, 2) + pow(lab1.a - lab2.a, 2) + pow(lab1.b - lab2.b, 2));

        cJSON_AddNumberToObject(out, "delta_e_2000", dE00);
        cJSON_AddNumberToObject(out, "delta_e_76", dE76);
        cJSON_AddBoolToObject(out, "perceptually_identical", dE00 < 1.0);

    } else if (strcmp(action, "kelvin") == 0) {
        cJSON *k_item = cJSON_GetObjectItem(args, "kelvin");
        double kelvin = k_item ? k_item->valuedouble : 6500.0;
        if (kelvin < 1000.0 || kelvin > 40000.0) {
            cJSON_Delete(out);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "status", "error");
            cJSON_AddStringToObject(err, "error", "Kelvin temperature must be between 1000 and 40000 K");
            char *json = cJSON_PrintUnformatted(err);
            sds res = sdsnew(json);
            free(json);
            cJSON_Delete(err);
            return res;
        }

        rgb_t rgb = kelvin_to_rgb(kelvin);
        char hex[16];
        snprintf(hex, sizeof(hex), "#%02X%02X%02X", (int)(rgb.r * 255 + 0.5), (int)(rgb.g * 255 + 0.5), (int)(rgb.b * 255 + 0.5));
        cJSON_AddNumberToObject(out, "kelvin", kelvin);
        cJSON_AddStringToObject(out, "hex", hex);

        cJSON *rgb_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(rgb_obj, "r", (int)(rgb.r * 255 + 0.5));
        cJSON_AddNumberToObject(rgb_obj, "g", (int)(rgb.g * 255 + 0.5));
        cJSON_AddNumberToObject(rgb_obj, "b", (int)(rgb.b * 255 + 0.5));
        cJSON_AddItemToObject(out, "rgb", rgb_obj);
    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: convert, delta_e, kelvin");
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

const alpha_tool_t tool_colormath = {
    .name = "colormath",
    .aliases = {"color_space", "ciede2000", "oklab"},
    .category = "graphics",
    .description = "Perceptual Color Science engine: convert between sRGB, HSL, CIELAB, OKLab, XYZ, and compute CIEDE2000 Delta-E.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"convert\", \"delta_e\", \"kelvin\"], \"description\": \"Action to perform\"},\n"
                   "    \"color\": {\"type\": \"string\", \"description\": \"Hex color (#RRGGBB)\"},\n"
                   "    \"color1\": {\"type\": \"string\", \"description\": \"First color for delta_e\"},\n"
                   "    \"color2\": {\"type\": \"string\", \"description\": \"Second color for delta_e\"},\n"
                   "    \"kelvin\": {\"type\": \"number\", \"description\": \"Temperature in Kelvin (1000 - 40000)\"}\n"
                   "  }\n"
                   "}",
    .run = tool_colormath_run
};
