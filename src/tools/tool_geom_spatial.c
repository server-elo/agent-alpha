/* tool_geom_spatial.c — 3D Vector & Quaternion Math, 2D Collisions, Color Codec & Easing Curves from raysan5/raylib */
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static sds tool_geom_spatial_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "vector";

    if (strcmp(action, "vector") == 0 || strcmp(action, "vec3") == 0) {
        double x1 = 0, y1 = 0, z1 = 0, x2 = 0, y2 = 0, z2 = 0, t = 0.5;
        cJSON *v1 = cJSON_GetObjectItem(args, "v1");
        cJSON *v2 = cJSON_GetObjectItem(args, "v2");
        if (v1 && cJSON_IsObject(v1)) {
            cJSON *ix = cJSON_GetObjectItem(v1, "x"); if (cJSON_IsNumber(ix)) x1 = ix->valuedouble;
            cJSON *iy = cJSON_GetObjectItem(v1, "y"); if (cJSON_IsNumber(iy)) y1 = iy->valuedouble;
            cJSON *iz = cJSON_GetObjectItem(v1, "z"); if (cJSON_IsNumber(iz)) z1 = iz->valuedouble;
        } else {
            cJSON *ix = cJSON_GetObjectItem(args, "x1"); if (cJSON_IsNumber(ix)) x1 = ix->valuedouble;
            cJSON *iy = cJSON_GetObjectItem(args, "y1"); if (cJSON_IsNumber(iy)) y1 = iy->valuedouble;
            cJSON *iz = cJSON_GetObjectItem(args, "z1"); if (cJSON_IsNumber(iz)) z1 = iz->valuedouble;
        }
        if (v2 && cJSON_IsObject(v2)) {
            cJSON *ix = cJSON_GetObjectItem(v2, "x"); if (cJSON_IsNumber(ix)) x2 = ix->valuedouble;
            cJSON *iy = cJSON_GetObjectItem(v2, "y"); if (cJSON_IsNumber(iy)) y2 = iy->valuedouble;
            cJSON *iz = cJSON_GetObjectItem(v2, "z"); if (cJSON_IsNumber(iz)) z2 = iz->valuedouble;
        } else {
            cJSON *ix = cJSON_GetObjectItem(args, "x2"); if (cJSON_IsNumber(ix)) x2 = ix->valuedouble;
            cJSON *iy = cJSON_GetObjectItem(args, "y2"); if (cJSON_IsNumber(iy)) y2 = iy->valuedouble;
            cJSON *iz = cJSON_GetObjectItem(args, "z2"); if (cJSON_IsNumber(iz)) z2 = iz->valuedouble;
        }
        cJSON *it = cJSON_GetObjectItem(args, "t"); if (cJSON_IsNumber(it)) t = it->valuedouble;

        double len1 = sqrt(x1 * x1 + y1 * y1 + z1 * z1);
        double len2 = sqrt(x2 * x2 + y2 * y2 + z2 * z2);
        double nx1 = len1 > 1e-9 ? x1 / len1 : 0, ny1 = len1 > 1e-9 ? y1 / len1 : 0, nz1 = len1 > 1e-9 ? z1 / len1 : 0;
        double dot = x1 * x2 + y1 * y2 + z1 * z2;
        double cx = y1 * z2 - z1 * y2;
        double cy = z1 * x2 - x1 * z2;
        double cz = x1 * y2 - y1 * x2;
        double dist = sqrt((x2 - x1)*(x2 - x1) + (y2 - y1)*(y2 - y1) + (z2 - z1)*(z2 - z1));
        double lerp_x = x1 + t * (x2 - x1);
        double lerp_y = y1 + t * (y2 - y1);
        double lerp_z = z1 + t * (z2 - z1);
        double angle_rad = 0;
        if (len1 > 1e-9 && len2 > 1e-9) {
            double cos_a = dot / (len1 * len2);
            if (cos_a > 1.0) cos_a = 1.0; if (cos_a < -1.0) cos_a = -1.0;
            angle_rad = acos(cos_a);
        }

        return sdscatprintf(sdsempty(),
            "{\"action\":\"vector\",\"len1\":%.6f,\"len2\":%.6f,\"dot\":%.6f,\"dist\":%.6f,"
            "\"normalized1\":{\"x\":%.6f,\"y\":%.6f,\"z\":%.6f},"
            "\"cross\":{\"x\":%.6f,\"y\":%.6f,\"z\":%.6f},"
            "\"lerp\":{\"x\":%.6f,\"y\":%.6f,\"z\":%.6f,\"t\":%.4f},"
            "\"angle_rad\":%.6f,\"angle_deg\":%.4f}",
            len1, len2, dot, dist, nx1, ny1, nz1, cx, cy, cz, lerp_x, lerp_y, lerp_z, t,
            angle_rad, angle_rad * (180.0 / 3.141592653589793));
    }

    if (strcmp(action, "quaternion") == 0 || strcmp(action, "quat") == 0) {
        const char *op = cJSON_GetStringValue(cJSON_GetObjectItem(args, "op"));
        if (!op || !op[0]) op = "from_euler";

        if (strcmp(op, "from_euler") == 0) {
            double pitch = 0, yaw = 0, roll = 0;
            cJSON *ip = cJSON_GetObjectItem(args, "pitch"); if (cJSON_IsNumber(ip)) pitch = ip->valuedouble;
            cJSON *iy = cJSON_GetObjectItem(args, "yaw"); if (cJSON_IsNumber(iy)) yaw = iy->valuedouble;
            cJSON *ir = cJSON_GetObjectItem(args, "roll"); if (cJSON_IsNumber(ir)) roll = ir->valuedouble;
            if (cJSON_IsTrue(cJSON_GetObjectItem(args, "degrees"))) {
                pitch *= (3.141592653589793 / 180.0);
                yaw *= (3.141592653589793 / 180.0);
                roll *= (3.141592653589793 / 180.0);
            }
            double cr = cos(roll * 0.5), sr = sin(roll * 0.5);
            double cp = cos(pitch * 0.5), sp = sin(pitch * 0.5);
            double cy = cos(yaw * 0.5), sy = sin(yaw * 0.5);
            double qx = sr * cp * cy - cr * sp * sy;
            double qy = cr * sp * cy + sr * cp * sy;
            double qz = cr * cp * sy - sr * sp * cy;
            double qw = cr * cp * cy + sr * sp * sy;
            return sdscatprintf(sdsempty(),
                "{\"action\":\"quaternion\",\"op\":\"from_euler\",\"x\":%.6f,\"y\":%.6f,\"z\":%.6f,\"w\":%.6f}",
                qx, qy, qz, qw);
        }

        if (strcmp(op, "rotate_vector") == 0) {
            double qx = 0, qy = 0, qz = 0, qw = 1.0, vx = 0, vy = 0, vz = 0;
            cJSON *iqx = cJSON_GetObjectItem(args, "qx"); if (cJSON_IsNumber(iqx)) qx = iqx->valuedouble;
            cJSON *iqy = cJSON_GetObjectItem(args, "qy"); if (cJSON_IsNumber(iqy)) qy = iqy->valuedouble;
            cJSON *iqz = cJSON_GetObjectItem(args, "qz"); if (cJSON_IsNumber(iqz)) qz = iqz->valuedouble;
            cJSON *iqw = cJSON_GetObjectItem(args, "qw"); if (cJSON_IsNumber(iqw)) qw = iqw->valuedouble;
            cJSON *ivx = cJSON_GetObjectItem(args, "vx"); if (cJSON_IsNumber(ivx)) vx = ivx->valuedouble;
            cJSON *ivy = cJSON_GetObjectItem(args, "vy"); if (cJSON_IsNumber(ivy)) vy = ivy->valuedouble;
            cJSON *ivz = cJSON_GetObjectItem(args, "vz"); if (cJSON_IsNumber(ivz)) vz = ivz->valuedouble;

            double uv_x = qy * vz - qz * vy;
            double uv_y = qz * vx - qx * vz;
            double uv_z = qx * vy - qy * vx;
            double uuv_x = qy * uv_z - qz * uv_y;
            double uuv_y = qz * uv_x - qx * uv_z;
            double uuv_z = qx * uv_y - qy * uv_x;

            double rx = vx + 2.0 * (qw * uv_x + uuv_x);
            double ry = vy + 2.0 * (qw * uv_y + uuv_y);
            double rz = vz + 2.0 * (qw * uv_z + uuv_z);

            return sdscatprintf(sdsempty(),
                "{\"action\":\"quaternion\",\"op\":\"rotate_vector\",\"x\":%.6f,\"y\":%.6f,\"z\":%.6f}",
                rx, ry, rz);
        }
    }

    if (strcmp(action, "collision_2d") == 0 || strcmp(action, "collision") == 0) {
        const char *mode = cJSON_GetStringValue(cJSON_GetObjectItem(args, "mode"));
        if (!mode || !mode[0]) mode = "rect_rect";

        if (strcmp(mode, "rect_rect") == 0) {
            double x1 = 0, y1 = 0, w1 = 0, h1 = 0, x2 = 0, y2 = 0, w2 = 0, h2 = 0;
            cJSON *i = cJSON_GetObjectItem(args, "x1"); if (cJSON_IsNumber(i)) x1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "y1"); if (cJSON_IsNumber(i)) y1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "w1"); if (cJSON_IsNumber(i)) w1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "h1"); if (cJSON_IsNumber(i)) h1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "x2"); if (cJSON_IsNumber(i)) x2 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "y2"); if (cJSON_IsNumber(i)) y2 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "w2"); if (cJSON_IsNumber(i)) w2 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "h2"); if (cJSON_IsNumber(i)) h2 = i->valuedouble;

            int collide = ((x1 < (x2 + w2)) && ((x1 + w1) > x2) &&
                           (y1 < (y2 + h2)) && ((y1 + h1) > y2));
            return sdscatprintf(sdsempty(), "{\"action\":\"collision_2d\",\"mode\":\"rect_rect\",\"collision\":%s}", collide ? "true" : "false");
        }

        if (strcmp(mode, "circle_circle") == 0) {
            double x1 = 0, y1 = 0, r1 = 0, x2 = 0, y2 = 0, r2 = 0;
            cJSON *i = cJSON_GetObjectItem(args, "x1"); if (cJSON_IsNumber(i)) x1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "y1"); if (cJSON_IsNumber(i)) y1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "r1"); if (cJSON_IsNumber(i)) r1 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "x2"); if (cJSON_IsNumber(i)) x2 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "y2"); if (cJSON_IsNumber(i)) y2 = i->valuedouble;
            i = cJSON_GetObjectItem(args, "r2"); if (cJSON_IsNumber(i)) r2 = i->valuedouble;

            double dx = x2 - x1, dy = y2 - y1;
            double dist_sq = dx * dx + dy * dy;
            double rad_sum = r1 + r2;
            int collide = dist_sq <= (rad_sum * rad_sum);
            return sdscatprintf(sdsempty(), "{\"action\":\"collision_2d\",\"mode\":\"circle_circle\",\"collision\":%s,\"distance\":%.4f}", collide ? "true" : "false", sqrt(dist_sq));
        }
    }

    if (strcmp(action, "color") == 0) {
        const char *hex_in = cJSON_GetStringValue(cJSON_GetObjectItem(args, "hex"));
        int r = 0, g = 0, b = 0, a = 255;
        if (hex_in) {
            const char *h = hex_in[0] == '#' ? hex_in + 1 : hex_in;
            unsigned int hr = 0, hg = 0, hb = 0, ha = 255;
            if (strlen(h) == 6 && sscanf(h, "%02x%02x%02x", &hr, &hg, &hb) == 3) {
                r = hr; g = hg; b = hb; a = 255;
            } else if (strlen(h) == 8 && sscanf(h, "%02x%02x%02x%02x", &hr, &hg, &hb, &ha) == 4) {
                r = hr; g = hg; b = hb; a = ha;
            }
        } else {
            cJSON *ir = cJSON_GetObjectItem(args, "r"); if (cJSON_IsNumber(ir)) r = (int)ir->valuedouble;
            cJSON *ig = cJSON_GetObjectItem(args, "g"); if (cJSON_IsNumber(ig)) g = (int)ig->valuedouble;
            cJSON *ib = cJSON_GetObjectItem(args, "b"); if (cJSON_IsNumber(ib)) b = (int)ib->valuedouble;
            cJSON *ia = cJSON_GetObjectItem(args, "a"); if (cJSON_IsNumber(ia)) a = (int)ia->valuedouble;
        }
        if (r < 0) r = 0; if (r > 255) r = 255;
        if (g < 0) g = 0; if (g > 255) g = 255;
        if (b < 0) b = 0; if (b > 255) b = 255;
        if (a < 0) a = 0; if (a > 255) a = 255;

        double rf = r / 255.0, gf = g / 255.0, bf = b / 255.0;
        double cmax = rf > gf ? (rf > bf ? rf : bf) : (gf > bf ? gf : bf);
        double cmin = rf < gf ? (rf < bf ? rf : bf) : (gf < bf ? gf : bf);
        double delta = cmax - cmin;
        double h = 0, s = cmax > 1e-6 ? (delta / cmax) : 0, v = cmax;
        if (delta > 1e-6) {
            if (cmax == rf) h = 60.0 * fmod(((gf - bf) / delta), 6.0);
            else if (cmax == gf) h = 60.0 * (((bf - rf) / delta) + 2.0);
            else h = 60.0 * (((rf - gf) / delta) + 4.0);
            if (h < 0) h += 360.0;
        }

        return sdscatprintf(sdsempty(),
            "{\"action\":\"color\",\"r\":%d,\"g\":%d,\"b\":%d,\"a\":%d,\"hex\":\"#%02X%02X%02X%02X\","
            "\"hsv\":{\"h\":%.2f,\"s\":%.4f,\"v\":%.4f}}",
            r, g, b, a, r, g, b, a, h, s, v);
    }

    if (strcmp(action, "easing") == 0) {
        double t = 0.5;
        cJSON *it = cJSON_GetObjectItem(args, "t"); if (cJSON_IsNumber(it)) t = it->valuedouble;
        if (t < 0.0) t = 0.0; if (t > 1.0) t = 1.0;
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(args, "type"));
        if (!type || !type[0]) type = "bounce_out";

        double val = t;
        if (strcmp(type, "bounce_out") == 0) {
            if (t < (1.0 / 2.75)) val = 7.5625 * t * t;
            else if (t < (2.0 / 2.75)) { t -= (1.5 / 2.75); val = 7.5625 * t * t + 0.75; }
            else if (t < (2.5 / 2.75)) { t -= (2.25 / 2.75); val = 7.5625 * t * t + 0.9375; }
            else { t -= (2.625 / 2.75); val = 7.5625 * t * t + 0.984375; }
        } else if (strcmp(type, "sine_in_out") == 0) {
            val = -0.5 * (cos(3.141592653589793 * t) - 1.0);
        } else if (strcmp(type, "expo_out") == 0) {
            val = (t == 1.0) ? 1.0 : 1.0 - pow(2.0, -10.0 * t);
        } else if (strcmp(type, "elastic_out") == 0) {
            if (t == 0.0 || t == 1.0) val = t;
            else val = pow(2.0, -10.0 * t) * sin((t - 0.075) * (2.0 * 3.141592653589793) / 0.3) + 1.0;
        }

        return sdscatprintf(sdsempty(), "{\"action\":\"easing\",\"type\":\"%s\",\"t\":%.4f,\"value\":%.6f}", type, it ? it->valuedouble : 0.5, val);
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown geom_spatial_2d3d action '%s'", action);
}

static const alpha_tool_t tool_geom_spatial = {
    .name = "geom_spatial_2d3d",
    .aliases = {"raylib_geom", NULL},
    .category = "spatial",
    .description = "3D Vector/Quaternion Transformations, 2D Geometric Collisions, Color RGBA/HSV/Hex Codec & Penner Easing Curves from raysan5/raylib. Actions: 'vector' (dot/cross/dist/lerp/angle/reflect), 'quaternion' (from_euler/rotate_vector), 'collision_2d' (rect_rect/circle_circle), 'color' (RGB/HSV/Hex), 'easing' (bounce/sine/expo/elastic).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"geom_spatial_2d3d\",\"description\":\"3D Vector/Quaternion Transformations, 2D Geometric Collisions, Color RGBA/HSV/Hex Codec & Penner Easing Curves from raysan5/raylib. Actions: 'vector' (dot/cross/dist/lerp/angle/reflect), 'quaternion' (from_euler/rotate_vector), 'collision_2d' (rect_rect/circle_circle), 'color' (RGB/HSV/Hex), 'easing' (bounce/sine/expo/elastic).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"vector\",\"quaternion\",\"collision_2d\",\"color\",\"easing\"]},\"op\":{\"type\":\"string\"},\"mode\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"x1\":{\"type\":\"number\"},\"y1\":{\"type\":\"number\"},\"z1\":{\"type\":\"number\"},\"x2\":{\"type\":\"number\"},\"y2\":{\"type\":\"number\"},\"z2\":{\"type\":\"number\"},\"r\":{\"type\":\"integer\"},\"g\":{\"type\":\"integer\"},\"b\":{\"type\":\"integer\"},\"a\":{\"type\":\"integer\"},\"hex\":{\"type\":\"string\"},\"t\":{\"type\":\"number\"}},\"required\":[]}}}",
    .run = tool_geom_spatial_run
};
