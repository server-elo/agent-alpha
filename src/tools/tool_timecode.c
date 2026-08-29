/* tool_timecode.c — Pure-C timecode / timebase engine (FFmpeg-domain)
 * Actions: rescale, frame2sec, sec2frame, tc_parse, tc_format
 * No I/O, no external deps beyond cJSON/sds.
 *
 *  - rescale: av_rescale_q-style rational timebase conversion with
 *    overflow-safe 64-bit math (manual 128-bit multiply/divide, no __int128).
 *  - frame2sec / sec2frame: frame number <-> seconds under a rational fps.
 *  - tc_parse / tc_format: SMPTE timecode "HH:MM:SS:FF" (non-drop) and
 *    "HH:MM:SS;FF" (drop-frame, NTSC 29.97/59.94 style).
 *
 * Rates (fps, timebases) are rationals given as "30000/1001", "29.97", "25"
 * or a JSON number. Numerator and denominator must be in 1..INT32_MAX, like
 * FFmpeg's AVRational.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>

/* --- small integer helpers ------------------------------------------------ */

static int64_t tc_gcd64(int64_t a, int64_t b) {
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b) { int64_t t = a % b; a = b; b = t; }
    return a ? a : 1;
}

/* rounding modes for rescale / sec2frame */
enum {
    TC_RND_NEAREST = 0, /* round to nearest, halfway away from zero (default) */
    TC_RND_ZERO,        /* toward zero */
    TC_RND_INF,         /* away from zero */
    TC_RND_DOWN,        /* toward -infinity (floor) */
    TC_RND_UP           /* toward +infinity (ceil) */
};

static int tc_parse_rounding(const char *s, int *out) {
    if (!s || !s[0] || strcmp(s, "nearest") == 0 || strcmp(s, "near") == 0) { *out = TC_RND_NEAREST; return 0; }
    if (strcmp(s, "zero") == 0)  { *out = TC_RND_ZERO;  return 0; }
    if (strcmp(s, "inf") == 0)   { *out = TC_RND_INF;   return 0; }
    if (strcmp(s, "down") == 0)  { *out = TC_RND_DOWN;  return 0; }
    if (strcmp(s, "up") == 0)    { *out = TC_RND_UP;    return 0; }
    return -1;
}

/* --- overflow-safe 128/64 arithmetic ------------------------------------- */

/* 64x64 -> 128 multiply. */
static void tc_umul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint64_t a_lo = a & 0xffffffffu, a_hi = a >> 32;
    uint64_t b_lo = b & 0xffffffffu, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_hi * b_lo;
    uint64_t p2 = a_lo * b_hi;
    uint64_t p3 = a_hi * b_hi;
    uint64_t cross = (p0 >> 32) + (p1 & 0xffffffffu) + (p2 & 0xffffffffu);
    *hi = p3 + (p1 >> 32) + (p2 >> 32) + (cross >> 32);
    *lo = (cross << 32) | (p0 & 0xffffffffu);
}

/* 128/64 -> 64 division. Requires hi < d so the quotient fits in 64 bits.
 * Returns 0 on success, -1 if d == 0 or quotient would exceed 64 bits. */
static int tc_udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t *q, uint64_t *r) {
    if (d == 0 || hi >= d) return -1;
    uint64_t rem = 0, quot = 0;
    for (int i = 127; i >= 0; i--) {
        uint64_t bit = (i >= 64) ? (hi >> (i - 64)) & 1u : (lo >> i) & 1u;
        uint64_t top = rem >> 63;
        rem = (rem << 1) | bit;
        if (top || rem >= d) {
            rem -= d;
            if (i < 64) quot |= 1ull << i;
        }
    }
    *q = quot;
    *r = rem;
    return 0;
}

/* Compute a*b/c with rounding; b,c must be > 0. The intermediate product is
 * held in 128 bits so no 64-bit input combination overflows silently.
 * Returns 0 on success, -1 if the rounded result does not fit in int64_t. */
static int tc_rescale_rnd(int64_t a, int64_t b, int64_t c, int rnd, int64_t *out) {
    if (b <= 0 || c <= 0) return -1;
    int64_t g = tc_gcd64(b, c);
    b /= g; c /= g;
    int neg = a < 0;
    uint64_t ua = neg ? (uint64_t)(-(a + 1)) + 1u : (uint64_t)a;
    uint64_t hi, lo, q, r;
    tc_umul64(ua, (uint64_t)b, &hi, &lo);
    if (tc_udiv128(hi, lo, (uint64_t)c, &q, &r) != 0) return -1;
    int inc = 0;
    switch (rnd) {
        case TC_RND_NEAREST: inc = (r >= (uint64_t)c - r); break; /* 2r >= c, overflow-free */
        case TC_RND_ZERO:    inc = 0; break;
        case TC_RND_INF:     inc = (r > 0); break;
        case TC_RND_DOWN:    inc = (neg && r > 0); break;
        case TC_RND_UP:      inc = (!neg && r > 0); break;
        default: return -1;
    }
    if (inc) {
        if (q == UINT64_MAX) return -1;
        q++;
    }
    if (neg) {
        if (q > (uint64_t)INT64_MAX + 1u) return -1;
        *out = (q == (uint64_t)INT64_MAX + 1u) ? INT64_MIN : -(int64_t)q;
    } else {
        if (q > (uint64_t)INT64_MAX) return -1;
        *out = (int64_t)q;
    }
    return 0;
}

/* --- rational rate parsing ("30000/1001", "29.97", "25") ------------------ */

/* Parse a strict non-negative decimal integer; -1 on bad syntax or > cap. */
static int tc_parse_uint(const char *s, size_t len, int64_t cap, int64_t *out) {
    if (len == 0 || len > 18) return -1;
    int64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i])) return -1;
        v = v * 10 + (s[i] - '0');
        if (v > cap) return -1;
    }
    *out = v;
    return 0;
}

static int tc_parse_rate_str(const char *s, int64_t *num, int64_t *den, sds *err) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) len--;
    if (len == 0) {
        if (err) *err = sdsnew("ERROR: rate is empty");
        return -1;
    }
    const char *slash = memchr(s, '/', len);
    if (slash) {
        if (memchr(slash + 1, '/', len - (size_t)(slash + 1 - s))) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
            return -1;
        }
        int64_t n, d;
        if (tc_parse_uint(s, (size_t)(slash - s), INT32_MAX, &n) != 0 ||
            tc_parse_uint(slash + 1, len - (size_t)(slash - s) - 1, INT32_MAX, &d) != 0) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
            return -1;
        }
        if (n < 1 || d < 1) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: rate '%s' must be positive", s);
            return -1;
        }
        int64_t g = tc_gcd64(n, d);
        *num = n / g; *den = d / g;
        return 0;
    }
    const char *dot = memchr(s, '.', len);
    if (dot) {
        if (memchr(dot + 1, '.', len - (size_t)(dot + 1 - s))) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
            return -1;
        }
        int64_t ip = 0, fp = 0;
        size_t ilen = (size_t)(dot - s);
        size_t flen = len - ilen - 1;
        if (flen == 0 || flen > 9) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
            return -1;
        }
        if (ilen > 0 && tc_parse_uint(s, ilen, INT32_MAX, &ip) != 0) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
            return -1;
        }
        if (tc_parse_uint(dot + 1, flen, INT64_MAX, &fp) != 0) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
            return -1;
        }
        int64_t d = 1;
        for (size_t i = 0; i < flen; i++) d *= 10;
        int64_t n = ip * d + fp;
        if (n < 1 || n > INT32_MAX) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: rate '%s' out of range", s);
            return -1;
        }
        int64_t g = tc_gcd64(n, d);
        *num = n / g; *den = d / g;
        return 0;
    }
    int64_t n;
    if (tc_parse_uint(s, len, INT32_MAX, &n) != 0 || n < 1) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: malformed rate '%s'", s);
        return -1;
    }
    *num = n; *den = 1;
    return 0;
}

/* Get a positive rational rate from a cJSON item (string or number). */
static int tc_get_rate(cJSON *args, const char *key, int64_t *num, int64_t *den, sds *err) {
    cJSON *it = cJSON_GetObjectItem(args, key);
    if (!it) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' (rational, e.g. \"30000/1001\") is required", key);
        return -1;
    }
    if (cJSON_IsString(it) && it->valuestring)
        return tc_parse_rate_str(it->valuestring, num, den, err);
    if (cJSON_IsNumber(it)) {
        double v = it->valuedouble;
        if (!(v > 0.0) || v > (double)INT32_MAX) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' must be a positive rate", key);
            return -1;
        }
        double ip;
        if (modf(v, &ip) == 0.0) { *num = (int64_t)ip; *den = 1; return 0; }
        int64_t n = (int64_t)(v * 100000.0 + 0.5);
        if (n < 1 || n > INT32_MAX) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' out of range", key);
            return -1;
        }
        int64_t g = tc_gcd64(n, 100000);
        *num = n / g; *den = 100000 / g;
        return 0;
    }
    if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' must be a string or number", key);
    return -1;
}

/* Get a strict int64 from a cJSON item (number or string). */
static int tc_get_i64(cJSON *args, const char *key, int64_t *out, sds *err) {
    cJSON *it = cJSON_GetObjectItem(args, key);
    if (!it) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' is required", key);
        return -1;
    }
    if (cJSON_IsNumber(it)) {
        double v = it->valuedouble;
        double ip;
        if (modf(v, &ip) != 0.0 || v < -9.2e18 || v > 9.2e18) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' must be an integer", key);
            return -1;
        }
        *out = (int64_t)ip;
        return 0;
    }
    if (cJSON_IsString(it) && it->valuestring) {
        const char *s = it->valuestring;
        while (*s && isspace((unsigned char)*s)) s++;
        int neg = 0;
        if (*s == '-') { neg = 1; s++; }
        else if (*s == '+') s++;
        size_t len = strlen(s);
        while (len > 0 && isspace((unsigned char)s[len-1])) len--;
        int64_t mag;
        if (tc_parse_uint(s, len, (int64_t)INT64_MAX, &mag) != 0) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' is not a valid integer", key);
            return -1;
        }
        *out = neg ? -mag : mag;
        return 0;
    }
    if (err) *err = sdscatprintf(sdsempty(), "ERROR: '%s' must be a number or string", key);
    return -1;
}

/* --- SMPTE timecode helpers ------------------------------------------------ */

/* nominal (integer) frame rate of a rational fps, rounded to nearest */
static int64_t tc_nominal_fps(int64_t num, int64_t den) {
    return (num + den / 2) / den;
}

/* frames-per-minute frame-number drop for NTSC-style drop-frame:
 * 2 at 29.97 (nominal 30), 4 at 59.94 (nominal 60). 0 if unsupported. */
static int64_t tc_drop_per_min(int64_t nominal) {
    if (nominal <= 0 || nominal % 30 != 0) return 0;
    return 2 * (nominal / 30);
}

/* Parse "HH:MM:SS:FF" or "HH:MM:SS;FF" (semicolon marks drop-frame).
 * Returns 0 and fills fields, or -1 with err set. */
static int tc_parse_tc_fields(const char *s, int64_t *hh, int64_t *mm, int64_t *ss,
                              int64_t *ff, int *drop_hint, sds *err) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) len--;
    if (len == 0) {
        if (err) *err = sdsnew("ERROR: timecode string is empty");
        return -1;
    }
    int64_t f[4];
    int seps[3];
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        size_t start = pos;
        while (pos < len && s[pos] != ':' && s[pos] != ';') pos++;
        if (i < 3) {
            if (pos >= len) {
                if (err) *err = sdscatprintf(sdsempty(), "ERROR: timecode must be HH:MM:SS:FF, got '%s'", s);
                return -1;
            }
            seps[i] = s[pos];
        } else if (pos != len) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: trailing garbage in timecode '%s'", s);
            return -1;
        }
        if (tc_parse_uint(s + start, pos - start, 1000000, &f[i]) != 0) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: bad field in timecode '%s'", s);
            return -1;
        }
        pos++;
    }
    if (seps[0] != ':' || seps[1] != ':') {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: timecode must use ':' between HH:MM:SS, got '%s'", s);
        return -1;
    }
    *drop_hint = (seps[2] == ';');
    *hh = f[0]; *mm = f[1]; *ss = f[2]; *ff = f[3];
    if (*mm > 59 || *ss > 59) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: minutes/seconds out of range in '%s'", s);
        return -1;
    }
    return 0;
}

static sds tc_finish_json(cJSON *obj) {
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    return res;
}

static void tc_add_i64(cJSON *obj, const char *key, int64_t v) {
    cJSON_AddNumberToObject(obj, key, (double)v);
    sds str = sdscatprintf(sdsempty(), "%lld", (long long)v);
    sds k2 = sdscatprintf(sdsempty(), "%s_string", key);
    cJSON_AddStringToObject(obj, k2, str);
    sdsfree(str);
    sdsfree(k2);
}

static void tc_add_rate(cJSON *obj, const char *key, int64_t num, int64_t den) {
    sds str = (den == 1) ? sdscatprintf(sdsempty(), "%lld", (long long)num)
                         : sdscatprintf(sdsempty(), "%lld/%lld", (long long)num, (long long)den);
    cJSON_AddStringToObject(obj, key, str);
    sdsfree(str);
}

/* --- tool entry point ------------------------------------------------------ */

static sds tool_timecode_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "rescale";

    if (strcmp(action, "rescale") == 0) {
        int64_t value, fn, fd, tn, td;
        sds err = NULL;
        if (tc_get_i64(args, "value", &value, &err) != 0) return err;
        cJSON *from = cJSON_GetObjectItem(args, "from");
        if (!from) from = cJSON_GetObjectItem(args, "from_tb");
        if (!from) {
            cJSON *tmp = cJSON_CreateObject();
            if (!tc_get_i64(tmp, "x", &value, NULL)) { /* unreachable; keep value */ }
            cJSON_Delete(tmp);
        }
        {
            cJSON *holder = cJSON_CreateObject();
            cJSON_AddItemToObject(holder, "from", from ? cJSON_Duplicate(from, 1) : NULL);
            if (!from || tc_get_rate(holder, "from", &fn, &fd, &err) != 0) {
                cJSON_Delete(holder);
                if (!err) err = sdsnew("ERROR: 'from' timebase (e.g. \"1/90000\") is required");
                return err;
            }
            cJSON_Delete(holder);
        }
        {
            cJSON *to = cJSON_GetObjectItem(args, "to");
            if (!to) to = cJSON_GetObjectItem(args, "to_tb");
            cJSON *holder = cJSON_CreateObject();
            cJSON_AddItemToObject(holder, "to", to ? cJSON_Duplicate(to, 1) : NULL);
            if (!to || tc_get_rate(holder, "to", &tn, &td, &err) != 0) {
                cJSON_Delete(holder);
                if (!err) err = sdsnew("ERROR: 'to' timebase (e.g. \"1/1000\") is required");
                return err;
            }
            cJSON_Delete(holder);
        }
        int rnd;
        const char *rs = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rounding"));
        if (tc_parse_rounding(rs, &rnd) != 0)
            return sdscatprintf(sdsempty(), "ERROR: unknown rounding '%s' (use nearest/zero/inf/down/up)", rs);
        /* result = value * (fn/fd) / (tn/td) = value * fn * td / (fd * tn) */
        if (fn > INT64_MAX / td || fd > INT64_MAX / tn)
            return sdsnew("ERROR: timebase product overflow");
        int64_t b = fn * td, c = fd * tn;
        int64_t result;
        if (tc_rescale_rnd(value, b, c, rnd, &result) != 0)
            return sdsnew("ERROR: rescale result overflows int64");
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "rescale");
        tc_add_i64(obj, "value", value);
        tc_add_rate(obj, "from", fn, fd);
        tc_add_rate(obj, "to", tn, td);
        cJSON_AddStringToObject(obj, "rounding", rs && rs[0] ? rs : "nearest");
        tc_add_i64(obj, "result", result);
        return tc_finish_json(obj);
    }

    if (strcmp(action, "frame2sec") == 0 || strcmp(action, "f2s") == 0) {
        int64_t frame, fn, fd;
        sds err = NULL;
        if (tc_get_i64(args, "frame", &frame, &err) != 0) return err;
        if (tc_get_rate(args, "fps", &fn, &fd, &err) != 0) return err;
        /* seconds = frame * fd / fn as an exact reduced rational */
        int neg = frame < 0;
        uint64_t uf = neg ? (uint64_t)(-(frame + 1)) + 1u : (uint64_t)frame;
        if (uf > (uint64_t)INT64_MAX / (uint64_t)fd)
            return sdsnew("ERROR: frame*denominator overflows int64");
        int64_t n = (int64_t)uf * fd;
        int64_t g = tc_gcd64(n, fn);
        int64_t rn = n / g, rd = fn / g;
        double secs = (double)rn / (double)rd;
        if (neg) { secs = -secs; rn = -rn; }
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "frame2sec");
        tc_add_i64(obj, "frame", frame);
        tc_add_rate(obj, "fps", fn, fd);
        cJSON_AddNumberToObject(obj, "seconds", secs);
        sds rat = sdscatprintf(sdsempty(), "%lld/%lld", (long long)rn, (long long)rd);
        cJSON_AddStringToObject(obj, "seconds_rational", rat);
        sdsfree(rat);
        return tc_finish_json(obj);
    }

    if (strcmp(action, "sec2frame") == 0 || strcmp(action, "s2f") == 0) {
        int64_t sn, sd, fn, fd;
        sds err = NULL;
        cJSON *sit = cJSON_GetObjectItem(args, "seconds");
        if (!sit) return sdsnew("ERROR: 'seconds' is required for sec2frame");
        {
            cJSON *holder = cJSON_CreateObject();
            cJSON_AddItemToObject(holder, "seconds", cJSON_Duplicate(sit, 1));
            int rc = tc_get_rate(holder, "seconds", &sn, &sd, &err);
            cJSON_Delete(holder);
            if (rc != 0) return err;
        }
        if (tc_get_rate(args, "fps", &fn, &fd, &err) != 0) return err;
        int rnd;
        const char *rs = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rounding"));
        if (tc_parse_rounding(rs, &rnd) != 0)
            return sdscatprintf(sdsempty(), "ERROR: unknown rounding '%s' (use nearest/zero/inf/down/up)", rs);
        /* frame = seconds * fps = sn * fn / (sd * fd) */
        if (fn > INT64_MAX / sn || sd > INT64_MAX / fd)
            return sdsnew("ERROR: rate product overflow");
        int64_t frame;
        if (tc_rescale_rnd(1, 1, 1, rnd, &frame) != 0) { /* sanity, always ok */ }
        if (tc_rescale_rnd(sn, fn, sd * fd, rnd, &frame) != 0)
            return sdsnew("ERROR: frame result overflows int64");
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "sec2frame");
        cJSON_AddNumberToObject(obj, "seconds", (double)sn / (double)sd);
        tc_add_rate(obj, "fps", fn, fd);
        cJSON_AddStringToObject(obj, "rounding", rs && rs[0] ? rs : "nearest");
        tc_add_i64(obj, "frame", frame);
        return tc_finish_json(obj);
    }

    if (strcmp(action, "tc_parse") == 0 || strcmp(action, "parse") == 0) {
        const char *tcs = cJSON_GetStringValue(cJSON_GetObjectItem(args, "timecode"));
        if (!tcs) tcs = cJSON_GetStringValue(cJSON_GetObjectItem(args, "tc"));
        if (!tcs) tcs = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
        if (!tcs) return sdsnew("ERROR: 'timecode' (e.g. \"01:00:00:00\") is required for tc_parse");
        int64_t fn, fd;
        sds err = NULL;
        if (tc_get_rate(args, "fps", &fn, &fd, &err) != 0) return err;
        int64_t hh, mm, ss, ff;
        int drop_hint = 0;
        if (tc_parse_tc_fields(tcs, &hh, &mm, &ss, &ff, &drop_hint, &err) != 0) return err;
        int drop = drop_hint;
        cJSON *darg = cJSON_GetObjectItem(args, "drop");
        if (cJSON_IsBool(darg)) drop = cJSON_IsTrue(darg) ? 1 : 0;
        int64_t nominal = tc_nominal_fps(fn, fd);
        if (nominal < 1) return sdsnew("ERROR: fps too small for timecode");
        if (ff >= nominal)
            return sdscatprintf(sdsempty(), "ERROR: frame field %lld out of range for nominal fps %lld",
                                (long long)ff, (long long)nominal);
        int64_t dpm = 0, total_minutes = hh * 60 + mm;
        if (drop) {
            dpm = tc_drop_per_min(nominal);
            if (dpm == 0)
                return sdscatprintf(sdsempty(), "ERROR: drop-frame requires nominal fps multiple of 30, got %lld",
                                    (long long)nominal);
            if (ss == 0 && (mm % 10) != 0 && ff < dpm)
                return sdscatprintf(sdsempty(),
                                    "ERROR: %s does not exist in drop-frame (frames 0-%lld skipped at minute %lld)",
                                    tcs, (long long)(dpm - 1), (long long)mm);
        }
        int64_t frames = (hh * 3600 + mm * 60 + ss) * nominal + ff
                       - dpm * (total_minutes - total_minutes / 10);
        double secs = (double)frames * (double)fd / (double)fn;
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "tc_parse");
        cJSON_AddStringToObject(obj, "input", tcs);
        tc_add_rate(obj, "fps", fn, fd);
        tc_add_i64(obj, "nominal_fps", nominal);
        cJSON_AddBoolToObject(obj, "drop", drop);
        tc_add_i64(obj, "frames", frames);
        cJSON_AddNumberToObject(obj, "seconds", secs);
        return tc_finish_json(obj);
    }

    if (strcmp(action, "tc_format") == 0 || strcmp(action, "format") == 0) {
        int64_t frames, fn, fd;
        sds err = NULL;
        if (tc_get_i64(args, "frames", &frames, &err) != 0) {
            sdsfree(err); err = NULL;
            if (tc_get_i64(args, "frame", &frames, &err) != 0) return err;
        }
        if (frames < 0) return sdsnew("ERROR: 'frames' must be non-negative for tc_format");
        if (tc_get_rate(args, "fps", &fn, &fd, &err) != 0) return err;
        int drop = cJSON_IsTrue(cJSON_GetObjectItem(args, "drop"));
        int64_t nominal = tc_nominal_fps(fn, fd);
        if (nominal < 1) return sdsnew("ERROR: fps too small for timecode");
        int64_t hh, mm, ss, ff;
        if (drop) {
            int64_t dpm = tc_drop_per_min(nominal);
            if (dpm == 0)
                return sdscatprintf(sdsempty(), "ERROR: drop-frame requires nominal fps multiple of 30, got %lld",
                                    (long long)nominal);
            int64_t fp10 = nominal * 600 - 9 * dpm;      /* frames per 10-minute block */
            int64_t d = frames / fp10;
            int64_t m = frames % fp10;
            int64_t fpm0 = nominal * 60;                 /* minute 0 of block: no drop */
            int64_t fpmd = nominal * 60 - dpm;           /* minutes 1-9 of block */
            int64_t min_in_block, r;
            if (m < fpm0) { min_in_block = 0; r = m; }
            else {
                min_in_block = 1 + (m - fpm0) / fpmd;
                r = (m - fpm0) % fpmd + dpm;             /* skip dropped frame numbers */
            }
            int64_t total_minutes = d * 10 + min_in_block;
            ss = r / nominal;
            ff = r % nominal;
            hh = total_minutes / 60;
            mm = total_minutes % 60;
        } else {
            ff = frames % nominal;
            int64_t secs_i = frames / nominal;
            ss = secs_i % 60;
            int64_t mins = secs_i / 60;
            mm = mins % 60;
            hh = mins / 60;
        }
        sds tcs = sdscatprintf(sdsempty(), "%02lld:%02lld:%02lld%c%02lld",
                               (long long)hh, (long long)mm, (long long)ss,
                               drop ? ';' : ':', (long long)ff);
        double secs = (double)frames * (double)fd / (double)fn;
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "tc_format");
        tc_add_i64(obj, "frames", frames);
        tc_add_rate(obj, "fps", fn, fd);
        tc_add_i64(obj, "nominal_fps", nominal);
        cJSON_AddBoolToObject(obj, "drop", drop);
        cJSON_AddStringToObject(obj, "timecode", tcs);
        cJSON_AddNumberToObject(obj, "seconds", secs);
        sdsfree(tcs);
        return tc_finish_json(obj);
    }

    return sdscatprintf(sdsempty(),
                        "ERROR: unknown timecode action '%s' (use rescale/frame2sec/sec2frame/tc_parse/tc_format)",
                        action);
}

static const alpha_tool_t tool_timecode = {
    .name = "timecode",
    .aliases = {"tc", "smpte", NULL},
    .category = "codec",
    .description = "Timecode/timebase engine (pure C): rescale (av_rescale_q-style rational timebase conversion, overflow-safe 64-bit via 128-bit intermediate), frame2sec, sec2frame, tc_parse/tc_format for SMPTE HH:MM:SS:FF with NTSC drop-frame (';' separator, 29.97/59.94). Rounding modes nearest/zero/inf/down/up.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"timecode\",\"description\":\"Timecode/timebase engine: rescale between rational timebases, frame<->seconds, SMPTE timecode parse/format with drop-frame support.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"rescale\",\"frame2sec\",\"sec2frame\",\"tc_parse\",\"tc_format\"],\"description\":\"Operation\"},\"value\":{\"type\":\"integer\",\"description\":\"Value to rescale (rescale)\"},\"from\":{\"type\":\"string\",\"description\":\"Source timebase as rational, e.g. 1/90000 (rescale)\"},\"to\":{\"type\":\"string\",\"description\":\"Target timebase as rational, e.g. 1/1000 (rescale)\"},\"rounding\":{\"type\":\"string\",\"enum\":[\"nearest\",\"zero\",\"inf\",\"down\",\"up\"],\"description\":\"Rounding mode (default nearest)\"},\"frame\":{\"type\":\"integer\",\"description\":\"Frame number (frame2sec)\"},\"frames\":{\"type\":\"integer\",\"description\":\"Frame number (tc_format)\"},\"seconds\":{\"type\":\"string\",\"description\":\"Seconds as decimal or rational, e.g. 1.5 or 3/2 (sec2frame)\"},\"fps\":{\"type\":\"string\",\"description\":\"Frame rate as rational/decimal, e.g. 30000/1001, 29.97, 25\"},\"timecode\":{\"type\":\"string\",\"description\":\"SMPTE timecode HH:MM:SS:FF or HH:MM:SS;FF (tc_parse)\"},\"drop\":{\"type\":\"boolean\",\"description\":\"Force drop-frame mode (tc_parse/tc_format)\"}}}}}",
    .run = tool_timecode_run
};
