/* tool_tswindow.c — Pure-C time-series window aggregation (TDengine-style)
 * Actions: aggregate (default; also "tumbling"/"sliding" as shorthand actions)
 * Input: array of {"ts": <int>, "value": <number>} points.
 * Tumbling windows: [offset + k*interval, offset + (k+1)*interval).
 * Sliding windows:  [offset + k*slide,    offset + k*slide + interval).
 * Per window: count/min/max/avg/sum/first/last.
 * Unsorted input is handled honestly: a stable copy sorted by ts is used and
 * the result reports "sorted_input": false. Duplicate ts keep input order.
 * No I/O, no external deps beyond cJSON/sds/math.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <float.h>

#define TSWINDOW_MAX_POINTS       100000
#define TSWINDOW_MAX_WINDOWS_EMIT 10000
#define TSWINDOW_MAX_WINDOWS_SCAN 1000000
/* Timestamps must be exact doubles and products must stay inside int64. */
#define TSWINDOW_TS_LIMIT 9007199254740991.0 /* 2^53 - 1 */

typedef struct {
    int64_t ts;
    double value;
    int64_t seq; /* original input order, tie-break for stable sort */
} tsw_point_t;

typedef struct {
    int64_t start;
    int64_t end;
    int64_t count;
    double sum;
    double min;
    double max;
    double first;
    double last;
} tsw_window_t;

static int tsw_point_cmp(const void *a, const void *b) {
    const tsw_point_t *pa = (const tsw_point_t *)a;
    const tsw_point_t *pb = (const tsw_point_t *)b;
    if (pa->ts < pb->ts) return -1;
    if (pa->ts > pb->ts) return 1;
    if (pa->seq < pb->seq) return -1;
    if (pa->seq > pb->seq) return 1;
    return 0;
}

/* Floor division for b > 0 (C integer division truncates toward zero). */
static int64_t tsw_floor_div(int64_t a, int64_t b) {
    int64_t q = a / b;
    int64_t r = a % b;
    if (r != 0 && a < 0) q--;
    return q;
}

/* Ceil division for b > 0, no overflow (avoids a + b - 1). */
static int64_t tsw_ceil_div(int64_t a, int64_t b) {
    return -tsw_floor_div(-a, b);
}

/* Parse an integer-valued JSON number into int64 with strict checks.
 * Returns 0 on success. */
static int tsw_parse_int64(const cJSON *item, int64_t *out) {
    if (!cJSON_IsNumber(item)) return -1;
    double d = item->valuedouble;
    if (!isfinite(d)) return -1;
    if (d != floor(d)) return -1;
    if (d > TSWINDOW_TS_LIMIT || d < -TSWINDOW_TS_LIMIT) return -1;
    *out = (int64_t)d;
    return 0;
}

/* Extract the points array from args. Accepts a JSON array, or a string
 * encoding a JSON array. On error returns NULL and sets *err (caller frees).
 * On success returns malloc'd array (caller frees) and sets *out_n and
 * *out_sorted_input. The returned array is stably sorted by ts. */
static tsw_point_t *tsw_get_points(cJSON *args, size_t *out_n, int *out_sorted_input, sds *err) {
    *out_n = 0;
    *err = NULL;
    cJSON *item = cJSON_GetObjectItem(args, "data");
    if (!item) item = cJSON_GetObjectItem(args, "points");
    if (!item) item = cJSON_GetObjectItem(args, "input");
    cJSON *arr = NULL;
    cJSON *parsed = NULL;
    if (cJSON_IsArray(item)) {
        arr = item;
    } else if (cJSON_IsString(item) && item->valuestring) {
        parsed = cJSON_Parse(item->valuestring);
        if (!parsed || !cJSON_IsArray(parsed)) {
            if (parsed) cJSON_Delete(parsed);
            *err = sdsnew("ERROR: 'data' string is not a JSON array");
            return NULL;
        }
        arr = parsed;
    }
    if (!arr) {
        *err = sdsnew("ERROR: 'data' array of {ts, value} points is required");
        return NULL;
    }
    size_t n = (size_t)cJSON_GetArraySize(arr);
    if (n == 0) {
        if (parsed) cJSON_Delete(parsed);
        *err = sdsnew("ERROR: 'data' array is empty");
        return NULL;
    }
    if (n > TSWINDOW_MAX_POINTS) {
        if (parsed) cJSON_Delete(parsed);
        *err = sdscatprintf(sdsempty(), "ERROR: 'data' exceeds max %d points", TSWINDOW_MAX_POINTS);
        return NULL;
    }
    tsw_point_t *pts = (tsw_point_t *)malloc(n * sizeof(tsw_point_t));
    if (!pts) {
        if (parsed) cJSON_Delete(parsed);
        *err = sdsnew("ERROR: allocation failed");
        return NULL;
    }
    int sorted = 1;
    for (size_t i = 0; i < n; i++) {
        cJSON *e = cJSON_GetArrayItem(arr, (int)i);
        if (!cJSON_IsObject(e)) {
            free(pts);
            if (parsed) cJSON_Delete(parsed);
            *err = sdscatprintf(sdsempty(), "ERROR: point %zu is not an object {ts, value}", i);
            return NULL;
        }
        cJSON *jts = cJSON_GetObjectItem(e, "ts");
        if (!jts) jts = cJSON_GetObjectItem(e, "timestamp");
        cJSON *jval = cJSON_GetObjectItem(e, "value");
        if (!jval) jval = cJSON_GetObjectItem(e, "v");
        if (tsw_parse_int64(jts, &pts[i].ts) != 0) {
            free(pts);
            if (parsed) cJSON_Delete(parsed);
            *err = sdscatprintf(sdsempty(), "ERROR: point %zu has invalid 'ts' (must be a finite integer within ±2^53)", i);
            return NULL;
        }
        if (!cJSON_IsNumber(jval) || !isfinite(jval->valuedouble)) {
            free(pts);
            if (parsed) cJSON_Delete(parsed);
            *err = sdscatprintf(sdsempty(), "ERROR: point %zu has invalid 'value' (must be a finite number)", i);
            return NULL;
        }
        pts[i].value = jval->valuedouble;
        pts[i].seq = (int64_t)i;
        if (i > 0 && pts[i].ts < pts[i-1].ts) sorted = 0;
    }
    if (parsed) cJSON_Delete(parsed);
    if (!sorted) qsort(pts, n, sizeof(tsw_point_t), tsw_point_cmp);
    *out_n = n;
    *out_sorted_input = sorted;
    return pts;
}

static void tsw_window_init(tsw_window_t *w, int64_t start, int64_t end) {
    w->start = start;
    w->end = end;
    w->count = 0;
    w->sum = 0.0;
    w->min = DBL_MAX;
    w->max = -DBL_MAX;
    w->first = 0.0;
    w->last = 0.0;
}

static void tsw_window_add(tsw_window_t *w, double value) {
    if (w->count == 0) w->first = value;
    if (value < w->min) w->min = value;
    if (value > w->max) w->max = value;
    w->sum += value;
    w->last = value;
    w->count++;
}

static void tsw_window_to_json(cJSON *arr, const tsw_window_t *w) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "start", (double)w->start);
    cJSON_AddNumberToObject(o, "end", (double)w->end);
    cJSON_AddNumberToObject(o, "count", (double)w->count);
    cJSON_AddNumberToObject(o, "min", w->min);
    cJSON_AddNumberToObject(o, "max", w->max);
    cJSON_AddNumberToObject(o, "avg", w->sum / (double)w->count);
    cJSON_AddNumberToObject(o, "sum", w->sum);
    cJSON_AddNumberToObject(o, "first", w->first);
    cJSON_AddNumberToObject(o, "last", w->last);
    cJSON_AddItemToArray(arr, o);
}

/* Run one aggregation pass. windows_cb emits up to TSWINDOW_MAX_WINDOWS_EMIT
 * non-empty windows into `out`; sets *truncated if more existed.
 * Returns total non-empty window count, or -1 with *err set. */
static int64_t tsw_tumbling(const tsw_point_t *pts, size_t n, int64_t interval,
                            int64_t offset, cJSON *out, int *truncated, sds *err) {
    (void)err;
    int64_t total = 0;
    size_t i = 0;
    while (i < n) {
        int64_t widx = tsw_floor_div(pts[i].ts - offset, interval);
        int64_t wstart = offset + widx * interval;
        tsw_window_t w;
        tsw_window_init(&w, wstart, wstart + interval);
        while (i < n && tsw_floor_div(pts[i].ts - offset, interval) == widx) {
            tsw_window_add(&w, pts[i].value);
            i++;
        }
        if (total < TSWINDOW_MAX_WINDOWS_EMIT) tsw_window_to_json(out, &w);
        else *truncated = 1;
        total++;
    }
    return total;
}

static int64_t tsw_sliding(const tsw_point_t *pts, size_t n, int64_t interval,
                           int64_t slide, int64_t offset, cJSON *out,
                           int *truncated, sds *err) {
    int64_t min_ts = pts[0].ts;
    int64_t max_ts = pts[n-1].ts;
    /* Window k = [offset + k*slide, offset + k*slide + interval).
     * It is non-empty only if some ts falls inside: k ranges from
     * ceil((min_ts - offset - interval + 1)/slide) to floor((max_ts - offset)/slide). */
    int64_t k_min = tsw_ceil_div(min_ts - offset - interval + 1, slide);
    int64_t k_max = tsw_floor_div(max_ts - offset, slide);
    if (k_max - k_min + 1 > TSWINDOW_MAX_WINDOWS_SCAN) {
        *err = sdscatprintf(sdsempty(),
            "ERROR: sliding scan would span %lld candidate windows (max %d); increase slide",
            (long long)(k_max - k_min + 1), TSWINDOW_MAX_WINDOWS_SCAN);
        return -1;
    }
    int64_t total = 0;
    size_t lo = 0; /* first point that can still belong to the current window */
    for (int64_t k = k_min; k <= k_max; k++) {
        int64_t wstart = offset + k * slide;
        int64_t wend = wstart + interval;
        while (lo < n && pts[lo].ts < wstart) lo++;
        tsw_window_t w;
        tsw_window_init(&w, wstart, wend);
        for (size_t i = lo; i < n && pts[i].ts < wend; i++)
            tsw_window_add(&w, pts[i].value);
        if (w.count == 0) continue;
        if (total < TSWINDOW_MAX_WINDOWS_EMIT) tsw_window_to_json(out, &w);
        else *truncated = 1;
        total++;
    }
    return total;
}

static sds tool_tswindow_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "aggregate";

    const char *mode = cJSON_GetStringValue(cJSON_GetObjectItem(args, "mode"));
    if (strcmp(action, "tumbling") == 0 || strcmp(action, "sliding") == 0) {
        mode = action; /* shorthand: action names the window mode */
    } else if (strcmp(action, "aggregate") != 0 && strcmp(action, "windows") != 0) {
        return sdscatprintf(sdsempty(),
            "ERROR: unknown tswindow action '%s' (use aggregate/tumbling/sliding)", action);
    }
    if (!mode || !mode[0]) mode = "tumbling";
    int sliding;
    if (strcasecmp(mode, "tumbling") == 0) sliding = 0;
    else if (strcasecmp(mode, "sliding") == 0 || strcasecmp(mode, "hopping") == 0) sliding = 1;
    else return sdscatprintf(sdsempty(),
        "ERROR: unknown mode '%s' (use tumbling/sliding)", mode);

    cJSON *jinterval = cJSON_GetObjectItem(args, "interval");
    int64_t interval = 0;
    if (tsw_parse_int64(jinterval, &interval) != 0 || interval <= 0)
        return sdsnew("ERROR: 'interval' must be a positive integer (window size, same unit as ts)");
    if (interval > (int64_t)TSWINDOW_TS_LIMIT)
        return sdsnew("ERROR: 'interval' too large");

    int64_t slide = interval; /* tumbling default: slide == interval */
    if (sliding) {
        cJSON *jslide = cJSON_GetObjectItem(args, "slide");
        if (!jslide) jslide = cJSON_GetObjectItem(args, "step");
        if (tsw_parse_int64(jslide, &slide) != 0 || slide <= 0)
            return sdsnew("ERROR: sliding mode requires 'slide' as a positive integer");
        if (slide > (int64_t)TSWINDOW_TS_LIMIT)
            return sdsnew("ERROR: 'slide' too large");
    }

    int64_t offset = 0;
    cJSON *joffset = cJSON_GetObjectItem(args, "offset");
    if (!joffset) joffset = cJSON_GetObjectItem(args, "start_offset");
    if (joffset && tsw_parse_int64(joffset, &offset) != 0)
        return sdsnew("ERROR: 'offset' must be an integer within ±2^53");

    size_t n = 0;
    int sorted_input = 1;
    sds err = NULL;
    tsw_point_t *pts = tsw_get_points(args, &n, &sorted_input, &err);
    if (!pts) return err ? err : sdsnew("ERROR: invalid 'data'");

    cJSON *windows = cJSON_CreateArray();
    int truncated = 0;
    sds agg_err = NULL;
    int64_t total = sliding
        ? tsw_sliding(pts, n, interval, slide, offset, windows, &truncated, &agg_err)
        : tsw_tumbling(pts, n, interval, offset, windows, &truncated, &agg_err);
    free(pts);
    if (total < 0) {
        cJSON_Delete(windows);
        return agg_err ? agg_err : sdsnew("ERROR: aggregation failed");
    }

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "aggregate");
    cJSON_AddStringToObject(obj, "mode", sliding ? "sliding" : "tumbling");
    cJSON_AddNumberToObject(obj, "interval", (double)interval);
    if (sliding) cJSON_AddNumberToObject(obj, "slide", (double)slide);
    cJSON_AddNumberToObject(obj, "offset", (double)offset);
    cJSON_AddNumberToObject(obj, "points", (double)n);
    cJSON_AddBoolToObject(obj, "sorted_input", sorted_input);
    cJSON_AddNumberToObject(obj, "windows_total", (double)total);
    cJSON_AddNumberToObject(obj, "windows_emitted", (double)cJSON_GetArraySize(windows));
    cJSON_AddBoolToObject(obj, "truncated", truncated);
    cJSON_AddItemToObject(obj, "windows", windows);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    return res;
}

static const alpha_tool_t tool_tswindow = {
    .name = "tswindow",
    .aliases = {"ts_window", "window_agg", NULL},
    .category = "data",
    .description = "Time-series window aggregation (pure C, TDengine-style): tumbling or sliding windows over {ts, value} points, per-window count/min/max/avg/sum/first/last. Unsorted input is sorted stably and reported via sorted_input; strict validation of ts/interval/slide.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"tswindow\",\"description\":\"Aggregate time-series points into tumbling or sliding windows with count/min/max/avg/sum/first/last per window.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"aggregate\",\"tumbling\",\"sliding\"],\"description\":\"Operation; tumbling/sliding are shorthands selecting the mode\"},\"data\":{\"type\":\"array\",\"items\":{\"type\":\"object\"},\"description\":\"Array of points {\\\"ts\\\": <integer timestamp>, \\\"value\\\": <number>}\"},\"mode\":{\"type\":\"string\",\"enum\":[\"tumbling\",\"sliding\"],\"description\":\"Window mode (default tumbling)\"},\"interval\":{\"type\":\"integer\",\"description\":\"Window size in the same unit as ts (required, positive)\"},\"slide\":{\"type\":\"integer\",\"description\":\"Slide step for sliding mode (required for sliding, positive)\"},\"offset\":{\"type\":\"integer\",\"description\":\"Window alignment offset (default 0)\"}},\"required\":[\"data\",\"interval\"]}}}",
    .run = tool_tswindow_run
};
