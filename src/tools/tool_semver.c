/* tool_semver.c — Pure-C Semantic Versioning (SemVer 2.0.0) engine
 * Actions: parse, valid, compare, inc, sort
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define SEMVER_MAX_LEN 256
#define SEMVER_MAX_IDENTS 32

typedef struct {
    int major;
    int minor;
    int patch;
    char prerelease[SEMVER_MAX_LEN];
    char build[SEMVER_MAX_LEN];
    int has_prerelease;
    int has_build;
} semver_t;

static int semver_is_ident_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') || c == '-';
}

/* Validate dot-separated identifiers. For prerelease, numeric identifiers
 * must not have leading zeros. Returns 1 if valid, 0 otherwise. */
static int semver_valid_idents(const char *s, int is_prerelease) {
    if (!s || !s[0]) return 0;
    size_t len = strlen(s);
    if (s[0] == '.' || s[len-1] == '.') return 0;
    if (strstr(s, "..")) return 0;
    const char *p = s;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t seg_len = dot ? (size_t)(dot - p) : strlen(p);
        if (seg_len == 0 || seg_len >= 64) return 0;
        for (size_t i = 0; i < seg_len; i++) {
            if (!semver_is_ident_char(p[i])) return 0;
        }
        if (is_prerelease) {
            int all_digits = 1;
            for (size_t i = 0; i < seg_len; i++) {
                if (!isdigit((unsigned char)p[i])) { all_digits = 0; break; }
            }
            if (all_digits && seg_len > 1 && p[0] == '0') return 0;
        }
        if (!dot) break;
        p = dot + 1;
    }
    return 1;
}

static int semver_parse(const char *s, semver_t *out, sds *err) {
    if (!s || !s[0]) {
        if (err) *err = sdsnew("ERROR: version string is empty");
        return -1;
    }
    /* Trim leading v/V prefix (common) but require strict otherwise.
     * Only allow one leading v. */
    if (s[0] == 'v' || s[0] == 'V') s++;
    if (!s[0]) {
        if (err) *err = sdsnew("ERROR: version string is empty after 'v' prefix");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    /* Split into core, prerelease, build */
    char core[SEMVER_MAX_LEN] = {0};
    char pre[SEMVER_MAX_LEN] = {0};
    char build[SEMVER_MAX_LEN] = {0};

    const char *plus = strchr(s, '+');
    const char *dash = strchr(s, '-');

    /* Validate ordering: dash before plus if both present */
    if (dash && plus && dash > plus) {
        if (err) *err = sdsnew("ERROR: '+' must come after '-' in semver");
        return -1;
    }

    const char *core_end = s + strlen(s);
    /* The core always ends at the first '-' or '+'. When both are present we
     * already validated that '-' precedes '+', so '-' wins: for
     * "2.0.0-alpha.1+001" the core is "2.0.0", not "2.0.0-alpha.1". */
    if (dash) core_end = dash;
    else if (plus) core_end = plus;

    /* Extract build */
    if (plus) {
        const char *b = plus + 1;
        if (!b[0]) {
            if (err) *err = sdsnew("ERROR: build metadata empty after '+'");
            return -1;
        }
        if (strlen(b) >= SEMVER_MAX_LEN) {
            if (err) *err = sdsnew("ERROR: build metadata too long");
            return -1;
        }
        strncpy(build, b, SEMVER_MAX_LEN - 1);
        if (!semver_valid_idents(build, 0)) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: invalid build metadata '%s'", build);
            return -1;
        }
        out->has_build = 1;
        strncpy(out->build, build, SEMVER_MAX_LEN - 1);
    }

    /* Extract prerelease */
    if (dash) {
        const char *pre_start = dash + 1;
        const char *pre_end = plus ? plus : s + strlen(s);
        size_t pre_len = (size_t)(pre_end - pre_start);
        if (pre_len == 0) {
            if (err) *err = sdsnew("ERROR: prerelease empty after '-'");
            return -1;
        }
        if (pre_len >= SEMVER_MAX_LEN) {
            if (err) *err = sdsnew("ERROR: prerelease too long");
            return -1;
        }
        strncpy(pre, pre_start, pre_len);
        pre[pre_len] = '\0';
        if (!semver_valid_idents(pre, 1)) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: invalid prerelease '%s'", pre);
            return -1;
        }
        out->has_prerelease = 1;
        strncpy(out->prerelease, pre, SEMVER_MAX_LEN - 1);
    }

    /* Parse core: MAJOR.MINOR.PATCH */
    size_t core_len = (size_t)(core_end - s);
    if (core_len >= SEMVER_MAX_LEN) {
        if (err) *err = sdsnew("ERROR: core version too long");
        return -1;
    }
    strncpy(core, s, core_len);
    core[core_len] = '\0';

    /* Must have exactly 2 dots */
    int dots = 0;
    for (size_t i = 0; i < core_len; i++) if (core[i] == '.') dots++;
    if (dots != 2) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: core version must be MAJOR.MINOR.PATCH, got '%s'", core);
        return -1;
    }

    char *save = NULL;
    /* Use strtok_r if available, else strtok */
    char *tok = strtok_r(core, ".", &save);
    int parts[3];
    for (int i = 0; i < 3; i++) {
        if (!tok) {
            if (err) *err = sdsnew("ERROR: missing version component");
            return -1;
        }
        /* Must be numeric, no leading zeros unless single 0 */
        if (!tok[0]) {
            if (err) *err = sdsnew("ERROR: empty version component");
            return -1;
        }
        for (size_t k = 0; tok[k]; k++) {
            if (!isdigit((unsigned char)tok[k])) {
                if (err) *err = sdscatprintf(sdsempty(), "ERROR: non-numeric version component '%s'", tok);
                return -1;
            }
        }
        if (tok[0] == '0' && tok[1] != '\0') {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: leading zero in component '%s'", tok);
            return -1;
        }
        char *ep = NULL;
        long v = strtol(tok, &ep, 10);
        if (*ep != '\0' || v < 0 || v > 1000000) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: invalid component '%s'", tok);
            return -1;
        }
        parts[i] = (int)v;
        tok = strtok_r(NULL, ".", &save);
    }
    if (tok) {
        if (err) *err = sdsnew("ERROR: too many components in core version");
        return -1;
    }
    out->major = parts[0];
    out->minor = parts[1];
    out->patch = parts[2];
    return 0;
}

static int semver_compare(const semver_t *a, const semver_t *b) {
    if (a->major != b->major) return a->major < b->major ? -1 : 1;
    if (a->minor != b->minor) return a->minor < b->minor ? -1 : 1;
    if (a->patch != b->patch) return a->patch < b->patch ? -1 : 1;
    /* Prerelease: absence has higher precedence */
    if (!a->has_prerelease && !b->has_prerelease) return 0;
    if (!a->has_prerelease && b->has_prerelease) return 1;
    if (a->has_prerelease && !b->has_prerelease) return -1;
    /* Both have prerelease: compare dot-separated identifiers */
    char ap[SEMVER_MAX_LEN], bp[SEMVER_MAX_LEN];
    strncpy(ap, a->prerelease, SEMVER_MAX_LEN - 1); ap[SEMVER_MAX_LEN-1]=0;
    strncpy(bp, b->prerelease, SEMVER_MAX_LEN - 1); bp[SEMVER_MAX_LEN-1]=0;
    char *save_a = NULL, *save_b = NULL;
    char *ta = strtok_r(ap, ".", &save_a);
    char *tb = strtok_r(bp, ".", &save_b);
    while (ta || tb) {
        if (!ta && tb) return -1;
        if (ta && !tb) return 1;
        int a_is_num = 1, b_is_num = 1;
        for (size_t i = 0; ta[i]; i++) if (!isdigit((unsigned char)ta[i])) { a_is_num = 0; break; }
        for (size_t i = 0; tb[i]; i++) if (!isdigit((unsigned char)tb[i])) { b_is_num = 0; break; }
        if (a_is_num && b_is_num) {
            long av = strtol(ta, NULL, 10);
            long bv = strtol(tb, NULL, 10);
            if (av != bv) return av < bv ? -1 : 1;
        } else if (a_is_num && !b_is_num) {
            return -1;
        } else if (!a_is_num && b_is_num) {
            return 1;
        } else {
            int c = strcmp(ta, tb);
            if (c != 0) return c < 0 ? -1 : 1;
        }
        ta = strtok_r(NULL, ".", &save_a);
        tb = strtok_r(NULL, ".", &save_b);
    }
    return 0;
}

static sds semver_to_string(const semver_t *v) {
    if (v->has_prerelease && v->has_build)
        return sdscatprintf(sdsempty(), "%d.%d.%d-%s+%s", v->major, v->minor, v->patch, v->prerelease, v->build);
    if (v->has_prerelease)
        return sdscatprintf(sdsempty(), "%d.%d.%d-%s", v->major, v->minor, v->patch, v->prerelease);
    if (v->has_build)
        return sdscatprintf(sdsempty(), "%d.%d.%d+%s", v->major, v->minor, v->patch, v->build);
    return sdscatprintf(sdsempty(), "%d.%d.%d", v->major, v->minor, v->patch);
}

static const char *semver_get_input(cJSON *args) {
    const char *keys[] = {"version", "data", "input", "text", "v", NULL};
    for (int i = 0; keys[i]; i++) {
        const char *s = cJSON_GetStringValue(cJSON_GetObjectItem(args, keys[i]));
        if (s) return s;
    }
    return NULL;
}

static sds tool_semver_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "parse";

    if (strcmp(action, "parse") == 0) {
        const char *ver = semver_get_input(args);
        if (!ver) return sdsnew("ERROR: 'version' (or 'data') is required for parse");
        semver_t sv; sds err = NULL;
        if (semver_parse(ver, &sv, &err) != 0) {
            sds e = err ? err : sdsnew("ERROR: parse failed");
            return e;
        }
        sds canon = semver_to_string(&sv);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "parse");
        cJSON_AddStringToObject(obj, "input", ver);
        cJSON_AddStringToObject(obj, "version", canon);
        cJSON_AddNumberToObject(obj, "major", sv.major);
        cJSON_AddNumberToObject(obj, "minor", sv.minor);
        cJSON_AddNumberToObject(obj, "patch", sv.patch);
        if (sv.has_prerelease) cJSON_AddStringToObject(obj, "prerelease", sv.prerelease);
        else cJSON_AddNullToObject(obj, "prerelease");
        if (sv.has_build) cJSON_AddStringToObject(obj, "build", sv.build);
        else cJSON_AddNullToObject(obj, "build");
        cJSON_AddBoolToObject(obj, "has_prerelease", sv.has_prerelease);
        cJSON_AddBoolToObject(obj, "has_build", sv.has_build);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); sdsfree(canon);
        return res;
    }

    if (strcmp(action, "valid") == 0 || strcmp(action, "validate") == 0) {
        const char *ver = semver_get_input(args);
        if (!ver) return sdsnew("ERROR: 'version' is required for valid");
        semver_t sv; sds err = NULL;
        int ok = semver_parse(ver, &sv, &err) == 0;
        if (err) sdsfree(err);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "valid");
        cJSON_AddStringToObject(obj, "input", ver);
        cJSON_AddBoolToObject(obj, "valid", ok);
        if (ok) {
            sds canon = semver_to_string(&sv);
            cJSON_AddStringToObject(obj, "version", canon);
            cJSON_AddNumberToObject(obj, "major", sv.major);
            cJSON_AddNumberToObject(obj, "minor", sv.minor);
            cJSON_AddNumberToObject(obj, "patch", sv.patch);
            sdsfree(canon);
        }
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj);
        return res;
    }

    if (strcmp(action, "compare") == 0 || strcmp(action, "cmp") == 0) {
        const char *v1s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "v1"));
        if (!v1s) v1s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "version"));
        if (!v1s) v1s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "a"));
        const char *v2s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "v2"));
        if (!v2s) v2s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "other"));
        if (!v2s) v2s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "b"));
        if (!v1s || !v2s) return sdsnew("ERROR: compare requires 'v1' and 'v2' (or 'version' and 'other')");
        semver_t s1, s2; sds e1 = NULL, e2 = NULL;
        if (semver_parse(v1s, &s1, &e1) != 0) { sds e = e1 ? e1 : sdsnew("ERROR: v1 parse failed"); if (e2) sdsfree(e2); return e; }
        if (semver_parse(v2s, &s2, &e2) != 0) { sdsfree(e1); sds e = e2 ? e2 : sdsnew("ERROR: v2 parse failed"); return e; }
        int cmp = semver_compare(&s1, &s2);
        const char *op = cmp < 0 ? "<" : cmp > 0 ? ">" : "==";
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "compare");
        cJSON_AddStringToObject(obj, "v1", v1s);
        cJSON_AddStringToObject(obj, "v2", v2s);
        cJSON_AddNumberToObject(obj, "cmp", cmp);
        cJSON_AddStringToObject(obj, "op", op);
        cJSON_AddBoolToObject(obj, "equal", cmp == 0);
        cJSON_AddBoolToObject(obj, "less", cmp < 0);
        cJSON_AddBoolToObject(obj, "greater", cmp > 0);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj);
        return res;
    }

    if (strcmp(action, "inc") == 0 || strcmp(action, "bump") == 0) {
        const char *ver = semver_get_input(args);
        if (!ver) return sdsnew("ERROR: 'version' is required for inc");
        const char *what = cJSON_GetStringValue(cJSON_GetObjectItem(args, "bump"));
        if (!what) what = cJSON_GetStringValue(cJSON_GetObjectItem(args, "field"));
        if (!what) what = cJSON_GetStringValue(cJSON_GetObjectItem(args, "type"));
        if (!what) what = cJSON_GetStringValue(cJSON_GetObjectItem(args, "part"));
        if (!what) what = "patch";
        semver_t sv; sds err = NULL;
        if (semver_parse(ver, &sv, &err) != 0) {
            sds e = err ? err : sdsnew("ERROR: parse failed");
            return e;
        }
        if (strcmp(what, "major") == 0) {
            sv.major++; sv.minor = 0; sv.patch = 0;
            sv.has_prerelease = 0; sv.has_build = 0; sv.prerelease[0]=0; sv.build[0]=0;
        } else if (strcmp(what, "minor") == 0) {
            sv.minor++; sv.patch = 0;
            sv.has_prerelease = 0; sv.has_build = 0; sv.prerelease[0]=0; sv.build[0]=0;
        } else if (strcmp(what, "patch") == 0) {
            sv.patch++;
            sv.has_prerelease = 0; sv.has_build = 0; sv.prerelease[0]=0; sv.build[0]=0;
        } else {
            return sdscatprintf(sdsempty(), "ERROR: unknown bump '%s' (use major/minor/patch)", what);
        }
        sds canon = semver_to_string(&sv);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "inc");
        cJSON_AddStringToObject(obj, "input", ver);
        cJSON_AddStringToObject(obj, "bump", what);
        cJSON_AddStringToObject(obj, "version", canon);
        cJSON_AddNumberToObject(obj, "major", sv.major);
        cJSON_AddNumberToObject(obj, "minor", sv.minor);
        cJSON_AddNumberToObject(obj, "patch", sv.patch);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); sdsfree(canon);
        return res;
    }

    if (strcmp(action, "sort") == 0) {
        cJSON *arr = cJSON_GetObjectItem(args, "data");
        if (!arr) arr = cJSON_GetObjectItem(args, "versions");
        if (!arr) arr = cJSON_GetObjectItem(args, "input");
        cJSON *parsed_tmp = NULL;
        if (cJSON_IsString(arr) && arr->valuestring) {
            parsed_tmp = cJSON_Parse(arr->valuestring);
            if (parsed_tmp && cJSON_IsArray(parsed_tmp)) arr = parsed_tmp;
            else {
                if (parsed_tmp) cJSON_Delete(parsed_tmp);
                parsed_tmp = NULL;
                /* try comma-separated string */
            }
        }
        /* handle comma-separated fallback */
        if (!cJSON_IsArray(arr)) {
            /* check if data was a string like "1.0.0, 2.0.0" */
            const char *raw = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
            if (!raw) raw = cJSON_GetStringValue(cJSON_GetObjectItem(args, "versions"));
            if (raw) {
                parsed_tmp = cJSON_CreateArray();
                char *copy = strdup(raw);
                char *tok = strtok(copy, ",");
                while (tok) {
                    while (*tok && isspace((unsigned char)*tok)) tok++;
                    char *end = tok + strlen(tok) - 1;
                    while (end > tok && isspace((unsigned char)*end)) { *end = '\0'; end--; }
                    if (*tok) cJSON_AddItemToArray(parsed_tmp, cJSON_CreateString(tok));
                    tok = strtok(NULL, ",");
                }
                free(copy);
                arr = parsed_tmp;
            }
        }
        if (!cJSON_IsArray(arr)) {
            if (parsed_tmp) cJSON_Delete(parsed_tmp);
            return sdsnew("ERROR: sort requires 'data' array of version strings");
        }
        int n = cJSON_GetArraySize(arr);
        if (n == 0) {
            if (parsed_tmp) cJSON_Delete(parsed_tmp);
            return sdsnew("ERROR: sort requires non-empty array");
        }
        if (n > 256) {
            if (parsed_tmp) cJSON_Delete(parsed_tmp);
            return sdsnew("ERROR: sort max 256 versions");
        }
        int order_desc = 0;
        const char *order = cJSON_GetStringValue(cJSON_GetObjectItem(args, "order"));
        if (order && (strcasecmp(order, "desc")==0 || strcasecmp(order, "descending")==0)) order_desc = 1;
        cJSON *dir = cJSON_GetObjectItem(args, "desc");
        if (cJSON_IsTrue(dir)) order_desc = 1;
        if (cJSON_IsNumber(cJSON_GetObjectItem(args, "desc")) && cJSON_GetObjectItem(args, "desc")->valueint) order_desc = 1;

        typedef struct { char raw[SEMVER_MAX_LEN]; semver_t sv; int idx; } item_t;
        item_t items[256];
        for (int i = 0; i < n; i++) {
            cJSON *e = cJSON_GetArrayItem(arr, i);
            if (!cJSON_IsString(e) || !e->valuestring) {
                if (parsed_tmp) cJSON_Delete(parsed_tmp);
                return sdscatprintf(sdsempty(), "ERROR: element %d is not a string", i);
            }
            strncpy(items[i].raw, e->valuestring, SEMVER_MAX_LEN - 1); items[i].raw[SEMVER_MAX_LEN-1]=0;
            items[i].idx = i;
            sds err = NULL;
            if (semver_parse(e->valuestring, &items[i].sv, &err) != 0) {
                sds msg = sdscatprintf(sdsempty(), "ERROR: element %d ('%s') invalid: %s", i, e->valuestring, err ? err : "parse failed");
                if (err) sdsfree(err);
                if (parsed_tmp) cJSON_Delete(parsed_tmp);
                return msg;
            }
            if (err) sdsfree(err);
        }
        /* bubble sort stable by semver */
        for (int i = 0; i < n-1; i++) {
            for (int j = 0; j < n-1-i; j++) {
                int c = semver_compare(&items[j].sv, &items[j+1].sv);
                int swap = order_desc ? (c < 0) : (c > 0);
                if (swap) { item_t t = items[j]; items[j]=items[j+1]; items[j+1]=t; }
            }
        }
        cJSON *out_arr = cJSON_CreateArray();
        for (int i = 0; i < n; i++) {
            sds canon = semver_to_string(&items[i].sv);
            cJSON_AddItemToArray(out_arr, cJSON_CreateString(canon));
            sdsfree(canon);
        }
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "sort");
        cJSON_AddNumberToObject(obj, "count", n);
        cJSON_AddStringToObject(obj, "order", order_desc ? "desc" : "asc");
        cJSON_AddItemToObject(obj, "versions", out_arr);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj);
        if (parsed_tmp) cJSON_Delete(parsed_tmp);
        return res;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown semver action '%s' (use parse/valid/compare/inc/sort)", action);
}

static const alpha_tool_t tool_semver = {
    .name = "semver",
    .aliases = {"version", "semver_compare", NULL},
    .category = "codec",
    .description = "Semantic Versioning 2.0.0 engine (pure C): parse (major/minor/patch/prerelease/build), valid, compare (cmp/op), inc/bump (major/minor/patch), sort (asc/desc). Strict numeric checks, prerelease precedence, build metadata.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"semver\",\"description\":\"Semantic Versioning 2.0.0 engine: parse, valid, compare, inc/bump, sort.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"parse\",\"valid\",\"compare\",\"inc\",\"sort\"],\"description\":\"Operation\"},\"version\":{\"type\":\"string\",\"description\":\"Version string (e.g. 1.2.3-alpha+001)\"},\"data\":{\"type\":\"string\",\"description\":\"Alias for version, or array for sort\"},\"v1\":{\"type\":\"string\",\"description\":\"First version for compare\"},\"v2\":{\"type\":\"string\",\"description\":\"Second version for compare\"},\"other\":{\"type\":\"string\",\"description\":\"Alias for v2\"},\"bump\":{\"type\":\"string\",\"enum\":[\"major\",\"minor\",\"patch\"],\"description\":\"Field to bump for inc\"},\"versions\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Array of versions for sort\"},\"order\":{\"type\":\"string\",\"enum\":[\"asc\",\"desc\"],\"description\":\"Sort order\"}}}}}",
    .run = tool_semver_run
};
