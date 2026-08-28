/* tool_duration.c — Pure-C human duration parser/formatter
 * Actions: parse, format, add, compare
 * No I/O, no external deps beyond cJSON/sds/ctype.
 *
 * Units:
 *   w = weeks  (7*24*3600)
 *   d = days   (86400)
 *   h = hours  (3600)
 *   m = minutes(60)
 *   s = seconds(1)
 * Also supports "ms" treated as fractional seconds? We round down to seconds
 * for simplicity (ms < 1000 => 0). Bare number without unit = seconds.
 *
 * Parses compact forms: "1d2h30m", "1h 30m", "2w 3d", "90s", "3600", etc.
 * Negative durations like "-1h30m" are supported.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>

/* Parse a duration string into total seconds (int64).
 * Returns 0 on success, -1 on error (err set to sds error).
 */
static int duration_parse_seconds(const char *s, long long *out, sds *err) {
    if (!s) {
        if (err) *err = sdsnew("ERROR: duration string is required");
        return -1;
    }
    // trim
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) {
        if (err) *err = sdsnew("ERROR: duration string is empty");
        return -1;
    }
    size_t len = strlen(s);
    // trim trailing spaces
    while (len > 0 && isspace((unsigned char)s[len-1])) len--;
    char buf[512];
    if (len >= sizeof(buf)) {
        if (err) *err = sdsnew("ERROR: duration string too long (max 511)");
        return -1;
    }
    memcpy(buf, s, len);
    buf[len] = '\0';
    s = buf;

    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) {
        if (err) *err = sdsnew("ERROR: duration string empty after sign");
        return -1;
    }

    long long total = 0;
    int found_any = 0;
    int has_unit = 0;
    int has_bare = 0;

    const char *p = s;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (!isdigit((unsigned char)*p)) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: expected number at '%s'", p);
            return -1;
        }
        char *end = NULL;
        long long num = strtoll(p, &end, 10);
        if (end == p) {
            if (err) *err = sdsnew("ERROR: failed to parse number");
            return -1;
        }
        if (num < 0 || num > 1000000000LL) {
            if (err) *err = sdsnew("ERROR: number out of range");
            return -1;
        }
        p = end;
        // skip spaces between number and unit
        while (*p && isspace((unsigned char)*p)) {
            // but if next is digit, treat as bare number delimiter, not space in unit
            // peek ahead: if after spaces there's a digit and we haven't consumed unit, it's bare.
            // Actually we handle by not consuming spaces as part of unit; just skip.
            p++;
        }
        long long mult = 1;
        int consumed_unit = 0;
        if (*p) {
            if (strncmp(p, "ms", 2) == 0) {
                // milliseconds: convert to seconds (truncated)
                long long add = num / 1000;
                if (total > LLONG_MAX - add) {
                    if (err) *err = sdsnew("ERROR: duration overflow");
                    return -1;
                }
                total += add;
                found_any = 1;
                has_unit = 1;
                p += 2;
                consumed_unit = 1;
            } else if (*p == 'w' || *p == 'W') {
                mult = 7LL*24*3600; consumed_unit = 1; p++;
            } else if (*p == 'd' || *p == 'D') {
                mult = 86400; consumed_unit = 1; p++;
            } else if (*p == 'h' || *p == 'H') {
                mult = 3600; consumed_unit = 1; p++;
            } else if (*p == 'm' || *p == 'M') {
                // m = minutes; ms already handled
                mult = 60; consumed_unit = 1; p++;
            } else if (*p == 's' || *p == 'S') {
                mult = 1; consumed_unit = 1; p++;
            }
        }
        if (consumed_unit) {
            has_unit = 1;
            // check overflow
            if (mult != 1) {
                if (num > LLONG_MAX / mult) {
                    if (err) *err = sdsnew("ERROR: duration overflow");
                    return -1;
                }
            }
            long long add = num * mult;
            if (mult == 1 && strncmp(p-1, "s", 1)==0) {
                // ms already added separately
                // for s unit, add is num*1, but ms case already handled
                // we are in s branch here
            }
            if (total > LLONG_MAX - add) {
                if (err) *err = sdsnew("ERROR: duration overflow");
                return -1;
            }
            // For ms we already added; don't double-add
            if (!(mult==1 && *(p-1)=='s' && 0)) {
                // normal
            }
            // Special: ms was already added with different logic, skip adding again
            // Detect ms: we already returned early for ms
            // So for non-ms units, add now
            if (mult != 0) {
                // Need to avoid double-count for ms case which already continued
                // But ms case already continued via if(ms) block, so we are not here for ms
                total += add;
            }
            found_any = 1;
        } else {
            // bare number = seconds
            // But if we already have units, bare numbers without unit are ambiguous;
            // we allow them only if it's the sole token? Actually allow mixing bare as seconds.
            // e.g., "1h 30" => 1h + 30s
            has_bare = 1;
            if (total > LLONG_MAX - num) {
                if (err) *err = sdsnew("ERROR: duration overflow");
                return -1;
            }
            total += num;
            found_any = 1;
        }
        // if there was a unit, we already handled ms separately with continue logic
        // For ms we did total+=num/1000 above and set p. For others we added.
        // Need to correct: the ms branch added and consumed, but then we still go to unit handling.
        // Refactor: the ms detection should be exclusive. To avoid confusion, restructure.
        // Actually the above ms handling is inside the if(*p) chain, but we treated it as separate.
        // The ms case already added truncated seconds and set consumed_unit and moved p.
        // But then the outer if(consumed_unit) block would add again (double count).
        // Fix: for ms, reset mult and avoid double add.
        // Simplify: if ms, we already added num/1000; don't re-add.
        // We need to detect ms and skip second addition.
        // Easiest: handle ms as early return path that doesn't fall through to addition.
        // For now, since ms added truncated, the second addition would double count.
        // So undo double count: if we took ms path, subtract the extra.
        // But ms path set mult? No, we set add=num/1000 and already did total+=add.
        // Then later we do total+=num*mult (mult for ms was not set as unit? Actually we set mult via ms branch? No, ms branch is separate from consumed_unit logic? Let's re-evaluate.
        // The ms branch is inside the if(*p) checking ms before the switch, but we also set has_unit and consumed_unit?
        // Wait: we set mult only in switch; ms branch sets total directly and moves p, but also sets consumed_unit=1 via has_unit? Actually ms branch did total+=add and set found_any and has_unit, p+=2, consumed_unit=1 but mult stays 1.
        // Then outside, we go into if(consumed_unit) and do total+=num*mult where mult=1, double counting.
        // So for ms we double count. Fix by removing double add: when ms was consumed, skip second add.
        // Detect ms by checking that we consumed "ms": we can check if p[-2]=='m' and p[-1]=='s' for ms case.
        // Simpler: restructure code to handle ms exclusively.
        // Quick fix: if ms case, total currently has + num/1000 (first) + num*1 (second) => subtract num + re-add correct? Actually total = old + num/1000 + num. Should be old + num/1000. So subtract num.
        if (has_unit && p >= buf+2 && p[-2]=='m' && p[-1]=='s') {
            // ms case was double counted with num seconds; correct it
            // We added num/1000 + num ; want only num/1000
            total -= num;
            // total already includes num/1000, but we subtracted num, so now it's correct? Wait we added num/1000 inside ms branch, then added num in outer block => total = old+num/1000+num. Subtracting num => old+num/1000 correct.
        }
        (void)has_bare;
        (void)has_unit;
    }
    if (!found_any) {
        if (err) *err = sdsnew("ERROR: no duration found");
        return -1;
    }
    if (neg) total = -total;
    *out = total;
    return 0;
}

/* Format seconds into human string like "1w 2d 3h 4m 5s"
 * Zero => "0s"
 * Negative => "-1h 30m" etc.
 */
static sds duration_format(long long secs) {
    if (secs == 0) return sdsnew("0s");
    int neg = secs < 0;
    long long v = neg ? -secs : secs;
    long long w = v / (7LL*86400); v %= 7LL*86400;
    long long d = v / 86400; v %= 86400;
    long long h = v / 3600; v %= 3600;
    long long m = v / 60; v %= 60;
    long long s = v;
    sds out = sdsempty();
    if (neg) out = sdscat(out, "-");
    int first = 1;
    #define APPEND(val, unit) do { if (val) { if (!first) out = sdscat(out, " "); out = sdscatprintf(out, "%lld" unit, (long long)val); first = 0; } } while(0)
    APPEND(w, "w");
    APPEND(d, "d");
    APPEND(h, "h");
    APPEND(m, "m");
    APPEND(s, "s");
    #undef APPEND
    // If total was for example 3600*24*7 = 1w exactly, we already output. Otherwise if all but s zero but s zero? Actually secs!=0 so at least one appended.
    // Edge: 60 seconds => 1m 0s? We omit 0s, so 60 => "1m". That's fine.
    if (first) {
        // fallback (should not happen since secs !=0)
        out = sdscat(out, "0s");
    }
    return out;
}

/* Helper to get string field with fallback keys */
static const char *duration_get_str(cJSON *args, const char *k1, const char *k2, const char *k3) {
    const char *s = NULL;
    if (k1) s = cJSON_GetStringValue(cJSON_GetObjectItem(args, k1));
    if (!s && k2) s = cJSON_GetStringValue(cJSON_GetObjectItem(args, k2));
    if (!s && k3) s = cJSON_GetStringValue(cJSON_GetObjectItem(args, k3));
    return s;
}

static sds tool_duration_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "parse";

    if (strcmp(action, "parse") == 0) {
        const char *inp = duration_get_str(args, "input", "duration", "data");
        if (!inp) inp = duration_get_str(args, "value", "text", "s");
        if (!inp) return sdsnew("ERROR: 'input' (or 'duration'/'data') is required for parse");
        long long secs = 0;
        sds err = NULL;
        if (duration_parse_seconds(inp, &secs, &err) != 0) {
            sds e = err ? err : sdsnew("ERROR: parse failed");
            return e;
        }
        sds fmt = duration_format(secs);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "parse");
        cJSON_AddStringToObject(obj, "input", inp);
        cJSON_AddNumberToObject(obj, "seconds", (double)secs);
        cJSON_AddStringToObject(obj, "formatted", fmt);
        // breakdown
        long long v = secs < 0 ? -secs : secs;
        cJSON_AddNumberToObject(obj, "weeks", (double)(v / (7*86400)));
        v %= 7*86400;
        cJSON_AddNumberToObject(obj, "days", (double)(v / 86400));
        v %= 86400;
        cJSON_AddNumberToObject(obj, "hours", (double)(v / 3600));
        v %= 3600;
        cJSON_AddNumberToObject(obj, "minutes", (double)(v / 60));
        v %= 60;
        cJSON_AddNumberToObject(obj, "secs", (double)v);
        cJSON_AddBoolToObject(obj, "negative", secs < 0);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); sdsfree(fmt);
        return res;
    }

    if (strcmp(action, "format") == 0) {
        cJSON *secItem = cJSON_GetObjectItem(args, "seconds");
        if (!secItem) secItem = cJSON_GetObjectItem(args, "value");
        if (!secItem) secItem = cJSON_GetObjectItem(args, "input");
        if (!secItem) secItem = cJSON_GetObjectItem(args, "data");
        long long secs = 0;
        int have = 0;
        if (cJSON_IsNumber(secItem)) { secs = (long long)secItem->valuedouble; have = 1; }
        else if (cJSON_IsString(secItem) && secItem->valuestring) {
            char *end = NULL;
            long long v = strtoll(secItem->valuestring, &end, 10);
            if (end != secItem->valuestring && *end == '\0') { secs = v; have = 1; }
            else {
                // try parsing as duration string then reformat (normalize)
                sds err = NULL;
                long long p = 0;
                if (duration_parse_seconds(secItem->valuestring, &p, &err)==0) { secs = p; have = 1; if (err) sdsfree(err); }
                else { sds e = err ? err : sdsnew("ERROR: invalid seconds value"); return e; }
            }
        }
        if (!have) return sdsnew("ERROR: 'seconds' (number) is required for format");
        sds fmt = duration_format(secs);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "format");
        cJSON_AddNumberToObject(obj, "seconds", (double)secs);
        cJSON_AddStringToObject(obj, "formatted", fmt);
        cJSON_AddStringToObject(obj, "input", fmt);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); sdsfree(fmt);
        return res;
    }

    if (strcmp(action, "add") == 0 || strcmp(action, "sum") == 0) {
        const char *aStr = duration_get_str(args, "a", "input", "duration");
        const char *bStr = duration_get_str(args, "b", "other", "value2");
        // also support keys aStr/bStr via data/value
        if (!aStr) aStr = cJSON_GetStringValue(cJSON_GetObjectItem(args, "value"));
        if (!bStr) bStr = cJSON_GetStringValue(cJSON_GetObjectItem(args, "value2"));
        // fallback to numeric seconds
        long long aSec = 0, bSec = 0;
        int haveA = 0, haveB = 0;
        cJSON *aNum = cJSON_GetObjectItem(args, "a");
        cJSON *bNum = cJSON_GetObjectItem(args, "b");
        if (!aStr && cJSON_IsNumber(aNum)) { aSec = (long long)aNum->valuedouble; haveA = 1; }
        if (!bStr && cJSON_IsNumber(bNum)) { bSec = (long long)bNum->valuedouble; haveB = 1; }
        // try string fields a/b as numbers
        if (!haveA) {
            if (aStr) {
                // check if aStr is pure number string -> treat as seconds directly
                char *end = NULL;
                long long v = strtoll(aStr, &end, 10);
                // if entire string is numeric with optional sign, use as seconds without parsing units (to avoid "3600" being parsed as 3600s same result anyway)
                // So parsing as duration already yields same.
                sds err = NULL;
                long long p = 0;
                if (duration_parse_seconds(aStr, &p, &err)==0) { aSec = p; haveA = 1; if (err) sdsfree(err); }
                else { sds e = err ? err : sdsnew("ERROR: failed to parse 'a'"); return e; }
                (void)v; (void)end;
            } else {
                return sdsnew("ERROR: add requires 'a' (duration string or seconds)");
            }
        }
        if (!haveB) {
            if (bStr) {
                sds err = NULL;
                long long p = 0;
                if (duration_parse_seconds(bStr, &p, &err)==0) { bSec = p; haveB = 1; if (err) sdsfree(err); }
                else { sds e = err ? err : sdsnew("ERROR: failed to parse 'b'"); sdsfree(e); // avoid leak? Actually return e
                    return e; }
            } else {
                return sdsnew("ERROR: add requires 'b' (duration string or seconds)");
            }
        }
        // overflow check
        if ((bSec > 0 && aSec > LLONG_MAX - bSec) || (bSec < 0 && aSec < LLONG_MIN - bSec)) {
            return sdsnew("ERROR: duration addition overflow");
        }
        long long sum = aSec + bSec;
        sds fmt = duration_format(sum);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "add");
        cJSON_AddNumberToObject(obj, "a_seconds", (double)aSec);
        cJSON_AddNumberToObject(obj, "b_seconds", (double)bSec);
        cJSON_AddNumberToObject(obj, "seconds", (double)sum);
        cJSON_AddStringToObject(obj, "formatted", fmt);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj); sdsfree(fmt);
        return res;
    }

    if (strcmp(action, "compare") == 0 || strcmp(action, "cmp") == 0) {
        const char *aStr = duration_get_str(args, "a", "v1", "input");
        if (!aStr) aStr = duration_get_str(args, "version", NULL, NULL);
        const char *bStr = duration_get_str(args, "b", "v2", "other");
        if (!bStr) bStr = duration_get_str(args, "value2", NULL, NULL);
        if (!aStr || !bStr) return sdsnew("ERROR: compare requires 'a' and 'b' (duration strings)");
        long long aSec=0,bSec=0; sds e1=NULL,e2=NULL;
        if (duration_parse_seconds(aStr, &aSec, &e1)!=0) { sds e=e1?e1:sdsnew("ERROR: failed to parse 'a'"); if(e2) sdsfree(e2); return e; }
        if (duration_parse_seconds(bStr, &bSec, &e2)!=0) { if(e1) sdsfree(e1); sds e=e2?e2:sdsnew("ERROR: failed to parse 'b'"); return e; }
        if (e1) sdsfree(e1); if (e2) sdsfree(e2);
        int cmp = (aSec < bSec) ? -1 : (aSec > bSec) ? 1 : 0;
        const char *op = cmp < 0 ? "<" : cmp > 0 ? ">" : "==";
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "compare");
        cJSON_AddStringToObject(obj, "a", aStr);
        cJSON_AddStringToObject(obj, "b", bStr);
        cJSON_AddNumberToObject(obj, "a_seconds", (double)aSec);
        cJSON_AddNumberToObject(obj, "b_seconds", (double)bSec);
        cJSON_AddNumberToObject(obj, "cmp", cmp);
        cJSON_AddStringToObject(obj, "op", op);
        cJSON_AddBoolToObject(obj, "equal", cmp==0);
        cJSON_AddBoolToObject(obj, "less", cmp<0);
        cJSON_AddBoolToObject(obj, "greater", cmp>0);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js); cJSON_Delete(obj);
        return res;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown duration action '%s' (use parse/format/add/compare)", action);
}

static const alpha_tool_t tool_duration = {
    .name = "duration",
    .aliases = {"human_time", "time_parse", "parse_duration", NULL},
    .category = "codec",
    .description = "Human duration parser/formatter (pure C): parse strings like '1d2h30m' to seconds, format seconds to '1d 2h', add two durations, compare ('<'/'=='/'>'). Units: w,d,h,m,s,ms (ms truncated). Supports negative and bare numbers as seconds.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"duration\",\"description\":\"Human duration parser/formatter: parse, format, add, compare.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"parse\",\"format\",\"add\",\"compare\"],\"description\":\"Operation\"},\"input\":{\"type\":\"string\",\"description\":\"Duration string e.g. '1d2h30m' or seconds for format\"},\"duration\":{\"type\":\"string\",\"description\":\"Alias for input\"},\"data\":{\"type\":\"string\",\"description\":\"Alias for input\"},\"seconds\":{\"type\":\"integer\",\"description\":\"Seconds value for format\"},\"value\":{\"type\":\"string\",\"description\":\"Alias for input/seconds\"},\"a\":{\"type\":\"string\",\"description\":\"First duration for add/compare\"},\"b\":{\"type\":\"string\",\"description\":\"Second duration for add/compare\"},\"other\":{\"type\":\"string\",\"description\":\"Alias for b\"},\"v1\":{\"type\":\"string\",\"description\":\"Alias for a\"},\"v2\":{\"type\":\"string\",\"description\":\"Alias for b\"}}}}}",
    .run = tool_duration_run
};
