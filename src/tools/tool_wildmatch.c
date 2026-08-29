/* tool_wildmatch.c — Pure-C gitignore-style pattern matcher (wildmatch)
 * Actions: match, filter
 *
 * Implements git's wildmatch semantics in pathname mode. A plain star
 * matches any run of characters except a slash; a question mark matches a
 * single non-slash character; a double-star delimited by slashes or string
 * ends matches across directory boundaries (a leading double-star tail
 * matches in all directories, a trailing one matches everything inside a
 * directory, and an inner one spans zero or more directories). Consecutive
 * stars not slash-delimited act like one star. Bracket expressions support
 * ranges, bang or caret negation, backslash escapes, and POSIX classes such
 * as alpha; an unterminated bracket opener is a literal. Backslash escapes
 * the next character.
 *
 * The filter action evaluates a gitignore ruleset against a list of paths:
 * blank lines and hash comments are skipped, a bang negates, a trailing
 * slash marks a directory-only rule, patterns without a slash match the
 * basename at any depth, patterns with a slash are anchored at the root,
 * and the last matching rule wins. Ignoring a directory ignores everything
 * under it. A path ending in a slash is treated as a directory.
 *
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define WM_MAX_PATTERN 1024
#define WM_MAX_PATH 4096
#define WM_MAX_RULES 4096
#define WM_MAX_RULES_TEXT (256 * 1024)
#define WM_MAX_PATHS 4096
#define WM_MAX_DEPTH 4096

/* returns 1 match, 0 no match, -1 abort (pattern too complex) */
static int wm_dowild(const char *p, const char *t, const char *pat0, int depth);

/* Match a character class. *pp points at '['. On success advances *pp past
 * the closing ']' and returns 1/0 (match/no-match). Returns -1 when the
 * class is unterminated — the caller then treats '[' as a literal. */
static int wm_class_match(const char **pp, unsigned char c) {
    const char *p = *pp + 1;
    int neg = 0, matched = 0, first = 1;
    if (*p == '!' || *p == '^') { neg = 1; p++; }
    while (*p) {
        if (*p == ']' && !first) {
            *pp = p + 1;
            return neg ? !matched : matched;
        }
        first = 0;
        if (*p == '[' && p[1] == ':') {
            /* POSIX named class [:name:] */
            const char *end = strstr(p + 2, ":]");
            if (!end) return -1;
            size_t n = (size_t)(end - (p + 2));
            const char *name = p + 2;
            int r = 0;
            if (n == 5 && strncmp(name, "alnum", 5) == 0) r = isalnum(c);
            else if (n == 5 && strncmp(name, "alpha", 5) == 0) r = isalpha(c);
            else if (n == 5 && strncmp(name, "blank", 5) == 0) r = (c == ' ' || c == '\t');
            else if (n == 5 && strncmp(name, "cntrl", 5) == 0) r = iscntrl(c);
            else if (n == 5 && strncmp(name, "digit", 5) == 0) r = isdigit(c);
            else if (n == 5 && strncmp(name, "graph", 5) == 0) r = isgraph(c);
            else if (n == 5 && strncmp(name, "lower", 5) == 0) r = islower(c);
            else if (n == 5 && strncmp(name, "print", 5) == 0) r = isprint(c);
            else if (n == 5 && strncmp(name, "punct", 5) == 0) r = ispunct(c);
            else if (n == 5 && strncmp(name, "space", 5) == 0) r = isspace(c);
            else if (n == 5 && strncmp(name, "upper", 5) == 0) r = isupper(c);
            else if (n == 6 && strncmp(name, "xdigit", 6) == 0) r = isxdigit(c);
            else return -1; /* unknown class: treat whole thing as malformed */
            if (r) matched = 1;
            p = end + 2;
            continue;
        }
        unsigned char lo;
        if (*p == '\\' && p[1]) { lo = (unsigned char)p[1]; p += 2; }
        else lo = (unsigned char)*p++;
        if (*p == '-' && p[1] != ']' && p[1] != '\0') {
            /* range */
            unsigned char hi;
            p++; /* skip '-' */
            if (*p == '\\' && p[1]) { hi = (unsigned char)p[1]; p += 2; }
            else hi = (unsigned char)*p++;
            if (lo <= hi && c >= lo && c <= hi) matched = 1;
            else if (lo > hi && c >= hi && c <= lo) matched = 1; /* be lenient */
        } else {
            if (c == lo) matched = 1;
        }
    }
    return -1; /* no closing ']' */
}

static int wm_dowild(const char *p, const char *t, const char *pat0, int depth) {
    if (depth > WM_MAX_DEPTH) return -1;
    while (*p) {
        char pc = *p;
        if (pc == '*') {
            const char *p2 = p;
            while (*p2 == '*') p2++;
            int is_ss = (p2 - p) >= 2 &&
                        (p == pat0 || p[-1] == '/') &&
                        (*p2 == '\0' || *p2 == '/');
            if (is_ss) {
                if (*p2 == '\0') {
                    /* trailing "**" matches everything remaining */
                    return 1;
                }
                /* "**\/": zero or more whole directories */
                const char *rest = p2 + 1;
                int r = wm_dowild(rest, t, pat0, depth + 1);
                if (r != 0) return r;
                for (const char *s = t; *s; s++) {
                    if (*s == '/') {
                        r = wm_dowild(rest, s + 1, pat0, depth + 1);
                        if (r != 0) return r;
                    }
                }
                return 0;
            }
            /* single '*': any run of non-'/' characters */
            int r = wm_dowild(p2, t, pat0, depth + 1);
            if (r != 0) return r;
            for (const char *s = t; *s && *s != '/'; s++) {
                r = wm_dowild(p2, s + 1, pat0, depth + 1);
                if (r != 0) return r;
            }
            return 0;
        }
        if (!*t) return 0;
        if (pc == '?') {
            if (*t == '/') return 0;
            p++; t++;
            continue;
        }
        if (pc == '[') {
            if (*t == '/') return 0;
            const char *pc2 = p;
            int m = wm_class_match(&p, (unsigned char)*t);
            if (m < 0) {
                /* unterminated class: literal '[' */
                p = pc2 + 1;
                if (*t != '[') return 0;
                t++;
                continue;
            }
            if (!m) return 0;
            t++;
            continue;
        }
        if (pc == '\\') {
            if (p[1]) { pc = p[1]; p += 2; }
            else p++; /* trailing backslash: literal '\' */
        } else {
            p++;
        }
        if ((unsigned char)*t != (unsigned char)pc) return 0;
        t++;
    }
    return *t == '\0' ? 1 : 0;
}

/* Top-level matcher: 1 match, 0 no match, -1 aborted. */
static int wm_match(const char *pattern, const char *path) {
    if (!pattern || !path) return -1;
    return wm_dowild(pattern, path, pattern, 0);
}

/* --- gitignore ruleset ---------------------------------------------------- */

typedef struct {
    char *pat;      /* owned; '!' prefix, leading '/' and trailing '/' stripped */
    int negated;
    int dir_only;
    int anchored;   /* pattern contains a '/' (after stripping trailing one) */
    int line;       /* 1-based line number in the rules text */
} wm_rule_t;

static void wm_rules_free(wm_rule_t *rules, int n) {
    if (!rules) return;
    for (int i = 0; i < n; i++) free(rules[i].pat);
    free(rules);
}

/* Parse ruleset text into rules. Returns rule count, or -1 on error with
 * *err set. Lines over WM_MAX_PATTERN are an error, not silently skipped. */
static int wm_rules_parse(const char *text, wm_rule_t **out, sds *err) {
    *out = NULL;
    int cap = 0, n = 0;
    wm_rule_t *rules = NULL;
    int lineno = 0;
    const char *cur = text;
    while (*cur) {
        lineno++;
        const char *nl = strchr(cur, '\n');
        size_t len = nl ? (size_t)(nl - cur) : strlen(cur);
        const char *next = nl ? nl + 1 : cur + len;
        if (len > 0 && cur[len - 1] == '\r') len--;
        if (len > WM_MAX_PATTERN) {
            *err = sdscatprintf(sdsempty(), "ERROR: rule line %d too long (max %d chars)", lineno, WM_MAX_PATTERN);
            wm_rules_free(rules, n);
            return -1;
        }
        char line[WM_MAX_PATTERN + 1];
        memcpy(line, cur, len);
        line[len] = '\0';
        cur = next;

        /* trim unescaped trailing whitespace (gitignore: trailing spaces are
         * ignored unless quoted with backslash) */
        for (;;) {
            size_t l = strlen(line);
            if (l == 0) break;
            if (line[l - 1] != ' ' && line[l - 1] != '\t') break;
            size_t bs = 0;
            for (size_t k = l - 1; k > 0 && line[k - 1] == '\\'; k--) bs++;
            if (bs % 2 == 1) break; /* escaped */
            line[l - 1] = '\0';
        }
        if (!line[0]) continue;                 /* blank */
        if (line[0] == '#') continue;           /* comment */

        const char *pat = line;
        int negated = 0;
        if (pat[0] == '!') { negated = 1; pat++; }
        else if (pat[0] == '\\' && (pat[1] == '!' || pat[1] == '#')) pat++;
        if (!pat[0]) continue;
        if (strcmp(pat, "/") == 0) continue;    /* meaningless */

        if (n >= WM_MAX_RULES) {
            *err = sdscatprintf(sdsempty(), "ERROR: too many rules (max %d)", WM_MAX_RULES);
            wm_rules_free(rules, n);
            return -1;
        }
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            wm_rule_t *nr = realloc(rules, (size_t)cap * sizeof(*nr));
            if (!nr) {
                *err = sdsnew("ERROR: out of memory");
                wm_rules_free(rules, n);
                return -1;
            }
            rules = nr;
        }
        char *copy = strdup(pat);
        if (!copy) {
            *err = sdsnew("ERROR: out of memory");
            wm_rules_free(rules, n);
            return -1;
        }
        wm_rule_t *r = &rules[n];
        memset(r, 0, sizeof(*r));
        r->negated = negated;
        r->line = lineno;
        size_t pl = strlen(copy);
        if (pl > 0 && copy[pl - 1] == '/') {
            r->dir_only = 1;
            copy[--pl] = '\0';
        }
        if (pl > 0 && copy[0] == '/') {
            memmove(copy, copy + 1, pl); /* leading '/' anchors; strip it */
            pl--;
        }
        if (!copy[0]) { free(copy); continue; }
        r->anchored = strchr(copy, '/') != NULL;
        r->pat = copy;
        n++;
    }
    *out = rules;
    return n;
}

/* Does rule r match the given normalized path (no leading '/')?
 * is_dir: path itself is a directory (caller marks it with a trailing '/').
 * Returns 1 match, 0 no match. Matcher aborts count as no match. */
static int wm_rule_matches(const wm_rule_t *r, const char *path, int is_dir) {
    if (!r->dir_only) {
        /* match the path itself (file semantics) */
        int m;
        if (r->anchored) m = wm_match(r->pat, path);
        else {
            const char *base = strrchr(path, '/');
            base = base ? base + 1 : path;
            m = wm_match(r->pat, base);
        }
        if (m == 1) return 1;
    } else if (is_dir) {
        /* dir-only rule may match the path itself when it is a directory */
        int m;
        if (r->anchored) m = wm_match(r->pat, path);
        else {
            const char *base = strrchr(path, '/');
            base = base ? base + 1 : path;
            m = wm_match(r->pat, base);
        }
        if (m == 1) return 1;
    }
    /* match any leading directory (ignoring a dir ignores its contents) */
    for (const char *s = path; *s; s++) {
        if (*s != '/') continue;
        size_t plen = (size_t)(s - path);
        if (plen == 0 || plen > WM_MAX_PATH) continue;
        char prefix[WM_MAX_PATH + 1];
        memcpy(prefix, path, plen);
        prefix[plen] = '\0';
        int m;
        if (r->anchored) m = wm_match(r->pat, prefix);
        else {
            const char *base = strrchr(prefix, '/');
            base = base ? base + 1 : prefix;
            m = wm_match(r->pat, base);
        }
        if (m == 1) return 1;
    }
    return 0;
}

/* --- tool entry point ----------------------------------------------------- */

static sds tool_wildmatch_match(cJSON *args) {
    const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
    if (!pattern) pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "glob"));
    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    if (!path) path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "subject"));
    if (!path) path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    if (!pattern || !pattern[0])
        return sdsnew("ERROR: 'pattern' is required and must not be empty");
    if (!path || !path[0])
        return sdsnew("ERROR: 'path' is required and must not be empty");
    if (strlen(pattern) > WM_MAX_PATTERN)
        return sdscatprintf(sdsempty(), "ERROR: pattern too long (max %d chars)", WM_MAX_PATTERN);
    if (strlen(path) > WM_MAX_PATH)
        return sdscatprintf(sdsempty(), "ERROR: path too long (max %d chars)", WM_MAX_PATH);

    int m = wm_match(pattern, path);
    if (m < 0) return sdsnew("ERROR: pattern too complex (recursion limit exceeded)");

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "match");
    cJSON_AddStringToObject(obj, "pattern", pattern);
    cJSON_AddStringToObject(obj, "path", path);
    cJSON_AddBoolToObject(obj, "match", m == 1);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    return res;
}

static sds tool_wildmatch_filter(cJSON *args) {
    const char *rules_text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rules"));
    if (!rules_text) rules_text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "gitignore"));
    if (!rules_text) rules_text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    if (!rules_text)
        return sdsnew("ERROR: 'rules' (gitignore text) is required for filter");
    if (strlen(rules_text) > WM_MAX_RULES_TEXT)
        return sdscatprintf(sdsempty(), "ERROR: rules text too long (max %d bytes)", WM_MAX_RULES_TEXT);

    cJSON *paths = cJSON_GetObjectItem(args, "paths");
    if (!paths) paths = cJSON_GetObjectItem(args, "files");
    if (!cJSON_IsArray(paths))
        return sdsnew("ERROR: 'paths' must be an array of path strings");
    int npaths = cJSON_GetArraySize(paths);
    if (npaths == 0) return sdsnew("ERROR: 'paths' array is empty");
    if (npaths > WM_MAX_PATHS)
        return sdscatprintf(sdsempty(), "ERROR: too many paths (max %d)", WM_MAX_PATHS);

    wm_rule_t *rules = NULL;
    sds err = NULL;
    int nrules = wm_rules_parse(rules_text, &rules, &err);
    if (nrules < 0) return err ? err : sdsnew("ERROR: failed to parse rules");

    cJSON *results = cJSON_CreateArray();
    cJSON *ignored = cJSON_CreateArray();
    int nignored = 0;
    for (int i = 0; i < npaths; i++) {
        cJSON *e = cJSON_GetArrayItem(paths, i);
        if (!cJSON_IsString(e) || !e->valuestring || !e->valuestring[0]) {
            cJSON_Delete(results);
            cJSON_Delete(ignored);
            wm_rules_free(rules, nrules);
            return sdscatprintf(sdsempty(), "ERROR: paths[%d] is not a non-empty string", i);
        }
        const char *raw = e->valuestring;
        if (strlen(raw) > WM_MAX_PATH) {
            cJSON_Delete(results);
            cJSON_Delete(ignored);
            wm_rules_free(rules, nrules);
            return sdscatprintf(sdsempty(), "ERROR: paths[%d] too long (max %d chars)", i, WM_MAX_PATH);
        }
        /* normalize: strip leading '/', note trailing '/' as directory */
        const char *path = raw;
        while (path[0] == '/') path++;
        size_t plen = strlen(path);
        int is_dir = plen > 0 && path[plen - 1] == '/';
        char norm[WM_MAX_PATH + 1];
        strncpy(norm, path, WM_MAX_PATH);
        norm[WM_MAX_PATH] = '\0';
        if (is_dir) norm[plen - 1] = '\0';
        if (!norm[0]) {
            cJSON_Delete(results);
            cJSON_Delete(ignored);
            wm_rules_free(rules, nrules);
            return sdscatprintf(sdsempty(), "ERROR: paths[%d] is not a usable relative path", i);
        }

        /* last matching rule wins */
        int matched = 0, negated = 0, rule_line = 0;
        const char *rule_pat = NULL;
        for (int k = 0; k < nrules; k++) {
            if (wm_rule_matches(&rules[k], norm, is_dir)) {
                matched = 1;
                negated = rules[k].negated;
                rule_line = rules[k].line;
                rule_pat = rules[k].pat;
            }
        }
        int is_ignored = matched && !negated;
        if (is_ignored) {
            nignored++;
            cJSON_AddItemToArray(ignored, cJSON_CreateString(raw));
        }
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "path", raw);
        cJSON_AddBoolToObject(item, "ignored", is_ignored);
        if (matched) {
            cJSON_AddNumberToObject(item, "rule_line", rule_line);
            cJSON_AddStringToObject(item, "rule", rule_pat);
            cJSON_AddBoolToObject(item, "negated", negated);
        } else {
            cJSON_AddNullToObject(item, "rule_line");
            cJSON_AddNullToObject(item, "rule");
        }
        cJSON_AddItemToArray(results, item);
    }

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "filter");
    cJSON_AddNumberToObject(obj, "rules", nrules);
    cJSON_AddNumberToObject(obj, "count", npaths);
    cJSON_AddNumberToObject(obj, "ignored_count", nignored);
    cJSON_AddItemToObject(obj, "results", results);
    cJSON_AddItemToObject(obj, "ignored_paths", ignored);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    wm_rules_free(rules, nrules);
    return res;
}

static sds tool_wildmatch_run(cJSON *args, const char *cwd) {
    (void)cwd;
    if (!cJSON_IsObject(args)) return sdsnew("ERROR: arguments must be a JSON object");
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "match";

    if (strcmp(action, "match") == 0 || strcmp(action, "test") == 0)
        return tool_wildmatch_match(args);
    if (strcmp(action, "filter") == 0 || strcmp(action, "gitignore") == 0)
        return tool_wildmatch_filter(args);

    return sdscatprintf(sdsempty(), "ERROR: unknown wildmatch action '%s' (use match/filter)", action);
}

static const alpha_tool_t tool_wildmatch = {
    .name = "wildmatch",
    .aliases = {"gitignore", "pathmatch", NULL},
    .category = "git",
    .description = "Gitignore-style pattern matcher (pure C wildmatch): '*'/'?' never cross '/', '**' spans directories (leading, trailing or between slashes), '[...]' classes with ranges/negation/POSIX names, backslash escaping. match: one pattern vs one path. filter: gitignore ruleset text vs path list — comments, '!' negation, dir-only trailing '/', basename vs anchored rules, last matching rule wins.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"wildmatch\",\"description\":\"Gitignore-style wildmatch pattern matching: match one pattern against a path, or filter paths with a gitignore ruleset.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"match\",\"filter\"],\"description\":\"Operation\"},\"pattern\":{\"type\":\"string\",\"description\":\"Glob pattern for match (supports **, [], ?, escapes)\"},\"path\":{\"type\":\"string\",\"description\":\"Path to test in match\"},\"rules\":{\"type\":\"string\",\"description\":\"Gitignore ruleset text for filter\"},\"paths\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Paths to evaluate in filter; trailing '/' marks a directory\"}}}}}",
    .run = tool_wildmatch_run
};
