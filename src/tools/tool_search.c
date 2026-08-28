/* tool_search.c — Web Search (DuckDuckGo HTML) and Code Search */
#include <fnmatch.h>
#include <regex.h>
#include <ctype.h>

#define ALPHA_GREP_DEFAULT_MAX 1000

static int file_is_binary(const char *path) {
    if (has_binary_extension(path)) return 1;
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    return has_nul(buf, n);
}

struct ws_buf { sds data; };
static size_t ws_write_cb(char *ptr, size_t sz, size_t nmemb, void *ud) {
    struct ws_buf *b = ud;
    size_t n = sz * nmemb;
    b->data = sdscatlen(b->data, ptr, n);
    return n;
}

static size_t url_decode_inplace(char *s) {
    char *w = s;
    for (const char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            int hi = r[1] >= 'a' ? r[1] - 'a' + 10 : r[1] >= 'A' ? r[1] - 'A' + 10 : r[1] - '0';
            int lo = r[2] >= 'a' ? r[2] - 'a' + 10 : r[2] >= 'A' ? r[2] - 'A' + 10 : r[2] - '0';
            *w++ = (char)((hi << 4) | lo);
            r += 2;
        } else if (*r == '+') {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
    }
    *w = 0;
    return (size_t)(w - s);
}

static sds ddg_decode_url(const char *href) {
    if (!href) return sdsempty();
    const char *p = strstr(href, "uddg=");
    if (!p) {
        if (href[0] == '/' && href[1] == '/') href += 2;
        return sdsnew(href);
    }
    p += 5;
    sds enc = sdsempty();
    while (*p && *p != '&') { enc = sdscatlen(enc, p, 1); p++; }
    url_decode_inplace(enc);
    return enc;
}

static void strip_html(char *s) {
    char *w = s;
    int in_tag = 0;
    for (const char *r = s; *r; r++) {
        if (*r == '<') { in_tag = 1; continue; }
        if (*r == '>') { in_tag = 0; continue; }
        if (in_tag) continue;
        if (strncmp(r, "&amp;", 5) == 0) { *w++ = '&'; r += 4; continue; }
        if (strncmp(r, "&lt;", 4) == 0)  { *w++ = '<'; r += 3; continue; }
        if (strncmp(r, "&gt;", 4) == 0)  { *w++ = '>'; r += 3; continue; }
        if (strncmp(r, "&quot;", 6) == 0) { *w++ = '"'; r += 5; continue; }
        if (strncmp(r, "&#x27;", 6) == 0) { *w++ = '\''; r += 5; continue; }
        if (strncmp(r, "&#39;", 5) == 0) { *w++ = '\''; r += 4; continue; }
        *w++ = *r;
    }
    *w = 0;
}

static void collapse_ws(char *s) {
    char *w = s;
    int space = 0;
    for (const char *r = s; *r; r++) {
        if (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r') {
            if (w > s) space = 1;
            continue;
        }
        if (space) { *w++ = ' '; space = 0; }
        *w++ = *r;
    }
    *w = 0;
    while (w > s && (w[-1] == ' ' || w[-1] == '\t')) { w--; *w = 0; }
}

static sds web_search(const char *query, int max_results) {
    if (!query || !query[0])
        return sdsnew("ERROR: query required for web_search");

    if (max_results <= 0 || max_results > 20) max_results = 10;

    sds enc = sdsempty();
    for (const unsigned char *p = (const unsigned char *)query; *p; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' ||
            *p == '~')
            enc = sdscatlen(enc, (const char *)p, 1);
        else if (*p == ' ')
            enc = sdscatlen(enc, "+", 1);
        else
            enc = sdscatprintf(enc, "%%%02X", *p);
    }

    sds post_body = sdscatprintf(sdsempty(), "q=%s", enc);
    sdsfree(enc);

    CURL *curl = curl_easy_init();
    if (!curl) { sdsfree(post_body); return sdsnew("ERROR: curl_easy_init failed"); }

    struct ws_buf buf = { .data = sdsempty() };
    curl_easy_setopt(curl, CURLOPT_URL, "https://html.duckduckgo.com/html/");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ws_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 12L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    sdsfree(post_body);

    if (res != CURLE_OK) {
        sds err = sdscatprintf(sdsempty(), "ERROR: web search request failed: %s",
                               curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        sdsfree(buf.data);
        return err;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        sds err = sdscatprintf(sdsempty(), "ERROR: web search returned HTTP %ld", http_code);
        sdsfree(buf.data);
        return err;
    }

    sds out = sdsempty();
    int found = 0;
    const char *p = buf.data;

    while (found < max_results) {
        const char *rstart = strstr(p, "class=\"result ");
        if (!rstart) rstart = strstr(p, "class=\"result__body");
        if (!rstart) break;

        const char *tlink = strstr(rstart, "class=\"result__a\"");
        if (!tlink) { p = rstart + 14; continue; }

        const char *hstart = strstr(rstart, "href=\"");
        if (!hstart || hstart > tlink + 40) { p = tlink + 17; continue; }
        hstart += 6;
        const char *hend = strchr(hstart, '"');
        if (!hend) { p = tlink + 17; continue; }

        sds raw_href = sdsnewlen(hstart, (size_t)(hend - hstart));
        sds real_url = ddg_decode_url(raw_href);
        sdsfree(raw_href);

        const char *title_start = strchr(tlink, '>');
        if (!title_start) { sdsfree(real_url); p = hend + 1; continue; }
        title_start++;
        const char *title_end = strstr(title_start, "</a>");
        if (!title_end) { sdsfree(real_url); p = hend + 1; continue; }

        sds title = sdsnewlen(title_start, (size_t)(title_end - title_start));
        strip_html(title);
        collapse_ws(title);

        sds snippet = sdsempty();
        const char *slink = strstr(title_end, "class=\"result__snippet\"");
        if (slink) {
            const char *snip_start = strchr(slink, '>');
            if (snip_start) {
                snip_start++;
                const char *snip_end = strstr(snip_start, "</a>");
                if (!snip_end) snip_end = strstr(snip_start, "</div>");
                if (snip_end) {
                    snippet = sdscatlen(snippet, snip_start, (size_t)(snip_end - snip_start));
                    strip_html(snippet);
                    collapse_ws(snippet);
                }
            }
        }

        if (sdslen(title) > 0 && sdslen(real_url) > 0) {
            found++;
            out = sdscatprintf(out, "%d. %s\n   URL: %s\n", found, title, real_url);
            if (sdslen(snippet) > 0)
                out = sdscatprintf(out, "   %s\n", snippet);
            out = sdscat(out, "\n");
        }

        sdsfree(title);
        sdsfree(real_url);
        sdsfree(snippet);

        p = title_end + 4;
    }

    sdsfree(buf.data);

    if (found == 0)
        out = sdscat(out, "(no results)\n");

    return out;
}

static sds tool_web_search_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *query = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
    if (!query || !query[0])
        return sdsnew("ERROR: query required for web_search");
    int max_results = 10;
    cJSON *mr = cJSON_GetObjectItem(args, "max_results");
    if (cJSON_IsNumber(mr)) max_results = mr->valueint;
    return web_search(query, max_results);
}

static const alpha_tool_t tool_web_search = {
    .name = "web_search",
    .aliases = {NULL},
    .category = "search",
    .description = "Search the web via DuckDuckGo HTML (no API key, no JS). Returns title, URL, and snippet for each result. Fast: one HTTP GET, ~0.5-2s.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"web_search\",\"description\":\"Search the web via DuckDuckGo HTML (no API key, no JS). Returns title, URL, and snippet for each result. Fast: one HTTP GET, ~0.5-2s.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Search query\"},\"max_results\":{\"type\":\"integer\",\"description\":\"Max results (1-20, default 10)\"}},\"required\":[\"query\"]}}}",
    .run = tool_web_search_run
};

/* Code search */
static int cg_ci_contains(const char *hay, const char *needle) {
    if (!needle || !needle[0]) return 1;
    if (!hay) return 0;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t k = 0;
        while (k < nl &&
               tolower((unsigned char)p[k]) == tolower((unsigned char)needle[k])) k++;
        if (k == nl) return 1;
    }
    return 0;
}

typedef struct {
    char *text;
    char *kinds[32];      int n_kinds;
    char *languages[32];  int n_langs;
    char *pathFilters[32]; int n_paths;
    char *nameFilters[32]; int n_names;
} cg_query_t;

static const char *cg_file_language(const char *path) {
    if (!path) return NULL;
    const char *dot = strrchr(path, '.');
    if (!dot || !dot[1]) return NULL;
    const char *ext = dot + 1;
    char buf[64];
    size_t k = 0;
    while (ext[k] && ext[k] != '/' && ext[k] != '\\' && k < sizeof(buf) - 1) {
        buf[k] = (char)tolower((unsigned char)ext[k]);
        k++;
    }
    buf[k] = 0;
    if (!buf[0]) return NULL;
    if (strcmp(buf, "c") == 0 || strcmp(buf, "h") == 0) return "c";
    if (strcmp(buf, "cpp") == 0 || strcmp(buf, "cc") == 0 || strcmp(buf, "cxx") == 0 ||
        strcmp(buf, "c++") == 0 || strcmp(buf, "hpp") == 0 || strcmp(buf, "hh") == 0)
        return "cpp";
    if (strcmp(buf, "rs") == 0) return "rust";
    if (strcmp(buf, "py") == 0) return "python";
    if (strcmp(buf, "go") == 0) return "go";
    if (strcmp(buf, "java") == 0) return "java";
    if (strcmp(buf, "cs") == 0) return "csharp";
    if (strcmp(buf, "ts") == 0 || strcmp(buf, "mts") == 0 || strcmp(buf, "cts") == 0)
        return "typescript";
    if (strcmp(buf, "js") == 0 || strcmp(buf, "mjs") == 0 || strcmp(buf, "cjs") == 0)
        return "javascript";
    if (strcmp(buf, "tsx") == 0) return "tsx";
    if (strcmp(buf, "jsx") == 0) return "jsx";
    if (strcmp(buf, "rb") == 0) return "ruby";
    if (strcmp(buf, "swift") == 0) return "swift";
    if (strcmp(buf, "kt") == 0 || strcmp(buf, "kts") == 0) return "kotlin";
    if (strcmp(buf, "dart") == 0) return "dart";
    if (strcmp(buf, "php") == 0) return "php";
    if (strcmp(buf, "vue") == 0) return "vue";
    if (strcmp(buf, "svelte") == 0) return "svelte";
    if (strcmp(buf, "lua") == 0) return "lua";
    if (strcmp(buf, "r") == 0) return "r";
    if (strcmp(buf, "tf") == 0 || strcmp(buf, "terraform") == 0) return "terraform";
    if (strcmp(buf, "yaml") == 0 || strcmp(buf, "yml") == 0) return "yaml";
    if (strcmp(buf, "xml") == 0) return "xml";
    return NULL;
}

static int cg_lang_filter_ok(const char *path, cg_query_t *q) {
    if (q->n_langs == 0) return 1;
    const char *lang = cg_file_language(path);
    if (!lang) return 0;
    for (int i = 0; i < q->n_langs; i++)
        if (strcmp(lang, q->languages[i]) == 0) return 1;
    return 0;
}

static int cg_path_filter_ok(const char *relpath, cg_query_t *q) {
    if (q->n_paths == 0) return 1;
    for (int i = 0; i < q->n_paths; i++)
        if (cg_ci_contains(relpath, q->pathFilters[i])) return 1;
    return 0;
}

static int cg_line_matches_kind(const char *line, const char *kind) {
    if (strcmp(kind, "class") == 0) return strstr(line, "class") != NULL;
    if (strcmp(kind, "struct") == 0) return strstr(line, "struct") != NULL;
    if (strcmp(kind, "interface") == 0) return strstr(line, "interface") != NULL;
    if (strcmp(kind, "trait") == 0) return strstr(line, "trait") != NULL;
    if (strcmp(kind, "protocol") == 0) return strstr(line, "protocol") != NULL;
    if (strcmp(kind, "enum") == 0) return strstr(line, "enum") != NULL;
    if (strcmp(kind, "namespace") == 0) return strstr(line, "namespace") != NULL;
    if (strcmp(kind, "import") == 0) return strstr(line, "import") != NULL || strstr(line, "include") != NULL;
    if (strcmp(kind, "export") == 0) return strstr(line, "export") != NULL;
    if (strcmp(kind, "module") == 0) return strstr(line, "module") != NULL;
    if (strcmp(kind, "route") == 0) return strstr(line, "route") != NULL || strstr(line, "router") != NULL;
    if (strcmp(kind, "component") == 0) return strstr(line, "component") != NULL;
    if (strcmp(kind, "union") == 0) return strstr(line, "union") != NULL;
    if (strcmp(kind, "property") == 0) return strstr(line, "property") != NULL;
    if (strcmp(kind, "field") == 0) return strstr(line, "field") != NULL;
    if (strcmp(kind, "method") == 0) return strstr(line, "method") != NULL;
    if (strcmp(kind, "parameter") == 0) return strstr(line, "param") != NULL;
    if (strcmp(kind, "file") == 0) return strstr(line, "file") != NULL;
    if (strcmp(kind, "function") == 0)
        return strstr(line, "function ") || strstr(line, "def ") || strstr(line, "fn ") ||
               strstr(line, "func ") || strstr(line, "void ") || strstr(line, "int ") ||
               strstr(line, "static ") || strstr(line, "def(");
    if (strcmp(kind, "variable") == 0)
        return strstr(line, "var ") || strstr(line, "let ") || strstr(line, "const ") ||
               strstr(line, "int ") || strstr(line, "float ");
    if (strcmp(kind, "constant") == 0)
        return strstr(line, "const ") || strstr(line, "#define") != NULL ||
               strstr(line, "constexpr") != NULL;
    if (strcmp(kind, "type_alias") == 0)
        return strstr(line, "type ") || strstr(line, "typedef") != NULL;
    return strstr(line, kind) != NULL;
}

static int cg_line_matches(cg_query_t *q, regex_t *re, const char *line_lower, const char *line) {
    for (int i = 0; i < q->n_kinds; i++)
        if (!cg_line_matches_kind(line_lower, q->kinds[i])) return 0;
    for (int i = 0; i < q->n_names; i++)
        if (!cg_ci_contains(line_lower, q->nameFilters[i])) return 0;
    if (re && regexec(re, line, 0, NULL, 0) != 0) return 0;
    return 1;
}

static const char *const CG_KINDS[] = {
    "file","module","class","struct","interface","trait","protocol",
    "function","method","property","field","variable","constant","enum",
    "enum_member","type_alias","namespace","parameter","import","export",
    "route","component","union", NULL };

static const char *const CG_LANGUAGES[] = {
    "typescript","javascript","tsx","jsx","arkts","python","go","rust","java",
    "c","cpp","csharp","razor","php","ruby","swift","kotlin","dart","svelte",
    "vue","astro","liquid","pascal","scala","lua","luau","objc","r","solidity",
    "nix","yaml","twig","xml","properties","cfml","cfscript","cfquery","cobol",
    "vbnet","erlang","terraform","unknown", NULL };

static int cg_set_has(const char *const *set, const char *v) {
    for (int i = 0; set[i]; i++) if (strcmp(set[i], v) == 0) return 1;
    return 0;
}

static void cg_add_str(char **arr, int *n, const char *v) {
    if (*n >= 32) return;
    arr[(*n)++] = strdup(v);
}

static sds cg_add_text(sds text, const char *tok) {
    text = sdscatlen(text, " ", 1);
    text = sdscat(text, tok);
    text = sdscatlen(text, " ", 1);
    return text;
}

static char **cg_tokenize(const char *raw, int *out_n) {
    *out_n = 0;
    if (!raw) return NULL;
    size_t len = strlen(raw);
    char **tokens = NULL;
    size_t cap = 0;
    size_t i = 0;
    while (i < len) {
        while (i < len && isspace((unsigned char)raw[i])) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && !isspace((unsigned char)raw[i])) {
            if (raw[i] == '"') {
                size_t end = i + 1;
                while (end < len && raw[end] != '"') end++;
                if (end >= len) { i = len; break; }
                i = end + 1;
                continue;
            }
            i++;
        }
        size_t tlen = i - start;
        char *t = malloc(tlen + 1);
        if (!t) break;
        memcpy(t, raw + start, tlen);
        t[tlen] = 0;
        if (cap == 0) {
            cap = 8;
            tokens = malloc(cap * sizeof(*tokens));
            if (!tokens) { free(t); break; }
        } else if (*out_n >= (int)cap) {
            size_t nc = cap * 2;
            char **nt = realloc(tokens, nc * sizeof(*nt));
            if (!nt) { free(t); free(tokens); *out_n = 0; return NULL; }
            tokens = nt; cap = nc;
        }
        tokens[(*out_n)++] = t;
    }
    return tokens;
}

static cg_query_t *cg_parse_query(const char *raw) {
    cg_query_t *q = calloc(1, sizeof(*q));
    if (!q) return NULL;
    int n = 0;
    char **tokens = cg_tokenize(raw, &n);
    if (!tokens) { free(q); return NULL; }
    sds text = sdsempty();
    for (int ti = 0; ti < n; ti++) {
        char *tok = tokens[ti];
        size_t tlen = strlen(tok);
        size_t colon = 0;
        while (colon < tlen && tok[colon] != ':') colon++;
        if (colon <= 0 || colon >= tlen - 1) { text = cg_add_text(text, tok); free(tok); continue; }
        char *key = malloc(colon + 1);
        if (!key) { free(tok); continue; }
        memcpy(key, tok, colon); key[colon] = 0;
        for (char *p = key; *p; p++) *p = (char)tolower((unsigned char)*p);
        const char *vraw = tok + colon + 1;
        size_t vlen = tlen - colon - 1;
        const char *vstart = vraw;
        size_t vend = vlen;
        if (vlen >= 2 && vraw[0] == '"' && vraw[vlen - 1] == '"') { vstart = vraw + 1; vend = vlen - 2; }
        char *val = malloc(vend + 1);
        if (!val) { free(key); free(tok); continue; }
        memcpy(val, vstart, vend); val[vend] = 0;
        if (val[0] == 0) { free(key); free(val); free(tok); text = cg_add_text(text, tok); continue; }
        if (strcmp(key, "kind") == 0) {
            if (cg_set_has(CG_KINDS, val)) cg_add_str(q->kinds, &q->n_kinds, val);
            else text = cg_add_text(text, tok);
        } else if (strcmp(key, "lang") == 0 || strcmp(key, "language") == 0) {
            if (cg_set_has(CG_LANGUAGES, val)) cg_add_str(q->languages, &q->n_langs, val);
            else text = cg_add_text(text, tok);
        } else if (strcmp(key, "path") == 0) {
            cg_add_str(q->pathFilters, &q->n_paths, val);
        } else if (strcmp(key, "name") == 0) {
            cg_add_str(q->nameFilters, &q->n_names, val);
        } else {
            text = cg_add_text(text, tok);
        }
        free(key); free(val); free(tok);
    }
    free(tokens);
    sdstrim(text, " ");
    q->text = sdslen(text) ? sdsdup(text) : sdsnew("");
    sdsfree(text);
    return q;
}

static void cg_free_query(cg_query_t *q) {
    if (!q) return;
    for (int i = 0; i < q->n_kinds; i++) free(q->kinds[i]);
    for (int i = 0; i < q->n_langs; i++) free(q->languages[i]);
    for (int i = 0; i < q->n_paths; i++) free(q->pathFilters[i]);
    for (int i = 0; i < q->n_names; i++) free(q->nameFilters[i]);
    sdsfree(q->text);
    free(q);
}

static void cg_search_file(const char *path, cg_query_t *q, regex_t *re,
                           sds *out, long *count, long max_results) {
    if (!cg_lang_filter_ok(path, q)) return;
    if (!cg_path_filter_ok(path, q)) return;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char *line = NULL;
    size_t cap = 0;
    ssize_t linelen;
    long lineno = 0;
    while ((linelen = getline(&line, &cap, f)) != -1) {
        if (*count >= max_results) break;
        lineno++;
        if (linelen > 0 && line[linelen - 1] == '\n') line[linelen - 1] = 0;
        char lower[1024];
        size_t k = 0;
        for (ssize_t p = 0; line[p] && k < sizeof(lower) - 1; p++)
            lower[k++] = (char)tolower((unsigned char)line[p]);
        lower[k] = 0;
        if (cg_line_matches(q, re, lower, line)) {
            *out = sdscatprintf(*out, "%s:%ld:%s\n", path, lineno, line);
            (*count)++;
        }
    }
    free(line);
    fclose(f);
}

static void cg_walk(const char *dir, cg_query_t *q, regex_t *re,
                    sds *out, long *count, long max_results, int depth) {
    if (depth > 40) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { cg_walk(full, q, re, out, count, max_results, depth + 1); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        if (file_is_binary(full)) continue;
        cg_search_file(full, q, re, out, count, max_results);
    }
    closedir(d);
}

static sds cg_filters_summary(cg_query_t *q) {
    sds s = sdsempty();
    int first = 1;
    if (q->n_kinds) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "kinds=");
        for (int i = 0; i < q->n_kinds; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->kinds[i]); }
    }
    if (q->n_langs) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "lang=");
        for (int i = 0; i < q->n_langs; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->languages[i]); }
    }
    if (q->n_paths) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "path=");
        for (int i = 0; i < q->n_paths; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->pathFilters[i]); }
    }
    if (q->n_names) {
        if (!first) s = sdscat(s, " "); first = 0;
        s = sdscat(s, "name=");
        for (int i = 0; i < q->n_names; i++) { if (i) s = sdscat(s, ","); s = sdscat(s, q->nameFilters[i]); }
    }
    if (q->text && q->text[0]) {
        if (!first) s = sdscat(s, " ");
        s = sdscat(s, "text="); s = sdscat(s, q->text);
    }
    if (sdslen(s) == 0) s = sdscat(s, "(none)");
    return s;
}

static sds tool_code_search_run(cJSON *args, const char *cwd) {
    const char *query = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
    if (!query || !query[0]) return sdsnew("ERROR: query required for code_search");

    cg_query_t *q = cg_parse_query(query);
    if (!q) return sdsnew("ERROR: out of memory parsing query");
    if (q->n_kinds == 0 && q->n_langs == 0 && q->n_paths == 0 && q->n_names == 0 &&
        (!q->text || !q->text[0])) {
        cg_free_query(q);
        return sdsnew("ERROR: query produced no filters or text to search");
    }

    regex_t re;
    int have_re = 0;
    if (q->text && q->text[0]) {
        int rc = regcomp(&re, q->text, REG_EXTENDED | REG_NOSUB | REG_ICASE);
        if (rc != 0) {
            char msg[256];
            regerror(rc, &re, msg, sizeof(msg));
            cg_free_query(q);
            return sdscatprintf(sdsempty(), "ERROR: invalid search text '%s': %s", q->text, msg);
        }
        have_re = 1;
    }

    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    if (!path || !path[0]) path = ".";
    long max_results = ALPHA_GREP_DEFAULT_MAX;
    cJSON *mr = cJSON_GetObjectItem(args, "max_results");
    if (cJSON_IsNumber(mr)) { max_results = (long)mr->valueint; if (max_results <= 0) max_results = ALPHA_GREP_DEFAULT_MAX; }
    int recursive = 1;
    cJSON *rec = cJSON_GetObjectItem(args, "recursive");
    if (cJSON_IsBool(rec)) recursive = cJSON_IsTrue(rec);

    char resolved[PATH_MAX];
    resolve_path(resolved, path, cwd);

    sds out = sdscatprintf(sdsempty(), "CODE SEARCH\nQuery: %s\n", query);
    sds filters = cg_filters_summary(q);
    out = sdscat(out, "Filters: ");
    out = sdscat(out, filters);
    sdsfree(filters);
    out = sdscat(out, "\n\n");

    long count = 0;
    struct stat st;
    if (stat(resolved, &st) == 0 && S_ISREG(st.st_mode)) {
        if (!file_is_binary(resolved))
            cg_search_file(resolved, q, have_re ? &re : NULL, &out, &count, max_results);
    } else if (recursive) {
        cg_walk(resolved, q, have_re ? &re : NULL, &out, &count, max_results, 0);
    } else {
        DIR *d = opendir(resolved);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", resolved, de->d_name);
                struct stat fst;
                if (stat(full, &fst) == 0 && S_ISREG(fst.st_mode) && !file_is_binary(full))
                    cg_search_file(full, q, have_re ? &re : NULL, &out, &count, max_results);
            }
            closedir(d);
        }
    }

    if (have_re) regfree(&re);
    cg_free_query(q);

    if (count == 0) {
        sdsfree(out);
        return sdscatprintf(sdsempty(), "No matches for query in %s\n", resolved);
    }
    out = sdscatprintf(out, "\n(%ld result%s)\n", count, count == 1 ? "" : "s");
    return out;
}

static const alpha_tool_t tool_code_search = {
    .name = "code_search",
    .aliases = {NULL},
    .category = "search",
    .description = "Field-qualified code search. Query like kind:function name:auth path:src/api authenticate splits into structured filters plus free text. Args: query (required), path, recursive, max_results.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"code_search\",\"description\":\"Field-qualified code search. Query like kind:function name:auth path:src/api authenticate splits into structured filters plus free text. Args: query (required), path, recursive, max_results.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Field-qualified query, e.g. kind:function name:auth\"},\"path\":{\"type\":\"string\",\"description\":\"File or directory to search (default .)\"},\"recursive\":{\"type\":\"boolean\"},\"max_results\":{\"type\":\"integer\",\"description\":\"Max results (default 1000)\"}},\"required\":[\"query\"]}}}",
    .run = tool_code_search_run
};
