/* tool_patch.c — Unified Diff & Patch Engine (Myers-style LCS) */

#ifndef ALPHA_DIFF_MAX_LINES
#define ALPHA_DIFF_MAX_LINES 20000
#endif

#define ALPHA_DIFF_DEFAULT_CONTEXT 3

typedef enum { DL_CONTEXT = 0, DL_DELETE = 1, DL_INSERT = 2 } diffline_kind_t;

typedef struct {
    diffline_kind_t kind;
    int a_line;
    int b_line;
    const char *text;
} diffline_t;

static char **line_split(const char *text, size_t *out_n, int *had_trailing_nl) {
    if (out_n) *out_n = 0;
    if (had_trailing_nl) *had_trailing_nl = 0;
    if (!text || !text[0]) return NULL;

    size_t nlines = 1;
    for (const char *p = text; *p; p++)
        if (*p == '\n') nlines++;
    if (text[strlen(text) - 1] == '\n') {
        if (had_trailing_nl) *had_trailing_nl = 1;
        nlines--;
    }
    if (nlines == 0) return NULL;

    char **lines = malloc(sizeof(char *) * nlines);
    if (!lines) return NULL;
    size_t idx = 0;
    const char *start = text;
    for (const char *p = text; ; p++) {
        if (*p == '\n' || *p == 0) {
            size_t len = (size_t)(p - start);
            lines[idx] = malloc(len + 1);
            if (!lines[idx]) {
                for (size_t k = 0; k < idx; k++) free(lines[k]);
                free(lines);
                return NULL;
            }
            memcpy(lines[idx], start, len);
            lines[idx][len] = 0;
            if (++idx >= nlines) break;
            if (*p == 0) break;
            start = p + 1;
        }
    }
    if (out_n) *out_n = idx;
    return lines;
}

static void line_free(char **lines, size_t n) {
    if (!lines) return;
    for (size_t i = 0; i < n; i++) free(lines[i]);
    free(lines);
}

typedef enum { OP_KEEP = 0, OP_DEL = 1, OP_INS = 2 } opkind_t;
typedef struct { opkind_t op; int idx; } edit_t;

static edit_t *line_diff(const char **a, size_t n_a,
                         const char **b, size_t n_b, size_t *out_n) {
    if (out_n) *out_n = 0;
    if (n_a > ALPHA_DIFF_MAX_LINES || n_b > ALPHA_DIFF_MAX_LINES) return NULL;

    size_t cols = n_b + 1;
    size_t rows = n_a + 1;
    int *dp = malloc(sizeof(int) * rows * cols);
    if (!dp) return NULL;
    memset(dp, 0, sizeof(int) * rows * cols);

    for (size_t i = n_a; i-- > 0;) {
        for (size_t j = n_b; j-- > 0;) {
            if (strcmp(a[i], b[j]) == 0)
                dp[i * cols + j] = dp[(i + 1) * cols + (j + 1)] + 1;
            else {
                int down  = dp[(i + 1) * cols + j];
                int right = dp[i * cols + (j + 1)];
                dp[i * cols + j] = (down >= right) ? down : right;
            }
        }
    }

    edit_t *edits = malloc(sizeof(edit_t) * (n_a + n_b + 1));
    if (!edits) { free(dp); return NULL; }
    size_t ne = 0;
    size_t i = n_a, j = n_b;
    while (i > 0 && j > 0) {
        if (strcmp(a[i - 1], b[j - 1]) == 0) {
            edits[ne] = (edit_t){ OP_KEEP, (int)(i - 1) }; ne++;
            i--; j--;
        } else if (dp[(i - 1) * cols + j] >= dp[i * cols + (j - 1)]) {
            edits[ne] = (edit_t){ OP_DEL, (int)(i - 1) }; ne++;
            i--;
        } else {
            edits[ne] = (edit_t){ OP_INS, (int)(j - 1) }; ne++;
            j--;
        }
    }
    while (i > 0) { edits[ne] = (edit_t){ OP_DEL, (int)(i - 1) }; ne++; i--; }
    while (j > 0) { edits[ne] = (edit_t){ OP_INS, (int)(j - 1) }; ne++; j--; }

    for (size_t x = 0, y = ne; x < y; x++, y--) {
        edit_t t = edits[x]; edits[x] = edits[y]; edits[y] = t;
    }
    free(dp);
    if (out_n) *out_n = ne;
    return edits;
}

static diffline_t *build_difflines(const char **a, size_t n_a,
                                   const char **b, size_t n_b,
                                   edit_t *edits, size_t ne, size_t *out_n) {
    (void)n_a;
    (void)n_b;
    diffline_t *dl = malloc(sizeof(diffline_t) * (ne + 1));
    if (!dl) { *out_n = 0; return NULL; }
    size_t idx = 0;
    for (size_t e = 0; e < ne; e++) {
        if (edits[e].op == OP_KEEP)
            dl[idx] = (diffline_t){ DL_CONTEXT, (int)edits[e].idx, (int)edits[e].idx, a[edits[e].idx] };
        else if (edits[e].op == OP_DEL)
            dl[idx] = (diffline_t){ DL_DELETE, (int)edits[e].idx, -1, a[edits[e].idx] };
        else
            dl[idx] = (diffline_t){ DL_INSERT, -1, (int)edits[e].idx, b[edits[e].idx] };
        idx++;
    }
    *out_n = idx;
    return dl;
}

static void emit_hunk(sds *out, diffline_t *dl, size_t start, size_t end) {
    int a_count = 0, b_count = 0;
    for (size_t i = start; i < end; i++) {
        if (dl[i].kind == DL_CONTEXT || dl[i].kind == DL_DELETE) a_count++;
        if (dl[i].kind == DL_CONTEXT || dl[i].kind == DL_INSERT) b_count++;
    }
    int a_start = (a_count == 0) ? 0 : dl[start].a_line + 1;
    int b_start = (b_count == 0) ? 0 : dl[start].b_line + 1;
    *out = sdscatprintf(*out, "@@ -%d,%d +%d,%d @@\n", a_start, a_count, b_start, b_count);
    for (size_t i = start; i < end; i++) {
        char p = ' ';
        if (dl[i].kind == DL_DELETE) p = '-';
        else if (dl[i].kind == DL_INSERT) p = '+';
        *out = sdscatprintf(*out, "%c%s\n", p, dl[i].text ? dl[i].text : "");
    }
}

static void emit_hunks(sds *out, diffline_t *dl, size_t nd, int context) {
    size_t i = 0;
    while (i < nd) {
        while (i < nd && dl[i].kind == DL_CONTEXT) i++;
        if (i >= nd) break;
        size_t run_start = i, run_end = i;
        while (run_end < nd && dl[run_end].kind != DL_CONTEXT) run_end++;
        size_t hunk_end = run_end;
        for (;;) {
            size_t ctx = hunk_end;
            while (ctx < nd && dl[ctx].kind == DL_CONTEXT) ctx++;
            size_t gap = ctx - hunk_end;
            if (ctx < nd && gap <= (size_t)(2 * context)) {
                hunk_end = ctx;
                while (hunk_end < nd && dl[hunk_end].kind != DL_CONTEXT) hunk_end++;
            } else break;
        }
        size_t hs = (run_start > (size_t)context) ? run_start - (size_t)context : 0;
        size_t he = (hunk_end + (size_t)context < nd) ? hunk_end + (size_t)context : nd;
        emit_hunk(out, dl, hs, he);
        i = he;
    }
}

static sds unified_diff(const char *path_a, const char *path_b,
                        const char *old_text, const char *new_text, int context) {
    if (context < 0) context = 0;
    size_t n_a = 0, n_b = 0, ne = 0, nd = 0;
    int had_a = 0, had_b = 0;
    char **a = line_split(old_text, &n_a, &had_a);
    char **b = line_split(new_text, &n_b, &had_b);
    edit_t *edits = line_diff((const char **)a, n_a, (const char **)b, n_b, &ne);
    diffline_t *dl = edits ? build_difflines((const char **)a, n_a, (const char **)b, n_b, edits, ne, &nd) : NULL;

    sds out = sdsempty();
    out = sdscatprintf(out, "--- %s\n", path_a ? path_a : "a/file");
    out = sdscatprintf(out, "+++ %s\n", path_b ? path_b : "b/file");
    if (dl) emit_hunks(&out, dl, nd, context);

    free(edits);
    free(dl);
    line_free(a, n_a);
    line_free(b, n_b);
    return out;
}

typedef struct {
    int a_l, a_s;
    int b_l, b_s;
    diffline_kind_t *ops;
    char **texts;
    size_t nops;
    size_t cap;
} patch_hunk_t;

static int parse_hunk_header(const char *hdr, int *a_l, int *a_s, int *b_l, int *b_s) {
    const char *p = hdr;
    while (*p && *p != '-') p++;
    if (!*p) return 0;
    p++;
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p) return 0;
    int l = (int)v; p = end;
    int s = 1;
    if (*p == ',') { p++; v = strtol(p, &end, 10); if (end == p) return 0; s = (int)v; p = end; }
    while (*p == ' ') p++;
    if (*p != '+') return 0;
    p++;
    v = strtol(p, &end, 10); if (end == p) return 0; int bl = (int)v; p = end;
    s = 1;
    if (*p == ',') { p++; v = strtol(p, &end, 10); if (end == p) return 0; s = (int)v; p = end; }
    *a_l = l; *a_s = s; *b_l = bl; *b_s = s;
    return 1;
}

static sds unified_apply(const char *content, const char *patch) {
    if (!content) content = "";
    if (!patch) return NULL;

    size_t n_content = 0;
    int had_nl = 0;
    char **clines = line_split(content, &n_content, &had_nl);

    size_t pn = 0;
    char **plines = line_split(patch, &pn, NULL);
    patch_hunk_t *hunks = NULL;
    size_t nhunks = 0, hcap = 0;
    patch_hunk_t *cur = NULL;

    for (size_t li = 0; li < pn; li++) {
        const char *pl = plines[li];
        if (strncmp(pl, "@@", 2) == 0) {
            int a_l, a_s, b_l, b_s;
            if (!parse_hunk_header(pl, &a_l, &a_s, &b_l, &b_s)) {
                free(hunks); free(plines); line_free(clines, n_content);
                return NULL;
            }
            if (nhunks == hcap) {
                size_t nc = hcap ? hcap * 2 : 8;
                patch_hunk_t *nb = realloc(hunks, nc * sizeof(patch_hunk_t));
                if (!nb) { free(hunks); free(plines); line_free(clines, n_content); return NULL; }
                hcap = nc; hunks = nb;
            }
            cur = &hunks[nhunks++];
            cur->a_l = a_l; cur->a_s = a_s; cur->b_l = b_l; cur->b_s = b_s;
            cur->ops = NULL; cur->texts = NULL; cur->nops = 0; cur->cap = 0;
        } else if (cur && (pl[0] == ' ' || pl[0] == '-' || pl[0] == '+')) {
            if (cur->nops == cur->cap) {
                size_t nc = cur->cap ? cur->cap * 2 : 8;
                diffline_kind_t *no = realloc(cur->ops, nc * sizeof(diffline_kind_t));
                if (!no) { free(hunks); free(plines); line_free(clines, n_content); return NULL; }
                cur->ops = no; cur->cap = nc;
                char **nt = realloc(cur->texts, nc * sizeof(char *));
                if (!nt) { free(hunks); free(plines); line_free(clines, n_content); return NULL; }
                cur->texts = nt;
            }
            if (pl[0] == ' ') cur->ops[cur->nops] = DL_CONTEXT;
            else if (pl[0] == '-') cur->ops[cur->nops] = DL_DELETE;
            else cur->ops[cur->nops] = DL_INSERT;
            cur->texts[cur->nops] = strdup(pl + 1);
            cur->nops++;
        }
    }

    char **out = NULL;
    size_t out_n = 0, out_cap = 0;
    size_t pos = 1;
    int failed = 0;

    for (size_t h = 0; h < nhunks && !failed; h++) {
        patch_hunk_t *hk = &hunks[h];
        size_t expect = (hk->a_s > 0) ? (size_t)hk->a_l : (size_t)hk->a_l + 1;
        if (pos != expect) { failed = 1; break; }
        for (size_t o = 0; o < hk->nops; o++) {
            if (hk->ops[o] == DL_CONTEXT) {
                if (pos > n_content || strcmp(clines[pos - 1], hk->texts[o]) != 0) {
                    failed = 1; break;
                }
                if (out_n == out_cap) {
                    size_t nc = out_cap ? out_cap * 2 : 64;
                    char **nb = realloc(out, nc * sizeof(char *));
                    if (!nb) { failed = 2; break; }
                    out_cap = nc; out = nb;
                }
                out[out_n++] = strdup(clines[pos - 1]);
                pos++;
            } else if (hk->ops[o] == DL_DELETE) {
                if (pos > n_content) { failed = 1; break; }
                pos++;
            } else {
                if (out_n == out_cap) {
                    size_t nc = out_cap ? out_cap * 2 : 64;
                    char **nb = realloc(out, nc * sizeof(char *));
                    if (!nb) { failed = 2; break; }
                    out_cap = nc; out = nb;
                }
                out[out_n++] = strdup(hk->texts[o]);
            }
        }
    }

    if (!failed) {
        for (; pos <= n_content; pos++) {
            if (out_n == out_cap) {
                size_t nc = out_cap ? out_cap * 2 : 64;
                char **nb = realloc(out, nc * sizeof(char *));
                if (!nb) { failed = 2; break; }
                out_cap = nc; out = nb;
            }
            out[out_n++] = strdup(clines[pos - 1]);
        }
    }

    sds result;
    if (failed) {
        result = NULL;
    } else {
        result = sdsempty();
        for (size_t i = 0; i < out_n; i++) {
            if (i > 0) sdscat(result, "\n");
            sdscat(result, out[i]);
        }
        if (had_nl && out_n > 0) sdscat(result, "\n");
    }

    for (size_t i = 0; i < out_n; i++) free(out[i]);
    free(out);
    for (size_t i = 0; i < nhunks; i++) {
        for (size_t o = 0; o < hunks[i].nops; o++) free(hunks[i].texts[o]);
        free(hunks[i].ops);
        free(hunks[i].texts);
    }
    free(hunks);
    line_free(plines, pn);
    line_free(clines, n_content);
    return result;
}

static sds tool_patch_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action) action = "diff";
    if (strcmp(action, "diff") == 0) {
        const char *old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old"));
        const char *new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new"));
        int context = ALPHA_DIFF_DEFAULT_CONTEXT;
        cJSON *c = cJSON_GetObjectItem(args, "context");
        if (cJSON_IsNumber(c)) context = c->valueint;
        const char *pa = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path_a"));
        const char *pb = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path_b"));
        return unified_diff(pa ? pa : "a/file", pb ? pb : "b/file",
                            old_s ? old_s : "", new_s ? new_s : "", context);
    }
    if (strcmp(action, "apply") == 0) {
        const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(args, "content"));
        const char *patch = cJSON_GetStringValue(cJSON_GetObjectItem(args, "patch"));
        sds result = unified_apply(content ? content : "", patch ? patch : "");
        if (!result)
            return sdsnew("ERROR: patch did not apply cleanly (malformed or context mismatch)");
        return result;
    }
    return sdsnew("ERROR: unknown patch action — use diff or apply");
}

static const alpha_tool_t tool_patch = {
    .name = "patch",
    .aliases = {NULL},
    .category = "git",
    .description = "Line-based unified diff and patch tool.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"patch\",\"description\":\"Line-based unified diff and patch tool.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"diff\",\"apply\"],\"description\":\"Action: diff (generate unified diff) or apply (apply patch to content)\"},\"old\":{\"type\":\"string\",\"description\":\"Original text (for diff)\"},\"new\":{\"type\":\"string\",\"description\":\"Modified text (for diff)\"},\"context\":{\"type\":\"integer\",\"description\":\"Context lines around hunks (default 3)\"},\"path_a\":{\"type\":\"string\",\"description\":\"Label for original file in header\"},\"path_b\":{\"type\":\"string\",\"description\":\"Label for modified file in header\"},\"content\":{\"type\":\"string\",\"description\":\"Text to apply patch to (for apply)\"},\"patch\":{\"type\":\"string\",\"description\":\"Unified diff patch text (for apply)\"}},\"required\":[\"action\"]}}}",
    .run = tool_patch_run
};
