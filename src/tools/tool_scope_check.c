/* tool_scope_check.c — Language-aware scope/delimiter balance checker
 * Domain: tree-sitter/tree-sitter-ruby (lexical structure checking).
 * Actions: check, profiles
 *
 * Single-pass scanner over in-memory source text driven by a language
 * profile (bracket pairs, line comment, block comment, string quotes,
 * long-string delimiters, escape char). Comments and strings are skipped
 * while matching brackets. Reports max nesting depth, the first
 * unbalanced position (unmatched close / mismatched pair / depth
 * overflow) and every construct left unclosed at EOF (brackets, strings,
 * block comments). Built-in profiles: c, ruby, python; every profile
 * field can be overridden per call.
 *
 * Pure C11, no I/O. cJSON/sds are already in scope (textually included
 * into src/tools.c).
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SCOPE_MAX_PAIRS 8
#define SCOPE_MAX_QUOTES 8
#define SCOPE_MAX_LONG 4
#define SCOPE_LONG_LEN 8
#define SCOPE_TOK_LEN 16
#define SCOPE_MAX_DEPTH 1024
#define SCOPE_UNCLOSED_LIST 32

typedef struct {
    char open[SCOPE_MAX_PAIRS];
    char close[SCOPE_MAX_PAIRS];
    int npairs;
    char line_comment[SCOPE_TOK_LEN];   /* "" = none */
    char block_start[SCOPE_TOK_LEN];    /* "" = none */
    char block_end[SCOPE_TOK_LEN];
    int block_bol;                      /* block tokens only match at start of line */
    char quotes[SCOPE_MAX_QUOTES];
    int nquotes;
    char long_str[SCOPE_MAX_LONG][SCOPE_LONG_LEN]; /* symmetric delimiters, e.g. """ */
    int nlong;
    char escape;                        /* 0 = none */
} scope_profile_t;

typedef struct {
    char open;
    size_t offset;
    int line;
    int col;
} scope_frame_t;

enum { SC_NORMAL = 0, SC_LINE, SC_BLOCK, SC_STRING, SC_LONG };

/* --- built-in profiles --------------------------------------------------- */

static void scope_profile_c(scope_profile_t *p) {
    memset(p, 0, sizeof(*p));
    p->open[0] = '(';  p->close[0] = ')';
    p->open[1] = '[';  p->close[1] = ']';
    p->open[2] = '{';  p->close[2] = '}';
    p->npairs = 3;
    strcpy(p->line_comment, "//");
    strcpy(p->block_start, "/*");
    strcpy(p->block_end, "*/");
    p->block_bol = 0;
    p->quotes[0] = '"'; p->quotes[1] = '\'';
    p->nquotes = 2;
    p->escape = '\\';
}

static void scope_profile_ruby(scope_profile_t *p) {
    memset(p, 0, sizeof(*p));
    p->open[0] = '(';  p->close[0] = ')';
    p->open[1] = '[';  p->close[1] = ']';
    p->open[2] = '{';  p->close[2] = '}';
    p->npairs = 3;
    strcpy(p->line_comment, "#");
    /* Ruby embedded documents: =begin/=end, only valid at start of line. */
    strcpy(p->block_start, "=begin");
    strcpy(p->block_end, "=end");
    p->block_bol = 1;
    p->quotes[0] = '"'; p->quotes[1] = '\'';
    p->nquotes = 2;
    p->escape = '\\';
}

static void scope_profile_python(scope_profile_t *p) {
    memset(p, 0, sizeof(*p));
    p->open[0] = '(';  p->close[0] = ')';
    p->open[1] = '[';  p->close[1] = ']';
    p->open[2] = '{';  p->close[2] = '}';
    p->npairs = 3;
    strcpy(p->line_comment, "#");
    p->quotes[0] = '"'; p->quotes[1] = '\'';
    p->nquotes = 2;
    strcpy(p->long_str[0], "\"\"\"");
    strcpy(p->long_str[1], "'''");
    p->nlong = 2;
    p->escape = '\\';
}

static int scope_profile_builtin(const char *lang, scope_profile_t *p) {
    if (strcmp(lang, "c") == 0 || strcmp(lang, "h") == 0 ||
        strcmp(lang, "cpp") == 0 || strcmp(lang, "c++") == 0 ||
        strcmp(lang, "cc") == 0) {
        scope_profile_c(p);
        return 1;
    }
    if (strcmp(lang, "ruby") == 0 || strcmp(lang, "rb") == 0) {
        scope_profile_ruby(p);
        return 1;
    }
    if (strcmp(lang, "python") == 0 || strcmp(lang, "py") == 0) {
        scope_profile_python(p);
        return 1;
    }
    return 0;
}

/* --- helpers ------------------------------------------------------------- */

static int scope_match(const char *text, size_t n, size_t i, const char *tok) {
    size_t tl = strlen(tok);
    if (tl == 0 || i + tl > n) return 0;
    return memcmp(text + i, tok, tl) == 0;
}

static void scope_adv(const char *text, size_t *i, int *line, int *col, size_t count) {
    for (size_t k = 0; k < count; k++) {
        if (text[*i] == '\n') { (*line)++; *col = 1; }
        else (*col)++;
        (*i)++;
    }
}

static int scope_is_bracket(const scope_profile_t *p, char c) {
    for (int b = 0; b < p->npairs; b++)
        if (c == p->open[b] || c == p->close[b]) return 1;
    return 0;
}

static int scope_tok_dirty(const char *tok) {
    /* tokens containing newline/CR can never match the scanner flow */
    return strchr(tok, '\n') != NULL || strchr(tok, '\r') != NULL;
}

/* Validate a fully assembled profile. Returns NULL when OK, else an sds
 * "ERROR: ..." the caller must return/free. */
static sds scope_validate(const scope_profile_t *p) {
    if (p->npairs < 1)
        return sdsnew("ERROR: profile must define at least one bracket pair");
    for (int b = 0; b < p->npairs; b++) {
        if (p->open[b] == p->close[b])
            return sdscatprintf(sdsempty(),
                "ERROR: pair %d has identical open/close char '%c'", b, p->open[b]);
        for (int j = b + 1; j < p->npairs; j++) {
            if (p->open[b] == p->open[j])
                return sdscatprintf(sdsempty(),
                    "ERROR: duplicate open char '%c' in pairs", p->open[b]);
            if (p->open[b] == p->close[j] || p->close[b] == p->open[j])
                return sdscatprintf(sdsempty(),
                    "ERROR: char '%c' used as both open and close across pairs", p->open[b]);
        }
    }
    if ((p->block_start[0] != '\0') != (p->block_end[0] != '\0'))
        return sdsnew("ERROR: block_comment_start and block_comment_end must both be set or both empty");
    if (p->line_comment[0] && scope_tok_dirty(p->line_comment))
        return sdsnew("ERROR: line_comment must not contain newline characters");
    if ((p->block_start[0] && scope_tok_dirty(p->block_start)) ||
        (p->block_end[0] && scope_tok_dirty(p->block_end)))
        return sdsnew("ERROR: block comment tokens must not contain newline characters");
    for (int q = 0; q < p->nquotes; q++) {
        if (scope_is_bracket(p, p->quotes[q]))
            return sdscatprintf(sdsempty(),
                "ERROR: quote char '%c' conflicts with a bracket char", p->quotes[q]);
        for (int j = q + 1; j < p->nquotes; j++)
            if (p->quotes[q] == p->quotes[j])
                return sdscatprintf(sdsempty(),
                    "ERROR: duplicate quote char '%c'", p->quotes[q]);
    }
    for (int L = 0; L < p->nlong; L++) {
        if (scope_is_bracket(p, p->long_str[L][0]))
            return sdscatprintf(sdsempty(),
                "ERROR: long string delimiter '%s' conflicts with a bracket char", p->long_str[L]);
        for (int j = L + 1; j < p->nlong; j++)
            if (strcmp(p->long_str[L], p->long_str[j]) == 0)
                return sdscatprintf(sdsempty(),
                    "ERROR: duplicate long string delimiter '%s'", p->long_str[L]);
    }
    if (p->line_comment[0] && scope_is_bracket(p, p->line_comment[0]))
        return sdsnew("ERROR: line_comment conflicts with a bracket char");
    if (p->block_start[0] && scope_is_bracket(p, p->block_start[0]))
        return sdsnew("ERROR: block_comment_start conflicts with a bracket char");
    return NULL;
}

/* --- profile assembly from args ------------------------------------------ */

static sds scope_build_profile(cJSON *args, scope_profile_t *p, const char **lang_label) {
    const char *lang = cJSON_GetStringValue(cJSON_GetObjectItem(args, "lang"));
    if (!lang) lang = cJSON_GetStringValue(cJSON_GetObjectItem(args, "language"));
    if (!lang) lang = cJSON_GetStringValue(cJSON_GetObjectItem(args, "profile"));

    cJSON *pairs_item = cJSON_GetObjectItem(args, "pairs");

    if (lang && lang[0]) {
        if (!scope_profile_builtin(lang, p))
            return sdscatprintf(sdsempty(),
                "ERROR: unknown lang '%s' (built-ins: c, ruby, python; or pass custom 'pairs')", lang);
        *lang_label = lang;
    } else if (cJSON_IsString(pairs_item)) {
        memset(p, 0, sizeof(*p));
        *lang_label = "custom";
    } else {
        scope_profile_c(p);
        *lang_label = "c";
    }

    if (cJSON_IsString(pairs_item)) {
        const char *ps = pairs_item->valuestring;
        size_t L = strlen(ps);
        if (L == 0 || L % 2 != 0)
            return sdscatprintf(sdsempty(),
                "ERROR: 'pairs' must be a non-empty even-length string like \"()[]{}\", got %zu chars", L);
        if (L / 2 > SCOPE_MAX_PAIRS)
            return sdscatprintf(sdsempty(), "ERROR: too many pairs (max %d)", SCOPE_MAX_PAIRS);
        p->npairs = (int)(L / 2);
        for (size_t k = 0; k < L / 2; k++) {
            if ((unsigned char)ps[2*k] <= ' ' || (unsigned char)ps[2*k+1] <= ' ')
                return sdsnew("ERROR: bracket chars must be printable non-space characters");
            p->open[k] = ps[2*k];
            p->close[k] = ps[2*k+1];
        }
    }

    cJSON *lc = cJSON_GetObjectItem(args, "line_comment");
    if (cJSON_IsString(lc)) {
        if (strlen(lc->valuestring) >= SCOPE_TOK_LEN)
            return sdsnew("ERROR: line_comment too long (max 15 chars)");
        strcpy(p->line_comment, lc->valuestring);
    }

    cJSON *bs = cJSON_GetObjectItem(args, "block_comment_start");
    cJSON *be = cJSON_GetObjectItem(args, "block_comment_end");
    if (bs || be) {
        const char *bsv = cJSON_GetStringValue(bs);
        const char *bev = cJSON_GetStringValue(be);
        if (!bsv || !bev)
            return sdsnew("ERROR: block_comment_start and block_comment_end must be given together");
        if (strlen(bsv) >= SCOPE_TOK_LEN || strlen(bev) >= SCOPE_TOK_LEN)
            return sdsnew("ERROR: block comment tokens too long (max 15 chars)");
        if ((bsv[0] != '\0') != (bev[0] != '\0'))
            return sdsnew("ERROR: block_comment_start and block_comment_end must both be non-empty or both empty");
        strcpy(p->block_start, bsv);
        strcpy(p->block_end, bev);
    }

    cJSON *bol = cJSON_GetObjectItem(args, "block_at_line_start");
    if (cJSON_IsBool(bol)) p->block_bol = cJSON_IsTrue(bol) ? 1 : 0;

    cJSON *qs = cJSON_GetObjectItem(args, "quotes");
    if (cJSON_IsString(qs)) {
        size_t L = strlen(qs->valuestring);
        if (L >= SCOPE_MAX_QUOTES)
            return sdscatprintf(sdsempty(), "ERROR: too many quote chars (max %d)", SCOPE_MAX_QUOTES - 1);
        for (size_t k = 0; k < L; k++)
            if ((unsigned char)qs->valuestring[k] <= ' ')
                return sdsnew("ERROR: quote chars must be printable non-space characters");
        memcpy(p->quotes, qs->valuestring, L);
        p->nquotes = (int)L;
    }

    cJSON *ls = cJSON_GetObjectItem(args, "long_strings");
    if (cJSON_IsArray(ls)) {
        int cnt = cJSON_GetArraySize(ls);
        if (cnt > SCOPE_MAX_LONG)
            return sdscatprintf(sdsempty(), "ERROR: too many long_strings (max %d)", SCOPE_MAX_LONG);
        p->nlong = 0;
        for (int k = 0; k < cnt; k++) {
            const char *dv = cJSON_GetStringValue(cJSON_GetArrayItem(ls, k));
            if (!dv)
                return sdscatprintf(sdsempty(), "ERROR: long_strings[%d] must be a string", k);
            size_t dl = strlen(dv);
            if (dl < 2 || dl >= SCOPE_LONG_LEN)
                return sdscatprintf(sdsempty(),
                    "ERROR: long string delimiter '%s' must be 2-%d chars", dv, SCOPE_LONG_LEN - 1);
            strcpy(p->long_str[p->nlong++], dv);
        }
    }

    cJSON *esc = cJSON_GetObjectItem(args, "escape");
    if (cJSON_IsString(esc)) {
        size_t L = strlen(esc->valuestring);
        if (L > 1)
            return sdsnew("ERROR: escape must be a single character (or \"\" to disable)");
        p->escape = L == 1 ? esc->valuestring[0] : '\0';
    }

    return scope_validate(p);
}

/* --- actions ------------------------------------------------------------- */

static sds tool_scope_check_profiles(void) {
    const char *names[] = {"c", "ruby", "python"};
    cJSON *arr = cJSON_CreateArray();
    for (int k = 0; k < 3; k++) {
        scope_profile_t p;
        scope_profile_builtin(names[k], &p);
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "lang", names[k]);
        char pairs[SCOPE_MAX_PAIRS * 2 + 1];
        for (int b = 0; b < p.npairs; b++) {
            pairs[2*b] = p.open[b];
            pairs[2*b+1] = p.close[b];
        }
        pairs[2*p.npairs] = '\0';
        cJSON_AddStringToObject(o, "pairs", pairs);
        cJSON_AddStringToObject(o, "line_comment", p.line_comment);
        cJSON_AddStringToObject(o, "block_comment_start", p.block_start);
        cJSON_AddStringToObject(o, "block_comment_end", p.block_end);
        cJSON_AddBoolToObject(o, "block_at_line_start", p.block_bol);
        char qbuf[SCOPE_MAX_QUOTES + 1];
        memcpy(qbuf, p.quotes, (size_t)p.nquotes);
        qbuf[p.nquotes] = '\0';
        cJSON_AddStringToObject(o, "quotes", qbuf);
        cJSON *la = cJSON_CreateArray();
        for (int L = 0; L < p.nlong; L++)
            cJSON_AddItemToArray(la, cJSON_CreateString(p.long_str[L]));
        cJSON_AddItemToObject(o, "long_strings", la);
        if (p.escape) {
            char eb[2] = {p.escape, '\0'};
            cJSON_AddStringToObject(o, "escape", eb);
        } else {
            cJSON_AddNullToObject(o, "escape");
        }
        cJSON_AddItemToArray(arr, o);
    }
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "action", "profiles");
    cJSON_AddItemToObject(out, "profiles", arr);
    char *js = cJSON_PrintUnformatted(out);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(out);
    return res;
}

static sds tool_scope_check_check(cJSON *args) {
    cJSON *text_item = cJSON_GetObjectItem(args, "text");
    if (!cJSON_IsString(text_item)) text_item = cJSON_GetObjectItem(args, "source");
    if (!cJSON_IsString(text_item)) text_item = cJSON_GetObjectItem(args, "code");
    if (!cJSON_IsString(text_item)) text_item = cJSON_GetObjectItem(args, "input");
    if (!cJSON_IsString(text_item))
        return sdsnew("ERROR: 'text' (source code string) is required for check");
    const char *text = text_item->valuestring;
    size_t n = strlen(text);

    scope_profile_t p;
    const char *lang_label = "c";
    sds perr = scope_build_profile(args, &p, &lang_label);
    if (perr) return perr;

    scope_frame_t *stack = malloc(sizeof(scope_frame_t) * SCOPE_MAX_DEPTH);
    if (!stack) return sdsnew("ERROR: out of memory");

    int depth = 0, max_depth = 0;
    size_t max_depth_off = 0;
    size_t i = 0;
    int line = 1, col = 1, at_bol = 1;
    int state = SC_NORMAL;
    int blk_at_bol = 0;
    char str_close = 0;
    char str_delim[SCOPE_LONG_LEN] = {0};
    size_t str_off = 0; int str_line = 0, str_col = 0;
    size_t blk_off = 0; int blk_line = 0, blk_col = 0;
    int open_count = 0, close_count = 0, comments = 0, strings = 0;

    const char *err_type = NULL;
    size_t err_off = 0; int err_line = 0, err_col = 0;
    char err_char = 0, err_expected = 0;
    size_t err_open_off = 0; int err_open_line = 0, err_open_col = 0;

    while (i < n) {
        char c = text[i];

        if (state == SC_LINE) {
            if (c == '\n') { state = SC_NORMAL; at_bol = 1; }
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        if (state == SC_BLOCK) {
            if (scope_match(text, n, i, p.block_end) && (!p.block_bol || blk_at_bol)) {
                scope_adv(text, &i, &line, &col, strlen(p.block_end));
                state = SC_NORMAL;
                at_bol = 0;
                continue;
            }
            if (c == '\n') blk_at_bol = 1;
            else if (c != ' ' && c != '\t' && c != '\r') blk_at_bol = 0;
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        if (state == SC_STRING) {
            if (p.escape && c == p.escape && i + 1 < n) {
                scope_adv(text, &i, &line, &col, 2);
                continue;
            }
            if (c == str_close) {
                scope_adv(text, &i, &line, &col, 1);
                state = SC_NORMAL;
                at_bol = 0;
                continue;
            }
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        if (state == SC_LONG) {
            if (p.escape && c == p.escape && i + 1 < n) {
                scope_adv(text, &i, &line, &col, 2);
                continue;
            }
            if (scope_match(text, n, i, str_delim)) {
                scope_adv(text, &i, &line, &col, strlen(str_delim));
                state = SC_NORMAL;
                at_bol = 0;
                continue;
            }
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }

        /* SC_NORMAL */
        if (c == '\n') {
            at_bol = 1;
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        if (p.line_comment[0] && scope_match(text, n, i, p.line_comment)) {
            state = SC_LINE;
            comments++;
            scope_adv(text, &i, &line, &col, strlen(p.line_comment));
            continue;
        }
        if (p.block_start[0] && scope_match(text, n, i, p.block_start) &&
            (!p.block_bol || at_bol)) {
            state = SC_BLOCK;
            comments++;
            blk_off = i; blk_line = line; blk_col = col;
            blk_at_bol = 0;
            scope_adv(text, &i, &line, &col, strlen(p.block_start));
            continue;
        }
        int matched = 0;
        for (int L = 0; L < p.nlong; L++) {
            if (scope_match(text, n, i, p.long_str[L])) {
                state = SC_LONG;
                strings++;
                strcpy(str_delim, p.long_str[L]);
                str_off = i; str_line = line; str_col = col;
                scope_adv(text, &i, &line, &col, strlen(p.long_str[L]));
                matched = 1;
                break;
            }
        }
        if (matched) continue;
        int qi = -1;
        for (int q = 0; q < p.nquotes; q++)
            if (c == p.quotes[q]) { qi = q; break; }
        if (qi >= 0) {
            state = SC_STRING;
            strings++;
            str_close = c;
            str_off = i; str_line = line; str_col = col;
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        int oi = -1;
        for (int b = 0; b < p.npairs; b++)
            if (c == p.open[b]) { oi = b; break; }
        if (oi >= 0) {
            if (depth >= SCOPE_MAX_DEPTH) {
                err_type = "depth_exceeded";
                err_off = i; err_line = line; err_col = col;
                err_char = c;
                break;
            }
            stack[depth].open = c;
            stack[depth].offset = i;
            stack[depth].line = line;
            stack[depth].col = col;
            depth++;
            open_count++;
            if (depth > max_depth) { max_depth = depth; max_depth_off = i; }
            at_bol = 0;
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        int ci = -1;
        for (int b = 0; b < p.npairs; b++)
            if (c == p.close[b]) { ci = b; break; }
        if (ci >= 0) {
            close_count++;
            if (depth == 0) {
                err_type = "unmatched_close";
                err_off = i; err_line = line; err_col = col;
                err_char = c;
                break;
            }
            scope_frame_t *top = &stack[depth - 1];
            int ti = -1;
            for (int b = 0; b < p.npairs; b++)
                if (top->open == p.open[b]) { ti = b; break; }
            if (ti < 0 || p.close[ti] != c) {
                err_type = "mismatch";
                err_off = i; err_line = line; err_col = col;
                err_char = c;
                err_expected = ti >= 0 ? p.close[ti] : 0;
                err_open_off = top->offset;
                err_open_line = top->line;
                err_open_col = top->col;
                break;
            }
            depth--;
            at_bol = 0;
            scope_adv(text, &i, &line, &col, 1);
            continue;
        }
        if (c != ' ' && c != '\t' && c != '\r') at_bol = 0;
        scope_adv(text, &i, &line, &col, 1);
    }

    int balanced = (err_type == NULL) && depth == 0 &&
                   (state == SC_NORMAL || state == SC_LINE);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "action", "check");
    cJSON_AddStringToObject(out, "lang", lang_label);
    cJSON_AddBoolToObject(out, "balanced", balanced);
    cJSON_AddNumberToObject(out, "bytes", (double)n);
    cJSON_AddNumberToObject(out, "lines", line);
    cJSON_AddNumberToObject(out, "open_count", open_count);
    cJSON_AddNumberToObject(out, "close_count", close_count);
    cJSON_AddNumberToObject(out, "max_depth", max_depth);
    if (max_depth > 0) cJSON_AddNumberToObject(out, "max_depth_offset", (double)max_depth_off);
    else cJSON_AddNullToObject(out, "max_depth_offset");
    cJSON_AddNumberToObject(out, "comments_skipped", comments);
    cJSON_AddNumberToObject(out, "strings_skipped", strings);
    cJSON_AddStringToObject(out, "final_state",
        state == SC_NORMAL ? "normal" :
        state == SC_LINE ? "line_comment" :
        state == SC_BLOCK ? "block_comment" :
        state == SC_STRING ? "string" : "long_string");

    if (err_type) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "type", err_type);
        cJSON_AddNumberToObject(e, "offset", (double)err_off);
        cJSON_AddNumberToObject(e, "line", err_line);
        cJSON_AddNumberToObject(e, "col", err_col);
        if (err_char) {
            char cb[2] = {err_char, '\0'};
            cJSON_AddStringToObject(e, "char", cb);
        }
        if (strcmp(err_type, "mismatch") == 0) {
            if (err_expected) {
                char eb[2] = {err_expected, '\0'};
                cJSON_AddStringToObject(e, "expected", eb);
            }
            cJSON_AddNumberToObject(e, "open_offset", (double)err_open_off);
            cJSON_AddNumberToObject(e, "open_line", err_open_line);
            cJSON_AddNumberToObject(e, "open_col", err_open_col);
        }
        cJSON_AddItemToObject(out, "first_error", e);
    } else {
        cJSON_AddNullToObject(out, "first_error");
    }

    if (state == SC_STRING || state == SC_LONG) {
        cJSON *u = cJSON_CreateObject();
        cJSON_AddStringToObject(u, "quote",
            state == SC_LONG ? str_delim : (char[]){str_close, '\0'});
        cJSON_AddNumberToObject(u, "offset", (double)str_off);
        cJSON_AddNumberToObject(u, "line", str_line);
        cJSON_AddNumberToObject(u, "col", str_col);
        cJSON_AddItemToObject(out, "unclosed_string", u);
    } else {
        cJSON_AddNullToObject(out, "unclosed_string");
    }

    if (state == SC_BLOCK) {
        cJSON *u = cJSON_CreateObject();
        cJSON_AddNumberToObject(u, "offset", (double)blk_off);
        cJSON_AddNumberToObject(u, "line", blk_line);
        cJSON_AddNumberToObject(u, "col", blk_col);
        cJSON_AddItemToObject(out, "unclosed_comment", u);
    } else {
        cJSON_AddNullToObject(out, "unclosed_comment");
    }

    cJSON *ua = cJSON_CreateArray();
    int listed = depth < SCOPE_UNCLOSED_LIST ? depth : SCOPE_UNCLOSED_LIST;
    for (int k = 0; k < listed; k++) {
        cJSON *u = cJSON_CreateObject();
        char cb[2] = {stack[k].open, '\0'};
        cJSON_AddStringToObject(u, "char", cb);
        cJSON_AddNumberToObject(u, "offset", (double)stack[k].offset);
        cJSON_AddNumberToObject(u, "line", stack[k].line);
        cJSON_AddNumberToObject(u, "col", stack[k].col);
        cJSON_AddItemToArray(ua, u);
    }
    cJSON_AddItemToObject(out, "unclosed", ua);
    cJSON_AddNumberToObject(out, "unclosed_count", depth);

    free(stack);

    char *js = cJSON_PrintUnformatted(out);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(out);
    return res;
}

static sds tool_scope_check_run(cJSON *args, const char *cwd) {
    (void)cwd;
    if (!args) return sdsnew("ERROR: args object required");
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "check";

    if (strcmp(action, "check") == 0 || strcmp(action, "scan") == 0 ||
        strcmp(action, "verify") == 0)
        return tool_scope_check_check(args);

    if (strcmp(action, "profiles") == 0 || strcmp(action, "langs") == 0)
        return tool_scope_check_profiles();

    return sdscatprintf(sdsempty(),
        "ERROR: unknown scope_check action '%s' (use check/profiles)", action);
}

static const alpha_tool_t tool_scope_check = {
    .name = "scope_check",
    .aliases = {"delimiter_check", "bracket_check", NULL},
    .category = "code",
    .description = "Language-aware scope/delimiter balance checker (pure C, in-memory). Skips comments and strings (with escape handling, long-string delimiters, and Ruby =begin/=end line-anchored blocks) while matching bracket pairs. Reports max nesting depth, the first unbalanced position (unmatched close, mismatched pair, depth overflow) and all constructs left unclosed at EOF (brackets, strings, block comments). Built-in profiles: c, ruby, python; every field (pairs, line_comment, block comments, quotes, long_strings, escape) overridable.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"scope_check\",\"description\":\"Language-aware scope/delimiter balance checker: verifies bracket nesting while skipping comments and strings. Built-in profiles: c, ruby, python.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"check\",\"profiles\"],\"description\":\"Operation (default check)\"},\"text\":{\"type\":\"string\",\"description\":\"Source code text to check\"},\"lang\":{\"type\":\"string\",\"enum\":[\"c\",\"ruby\",\"python\"],\"description\":\"Built-in language profile (default c)\"},\"pairs\":{\"type\":\"string\",\"description\":\"Custom bracket pairs, e.g. \\\"()[]{}\\\" (overrides profile)\"},\"line_comment\":{\"type\":\"string\",\"description\":\"Line comment token, e.g. \\\"#\\\" (\\\"\\\" disables)\"},\"block_comment_start\":{\"type\":\"string\",\"description\":\"Block comment start token (with block_comment_end)\"},\"block_comment_end\":{\"type\":\"string\",\"description\":\"Block comment end token\"},\"block_at_line_start\":{\"type\":\"boolean\",\"description\":\"Block comment tokens only match at start of line\"},\"quotes\":{\"type\":\"string\",\"description\":\"String quote chars, e.g. \\\"'\\\"\"},\"long_strings\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Symmetric multi-char string delimiters, e.g. [\\\"\\\\\\\"\\\\\\\"\\\\\\\"\\\"]\"},\"escape\":{\"type\":\"string\",\"description\":\"Escape character for strings (\\\"\\\" disables)\"}},\"required\":[\"text\"]}}}",
    .run = tool_scope_check_run
};
