/* tool_tokenizer.c — PackCC-domain spec-driven longest-match tokenizer (pure C11)
 * Actions: tokenize (default), validate
 *
 * The user supplies token specs [{name, pattern, skip?}] and input text.
 * Patterns use a small regular subset: literals, '.' any char, [a-z] and [^...]
 * classes with ranges, escapes (\\ \n \t \r and escaped metachars), () groups,
 * | alternation, and * + ? repetition. At each input position every spec is
 * matched with true longest-match (POSIX) semantics via position-set closure
 * (no backtracking, no ordered-choice bias); the longest match wins and ties
 * go to the earliest spec. Skipped specs are consumed but not emitted.
 * Unlexable input is an error reporting byte offset, line and column.
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define TKZ_MAX_SPECS 64
#define TKZ_MAX_PAT 2048
#define TKZ_MAX_NODES 4096
#define TKZ_MAX_NAME 64
#define TKZ_MAX_INPUT 65536
#define TKZ_BUDGET (256L * 1024 * 1024)

typedef enum { TKZ_LIT, TKZ_CLASS, TKZ_DOT, TKZ_SEQ, TKZ_ALT, TKZ_STAR, TKZ_PLUS, TKZ_QUEST } tkz_kind_t;
typedef struct tkz_node {
    tkz_kind_t kind;
    unsigned char ch;
    unsigned char cls[32];
    int cls_neg;
    struct tkz_node *child;
    struct tkz_node *next;
} tkz_node_t;

typedef struct {
    tkz_node_t *pool;
    int used;
    int cap;
    const char *pat;
    size_t len;
    size_t pos;
    char err[160];
} tkz_pc_t;

typedef struct { char name[TKZ_MAX_NAME]; tkz_node_t *root; int skip; } tkz_spec_t;

#define TKZ_SET(b, p) ((b)[(p) >> 3] |= (unsigned char)(1u << ((p) & 7)))
#define TKZ_TST(b, p) (((b)[(p) >> 3] >> ((p) & 7)) & 1u)

/* --- pattern compiler ---------------------------------------------------- */

static tkz_node_t *tkz_new(tkz_pc_t *pc, tkz_kind_t k) {
    if (pc->used >= pc->cap) {
        if (!pc->err[0]) snprintf(pc->err, sizeof(pc->err), "patterns too complex (node limit)");
        return NULL;
    }
    tkz_node_t *n = &pc->pool[pc->used++];
    memset(n, 0, sizeof(*n));
    n->kind = k;
    return n;
}

/* Read one logical pattern char, resolving backslash escapes. */
static int tkz_esc(tkz_pc_t *pc, unsigned char *out) {
    unsigned char c = (unsigned char)pc->pat[pc->pos++];
    if (c == '\\') {
        if (pc->pos >= pc->len) {
            snprintf(pc->err, sizeof(pc->err), "trailing backslash in pattern");
            return 0;
        }
        c = (unsigned char)pc->pat[pc->pos++];
        if (c == 'n') c = '\n';
        else if (c == 't') c = '\t';
        else if (c == 'r') c = '\r';
    }
    *out = c;
    return 1;
}

static tkz_node_t *tkz_parse_alt(tkz_pc_t *pc);

/* Parse a sequence; returns NULL for an empty sequence (matches empty). */
static tkz_node_t *tkz_parse_seq(tkz_pc_t *pc) {
    tkz_node_t *head = NULL, *tail = NULL;
    int cnt = 0;
    while (pc->pos < pc->len && pc->pat[pc->pos] != '|' && pc->pat[pc->pos] != ')') {
        /* repeat := primary quantifier* ; primary errors set pc->err */
        tkz_node_t *n;
        char c = pc->pat[pc->pos];
        if (c == '(') {
            pc->pos++;
            n = tkz_parse_alt(pc);
            if (pc->err[0]) return NULL;
            if (pc->pos >= pc->len || pc->pat[pc->pos] != ')') {
                snprintf(pc->err, sizeof(pc->err), "unclosed parenthesis");
                return NULL;
            }
            pc->pos++;
        } else if (c == '.') {
            pc->pos++;
            n = tkz_new(pc, TKZ_DOT);
            if (!n) return NULL;
        } else if (c == '[') {
            pc->pos++;
            n = tkz_new(pc, TKZ_CLASS);
            if (!n) return NULL;
            if (pc->pos < pc->len && pc->pat[pc->pos] == '^') { n->cls_neg = 1; pc->pos++; }
            int any = 0;
            while (pc->pos < pc->len && pc->pat[pc->pos] != ']') {
                unsigned char c1, c2;
                if (!tkz_esc(pc, &c1)) return NULL;
                if (pc->pos + 1 < pc->len && pc->pat[pc->pos] == '-' && pc->pat[pc->pos + 1] != ']') {
                    pc->pos++;
                    if (!tkz_esc(pc, &c2)) return NULL;
                    if (c2 < c1) {
                        snprintf(pc->err, sizeof(pc->err), "invalid range '%c-%c'", c1, c2);
                        return NULL;
                    }
                    for (int ch = c1; ch <= c2; ch++) n->cls[ch / 8] |= (unsigned char)(1 << (ch % 8));
                } else {
                    n->cls[c1 / 8] |= (unsigned char)(1 << (c1 % 8));
                }
                any = 1;
            }
            if (pc->pos >= pc->len || pc->pat[pc->pos] != ']') {
                snprintf(pc->err, sizeof(pc->err), "unclosed character class");
                return NULL;
            }
            pc->pos++;
            if (!any) {
                snprintf(pc->err, sizeof(pc->err), "empty character class");
                return NULL;
            }
        } else if (c == '\\') {
            unsigned char e;
            pc->pos++;
            if (pc->pos >= pc->len) {
                snprintf(pc->err, sizeof(pc->err), "trailing backslash in pattern");
                return NULL;
            }
            e = (unsigned char)pc->pat[pc->pos++];
            if (e == 'n') e = '\n';
            else if (e == 't') e = '\t';
            else if (e == 'r') e = '\r';
            n = tkz_new(pc, TKZ_LIT);
            if (!n) return NULL;
            n->ch = e;
        } else if (c == '|' || c == ')' || c == '*' || c == '+' || c == '?') {
            snprintf(pc->err, sizeof(pc->err), "unexpected character '%c' (escape it with \\\\)", c);
            return NULL;
        } else {
            pc->pos++;
            n = tkz_new(pc, TKZ_LIT);
            if (!n) return NULL;
            n->ch = (unsigned char)c;
        }
        /* quantifiers */
        while (pc->pos < pc->len) {
            char q = pc->pat[pc->pos];
            if (q != '*' && q != '+' && q != '?') break;
            pc->pos++;
            tkz_node_t *r = tkz_new(pc, q == '*' ? TKZ_STAR : (q == '+' ? TKZ_PLUS : TKZ_QUEST));
            if (!r) return NULL;
            r->child = n;
            n = r;
        }
        if (!n) continue; /* empty group: no-op in a sequence */
        if (!head) head = n; else tail->next = n;
        tail = n;
        cnt++;
    }
    if (cnt == 0) return NULL;
    if (cnt == 1) return head;
    tkz_node_t *s = tkz_new(pc, TKZ_SEQ);
    if (!s) return NULL;
    s->child = head;
    return s;
}

/* Parse alternation; NULL return means empty (matches empty) unless pc->err set. */
static tkz_node_t *tkz_parse_alt(tkz_pc_t *pc) {
    tkz_node_t *first = tkz_parse_seq(pc);
    if (pc->err[0]) return NULL;
    if (pc->pos >= pc->len || pc->pat[pc->pos] != '|') return first;
    tkz_node_t *alt = tkz_new(pc, TKZ_ALT);
    if (!alt) return NULL;
    alt->child = first; /* may be NULL: empty branch matches empty */
    tkz_node_t *curr = first;
    while (pc->pos < pc->len && pc->pat[pc->pos] == '|') {
        pc->pos++;
        tkz_node_t *nxt = tkz_parse_seq(pc);
        if (pc->err[0]) return NULL;
        if (curr) curr->next = nxt; else alt->child = nxt;
        if (nxt) curr = nxt;
    }
    return alt;
}

/* Can this pattern match the empty string? */
static int tkz_nullable(tkz_node_t *n) {
    if (!n) return 1;
    switch (n->kind) {
        case TKZ_LIT: case TKZ_CLASS: case TKZ_DOT: return 0;
        case TKZ_STAR: case TKZ_QUEST: return 1;
        case TKZ_PLUS: return tkz_nullable(n->child);
        case TKZ_SEQ:
            for (tkz_node_t *c = n->child; c; c = c->next)
                if (!tkz_nullable(c)) return 0;
            return 1;
        case TKZ_ALT:
            for (tkz_node_t *c = n->child; c; c = c->next)
                if (tkz_nullable(c)) return 1;
            return n->child == NULL;
    }
    return 0;
}

/* --- matcher: position-set closure (true longest match, no backtracking) - */

typedef struct tkz_buf { struct tkz_buf *next_all; } tkz_buf_t;
typedef struct {
    const char *in;
    size_t ilen;
    size_t psz;          /* bytes per position bitset: bits 0..ilen */
    tkz_buf_t *all;      /* every allocation, for cleanup */
    tkz_buf_t *freelist; /* recycled buffers */
    long budget;
    int over;
} tkz_mx_t;

static unsigned char *tkz_pset_get(tkz_mx_t *mx) {
    if (mx->freelist) {
        tkz_buf_t *b = mx->freelist;
        mx->freelist = b->next_all;
        return (unsigned char *)(b + 1);
    }
    tkz_buf_t *b = malloc(sizeof(tkz_buf_t) + mx->psz);
    if (!b) { mx->over = 1; return NULL; }
    b->next_all = mx->all;
    mx->all = b;
    return (unsigned char *)(b + 1);
}

static void tkz_pset_put(tkz_mx_t *mx, unsigned char *p) {
    if (!p) return;
    tkz_buf_t *b = ((tkz_buf_t *)p) - 1;
    b->next_all = mx->freelist;
    mx->freelist = b;
}

static void tkz_mx_free(tkz_mx_t *mx) {
    while (mx->all) { tkz_buf_t *n = mx->all->next_all; free(mx->all); mx->all = n; }
    mx->freelist = NULL;
}

/* out := set of positions reachable by matching n from any position in in_set.
 * A NULL node matches empty (out := in_set). */
static void tkz_ends(tkz_mx_t *mx, tkz_node_t *n, const unsigned char *in_set, unsigned char *out) {
    if (mx->over) return;
    size_t psz = mx->psz;
    mx->budget -= (long)psz;
    if (mx->budget <= 0) { mx->over = 1; return; }
    memset(out, 0, psz);
    if (!n) { memcpy(out, in_set, psz); return; }
    switch (n->kind) {
        case TKZ_LIT:
            for (size_t p = 0; p < mx->ilen; p++)
                if (TKZ_TST(in_set, p) && (unsigned char)mx->in[p] == n->ch) TKZ_SET(out, p + 1);
            break;
        case TKZ_DOT:
            for (size_t p = 0; p < mx->ilen; p++)
                if (TKZ_TST(in_set, p)) TKZ_SET(out, p + 1);
            break;
        case TKZ_CLASS:
            for (size_t p = 0; p < mx->ilen; p++) {
                if (!TKZ_TST(in_set, p)) continue;
                unsigned char c = (unsigned char)mx->in[p];
                int in_cls = (n->cls[c / 8] & (1 << (c % 8))) != 0;
                if (n->cls_neg) in_cls = !in_cls;
                if (in_cls) TKZ_SET(out, p + 1);
            }
            break;
        case TKZ_SEQ: {
            unsigned char *cur = tkz_pset_get(mx), *nxt = tkz_pset_get(mx);
            if (!cur || !nxt) { mx->over = 1; tkz_pset_put(mx, cur); tkz_pset_put(mx, nxt); return; }
            memcpy(cur, in_set, psz);
            for (tkz_node_t *c = n->child; c; c = c->next) {
                tkz_ends(mx, c, cur, nxt);
                if (mx->over) break;
                memcpy(cur, nxt, psz);
                int empty = 1;
                for (size_t i = 0; i < psz; i++) if (cur[i]) { empty = 0; break; }
                if (empty) break;
            }
            if (!mx->over) memcpy(out, cur, psz);
            tkz_pset_put(mx, cur);
            tkz_pset_put(mx, nxt);
            break;
        }
        case TKZ_ALT: {
            unsigned char *tmp = tkz_pset_get(mx);
            if (!tmp) { mx->over = 1; return; }
            for (tkz_node_t *c = n->child; c; c = c->next) {
                tkz_ends(mx, c, in_set, tmp);
                if (mx->over) break;
                for (size_t i = 0; i < psz; i++) out[i] |= tmp[i];
            }
            tkz_pset_put(mx, tmp);
            break;
        }
        case TKZ_STAR: case TKZ_PLUS: {
            unsigned char *fr = tkz_pset_get(mx), *seen = tkz_pset_get(mx), *tmp = tkz_pset_get(mx);
            if (!fr || !seen || !tmp) {
                mx->over = 1;
                tkz_pset_put(mx, fr); tkz_pset_put(mx, seen); tkz_pset_put(mx, tmp);
                return;
            }
            if (n->kind == TKZ_PLUS) {
                tkz_ends(mx, n->child, in_set, fr); /* one required repetition */
                if (mx->over) { tkz_pset_put(mx, fr); tkz_pset_put(mx, seen); tkz_pset_put(mx, tmp); return; }
            } else {
                memcpy(fr, in_set, psz);
            }
            memcpy(seen, fr, psz);
            memcpy(out, fr, psz);
            while (!mx->over) {
                tkz_ends(mx, n->child, fr, tmp);
                if (mx->over) break;
                mx->budget -= (long)psz;
                if (mx->budget <= 0) { mx->over = 1; break; }
                int any = 0;
                for (size_t i = 0; i < psz; i++) {
                    unsigned char nw = tmp[i] & (unsigned char)~seen[i];
                    fr[i] = nw;
                    seen[i] |= tmp[i];
                    out[i] |= tmp[i];
                    if (nw) any = 1;
                }
                if (!any) break;
            }
            tkz_pset_put(mx, fr);
            tkz_pset_put(mx, seen);
            tkz_pset_put(mx, tmp);
            break;
        }
        case TKZ_QUEST: {
            unsigned char *tmp = tkz_pset_get(mx);
            if (!tmp) { mx->over = 1; return; }
            tkz_ends(mx, n->child, in_set, tmp);
            memcpy(out, in_set, psz);
            if (!mx->over)
                for (size_t i = 0; i < psz; i++) out[i] |= tmp[i];
            tkz_pset_put(mx, tmp);
            break;
        }
    }
}

/* Longest match length of spec at pos, or 0 when there is no nonempty match. */
static size_t tkz_match_at(tkz_mx_t *mx, tkz_node_t *root, size_t pos,
                           unsigned char *startset, unsigned char *outset) {
    memset(startset, 0, mx->psz);
    TKZ_SET(startset, pos);
    tkz_ends(mx, root, startset, outset);
    if (mx->over) return 0;
    for (size_t e = mx->ilen; e > pos; e--)
        if (TKZ_TST(outset, e)) return e - pos;
    return 0;
}

/* --- tool entry ----------------------------------------------------------- */

static sds tool_tokenizer_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "tokenize";
    int do_validate = 0;
    if (strcmp(action, "tokenize") == 0 || strcmp(action, "lex") == 0) {
        do_validate = 0;
    } else if (strcmp(action, "validate") == 0) {
        do_validate = 1;
    } else {
        return sdscatprintf(sdsempty(), "ERROR: unknown tokenizer action '%s' (use tokenize/validate)", action);
    }

    cJSON *specs = cJSON_GetObjectItem(args, "specs");
    if (!cJSON_IsArray(specs)) return sdsnew("ERROR: 'specs' array of {name, pattern, skip?} objects required");
    int ns = cJSON_GetArraySize(specs);
    if (ns <= 0) return sdsnew("ERROR: 'specs' must contain at least one token spec");
    if (ns > TKZ_MAX_SPECS)
        return sdscatprintf(sdsempty(), "ERROR: too many specs (max %d)", TKZ_MAX_SPECS);

    tkz_node_t *pool = calloc(TKZ_MAX_NODES, sizeof(tkz_node_t));
    if (!pool) return sdsnew("ERROR: out of memory");
    tkz_pc_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.pool = pool;
    pc.cap = TKZ_MAX_NODES;
    tkz_spec_t specv[TKZ_MAX_SPECS];
    memset(specv, 0, sizeof(specv));

    for (int i = 0; i < ns; i++) {
        cJSON *item = cJSON_GetArrayItem(specs, i);
        if (!cJSON_IsObject(item)) {
            free(pool);
            return sdscatprintf(sdsempty(), "ERROR: spec %d must be an object {name, pattern, skip?}", i);
        }
        const char *nm = cJSON_GetStringValue(cJSON_GetObjectItem(item, "name"));
        if (!nm || !nm[0]) {
            free(pool);
            return sdscatprintf(sdsempty(), "ERROR: spec %d missing 'name'", i);
        }
        if (strlen(nm) >= TKZ_MAX_NAME) {
            free(pool);
            return sdscatprintf(sdsempty(), "ERROR: spec %d name too long (max %d)", i, TKZ_MAX_NAME - 1);
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(specv[j].name, nm) == 0) {
                free(pool);
                return sdscatprintf(sdsempty(), "ERROR: duplicate spec name '%s'", nm);
            }
        }
        const char *pat = cJSON_GetStringValue(cJSON_GetObjectItem(item, "pattern"));
        if (!pat) {
            free(pool);
            return sdscatprintf(sdsempty(), "ERROR: spec '%s' missing 'pattern'", nm);
        }
        if (strlen(pat) > TKZ_MAX_PAT) {
            free(pool);
            return sdscatprintf(sdsempty(), "ERROR: spec '%s' pattern too long (max %d)", nm, TKZ_MAX_PAT);
        }
        pc.pat = pat;
        pc.len = strlen(pat);
        pc.pos = 0;
        pc.err[0] = 0;
        tkz_node_t *root = tkz_parse_alt(&pc);
        if (pc.err[0]) {
            sds e = sdscatprintf(sdsempty(), "ERROR: spec '%s' pattern error: %s (pos %zu)", nm, pc.err, pc.pos);
            free(pool);
            return e;
        }
        if (pc.pos < pc.len) {
            sds e = sdscatprintf(sdsempty(), "ERROR: spec '%s' pattern error: unexpected trailing syntax (pos %zu)", nm, pc.pos);
            free(pool);
            return e;
        }
        if (!root || tkz_nullable(root)) {
            free(pool);
            return sdscatprintf(sdsempty(), "ERROR: spec '%s' pattern can match empty string; token patterns must consume input", nm);
        }
        strncpy(specv[i].name, nm, TKZ_MAX_NAME - 1);
        specv[i].root = root;
        specv[i].skip = cJSON_IsTrue(cJSON_GetObjectItem(item, "skip")) ||
                        cJSON_IsTrue(cJSON_GetObjectItem(item, "ignore"));
    }

    if (do_validate) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "validate");
        cJSON_AddBoolToObject(obj, "valid", 1);
        cJSON_AddNumberToObject(obj, "count", ns);
        cJSON *names = cJSON_CreateArray();
        for (int i = 0; i < ns; i++) cJSON_AddItemToArray(names, cJSON_CreateString(specv[i].name));
        cJSON_AddItemToObject(obj, "names", names);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js);
        cJSON_Delete(obj);
        free(pool);
        return res;
    }

    const char *input = cJSON_GetStringValue(cJSON_GetObjectItem(args, "input"));
    if (!input) input = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    if (!input) {
        free(pool);
        return sdsnew("ERROR: 'input' text required for tokenize");
    }
    size_t ilen = strlen(input);
    if (ilen > TKZ_MAX_INPUT) {
        free(pool);
        return sdscatprintf(sdsempty(), "ERROR: input too long (max %d bytes, got %zu)", TKZ_MAX_INPUT, ilen);
    }

    tkz_mx_t mx;
    memset(&mx, 0, sizeof(mx));
    mx.in = input;
    mx.ilen = ilen;
    mx.psz = (ilen + 8) / 8;
    if (mx.psz == 0) mx.psz = 1;
    mx.budget = TKZ_BUDGET;
    unsigned char *startset = malloc(mx.psz);
    unsigned char *outset = malloc(mx.psz);
    if (!startset || !outset) {
        free(startset); free(outset); free(pool);
        return sdsnew("ERROR: out of memory");
    }

    cJSON *toks = cJSON_CreateArray();
    size_t pos = 0;
    int line = 1, col = 1;
    sds err = NULL;
    while (pos < ilen) {
        size_t best_len = 0;
        int best = -1;
        for (int i = 0; i < ns && !mx.over; i++) {
            size_t l = tkz_match_at(&mx, specv[i].root, pos, startset, outset);
            if (!mx.over && l > best_len) { best_len = l; best = i; }
        }
        if (mx.over) {
            err = sdsnew("ERROR: match budget exceeded (input or patterns too complex)");
            break;
        }
        if (best < 0) {
            unsigned char c = (unsigned char)input[pos];
            if (isprint(c))
                err = sdscatprintf(sdsempty(), "ERROR: unlexable input at offset %zu (line %d, col %d): unexpected '%c'",
                                   pos, line, col, c);
            else
                err = sdscatprintf(sdsempty(), "ERROR: unlexable input at offset %zu (line %d, col %d): unexpected byte 0x%02x",
                                   pos, line, col, c);
            break;
        }
        if (!specv[best].skip) {
            char *val = malloc(best_len + 1);
            if (!val) { err = sdsnew("ERROR: out of memory"); break; }
            memcpy(val, input + pos, best_len);
            val[best_len] = '\0';
            cJSON *t = cJSON_CreateObject();
            cJSON_AddStringToObject(t, "type", specv[best].name);
            cJSON_AddStringToObject(t, "value", val);
            cJSON_AddNumberToObject(t, "start", (double)pos);
            cJSON_AddNumberToObject(t, "end", (double)(pos + best_len));
            cJSON_AddNumberToObject(t, "line", line);
            cJSON_AddNumberToObject(t, "col", col);
            cJSON_AddItemToArray(toks, t);
            free(val);
        }
        for (size_t k = pos; k < pos + best_len; k++) {
            if (input[k] == '\n') { line++; col = 1; } else col++;
        }
        pos += best_len;
    }

    free(startset);
    free(outset);
    tkz_mx_free(&mx);
    free(pool);
    if (err) {
        cJSON_Delete(toks);
        return err;
    }
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "tokenize");
    cJSON_AddNumberToObject(obj, "count", cJSON_GetArraySize(toks));
    cJSON_AddNumberToObject(obj, "consumed", (double)pos);
    cJSON_AddItemToObject(obj, "tokens", toks);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    return res;
}

static const alpha_tool_t tool_tokenizer = {
    .name = "tokenizer",
    .aliases = {"tokenize", "lex", "lexer", NULL},
    .category = "parsing",
    .description = "Spec-driven longest-match tokenizer (pure C). Supply token specs [{name, pattern, skip?}] and input; returns the JSON token stream with type/value/start/end/line/col. Pattern subset: literals, '.' any char, [a-z] and [^...] classes with ranges, escapes (\\\\ \\n \\t \\r), () groups, | alternation, * + ? repetition. True POSIX longest-match per position (no backtracking bias); ties go to the earliest spec; skip:true specs are consumed but not emitted. Unlexable input errors with byte offset, line and column. Actions: tokenize (default), validate (check specs only). Limits: 64 specs, 2048-char patterns, 64KB input.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"tokenizer\",\"description\":\"Spec-driven longest-match tokenizer: compile token specs and lex input into a JSON token stream with positions; longest match wins, ties go to the earliest spec, unlexable input errors with position.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"tokenize\",\"validate\"],\"description\":\"tokenize (default) lexes input; validate only checks the specs\"},\"specs\":{\"type\":\"array\",\"description\":\"Token specs, tried at each position; longest match wins, ties prefer earlier specs\",\"items\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Token type name\"},\"pattern\":{\"type\":\"string\",\"description\":\"Pattern: literals, . [a-z] [^...] () | * + ? and backslash escapes\"},\"skip\":{\"type\":\"boolean\",\"description\":\"Consume but do not emit (e.g. whitespace)\"}},\"required\":[\"name\",\"pattern\"]}},\"input\":{\"type\":\"string\",\"description\":\"Text to tokenize (max 64KB)\"},\"text\":{\"type\":\"string\",\"description\":\"Alias for input\"}},\"required\":[\"specs\"]}}}",
    .run = tool_tokenizer_run
};
