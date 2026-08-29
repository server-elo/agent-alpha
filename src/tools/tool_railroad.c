/* tool_railroad.c — ASCII railroad-diagram renderer for an EBNF subset
 * (inspired by katef/kgt). Pure C11, in-memory only.
 *
 * Grammar subset:
 *   rule    := IDENT ('=' | '::=') alt [';']
 *   alt     := seq ('|' seq)*
 *   seq     := factor+            (factors separated by whitespace or ',')
 *   factor  := STRING | IDENT
 *            | '[' alt ']'        (option)
 *            | '{' alt '}'        (repetition)
 *            | '(' alt ')'        (group)
 *   STRING  := "..." or '...' (non-empty, single line)
 *   comment := (* ... *)
 * Rules may also be separated by a newline (a rule ends when a new line
 * starts with IDENT followed by '=' or '::=').
 *
 * Action: render (default), validate.
 * Parse errors are strict and reported with 1-based line/col position.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define RR_MAX_INPUT   65536
#define RR_MAX_RULES   128
#define RR_MAX_NODES   1024
#define RR_MAX_DEPTH   48
#define RR_MAX_NAME    64
#define RR_MAX_TEXT    96
#define RR_MAX_W       500
#define RR_MAX_H       300

typedef enum {
    RR_TERM, RR_NONTERM, RR_SEQ, RR_ALT, RR_OPT, RR_REP
} rr_type_t;

typedef struct rr_node_s {
    rr_type_t type;
    char text[RR_MAX_TEXT];        /* TERM / NONTERM */
    struct rr_node_s **kids;
    int nk;
    int cap;
    int w, h, ey;                  /* layout: width, height, entry row */
} rr_node_t;

/* ---------- node helpers ---------- */

static rr_node_t *rr_new_node(rr_type_t t, int *count) {
    if (*count >= RR_MAX_NODES) return NULL;
    rr_node_t *n = (rr_node_t *)calloc(1, sizeof(rr_node_t));
    if (!n) return NULL;
    n->type = t;
    (*count)++;
    return n;
}

static int rr_add_kid(rr_node_t *parent, rr_node_t *kid) {
    if (parent->nk >= parent->cap) {
        int ncap = parent->cap ? parent->cap * 2 : 4;
        rr_node_t **nk = (rr_node_t **)realloc(parent->kids,
                                               (size_t)ncap * sizeof(rr_node_t *));
        if (!nk) return -1;
        parent->kids = nk;
        parent->cap = ncap;
    }
    parent->kids[parent->nk++] = kid;
    return 0;
}

static void rr_free_node(rr_node_t *n) {
    if (!n) return;
    for (int i = 0; i < n->nk; i++) rr_free_node(n->kids[i]);
    free(n->kids);
    free(n);
}

/* ---------- lexer ---------- */

typedef enum {
    TK_EOF, TK_IDENT, TK_STRING, TK_EQ, TK_PIPE,
    TK_LB, TK_RB, TK_LC, TK_RC, TK_LP, TK_RP, TK_SEMI, TK_COMMA, TK_ERR
} rr_tok_t;

typedef struct {
    const char *src;
    size_t pos;
    int line;
    int col;
} rr_lexer_t;

typedef struct {
    rr_tok_t type;
    char text[RR_MAX_TEXT];
    int line;
    int col;
} rr_token_t;

static void rr_lex_ws(rr_lexer_t *lx) {
    for (;;) {
        char c = lx->src[lx->pos];
        if (c == '\n') { lx->pos++; lx->line++; lx->col = 1; }
        else if (isspace((unsigned char)c)) { lx->pos++; lx->col++; }
        else if (c == '(' && lx->src[lx->pos + 1] == '*') {
            /* (* ... *) comment */
            lx->pos += 2; lx->col += 2;
            while (lx->src[lx->pos] &&
                   !(lx->src[lx->pos] == '*' && lx->src[lx->pos + 1] == ')')) {
                if (lx->src[lx->pos] == '\n') { lx->line++; lx->col = 1; lx->pos++; }
                else { lx->pos++; lx->col++; }
            }
            if (lx->src[lx->pos]) { lx->pos += 2; lx->col += 2; }
            else return; /* unterminated comment: next lex call hits EOF/ERR */
        } else break;
    }
}

static rr_token_t rr_lex(rr_lexer_t *lx) {
    rr_token_t t;
    memset(&t, 0, sizeof(t));
    rr_lex_ws(lx);
    t.line = lx->line;
    t.col = lx->col;
    char c = lx->src[lx->pos];
    if (!c) { t.type = TK_EOF; return t; }

    if (isalpha((unsigned char)c) || c == '_') {
        size_t k = 0;
        while (isalnum((unsigned char)lx->src[lx->pos]) ||
               lx->src[lx->pos] == '_' || lx->src[lx->pos] == '-') {
            if (k < RR_MAX_TEXT - 1) t.text[k++] = lx->src[lx->pos];
            lx->pos++; lx->col++;
        }
        t.text[k] = '\0';
        t.type = TK_IDENT;
        return t;
    }
    if (c == '"' || c == '\'') {
        char q = c;
        lx->pos++; lx->col++;
        size_t k = 0;
        while (lx->src[lx->pos] && lx->src[lx->pos] != q &&
               lx->src[lx->pos] != '\n') {
            if (k < RR_MAX_TEXT - 1) t.text[k++] = lx->src[lx->pos];
            lx->pos++; lx->col++;
        }
        if (lx->src[lx->pos] != q) {
            t.type = TK_ERR;
            snprintf(t.text, sizeof(t.text), "unterminated string literal");
            return t;
        }
        lx->pos++; lx->col++;
        t.text[k] = '\0';
        if (k == 0) {
            t.type = TK_ERR;
            snprintf(t.text, sizeof(t.text), "empty string literal");
            return t;
        }
        t.type = TK_STRING;
        return t;
    }
    lx->pos++; lx->col++;
    switch (c) {
    case '|': t.type = TK_PIPE; return t;
    case '[': t.type = TK_LB; return t;
    case ']': t.type = TK_RB; return t;
    case '{': t.type = TK_LC; return t;
    case '}': t.type = TK_RC; return t;
    case '(': t.type = TK_LP; return t;
    case ')': t.type = TK_RP; return t;
    case ';': t.type = TK_SEMI; return t;
    case ',': t.type = TK_COMMA; return t;
    case '=':
        t.type = TK_EQ;
        return t;
    case ':':
        if (lx->src[lx->pos] == ':' && lx->src[lx->pos + 1] == '=') {
            lx->pos += 2; lx->col += 2;
            t.type = TK_EQ;
            return t;
        }
        t.type = TK_ERR;
        snprintf(t.text, sizeof(t.text), "unexpected ':' (use '=' or '::=')");
        return t;
    default:
        t.type = TK_ERR;
        snprintf(t.text, sizeof(t.text), "unexpected character '%c'", c);
        return t;
    }
}

/* ---------- parser ---------- */

typedef struct {
    rr_lexer_t lx;
    rr_token_t cur;
    rr_token_t next;
    int last_line;   /* line of most recently consumed token */
    int node_count;
    char err[256];
    int err_line;
    int err_col;
} rr_parser_t;

typedef struct {
    char name[RR_MAX_NAME];
    rr_node_t *root;
} rr_rule_t;

typedef struct {
    rr_rule_t rules[RR_MAX_RULES];
    int count;
} rr_grammar_t;

static void rr_perr(rr_parser_t *p, int line, int col, const char *msg) {
    if (p->err[0]) return; /* keep first error */
    snprintf(p->err, sizeof(p->err), "%s", msg);
    p->err_line = line;
    p->err_col = col;
}

static void rr_perr_tok(rr_parser_t *p, const rr_token_t *t, const char *msg) {
    if (t->type == TK_ERR) rr_perr(p, t->line, t->col, t->text);
    else rr_perr(p, t->line, t->col, msg);
}

static void rr_advance(rr_parser_t *p) {
    p->last_line = p->cur.line;
    p->cur = p->next;
    p->next = rr_lex(&p->lx);
    if (p->next.type == TK_ERR)
        rr_perr(p, p->next.line, p->next.col, p->next.text);
}

static rr_node_t *rr_parse_alt(rr_parser_t *p, int depth);

/* seq := factor+ ; stops at | ] } ) ; EOF or a new-line rule boundary. */
static rr_node_t *rr_parse_seq(rr_parser_t *p, int depth) {
    rr_node_t *seq = rr_new_node(RR_SEQ, &p->node_count);
    if (!seq) { rr_perr(p, p->cur.line, p->cur.col, "too many nodes"); return NULL; }
    for (;;) {
        rr_token_t *t = &p->cur;
        if (t->type == TK_COMMA) { rr_advance(p); continue; }
        if (t->type == TK_PIPE || t->type == TK_RB || t->type == TK_RC ||
            t->type == TK_RP || t->type == TK_SEMI || t->type == TK_EOF ||
            t->type == TK_ERR)
            break;
        /* newline-separated rule boundary: IDENT at a fresh line followed
         * by '=' / '::=' starts the next rule */
        if (t->type == TK_IDENT && seq->nk > 0 && t->line > p->last_line &&
            p->next.type == TK_EQ)
            break;
        if (seq->nk > 0 && t->line > p->last_line && p->next.type == TK_EQ)
            break; /* defensive; covered above for IDENT */
        rr_node_t *f = NULL;
        if (t->type == TK_STRING) {
            f = rr_new_node(RR_TERM, &p->node_count);
            if (f) snprintf(f->text, sizeof(f->text), "%s", t->text);
            rr_advance(p);
        } else if (t->type == TK_IDENT) {
            f = rr_new_node(RR_NONTERM, &p->node_count);
            if (f) snprintf(f->text, sizeof(f->text), "%s", t->text);
            rr_advance(p);
        } else if (t->type == TK_LB || t->type == TK_LC || t->type == TK_LP) {
            rr_tok_t open = t->type;
            if (depth >= RR_MAX_DEPTH) {
                rr_perr(p, t->line, t->col, "nesting too deep");
                rr_free_node(seq);
                return NULL;
            }
            rr_advance(p);
            rr_node_t *inner = rr_parse_alt(p, depth + 1);
            if (!inner) { rr_free_node(seq); return NULL; }
            rr_tok_t want = (open == TK_LB) ? TK_RB : (open == TK_LC) ? TK_RC : TK_RP;
            if (p->cur.type != want) {
                rr_perr_tok(p, &p->cur,
                            (open == TK_LB) ? "expected ']'" :
                            (open == TK_LC) ? "expected '}'" : "expected ')'");
                rr_free_node(inner);
                rr_free_node(seq);
                return NULL;
            }
            rr_advance(p);
            if (open == TK_LP) {
                f = inner; /* grouping is transparent */
            } else {
                f = rr_new_node(open == TK_LB ? RR_OPT : RR_REP, &p->node_count);
                if (f && rr_add_kid(f, inner) != 0) {
                    rr_perr(p, t->line, t->col, "out of memory");
                    rr_free_node(inner);
                }
            }
        } else {
            rr_perr_tok(p, t, "expected terminal, identifier, '[', '{' or '('");
            rr_free_node(seq);
            return NULL;
        }
        if (!f) {
            if (!p->err[0]) rr_perr(p, t->line, t->col, "too many nodes");
            rr_free_node(seq);
            return NULL;
        }
        if (rr_add_kid(seq, f) != 0) {
            rr_perr(p, t->line, t->col, "out of memory");
            rr_free_node(f);
            rr_free_node(seq);
            return NULL;
        }
    }
    if (seq->nk == 0) {
        rr_perr(p, p->cur.line, p->cur.col, "empty alternative or rule body");
        rr_free_node(seq);
        return NULL;
    }
    if (seq->nk == 1) {
        rr_node_t *only = seq->kids[0];
        seq->kids[0] = NULL;
        rr_free_node(seq);
        return only;
    }
    return seq;
}

static rr_node_t *rr_parse_alt(rr_parser_t *p, int depth) {
    rr_node_t *first = rr_parse_seq(p, depth);
    if (!first) return NULL;
    if (p->cur.type != TK_PIPE) return first;
    rr_node_t *alt = rr_new_node(RR_ALT, &p->node_count);
    if (!alt) { rr_perr(p, p->cur.line, p->cur.col, "too many nodes"); rr_free_node(first); return NULL; }
    if (rr_add_kid(alt, first) != 0) { rr_free_node(first); rr_free_node(alt); return NULL; }
    while (p->cur.type == TK_PIPE) {
        rr_advance(p);
        rr_node_t *s = rr_parse_seq(p, depth);
        if (!s) { rr_free_node(alt); return NULL; }
        if (rr_add_kid(alt, s) != 0) { rr_free_node(s); rr_free_node(alt); return NULL; }
    }
    return alt;
}

static void rr_grammar_free(rr_grammar_t *g) {
    for (int i = 0; i < g->count; i++) rr_free_node(g->rules[i].root);
    g->count = 0;
}

static int rr_parse_grammar(const char *text, rr_grammar_t *g,
                            char *err, size_t errsz, int *err_line, int *err_col) {
    g->count = 0;
    if (!text || !text[0]) {
        snprintf(err, errsz, "grammar is empty");
        *err_line = 1; *err_col = 1;
        return -1;
    }
    if (strlen(text) > RR_MAX_INPUT) {
        snprintf(err, errsz, "grammar exceeds %d bytes", RR_MAX_INPUT);
        *err_line = 1; *err_col = 1;
        return -1;
    }
    rr_parser_t p;
    memset(&p, 0, sizeof(p));
    p.lx.src = text;
    p.lx.pos = 0;
    p.lx.line = 1;
    p.lx.col = 1;
    p.last_line = 1;
    p.cur = rr_lex(&p.lx);
    if (p.cur.type == TK_ERR) rr_perr(&p, p.cur.line, p.cur.col, p.cur.text);
    p.next = rr_lex(&p.lx);
    if (p.next.type == TK_ERR) rr_perr(&p, p.next.line, p.next.col, p.next.text);

    while (p.cur.type != TK_EOF && !p.err[0]) {
        if (p.cur.type == TK_SEMI) { rr_advance(&p); continue; }
        if (p.cur.type != TK_IDENT) {
            rr_perr_tok(&p, &p.cur, "expected rule name");
            break;
        }
        if (g->count >= RR_MAX_RULES) {
            rr_perr(&p, p.cur.line, p.cur.col, "too many rules");
            break;
        }
        rr_rule_t *r = &g->rules[g->count];
        snprintf(r->name, sizeof(r->name), "%s", p.cur.text);
        r->root = NULL;
        rr_advance(&p);
        if (p.cur.type != TK_EQ) {
            rr_perr_tok(&p, &p.cur, "expected '=' or '::=' after rule name");
            break;
        }
        rr_advance(&p);
        r->root = rr_parse_alt(&p, 0);
        if (!r->root) break;
        g->count++;
        if (p.cur.type == TK_SEMI) rr_advance(&p);
    }
    if (p.err[0]) {
        snprintf(err, errsz, "%s", p.err);
        *err_line = p.err_line;
        *err_col = p.err_col;
        rr_grammar_free(g);
        return -1;
    }
    if (g->count == 0) {
        snprintf(err, errsz, "grammar has no rules");
        *err_line = 1; *err_col = 1;
        return -1;
    }
    return 0;
}

/* ---------- layout ---------- */

static void rr_layout(rr_node_t *n) {
    for (int i = 0; i < n->nk; i++) rr_layout(n->kids[i]);
    switch (n->type) {
    case RR_TERM:
    case RR_NONTERM:
        n->w = (int)strlen(n->text) + 2;
        n->h = 1;
        n->ey = 0;
        break;
    case RR_SEQ: {
        int w = 0, ey = 0;
        for (int i = 0; i < n->nk; i++) {
            w += n->kids[i]->w;
            if (n->kids[i]->ey > ey) ey = n->kids[i]->ey;
        }
        w += n->nk - 1;
        int h = 0;
        for (int i = 0; i < n->nk; i++) {
            int b = ey - n->kids[i]->ey + n->kids[i]->h;
            if (b > h) h = b;
        }
        n->w = w; n->h = h; n->ey = ey;
        break;
    }
    case RR_ALT: {
        int wmax = 0;
        for (int i = 0; i < n->nk; i++)
            if (n->kids[i]->w > wmax) wmax = n->kids[i]->w;
        int t = 0;
        for (int i = 0; i < n->nk; i++) {
            if (i > 0) t += n->kids[i - 1]->h + 1;
            if (i == n->nk - 1) n->h = t + n->kids[i]->h;
        }
        n->w = wmax + 4;
        n->ey = n->kids[0]->ey;
        break;
    }
    case RR_OPT:
        n->w = n->kids[0]->w + 4;
        n->h = n->kids[0]->h + 2;
        n->ey = 0;
        break;
    case RR_REP:
        n->w = n->kids[0]->w + 4;
        n->h = n->kids[0]->h + 2;
        n->ey = n->kids[0]->ey;
        break;
    }
}

/* ---------- grid drawing ---------- */

typedef struct {
    char *cells;
    int w, h;
} rr_grid_t;

static void rr_put(rr_grid_t *g, int row, int col, char c) {
    if (row < 0 || row >= g->h || col < 0 || col >= g->w) return;
    g->cells[(size_t)row * (size_t)g->w + (size_t)col] = c;
}

static void rr_put_str(rr_grid_t *g, int row, int col, const char *s) {
    for (int i = 0; s[i]; i++) rr_put(g, row, col + i, s[i]);
}

static void rr_fill(rr_grid_t *g, int row, int c0, int c1, char ch) {
    for (int c = c0; c <= c1; c++) rr_put(g, row, c, ch);
}

static void rr_draw(rr_grid_t *g, const rr_node_t *n, int row, int col) {
    switch (n->type) {
    case RR_TERM:
        rr_put(g, row, col, '[');
        rr_put_str(g, row, col + 1, n->text);
        rr_put(g, row, col + n->w - 1, ']');
        break;
    case RR_NONTERM:
        rr_put(g, row, col, '(');
        rr_put_str(g, row, col + 1, n->text);
        rr_put(g, row, col + n->w - 1, ')');
        break;
    case RR_SEQ: {
        int x = col;
        for (int i = 0; i < n->nk; i++) {
            const rr_node_t *k = n->kids[i];
            rr_draw(g, k, row + (n->ey - k->ey), x);
            x += k->w;
            if (i < n->nk - 1) { rr_put(g, row + n->ey, x, '-'); x++; }
        }
        break;
    }
    case RR_ALT: {
        int wmax = n->w - 4;
        int t = row;
        int e_first = -1, e_last = -1;
        for (int i = 0; i < n->nk; i++) {
            const rr_node_t *k = n->kids[i];
            if (i > 0) t += n->kids[i - 1]->h + 1;
            int e = t + k->ey;
            if (e_first < 0) e_first = e;
            e_last = e;
            rr_draw(g, k, t, col + 2);
            rr_put(g, e, col, '+');
            rr_put(g, e, col + 1, '-');
            rr_fill(g, e, col + 2 + k->w, col + 2 + wmax, '-');
            rr_put(g, e, col + n->w - 1, '+');
        }
        for (int r = e_first + 1; r < e_last; r++) {
            rr_put(g, r, col, '|');
            rr_put(g, r, col + n->w - 1, '|');
        }
        break;
    }
    case RR_OPT: {
        const rr_node_t *k = n->kids[0];
        /* skip path on the entry row (top) */
        rr_fill(g, row, col, col + n->w - 1, '-');
        rr_put(g, row, col, '+');
        rr_put(g, row, col + n->w - 1, '+');
        int ek = row + 2 + k->ey;
        rr_draw(g, k, row + 2, col + 2);
        rr_put(g, ek, col, '+');
        rr_put(g, ek, col + 1, '-');
        rr_fill(g, ek, col + 2 + k->w, col + n->w - 2, '-');
        rr_put(g, ek, col + n->w - 1, '+');
        for (int r = row + 1; r < ek; r++) {
            rr_put(g, r, col, '|');
            rr_put(g, r, col + n->w - 1, '|');
        }
        break;
    }
    case RR_REP: {
        const rr_node_t *k = n->kids[0];
        int ek = row + k->ey;
        rr_draw(g, k, row, col + 2);
        rr_put(g, ek, col, '+');
        rr_put(g, ek, col + 1, '-');
        rr_fill(g, ek, col + 2 + k->w, col + n->w - 2, '-');
        rr_put(g, ek, col + n->w - 1, '+');
        int rb = row + n->h - 1;
        for (int r = ek + 1; r < rb; r++) {
            rr_put(g, r, col, '|');
            rr_put(g, r, col + n->w - 1, '|');
        }
        rr_fill(g, rb, col, col + n->w - 1, '-');
        rr_put(g, rb, col, '+');
        rr_put(g, rb, col + n->w - 1, '+');
        rr_put(g, rb, col + n->w / 2, '<');
        break;
    }
    }
}

/* Render one rule body into an sds; caller frees. NULL on size overflow. */
static sds rr_render_node(const rr_node_t *n) {
    if (n->w > RR_MAX_W || n->h > RR_MAX_H) return NULL;
    rr_grid_t g;
    g.w = n->w;
    g.h = n->h;
    g.cells = (char *)malloc((size_t)g.w * (size_t)g.h);
    if (!g.cells) return NULL;
    memset(g.cells, ' ', (size_t)g.w * (size_t)g.h);
    rr_draw(&g, n, 0, 0);
    sds out = sdsempty();
    for (int r = 0; r < g.h; r++) {
        const char *rowp = g.cells + (size_t)r * (size_t)g.w;
        int len = g.w;
        while (len > 0 && rowp[len - 1] == ' ') len--;
        if (r == n->ey) {
            out = sdscat(out, "--");
            out = sdscatlen(out, rowp, len);
            out = sdscat(out, "--");
        } else {
            out = sdscat(out, "  ");
            out = sdscatlen(out, rowp, len);
        }
        out = sdscat(out, "\n");
    }
    free(g.cells);
    return out;
}

/* ---------- tool entry ---------- */

static sds tool_railroad_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "render";
    if (strcmp(action, "render") != 0 && strcmp(action, "validate") != 0) {
        return sdscatprintf(sdsempty(),
            "ERROR: unknown railroad action '%s' (use render/validate)", action);
    }

    const char *grammar = cJSON_GetStringValue(cJSON_GetObjectItem(args, "grammar"));
    if (!grammar) grammar = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    if (!grammar) grammar = cJSON_GetStringValue(cJSON_GetObjectItem(args, "input"));
    if (!grammar) return sdsnew("ERROR: missing required parameter 'grammar' (or 'text')");

    rr_grammar_t g;
    char err[256] = {0};
    int err_line = 0, err_col = 0;
    if (rr_parse_grammar(grammar, &g, err, sizeof(err), &err_line, &err_col) != 0) {
        return sdscatprintf(sdsempty(), "ERROR: parse error at line %d col %d: %s",
                            err_line, err_col, err);
    }

    for (int i = 0; i < g.count; i++) rr_layout(g.rules[i].root);

    if (strcmp(action, "validate") == 0) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "validate");
        cJSON_AddBoolToObject(obj, "valid", 1);
        cJSON_AddNumberToObject(obj, "rule_count", g.count);
        cJSON *names = cJSON_CreateArray();
        for (int i = 0; i < g.count; i++)
            cJSON_AddItemToArray(names, cJSON_CreateString(g.rules[i].name));
        cJSON_AddItemToObject(obj, "rules", names);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js);
        cJSON_Delete(obj);
        rr_grammar_free(&g);
        return res;
    }

    /* render */
    cJSON *rules_arr = cJSON_CreateArray();
    sds text = sdsempty();
    for (int i = 0; i < g.count; i++) {
        rr_rule_t *r = &g.rules[i];
        sds dia = rr_render_node(r->root);
        if (!dia) {
            rr_grammar_free(&g);
            cJSON_Delete(rules_arr);
            sdsfree(text);
            return sdscatprintf(sdsempty(),
                "ERROR: diagram for rule '%s' exceeds %dx%d cells",
                r->name, RR_MAX_W, RR_MAX_H);
        }
        cJSON *ro = cJSON_CreateObject();
        cJSON_AddStringToObject(ro, "name", r->name);
        cJSON_AddNumberToObject(ro, "width", r->root->w);
        cJSON_AddNumberToObject(ro, "height", r->root->h);
        cJSON_AddStringToObject(ro, "diagram", dia);
        cJSON_AddItemToArray(rules_arr, ro);
        text = sdscatprintf(text, "%s:\n%s", r->name, dia);
        if (i < g.count - 1) text = sdscat(text, "\n");
        sdsfree(dia);
    }
    rr_grammar_free(&g);

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "render");
    cJSON_AddNumberToObject(obj, "rule_count", (int)cJSON_GetArraySize(rules_arr));
    cJSON_AddItemToObject(obj, "rules", rules_arr);
    cJSON_AddStringToObject(obj, "text", text);
    sdsfree(text);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    return res;
}

static const alpha_tool_t tool_railroad = {
    .name = "railroad",
    .aliases = {"railroad_diagram", "ebnf_diagram", NULL},
    .category = "generator",
    .description = "ASCII railroad-diagram (syntax diagram) renderer for an EBNF subset, inspired by katef/kgt. Parses rules with terminals ('...' or \"...\"), identifiers, sequence, alternation '|', option '[ ]', repetition '{ }' and grouping '( )', then renders each rule as an ASCII railroad diagram. Strict parse errors with line/col position. Actions: render (default), validate. Pure C11, in-memory only.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"railroad\",\"description\":\"Render EBNF grammar rules as ASCII railroad (syntax) diagrams. Supports terminals in quotes, identifiers, sequence, alternation '|', option '[ ]', repetition '{ }', grouping '( )'. Strict parse errors with position.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"render\",\"validate\"],\"description\":\"render diagrams (default) or validate-only\"},\"grammar\":{\"type\":\"string\",\"description\":\"EBNF grammar text, e.g. \\\"expr = term { '+' term } ;\\\"\"},\"text\":{\"type\":\"string\",\"description\":\"Alias for grammar\"},\"input\":{\"type\":\"string\",\"description\":\"Alias for grammar\"}},\"required\":[\"grammar\"]}}}",
    .run = tool_railroad_run
};
