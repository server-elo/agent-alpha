/* tool_peg_match.c — PackCC-inspired PEG pattern matcher (pure C11) */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PEG_MAX_NODES 512
#define PEG_MAX_PAT 4096
typedef enum { PEG_LIT, PEG_DOT, PEG_CLASS, PEG_SEQ, PEG_CHOICE, PEG_STAR, PEG_PLUS, PEG_QUESTION, PEG_AND, PEG_NOT } peg_kind_t;
typedef struct peg_node { peg_kind_t kind; char *lit; size_t lit_len; unsigned char cls[32]; int cls_neg; struct peg_node *child; struct peg_node *next; } peg_node_t;
typedef struct { peg_node_t pool[PEG_MAX_NODES]; int used; const char *pat; size_t pat_len; size_t pos; char err[128]; } peg_parser_t;

static peg_node_t *peg_new(peg_parser_t *p, peg_kind_t k){ if(p->used>=PEG_MAX_NODES){ snprintf(p->err,sizeof(p->err),"pattern too complex"); return NULL; } peg_node_t *n=&p->pool[p->used++]; memset(n,0,sizeof(*n)); n->kind=k; return n; }
static void peg_skip(peg_parser_t *p){ while(p->pos<p->pat_len && (p->pat[p->pos]==' '||p->pat[p->pos]=='\t'||p->pat[p->pos]=='\n'||p->pat[p->pos]=='\r')) p->pos++; }
static peg_node_t *peg_parse_choice(peg_parser_t *p);
static peg_node_t *peg_parse_seq(peg_parser_t *p);
static peg_node_t *peg_parse_repeat(peg_parser_t *p);
static peg_node_t *peg_parse_prefix(peg_parser_t *p);
static peg_node_t *peg_parse_primary(peg_parser_t *p);

static peg_node_t *peg_parse_choice(peg_parser_t *pp){
    peg_node_t *first = peg_parse_seq(pp);
    if (!first) return NULL;
    peg_skip(pp);
    if (pp->pos < pp->pat_len && pp->pat[pp->pos] == '/') {
        peg_node_t *ch = peg_new(pp, PEG_CHOICE);
        if (!ch) return NULL;
        ch->child = first;
        peg_node_t *curr = first;
        while (pp->pos < pp->pat_len && pp->pat[pp->pos] == '/') {
            pp->pos++;
            peg_skip(pp);
            peg_node_t *nxt = peg_parse_seq(pp);
            if (!nxt){ snprintf(pp->err, sizeof(pp->err), "expected choice branch after /"); return NULL; }
            curr->next = nxt;
            curr = nxt;
            peg_skip(pp);
        }
        return ch;
    }
    return first;
}

static peg_node_t *peg_parse_seq(peg_parser_t *pp){
    peg_node_t *head = peg_parse_repeat(pp);
    if (!head) return NULL;
    peg_node_t *curr = head;
    for (;;) {
        peg_skip(pp);
        if (pp->pos >= pp->pat_len || pp->pat[pp->pos] == '/' || pp->pat[pp->pos] == ')') break;
        peg_node_t *nxt = peg_parse_repeat(pp);
        if (!nxt) break;
        if (head->kind != PEG_SEQ) {
            peg_node_t *s = peg_new(pp, PEG_SEQ);
            if (!s) return NULL;
            s->child = head;
            head = s;
            curr = s->child;
        }
        curr->next = nxt;
        curr = nxt;
    }
    return head;
}

static peg_node_t *peg_parse_repeat(peg_parser_t *pp){
    peg_node_t *n = peg_parse_prefix(pp);
    if (!n) return NULL;
    peg_skip(pp);
    while (pp->pos < pp->pat_len) {
        char c = pp->pat[pp->pos];
        if (c == '*' || c == '+' || c == '?') {
            pp->pos++;
            peg_node_t *r = peg_new(pp, c=='*'?PEG_STAR : (c=='+'?PEG_PLUS : PEG_QUESTION));
            if (!r) return NULL;
            r->child = n;
            n = r;
            peg_skip(pp);
        } else break;
    }
    return n;
}

static peg_node_t *peg_parse_prefix(peg_parser_t *pp){
    peg_skip(pp);
    if (pp->pos < pp->pat_len) {
        char c = pp->pat[pp->pos];
        if (c == '&' || c == '!') {
            pp->pos++;
            peg_node_t *pref = peg_new(pp, c=='&'?PEG_AND : PEG_NOT);
            if (!pref) return NULL;
            pref->child = peg_parse_prefix(pp);
            if (!pref->child){ snprintf(pp->err,sizeof(pp->err),"expected expression after predicate %c", c); return NULL; }
            return pref;
        }
    }
    return peg_parse_primary(pp);
}

static peg_node_t *peg_parse_primary(peg_parser_t *pp){
    peg_skip(pp);
    if (pp->pos >= pp->pat_len){ snprintf(pp->err,sizeof(pp->err),"unexpected end of pattern"); return NULL; }
    char c = pp->pat[pp->pos];
    if (c == '(') {
        pp->pos++;
        peg_node_t *sub = peg_parse_choice(pp);
        peg_skip(pp);
        if (pp->pos >= pp->pat_len || pp->pat[pp->pos] != ')'){ snprintf(pp->err,sizeof(pp->err),"unclosed parenthesis"); return NULL; }
        pp->pos++;
        return sub;
    }
    if (c == '.') {
        pp->pos++;
        return peg_new(pp, PEG_DOT);
    }
    if (c == '"' || c == '\'') {
        char quote = c;
        pp->pos++;
        size_t st = pp->pos;
        while (pp->pos < pp->pat_len && pp->pat[pp->pos] != quote) {
            if (pp->pat[pp->pos] == '\\' && pp->pos + 1 < pp->pat_len) pp->pos += 2;
            else pp->pos++;
        }
        if (pp->pos >= pp->pat_len){ snprintf(pp->err,sizeof(pp->err),"unterminated string literal"); return NULL; }
        size_t len = pp->pos - st;
        char *lit = malloc(len + 1);
        size_t out_len = 0;
        for (size_t i = st; i < pp->pos; i++) {
            if (pp->pat[i] == '\\' && i + 1 < pp->pos) {
                i++;
                char esc = pp->pat[i];
                if (esc == 'n') lit[out_len++] = '\n';
                else if (esc == 't') lit[out_len++] = '\t';
                else if (esc == 'r') lit[out_len++] = '\r';
                else lit[out_len++] = esc;
            } else lit[out_len++] = pp->pat[i];
        }
        lit[out_len] = '\0';
        pp->pos++;
        peg_node_t *n = peg_new(pp, PEG_LIT);
        if (!n){ free(lit); return NULL; }
        n->lit = lit;
        n->lit_len = out_len;
        return n;
    }
    if (c == '[') {
        pp->pos++;
        peg_node_t *n = peg_new(pp, PEG_CLASS);
        if (!n) return NULL;
        if (pp->pos < pp->pat_len && pp->pat[pp->pos] == '^') { n->cls_neg = 1; pp->pos++; }
        while (pp->pos < pp->pat_len && pp->pat[pp->pos] != ']') {
            unsigned char c1 = (unsigned char)pp->pat[pp->pos++];
            if (c1 == '\\' && pp->pos < pp->pat_len) c1 = (unsigned char)pp->pat[pp->pos++];
            if (pp->pos + 1 < pp->pat_len && pp->pat[pp->pos] == '-' && pp->pat[pp->pos+1] != ']') {
                pp->pos++;
                unsigned char c2 = (unsigned char)pp->pat[pp->pos++];
                if (c2 == '\\' && pp->pos < pp->pat_len) c2 = (unsigned char)pp->pat[pp->pos++];
                for (int ch = c1; ch <= c2; ch++) n->cls[ch / 8] |= (1 << (ch % 8));
            } else {
                n->cls[c1 / 8] |= (1 << (c1 % 8));
            }
        }
        if (pp->pos >= pp->pat_len || pp->pat[pp->pos] != ']'){ snprintf(pp->err,sizeof(pp->err),"unclosed character class"); return NULL; }
        pp->pos++;
        return n;
    }
    snprintf(pp->err,sizeof(pp->err),"unexpected character '%c' in pattern", c);
    return NULL;
}

static int peg_match_node(peg_node_t *n, const char *inp, size_t ilen, size_t *pos){
    if (!n) return 1;
    switch(n->kind){
        case PEG_LIT:
            if (*pos + n->lit_len > ilen) return 0;
            if (memcmp(inp + *pos, n->lit, n->lit_len) != 0) return 0;
            *pos += n->lit_len;
            return 1;
        case PEG_DOT:
            if (*pos >= ilen) return 0;
            (*pos)++;
            return 1;
        case PEG_CLASS: {
            if (*pos >= ilen) return 0;
            unsigned char ch = (unsigned char)inp[*pos];
            int in_set = (n->cls[ch / 8] & (1 << (ch % 8))) != 0;
            if (n->cls_neg) in_set = !in_set;
            if (!in_set) return 0;
            (*pos)++;
            return 1;
        }
        case PEG_SEQ:
            for(peg_node_t *c=n->child;c;c=c->next){ if(!peg_match_node(c,inp,ilen,pos)) return 0; } return 1;
        case PEG_CHOICE:
            for(peg_node_t *alt=n->child;alt;alt=alt->next){ size_t save=*pos; if(peg_match_node(alt,inp,ilen,pos)) return 1; *pos=save; } return 0;
        case PEG_STAR:
            while(1){ size_t save=*pos; if(!peg_match_node(n->child,inp,ilen,pos)){ *pos=save; break; } if(*pos==save) break; if(*pos>=ilen) break; } return 1;
        case PEG_PLUS: {
            if(!peg_match_node(n->child,inp,ilen,pos)) return 0; while(1){ size_t save=*pos; if(!peg_match_node(n->child,inp,ilen,pos)){ *pos=save; break; } if(*pos==save) break; } return 1;
        }
        case PEG_QUESTION: { size_t save=*pos; if(!peg_match_node(n->child,inp,ilen,pos)) *pos=save; return 1; }
        case PEG_AND: { size_t save=*pos; int ok=peg_match_node(n->child,inp,ilen,&save); (void)ok; return ok; }
        case PEG_NOT: { size_t save=*pos; int ok=peg_match_node(n->child,inp,ilen,&save); return !ok; }
    }
    return 0;
}
static void peg_free_lits(peg_parser_t *pp){ for(int i=0;i<pp->used;i++) if(pp->pool[i].kind==PEG_LIT && pp->pool[i].lit && pp->pool[i].lit_len>0) free(pp->pool[i].lit); }

static sds tool_peg_match_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *pattern = cJSON_GetStringValue(cJSON_GetObjectItem(args, "pattern"));
    const char *input = cJSON_GetStringValue(cJSON_GetObjectItem(args, "input"));
    cJSON *st_item = cJSON_GetObjectItem(args, "start");
    int start_pos = st_item ? (int)st_item->valuedouble : 0;
    if (!pattern) return sdsnew("ERROR: pattern required");
    if (!input) return sdsnew("ERROR: input required");
    if (start_pos < 0) return sdsnew("ERROR: start must be >= 0");
    size_t inp_len = strlen(input);
    if ((size_t)start_pos > inp_len) return sdsnew("ERROR: start exceeds input length");

    peg_parser_t pp;
    memset(&pp, 0, sizeof(pp));
    pp.pat = pattern;
    pp.pat_len = strlen(pattern);

    peg_node_t *root = peg_parse_choice(&pp);
    peg_skip(&pp);
    if (!root || pp.err[0] || pp.pos < pp.pat_len) {
        char emsg[256];
        snprintf(emsg, sizeof(emsg), "ERROR in PEG pattern: %s (pos %zu)", pp.err[0]?pp.err:"unexpected trailing syntax", pp.pos);
        peg_free_lits(&pp);
        return sdsnew(emsg);
    }

    size_t pos = (size_t)start_pos;
    int ok = peg_match_node(root, input, inp_len, &pos);
    size_t matched_len = ok ? (pos - start_pos) : 0;
    char *matched_text = NULL;
    if (ok && matched_len > 0) {
        matched_text = malloc(matched_len + 1);
        memcpy(matched_text, input + start_pos, matched_len);
        matched_text[matched_len] = '\0';
    }

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "matched", ok ? 1 : 0);
    cJSON_AddNumberToObject(obj, "start", (double)start_pos);
    cJSON_AddNumberToObject(obj, "end", (double)pos);
    cJSON_AddNumberToObject(obj, "length", (double)matched_len);
    if (matched_text) { cJSON_AddStringToObject(obj, "text", matched_text); free(matched_text); }
    else cJSON_AddStringToObject(obj, "text", ok ? "" : "");
    char *js2 = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js2 ? js2 : "{}");
    free(js2); cJSON_Delete(obj); peg_free_lits(&pp);
    return res;
}

static const alpha_tool_t tool_peg_match = {
    .name = "peg_match",
    .aliases = {"peg", "packcc_match", NULL},
    .category = "parsing",
    .description = "PackCC-inspired PEG pattern matcher (pure C). PEG ops: quoted string literals, [a-z] and [^...] char classes, . any char, / ordered choice, adjacency sequence, * + ? repetition, ! and & predicates, () grouping. Returns matched, length, text, end.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"peg_match\",\"description\":\"PackCC-inspired PEG pattern matcher (pure C). PEG ops: quoted string literals, [a-z] and [^...] char classes, . any char, / ordered choice, adjacency sequence, * + ? repetition, ! and & predicates, () grouping. Returns matched, length, text, end.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\",\"description\":\"PEG expression\"},\"input\":{\"type\":\"string\"},\"start\":{\"type\":\"integer\"}},\"required\":[\"pattern\",\"input\"]}}}",
    .run = tool_peg_match_run
};
