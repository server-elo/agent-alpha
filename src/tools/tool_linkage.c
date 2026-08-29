/* tool_linkage.c — Pure-C simplified link-grammar planar linkage validator
 * Inspired by opencog/link-grammar.
 *
 * Given a small connector dictionary (word -> disjuncts, each a pair of
 * left/right connector name lists) and a sentence, decide whether a valid
 * planar linkage exists and, if so, return one.
 *
 * Simplified link-grammar rules enforced:
 *   1. Satisfaction: every connector of every chosen disjunct is matched by
 *      a link to a same-named connector of opposite direction; right
 *      connectors of word i only match left connectors of words j > i.
 *   2. Planarity: no two links cross.
 *   3. Exclusion: no two links join the same pair of words.
 *   4. Ordering: each list is nearest-first; a word's right links land on
 *      strictly increasing positions, its left links on strictly decreasing
 *      positions (in list order).
 *   5. Connectivity: all words form a single connected component.
 *
 * Algorithm: exhaustive backtracking — choose one disjunct per word, then
 * match right-connector instances to later left-connector instances with an
 * incremental planarity check. Strict limits keep the search tiny and exact.
 * No I/O, no external deps beyond cJSON/sds.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define LG_MAX_WORDS     12   /* sentence length limit */
#define LG_MAX_DICT      64   /* dictionary entries (disjuncts) */
#define LG_MAX_CONNS      8   /* connectors per side per disjunct */
#define LG_MAX_CONN_NAME 32   /* connector name length (incl NUL) */
#define LG_MAX_WORD_LEN  48   /* word length (incl NUL) */
#define LG_MAX_LINKS     (LG_MAX_WORDS * LG_MAX_CONNS)
#define LG_BUDGET      500000 /* search node budget */

typedef struct {
    char word[LG_MAX_WORD_LEN];
    int  n_left, n_right;
    char left[LG_MAX_CONNS][LG_MAX_CONN_NAME];
    char right[LG_MAX_CONNS][LG_MAX_CONN_NAME];
} lg_disj_t;

typedef struct {
    lg_disj_t dict[LG_MAX_DICT];
    int       n_dict;
    char      words[LG_MAX_WORDS][LG_MAX_WORD_LEN];
    int       n_words;
    /* per-word candidate disjunct indices (words may repeat in dict) */
    int       cand[LG_MAX_WORDS][LG_MAX_DICT];
    int       n_cand[LG_MAX_WORDS];
    int       choice[LG_MAX_WORDS];       /* chosen dict index per word */
    /* link state */
    int       link_a[LG_MAX_LINKS];       /* left word index */
    int       link_b[LG_MAX_LINKS];       /* right word index */
    int       n_links;
    /* right-connector instance target word; left-connector instance source */
    int       rtgt[LG_MAX_WORDS][LG_MAX_CONNS];
    int       lsrc[LG_MAX_WORDS][LG_MAX_CONNS];
    int       lused[LG_MAX_WORDS][LG_MAX_CONNS];
    long      budget;
} lg_ctx_t;

/* Connector names: alnum plus a few link-grammar-ish punct chars. */
static int lg_valid_conn_name(const char *s) {
    if (!s || !s[0]) return 0;
    size_t len = strlen(s);
    if (len >= LG_MAX_CONN_NAME) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.' &&
            c != '@' && c != '*' && c != '+')
            return 0;
    }
    return 1;
}

static int lg_valid_word(const char *s) {
    if (!s || !s[0]) return 0;
    size_t len = strlen(s);
    if (len >= LG_MAX_WORD_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        if (isspace((unsigned char)s[i])) return 0;
    }
    return 1;
}

/* Does new link (a,b), a<b, cross an existing link? */
static int lg_crosses(const lg_ctx_t *c, int a, int b) {
    for (int i = 0; i < c->n_links; i++) {
        int x = c->link_a[i], y = c->link_b[i];
        if (x == a && y == b) return 2; /* duplicate pair (exclusion) */
        if ((x < a && a < y && y < b) || (a < x && x < b && b < y)) return 1;
    }
    return 0;
}

/* Union-find over words for the connectivity check. */
static int lg_uf_find(int *parent, int x) {
    while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
    return x;
}

static int lg_connected(lg_ctx_t *c) {
    int parent[LG_MAX_WORDS];
    for (int i = 0; i < c->n_words; i++) parent[i] = i;
    for (int i = 0; i < c->n_links; i++) {
        int ra = lg_uf_find(parent, c->link_a[i]);
        int rb = lg_uf_find(parent, c->link_b[i]);
        if (ra != rb) parent[ra] = rb;
    }
    int root = lg_uf_find(parent, 0);
    for (int i = 1; i < c->n_words; i++)
        if (lg_uf_find(parent, i) != root) return 0;
    return 1;
}

/* Count total right/left connector instances under current disjunct choices. */
static void lg_conn_totals(const lg_ctx_t *c, int *n_right, int *n_left) {
    int nr = 0, nl = 0;
    for (int w = 0; w < c->n_words; w++) {
        const lg_disj_t *d = &c->dict[c->choice[w]];
        nr += d->n_right;
        nl += d->n_left;
    }
    *n_right = nr;
    *n_left = nl;
}

/* Matching phase: right-connector instances are visited in (word, index)
 * order; rinst is the ordinal of the next instance to assign. Returns
 * 1 = linkage found, 0 = none, -1 = budget exhausted. */
static int lg_match(lg_ctx_t *c, int rinst) {
    if (--c->budget <= 0) return -1;

    /* Locate the rinst-th right-connector instance. */
    int w = -1, k = -1, seen = 0;
    for (int i = 0; i < c->n_words; i++) {
        const lg_disj_t *d = &c->dict[c->choice[i]];
        for (int j = 0; j < d->n_right; j++) {
            if (seen == rinst) { w = i; k = j; goto found; }
            seen++;
        }
    }
found:
    if (w < 0) {
        /* All right connectors assigned; left counts matched already. */
        return lg_connected(c) ? 1 : 0;
    }
    const lg_disj_t *d = &c->dict[c->choice[w]];
    const char *name = d->right[k];

    for (int j = w + 1; j < c->n_words; j++) {
        const lg_disj_t *dj = &c->dict[c->choice[j]];
        for (int m = 0; m < dj->n_left; m++) {
            if (c->lused[j][m]) continue;
            if (strcmp(dj->left[m], name) != 0) continue;
            /* Ordering: right targets of w strictly increasing. */
            if (k > 0 && c->rtgt[w][k - 1] >= j) continue;
            /* Ordering: left sources of j strictly decreasing in list order. */
            int bad = 0;
            for (int p = 0; p < dj->n_left; p++) {
                if (!c->lused[j][p] || p == m) continue;
                if (p < m && c->lsrc[j][p] <= w) { bad = 1; break; }
                if (p > m && c->lsrc[j][p] >= w) { bad = 1; break; }
            }
            if (bad) continue;
            int cr = lg_crosses(c, w, j);
            if (cr != 0) continue;

            /* Commit link (w,j). */
            c->link_a[c->n_links] = w;
            c->link_b[c->n_links] = j;
            c->n_links++;
            c->lused[j][m] = 1;
            c->lsrc[j][m] = w;
            c->rtgt[w][k] = j;

            int r = lg_match(c, rinst + 1);
            if (r != 0) return r; /* found or budget exhausted */

            /* Undo. */
            c->n_links--;
            c->lused[j][m] = 0;
            c->lsrc[j][m] = -1;
            c->rtgt[w][k] = -1;
        }
    }
    return 0;
}

/* Disjunct-choice phase: pick one dictionary entry per word. */
static int lg_choose(lg_ctx_t *c, int w) {
    if (--c->budget <= 0) return -1;
    if (w == c->n_words) {
        int nr, nl;
        lg_conn_totals(c, &nr, &nl);
        if (nr != nl) return 0; /* counts must balance to satisfy all */
        memset(c->lused, 0, sizeof(c->lused));
        for (int i = 0; i < c->n_words; i++) {
            for (int j = 0; j < LG_MAX_CONNS; j++) {
                c->rtgt[i][j] = -1;
                c->lsrc[i][j] = -1;
            }
        }
        c->n_links = 0;
        return lg_match(c, 0);
    }
    for (int i = 0; i < c->n_cand[w]; i++) {
        c->choice[w] = c->cand[w][i];
        int r = lg_choose(c, w + 1);
        if (r != 0) return r;
    }
    c->choice[w] = -1;
    return 0;
}

/* Parse a connector-name array member ("left"/"right") of a dict entry. */
static sds lg_parse_conn_list(cJSON *arr, char out[][LG_MAX_CONN_NAME],
                              int *n_out, const char *word, const char *side) {
    *n_out = 0;
    if (!arr) return NULL; /* absent = empty list */
    if (!cJSON_IsArray(arr))
        return sdscatprintf(sdsempty(), "ERROR: '%s' of word '%s' must be an array", side, word);
    int n = cJSON_GetArraySize(arr);
    if (n > LG_MAX_CONNS)
        return sdscatprintf(sdsempty(), "ERROR: word '%s' has too many %s connectors (max %d)",
                            word, side, LG_MAX_CONNS);
    for (int i = 0; i < n; i++) {
        cJSON *e = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsString(e) || !lg_valid_conn_name(e->valuestring))
            return sdscatprintf(sdsempty(), "ERROR: invalid %s connector name in word '%s'", side, word);
        strncpy(out[i], e->valuestring, LG_MAX_CONN_NAME - 1);
        out[i][LG_MAX_CONN_NAME - 1] = '\0';
    }
    *n_out = n;
    return NULL;
}

static sds tool_linkage_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "validate";
    if (strcmp(action, "validate") != 0 && strcmp(action, "check") != 0 &&
        strcmp(action, "parse") != 0)
        return sdscatprintf(sdsempty(), "ERROR: unknown linkage action '%s' (use validate)", action);

    /* --- dictionary --- */
    cJSON *dict = cJSON_GetObjectItem(args, "dictionary");
    if (!dict) dict = cJSON_GetObjectItem(args, "dict");
    if (!cJSON_IsArray(dict))
        return sdsnew("ERROR: 'dictionary' array of {word,left,right} entries is required");
    lg_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.n_dict = cJSON_GetArraySize(dict);
    if (ctx.n_dict == 0)
        return sdsnew("ERROR: 'dictionary' must be non-empty");
    if (ctx.n_dict > LG_MAX_DICT)
        return sdscatprintf(sdsempty(), "ERROR: dictionary too large (max %d entries)", LG_MAX_DICT);
    for (int i = 0; i < ctx.n_dict; i++) {
        cJSON *e = cJSON_GetArrayItem(dict, i);
        if (!cJSON_IsObject(e))
            return sdscatprintf(sdsempty(), "ERROR: dictionary entry %d is not an object", i);
        const char *word = cJSON_GetStringValue(cJSON_GetObjectItem(e, "word"));
        if (!lg_valid_word(word))
            return sdscatprintf(sdsempty(), "ERROR: dictionary entry %d has a missing/invalid 'word'", i);
        lg_disj_t *d = &ctx.dict[i];
        strncpy(d->word, word, LG_MAX_WORD_LEN - 1);
        d->word[LG_MAX_WORD_LEN - 1] = '\0';
        sds err = lg_parse_conn_list(cJSON_GetObjectItem(e, "left"),
                                     d->left, &d->n_left, d->word, "left");
        if (err) return err;
        err = lg_parse_conn_list(cJSON_GetObjectItem(e, "right"),
                                 d->right, &d->n_right, d->word, "right");
        if (err) return err;
    }

    /* --- sentence: array of words or a whitespace-separated string --- */
    cJSON *sent = cJSON_GetObjectItem(args, "sentence");
    if (!sent) sent = cJSON_GetObjectItem(args, "words");
    if (cJSON_IsString(sent) && sent->valuestring) {
        char buf[1024];
        if (strlen(sent->valuestring) >= sizeof(buf))
            return sdsnew("ERROR: sentence string too long");
        strncpy(buf, sent->valuestring, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *save = NULL;
        char *tok = strtok_r(buf, " \t\r\n", &save);
        while (tok) {
            if (ctx.n_words >= LG_MAX_WORDS)
                return sdscatprintf(sdsempty(), "ERROR: sentence too long (max %d words)", LG_MAX_WORDS);
            strncpy(ctx.words[ctx.n_words], tok, LG_MAX_WORD_LEN - 1);
            ctx.words[ctx.n_words][LG_MAX_WORD_LEN - 1] = '\0';
            ctx.n_words++;
            tok = strtok_r(NULL, " \t\r\n", &save);
        }
    } else if (cJSON_IsArray(sent)) {
        int n = cJSON_GetArraySize(sent);
        if (n > LG_MAX_WORDS)
            return sdscatprintf(sdsempty(), "ERROR: sentence too long (max %d words)", LG_MAX_WORDS);
        for (int i = 0; i < n; i++) {
            cJSON *e = cJSON_GetArrayItem(sent, i);
            if (!cJSON_IsString(e) || !lg_valid_word(e->valuestring))
                return sdscatprintf(sdsempty(), "ERROR: sentence word %d is not a valid word string", i);
            strncpy(ctx.words[ctx.n_words], e->valuestring, LG_MAX_WORD_LEN - 1);
            ctx.words[ctx.n_words][LG_MAX_WORD_LEN - 1] = '\0';
            ctx.n_words++;
        }
    } else {
        return sdsnew("ERROR: 'sentence' (string or array of words) is required");
    }
    if (ctx.n_words == 0)
        return sdsnew("ERROR: sentence is empty");

    /* --- candidate disjuncts per word --- */
    for (int w = 0; w < ctx.n_words; w++) {
        ctx.n_cand[w] = 0;
        ctx.choice[w] = -1;
        for (int i = 0; i < ctx.n_dict; i++) {
            if (strcmp(ctx.dict[i].word, ctx.words[w]) == 0)
                ctx.cand[w][ctx.n_cand[w]++] = i;
        }
        if (ctx.n_cand[w] == 0) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "action", "validate");
            cJSON_AddBoolToObject(obj, "valid", 0);
            cJSON_AddStringToObject(obj, "reason", "word not in dictionary");
            cJSON_AddStringToObject(obj, "word", ctx.words[w]);
            cJSON_AddNumberToObject(obj, "position", w);
            char *js = cJSON_PrintUnformatted(obj);
            sds res = sdsnew(js ? js : "{}");
            free(js); cJSON_Delete(obj);
            return res;
        }
    }

    /* --- exact backtracking search --- */
    ctx.budget = LG_BUDGET;
    int r = lg_choose(&ctx, 0);
    if (r < 0)
        return sdsnew("ERROR: search budget exceeded; sentence/dictionary too complex for this validator");

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "validate");
    cJSON_AddNumberToObject(obj, "word_count", ctx.n_words);
    cJSON *warr = cJSON_CreateArray();
    for (int w = 0; w < ctx.n_words; w++)
        cJSON_AddItemToArray(warr, cJSON_CreateString(ctx.words[w]));
    cJSON_AddItemToObject(obj, "words", warr);
    if (r == 1) {
        cJSON_AddBoolToObject(obj, "valid", 1);
        cJSON_AddNumberToObject(obj, "link_count", ctx.n_links);
        cJSON *links = cJSON_CreateArray();
        for (int i = 0; i < ctx.n_links; i++) {
            int a = ctx.link_a[i], b = ctx.link_b[i];
            /* Recover the connector name: the right connector of a whose
             * target is b (there is exactly one, by exclusion). */
            const char *cname = "?";
            const lg_disj_t *da = &ctx.dict[ctx.choice[a]];
            for (int k = 0; k < da->n_right; k++)
                if (ctx.rtgt[a][k] == b) { cname = da->right[k]; break; }
            cJSON *ln = cJSON_CreateObject();
            cJSON_AddNumberToObject(ln, "left", a);
            cJSON_AddNumberToObject(ln, "right", b);
            cJSON_AddStringToObject(ln, "left_word", ctx.words[a]);
            cJSON_AddStringToObject(ln, "right_word", ctx.words[b]);
            cJSON_AddStringToObject(ln, "connector", cname);
            cJSON_AddItemToArray(links, ln);
        }
        cJSON_AddItemToObject(obj, "links", links);
    } else {
        cJSON_AddBoolToObject(obj, "valid", 0);
        cJSON_AddStringToObject(obj, "reason",
            "no planar linkage satisfies all connectors (satisfaction, ordering, exclusion, connectivity)");
        cJSON_AddItemToObject(obj, "links", cJSON_CreateArray());
    }
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js); cJSON_Delete(obj);
    return res;
}

static const alpha_tool_t tool_linkage = {
    .name = "linkage",
    .aliases = {"linkgrammar", "link_grammar", NULL},
    .category = "codec",
    .description = "Simplified link-grammar planar linkage validator (pure C): given a connector dictionary (word -> left/right connector lists; repeated words = alternative disjuncts) and a sentence, decides by exact backtracking whether a valid linkage exists — connector satisfaction, planarity (no crossing links), exclusion, ordering, connectivity — and returns the links or a clear failure reason.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"linkage\",\"description\":\"Validate a sentence against a small link-grammar connector dictionary; returns a planar linkage or a failure reason.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"validate\"],\"description\":\"Operation (default validate)\"},\"dictionary\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"word\":{\"type\":\"string\"},\"left\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},\"right\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}},\"required\":[\"word\"]},\"description\":\"Connector dictionary; repeat a word for alternative disjuncts. Connector lists are nearest-first.\"},\"sentence\":{\"type\":\"string\",\"description\":\"Sentence as a whitespace-separated string or an array of word strings (max 12 words)\"}}},\"required\":[\"dictionary\",\"sentence\"]}}",
    .run = tool_linkage_run
};
