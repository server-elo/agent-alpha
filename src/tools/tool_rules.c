/* tool_rules.c — Tasmota-style rules evaluator (arendst/Tasmota domain)
 *
 * Evaluates rules of the form:
 *     ON <trigger> DO <command>[; <command>...] [ENDON]
 * where <trigger> is an event name with an optional '#field' selector and an
 * optional comparison against a number or string:
 *     ON System#Boot DO Power1 1 ENDON
 *     ON DHT11#Temperature>25 DO Power1 1; Publish stat/fan/speed 2 ENDON
 *     ON Power1#State==1 DO Power2 0 ENDON
 * Operators: == != >= <= > < (bare '=' accepted as equality, Tasmota style).
 * Trigger/event key matching is case-insensitive (Tasmota triggers are).
 * One rule per line; blank lines are skipped; anything else is a strict
 * parse error. Pure C11, in-memory only, no I/O.
 *
 * Actions: parse (validate + dump structure), eval (fire against an event).
 */
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>

#define TR_MAX_RULES    64
#define TR_MAX_LINE     1024
#define TR_MAX_CMDS     16
#define TR_MAX_CMD_LEN  256
#define TR_MAX_NAME     64
#define TR_MAX_STR      128

typedef enum {
    TR_OP_NONE = 0, /* presence trigger: event exists */
    TR_OP_EQ, TR_OP_NE, TR_OP_GT, TR_OP_LT, TR_OP_GE, TR_OP_LE
} tr_op_t;

typedef struct {
    int    line;
    char   name[TR_MAX_NAME];   /* trigger event name, e.g. "DHT11" */
    char   field[TR_MAX_NAME];  /* selector after '#', e.g. "Temperature" */
    int    has_field;
    tr_op_t op;
    int    rhs_numeric;         /* 1 if RHS parsed as a finite number */
    double rhs_num;
    char   rhs_str[TR_MAX_STR]; /* raw RHS token (string compare for ==/!=) */
    int    ncmds;
    char   cmds[TR_MAX_CMDS][TR_MAX_CMD_LEN];
} tr_rule_t;

static const char *tr_op_str(tr_op_t op) {
    switch (op) {
        case TR_OP_EQ: return "==";
        case TR_OP_NE: return "!=";
        case TR_OP_GT: return ">";
        case TR_OP_LT: return "<";
        case TR_OP_GE: return ">=";
        case TR_OP_LE: return "<=";
        default: return NULL; /* presence trigger */
    }
}

/* Strict number parse: whole token must be a finite double; ERANGE
 * (overflow like 1e999, underflow like 1e-999) and inf/nan are rejected. */
static int tr_parse_number(const char *s, double *out) {
    if (!s || !*s) return 0;
    errno = 0;
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == s || !end || *end != '\0') return 0;
    if (errno == ERANGE) return 0;
    if (!isfinite(v)) return 0;
    *out = v;
    return 1;
}

static void tr_trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
}

/* Does s start with word w followed by whitespace or end-of-string? */
static int tr_starts_word(const char *s, const char *w) {
    size_t n = strlen(w);
    if (strncasecmp(s, w, n) != 0) return 0;
    return s[n] == '\0' || isspace((unsigned char)s[n]);
}

/* Trigger name/field charset: alnum, '_', '-', '.' (Tasmota identifiers). */
static int tr_valid_ident(const char *s) {
    if (!s || !*s) return 0;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.') return 0;
    }
    return 1;
}

/* Parse one trigger token (no whitespace), e.g. "DHT11#Temperature>25".
 * Returns 0 on success, or sets *err and returns -1. */
static int tr_parse_trigger(const char *tok, int line, tr_rule_t *r, sds *err) {
    memset(r->name, 0, sizeof(r->name));
    memset(r->field, 0, sizeof(r->field));
    r->has_field = 0;
    r->op = TR_OP_NONE;
    r->rhs_numeric = 0;
    r->rhs_num = 0.0;
    r->rhs_str[0] = '\0';

    /* locate the comparison operator: first of '=', '!', '>', '<' */
    const char *op_at = NULL;
    for (const char *p = tok; *p; p++) {
        if (*p == '=' || *p == '!' || *p == '>' || *p == '<') { op_at = p; break; }
    }
    char ident[TR_MAX_NAME * 2];
    size_t idlen = op_at ? (size_t)(op_at - tok) : strlen(tok);
    if (idlen == 0) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: empty trigger name", line);
        return -1;
    }
    if (idlen >= sizeof(ident)) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: trigger name too long", line);
        return -1;
    }
    memcpy(ident, tok, idlen);
    ident[idlen] = '\0';

    /* split optional '#field' selector (at most one '#') */
    char *hash = strchr(ident, '#');
    if (hash) {
        *hash = '\0';
        const char *fld = hash + 1;
        if (strchr(fld, '#')) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: too many '#' in trigger '%s'", line, tok);
            return -1;
        }
        if (strlen(fld) >= TR_MAX_NAME) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: trigger field too long", line);
            return -1;
        }
        if (!tr_valid_ident(fld)) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: invalid trigger field '%s'", line, fld);
            return -1;
        }
        strcpy(r->field, fld);
        r->has_field = 1;
    }
    if (strlen(ident) >= TR_MAX_NAME) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: trigger name too long", line);
        return -1;
    }
    if (!tr_valid_ident(ident)) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: invalid trigger name '%s'", line, ident);
        return -1;
    }
    strcpy(r->name, ident);

    if (!op_at) return 0; /* presence trigger */

    /* parse operator (two-char first) */
    const char *rhs = op_at;
    if (op_at[0] == '=' && op_at[1] == '=') { r->op = TR_OP_EQ; rhs = op_at + 2; }
    else if (op_at[0] == '!' && op_at[1] == '=') { r->op = TR_OP_NE; rhs = op_at + 2; }
    else if (op_at[0] == '>' && op_at[1] == '=') { r->op = TR_OP_GE; rhs = op_at + 2; }
    else if (op_at[0] == '<' && op_at[1] == '=') { r->op = TR_OP_LE; rhs = op_at + 2; }
    else if (op_at[0] == '>') { r->op = TR_OP_GT; rhs = op_at + 1; }
    else if (op_at[0] == '<') { r->op = TR_OP_LT; rhs = op_at + 1; }
    else if (op_at[0] == '=') { r->op = TR_OP_EQ; rhs = op_at + 1; } /* Tasmota '=' alias */
    else {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: bad operator in trigger '%s'", line, tok);
        return -1;
    }
    if (!*rhs) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: missing value after operator in trigger '%s'", line, tok);
        return -1;
    }
    if (strlen(rhs) >= TR_MAX_STR) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: trigger value too long", line);
        return -1;
    }
    strcpy(r->rhs_str, rhs);
    r->rhs_numeric = tr_parse_number(rhs, &r->rhs_num);
    if (!r->rhs_numeric && r->op != TR_OP_EQ && r->op != TR_OP_NE) {
        if (err) *err = sdscatprintf(sdsempty(),
            "ERROR: line %d: relational operator requires a numeric value, got '%s'", line, rhs);
        return -1;
    }
    return 0;
}

/* Parse one rule line. *err set on failure. */
static int tr_parse_line(char *line, int lineno, tr_rule_t *r, sds *err) {
    tr_trim(line);
    r->line = lineno;
    r->ncmds = 0;

    if (!tr_starts_word(line, "ON")) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: rule must start with 'ON', got '%s'", lineno, line);
        return -1;
    }
    char *p = line + 2;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: missing trigger after 'ON'", lineno);
        return -1;
    }
    /* trigger token: up to next whitespace */
    char *ws = p;
    while (*ws && !isspace((unsigned char)*ws)) ws++;
    char tok[TR_MAX_NAME * 2 + TR_MAX_STR];
    size_t tlen = (size_t)(ws - p);
    if (tlen >= sizeof(tok)) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: trigger token too long", lineno);
        return -1;
    }
    memcpy(tok, p, tlen);
    tok[tlen] = '\0';
    p = ws;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!tr_starts_word(p, "DO")) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: expected 'DO' after trigger '%s'", lineno, tok);
        return -1;
    }
    p += 2;
    if (*p && !isspace((unsigned char)*p)) {
        /* tr_starts_word already guarantees boundary, but keep defensive */
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: expected whitespace after 'DO'", lineno);
        return -1;
    }
    while (*p && isspace((unsigned char)*p)) p++;

    /* strip a trailing whole-word 'ENDON' (Tasmota rule terminator) */
    size_t rest = strlen(p);
    if (rest >= 5 && strncasecmp(p + rest - 5, "ENDON", 5) == 0 &&
        (rest == 5 || isspace((unsigned char)p[rest - 6]))) {
        p[rest - 5] = '\0';
    }
    tr_trim(p);
    if (!*p) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: no commands after 'DO'", lineno);
        return -1;
    }
    if (tr_parse_trigger(tok, lineno, r, err) != 0) return -1;

    /* commands separated by ';' (Tasmota Backlog style), each non-empty.
     * Manual split: strtok collapses ';' runs so "a;;b" reached us as "a;b"
     * and the empty-command check below could never fire. */
    for (;;) {
        char *semi = strchr(p, ';');
        size_t l = semi ? (size_t)(semi - p) : strlen(p);
        if (l >= TR_MAX_CMD_LEN) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: command too long (max %d chars)", lineno, TR_MAX_CMD_LEN - 1);
            return -1;
        }
        char cbuf[TR_MAX_CMD_LEN];
        memcpy(cbuf, p, l);
        cbuf[l] = '\0';
        tr_trim(cbuf);
        if (!*cbuf) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: empty command (stray ';')", lineno);
            return -1;
        }
        if (r->ncmds >= TR_MAX_CMDS) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: too many commands (max %d)", lineno, TR_MAX_CMDS);
            return -1;
        }
        strcpy(r->cmds[r->ncmds++], cbuf);
        if (!semi) break;
        p = semi + 1;
    }
    if (r->ncmds == 0) {
        if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: no commands", lineno);
        return -1;
    }
    return 0;
}

/* Parse rules text into out[] (cap TR_MAX_RULES). Returns rule count or -1. */
static int tr_parse_rules(const char *text, tr_rule_t *out, sds *err) {
    if (!text) {
        if (err) *err = sdsnew("ERROR: 'rules' text is required");
        return -1;
    }
    if (!*text) {
        if (err) *err = sdsnew("ERROR: 'rules' text is empty");
        return -1;
    }
    size_t len = strlen(text);
    if (len > (size_t)TR_MAX_RULES * TR_MAX_LINE) {
        if (err) *err = sdsnew("ERROR: rules text too large");
        return -1;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        if (err) *err = sdsnew("ERROR: out of memory");
        return -1;
    }
    memcpy(buf, text, len + 1);
    int n = 0, lineno = 0, rc = 0;
    /* Manual split: strtok collapses '\n' runs so blank lines would shift
     * the 1-based source line numbers we report in errors and JSON. */
    for (char *ln = buf; ; lineno++) {
        char *nl = strchr(ln, '\n');
        size_t l = nl ? (size_t)(nl - ln) : strlen(ln);
        if (l > 0 && ln[l - 1] == '\r') l--;
        if (l >= TR_MAX_LINE) {
            if (err) *err = sdscatprintf(sdsempty(), "ERROR: line %d: rule too long (max %d chars)", lineno + 1, TR_MAX_LINE - 1);
            rc = -1;
            break;
        }
        char tmp[TR_MAX_LINE];
        memcpy(tmp, ln, l);
        tmp[l] = '\0';
        tr_trim(tmp);
        if (*tmp) { /* blank lines are skipped but still counted */
            if (n >= TR_MAX_RULES) {
                if (err) *err = sdscatprintf(sdsempty(), "ERROR: too many rules (max %d)", TR_MAX_RULES);
                rc = -1;
                break;
            }
            if (tr_parse_line(tmp, lineno + 1, &out[n], err) != 0) {
                rc = -1;
                break;
            }
            n++;
        }
        if (!nl) break;
        ln = nl + 1;
    }
    free(buf);
    if (rc == 0 && n == 0) {
        if (err) *err = sdsnew("ERROR: rules text contains no rules");
        return -1;
    }
    return rc == 0 ? n : -1;
}

/* Case-insensitive key lookup in a JSON object (Tasmota keys vary in case). */
static cJSON *tr_find_key(cJSON *obj, const char *key) {
    if (!cJSON_IsObject(obj)) return NULL;
    for (cJSON *it = obj->child; it; it = it->next) {
        if (it->string && strcasecmp(it->string, key) == 0) return it;
    }
    return NULL;
}

/* Resolve the value a trigger refers to inside the event object.
 * Supports both Tasmota telemetry shape {"DHT11":{"Temperature":25}} and
 * the flat {"name":"DHT11","value":25} shape. NULL = event not present. */
static cJSON *tr_resolve(cJSON *event, const tr_rule_t *r) {
    if (r->has_field) {
        cJSON *sub = tr_find_key(event, r->name);
        if (!sub || !cJSON_IsObject(sub)) return NULL;
        return tr_find_key(sub, r->field);
    }
    cJSON *nm = tr_find_key(event, "name");
    if (nm && cJSON_IsString(nm) && nm->valuestring &&
        strcasecmp(nm->valuestring, r->name) == 0) {
        cJSON *v = tr_find_key(event, "value");
        if (v) return v;
    }
    return tr_find_key(event, r->name);
}

static int tr_fires(cJSON *event, const tr_rule_t *r) {
    cJSON *v = tr_resolve(event, r);
    if (!v) return 0;
    if (r->op == TR_OP_NONE) return 1; /* presence */
    if (r->rhs_numeric) {
        double ev;
        if (cJSON_IsNumber(v)) {
            ev = v->valuedouble;
        } else if (cJSON_IsString(v) && v->valuestring) {
            if (!tr_parse_number(v->valuestring, &ev)) return 0; /* non-numeric event value: no fire */
        } else {
            return 0; /* bool/object/array: no numeric comparison */
        }
        switch (r->op) {
            case TR_OP_EQ: return ev == r->rhs_num;
            case TR_OP_NE: return ev != r->rhs_num;
            case TR_OP_GT: return ev >  r->rhs_num;
            case TR_OP_LT: return ev <  r->rhs_num;
            case TR_OP_GE: return ev >= r->rhs_num;
            case TR_OP_LE: return ev <= r->rhs_num;
            default: return 0;
        }
    }
    /* string RHS: only == and != (enforced at parse time) */
    if (!cJSON_IsString(v) || !v->valuestring) return 0;
    int eq = strcmp(v->valuestring, r->rhs_str) == 0;
    if (r->op == TR_OP_EQ) return eq;
    if (r->op == TR_OP_NE) return !eq;
    return 0;
}

static sds tr_rules_to_json(cJSON *args) {
    const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rules"));
    if (!text) text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rule"));
    if (!text) text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    if (!text) text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    tr_rule_t rules[TR_MAX_RULES];
    sds err = NULL;
    int n = tr_parse_rules(text, rules, &err);
    if (n < 0) return err ? err : sdsnew("ERROR: rules parse failed");

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "parse");
    cJSON_AddNumberToObject(obj, "rules", n);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *it = cJSON_CreateObject();
        cJSON_AddNumberToObject(it, "line", rules[i].line);
        sds trig = sdscatprintf(sdsempty(), "%s%s%s", rules[i].name,
                                rules[i].has_field ? "#" : "",
                                rules[i].has_field ? rules[i].field : "");
        cJSON_AddStringToObject(it, "trigger", trig);
        sdsfree(trig);
        const char *ops = tr_op_str(rules[i].op);
        if (ops) cJSON_AddStringToObject(it, "op", ops);
        else cJSON_AddNullToObject(it, "op");
        if (rules[i].op != TR_OP_NONE) {
            if (rules[i].rhs_numeric) cJSON_AddNumberToObject(it, "value", rules[i].rhs_num);
            else cJSON_AddStringToObject(it, "value", rules[i].rhs_str);
        } else {
            cJSON_AddNullToObject(it, "value");
        }
        cJSON *cs = cJSON_CreateArray();
        for (int j = 0; j < rules[i].ncmds; j++)
            cJSON_AddItemToArray(cs, cJSON_CreateString(rules[i].cmds[j]));
        cJSON_AddItemToObject(it, "commands", cs);
        cJSON_AddItemToArray(arr, it);
    }
    cJSON_AddItemToObject(obj, "items", arr);
    char *js = cJSON_PrintUnformatted(obj);
    sds res = sdsnew(js ? js : "{}");
    free(js);
    cJSON_Delete(obj);
    return res;
}

static sds tool_rules_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "eval";

    if (strcmp(action, "parse") == 0 || strcmp(action, "validate") == 0) {
        return tr_rules_to_json(args);
    }

    if (strcmp(action, "eval") == 0 || strcmp(action, "fire") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rules"));
        if (!text) text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "rule"));
        tr_rule_t rules[TR_MAX_RULES];
        sds err = NULL;
        int n = tr_parse_rules(text, rules, &err);
        if (n < 0) return err ? err : sdsnew("ERROR: rules parse failed");

        /* event may be a JSON object or a JSON-encoded object string */
        cJSON *event = cJSON_GetObjectItem(args, "event");
        cJSON *owned = NULL;
        if (cJSON_IsString(event) && event->valuestring) {
            owned = cJSON_Parse(event->valuestring);
            event = owned;
        }
        if (!cJSON_IsObject(event)) {
            if (owned) cJSON_Delete(owned);
            return sdsnew("ERROR: 'event' object is required for eval");
        }

        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "action", "eval");
        cJSON_AddNumberToObject(obj, "rules", n);
        cJSON *fired = cJSON_CreateArray();
        cJSON *matches = cJSON_CreateArray();
        int nfired = 0;
        for (int i = 0; i < n; i++) {
            if (!tr_fires(event, &rules[i])) continue;
            for (int j = 0; j < rules[i].ncmds; j++) {
                cJSON_AddItemToArray(fired, cJSON_CreateString(rules[i].cmds[j]));
                cJSON *m = cJSON_CreateObject();
                cJSON_AddNumberToObject(m, "line", rules[i].line);
                cJSON_AddStringToObject(m, "command", rules[i].cmds[j]);
                cJSON_AddItemToArray(matches, m);
                nfired++;
            }
        }
        cJSON_AddNumberToObject(obj, "fired", nfired);
        cJSON_AddItemToObject(obj, "commands", fired);
        cJSON_AddItemToObject(obj, "matches", matches);
        char *js = cJSON_PrintUnformatted(obj);
        sds res = sdsnew(js ? js : "{}");
        free(js);
        cJSON_Delete(obj);
        if (owned) cJSON_Delete(owned);
        return res;
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown rules action '%s' (use eval/parse)", action);
}

static const alpha_tool_t tool_rules = {
    .name = "rules",
    .aliases = {"tasmota_rules", "rule_eval", NULL},
    .category = "eval",
    .description = "Tasmota-style rules evaluator (pure C): rules 'ON <trigger> DO <cmd>[; <cmd>...] [ENDON]', one per line. Triggers match event names (case-insensitive) with optional '#field' selector and comparison (== != >= <= > <) against numbers or strings, e.g. 'ON DHT11#Temperature>25 DO Power1 1'. eval fires against an event object and returns the triggered commands; parse validates and dumps rule structure. Strict parse errors with line numbers.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"rules\",\"description\":\"Tasmota-style rules evaluator: parse or eval 'ON <trigger> DO <commands>' rules against an event object.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"eval\",\"parse\"],\"description\":\"eval fires rules against an event; parse validates and dumps rule structure\"},\"rules\":{\"type\":\"string\",\"description\":\"Rules text, one rule per line: ON <name[#field][op value]> DO <cmd>[; <cmd>...] [ENDON]\"},\"event\":{\"type\":\"object\",\"description\":\"Event object, e.g. {\\\"DHT11\\\":{\\\"Temperature\\\":26}} or {\\\"name\\\":\\\"Power1\\\",\\\"value\\\":1}\"}},\"required\":[\"rules\"]}}}",
    .run = tool_rules_run
};
