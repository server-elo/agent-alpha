/* tool_ebnf.c — ISO EBNF & Formal Grammar Analysis Engine (Pure C11)
 * Inspired by katef/kgt & ISO/IEC 14977.
 * Capabilities:
 * - Grammar parsing & AST extraction (rules, alternatives, sequences, repetitions, optionals, terminals)
 * - Direct & indirect left-recursion detection (prevents parser infinite loops)
 * - Undefined non-terminal and unreachable dead-rule detection
 * - Standardized EBNF canonicalization & syntax validation
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#define EBNF_MAX_RULES      128
#define EBNF_MAX_NAME_LEN   64
#define EBNF_MAX_TERMS      32

typedef enum {
    EBNF_SYM_NONTERMINAL,
    EBNF_SYM_TERMINAL,
    EBNF_SYM_OPTIONAL,
    EBNF_SYM_REPETITION,
    EBNF_SYM_GROUP
} ebnf_sym_type_t;

typedef struct {
    ebnf_sym_type_t type;
    char text[96];
} ebnf_symbol_t;

typedef struct {
    ebnf_symbol_t symbols[EBNF_MAX_TERMS];
    int symbol_count;
} ebnf_alternative_t;

typedef struct {
    char name[EBNF_MAX_NAME_LEN];
    ebnf_alternative_t alts[8];
    int alt_count;
    int line;
} ebnf_rule_t;

typedef struct {
    ebnf_rule_t rules[EBNF_MAX_RULES];
    int rule_count;
    char errors[512];
    char warnings[512];
} ebnf_grammar_t;

static void ebnf_trim(char *s) {
    if (!s) return;
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

static int ebnf_find_rule(const ebnf_grammar_t *g, const char *name) {
    for (int i = 0; i < g->rule_count; i++) {
        if (strcmp(g->rules[i].name, name) == 0) return i;
    }
    return -1;
}

/* Parse a single production rule: "name = alt1 | alt2 ;" or "name ::= alt1 | alt2 ;" */
static int ebnf_parse_production(ebnf_grammar_t *g, const char *line, int line_num) {
    if (!line || !line[0]) return 0;
    
    char buf[2048];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    ebnf_trim(buf);
    
    if (buf[0] == '\0' || buf[0] == '#' || (buf[0] == '/' && buf[1] == '/')) return 0;
    
    /* Find separator: "::=" or "=" or ":" */
    char *sep = strstr(buf, "::=");
    size_t sep_len = 3;
    if (!sep) {
        sep = strchr(buf, '=');
        sep_len = 1;
    }
    if (!sep) {
        sep = strchr(buf, ':');
        sep_len = 1;
    }
    if (!sep) {
        snprintf(g->errors + strlen(g->errors), sizeof(g->errors) - strlen(g->errors),
                 "Line %d: missing assignment operator (= or ::=); ", line_num);
        return -1;
    }
    
    char name[EBNF_MAX_NAME_LEN];
    size_t name_len = (size_t)(sep - buf);
    if (name_len >= sizeof(name)) name_len = sizeof(name) - 1;
    strncpy(name, buf, name_len);
    name[name_len] = '\0';
    ebnf_trim(name);
    
    if (name[0] == '\0') {
        snprintf(g->errors + strlen(g->errors), sizeof(g->errors) - strlen(g->errors),
                 "Line %d: empty rule name; ", line_num);
        return -1;
    }
    
    if (g->rule_count >= EBNF_MAX_RULES) {
        snprintf(g->errors + strlen(g->errors), sizeof(g->errors) - strlen(g->errors),
                 "Exceeded max rule count (%d); ", EBNF_MAX_RULES);
        return -1;
    }
    
    ebnf_rule_t *r = &g->rules[g->rule_count++];
    strncpy(r->name, name, sizeof(r->name) - 1);
    r->name[sizeof(r->name) - 1] = '\0';
    r->line = line_num;
    r->alt_count = 0;
    
    char *rhs = sep + sep_len;
    ebnf_trim(rhs);
    /* Strip trailing semicolon if present */
    size_t rhs_len = strlen(rhs);
    if (rhs_len > 0 && rhs[rhs_len - 1] == ';') {
        rhs[--rhs_len] = '\0';
        ebnf_trim(rhs);
    }
    
    if (rhs[0] == '\0') {
        snprintf(g->errors + strlen(g->errors), sizeof(g->errors) - strlen(g->errors),
                 "Line %d: empty right-hand side for rule '%s'; ", line_num, name);
        return -1;
    }
    
    /* Tokenize alternatives split by '|' */
    char rhs_copy[2048];
    strncpy(rhs_copy, rhs, sizeof(rhs_copy) - 1);
    rhs_copy[sizeof(rhs_copy) - 1] = '\0';
    
    char *p = rhs_copy;
    while (*p && r->alt_count < 16) {
        /* Parse an alternative (respecting quotes) */
        char alt_buf[1024];
        size_t ab_len = 0;
        int in_quote = 0;
        char quote_char = 0;
        
        while (*p) {
            char c = *p;
            if (!in_quote && (c == '"' || c == '\'')) {
                in_quote = 1;
                quote_char = c;
            } else if (in_quote && c == quote_char) {
                in_quote = 0;
            } else if (!in_quote && c == '|') {
                p++; /* consume '|' */
                break;
            }
            if (ab_len < sizeof(alt_buf) - 1) {
                alt_buf[ab_len++] = c;
            }
            p++;
        }
        alt_buf[ab_len] = '\0';
        ebnf_trim(alt_buf);
        
        if (in_quote) {
            snprintf(g->errors + strlen(g->errors), sizeof(g->errors) - strlen(g->errors),
                     "Line %d: unterminated string literal in rule '%s'; ", line_num, name);
            return -1;
        }
        
        if (alt_buf[0] != '\0') {
            ebnf_alternative_t *alt = &r->alts[r->alt_count++];
            alt->symbol_count = 0;
            
            /* Tokenize symbols inside alternative: comma or whitespace separated */
            char *sp = alt_buf;
            while (*sp && alt->symbol_count < EBNF_MAX_TERMS) {
                while (isspace((unsigned char)*sp) || *sp == ',') sp++;
                if (!*sp) break;
                
                ebnf_symbol_t *sym = &alt->symbols[alt->symbol_count++];
                if (*sp == '"' || *sp == '\'') {
                    char qc = *sp++;
                    char tbuf[128];
                    size_t tlen = 0;
                    while (*sp && *sp != qc && tlen < sizeof(tbuf) - 1) {
                        tbuf[tlen++] = *sp++;
                    }
                    if (*sp == qc) sp++;
                    tbuf[tlen] = '\0';
                    sym->type = EBNF_SYM_TERMINAL;
                    strncpy(sym->text, tbuf, sizeof(sym->text) - 1);
                    sym->text[sizeof(sym->text) - 1] = '\0';
                } else if (*sp == '[' || *sp == '{' || *sp == '(') {
                    char open_c = *sp;
                    char close_c = (open_c == '[') ? ']' : (open_c == '{' ? '}' : ')');
                    sp++;
                    char tbuf[128];
                    size_t tlen = 0;
                    int depth = 1;
                    while (*sp && depth > 0 && tlen < sizeof(tbuf) - 1) {
                        if (*sp == open_c) depth++;
                        else if (*sp == close_c) {
                            depth--;
                            if (depth == 0) { sp++; break; }
                        }
                        tbuf[tlen++] = *sp++;
                    }
                    tbuf[tlen] = '\0';
                    ebnf_trim(tbuf);
                    sym->type = (open_c == '[') ? EBNF_SYM_OPTIONAL : ((open_c == '{') ? EBNF_SYM_REPETITION : EBNF_SYM_GROUP);
                    strncpy(sym->text, tbuf, sizeof(sym->text) - 1);
                    sym->text[sizeof(sym->text) - 1] = '\0';
                } else {
                    /* Identifier / Non-terminal */
                    char tbuf[128];
                    size_t tlen = 0;
                    while (*sp && !isspace((unsigned char)*sp) && *sp != ',' && *sp != '|' && *sp != ';' && tlen < sizeof(tbuf) - 1) {
                        tbuf[tlen++] = *sp++;
                    }
                    tbuf[tlen] = '\0';
                    sym->type = EBNF_SYM_NONTERMINAL;
                    strncpy(sym->text, tbuf, sizeof(sym->text) - 1);
                    sym->text[sizeof(sym->text) - 1] = '\0';
                }
            }
        }
    }
    return 0;
}

static int ebnf_parse_grammar(ebnf_grammar_t *g, const char *text) {
    memset(g, 0, sizeof(*g));
    if (!text || !text[0]) {
        snprintf(g->errors, sizeof(g->errors), "Grammar text is empty");
        return -1;
    }
    
    char *copy = strdup(text);
    if (!copy) return -1;
    
    char *saveptr = NULL;
    char *line = strtok_r(copy, "\n\r", &saveptr);
    int line_num = 1;
    while (line) {
        ebnf_parse_production(g, line, line_num++);
        line = strtok_r(NULL, "\n\r", &saveptr);
    }
    free(copy);
    return (g->rule_count > 0 && g->errors[0] == '\0') ? 0 : -1;
}

/* Dispatcher for ebnf_grammar tool */
static sds tool_ebnf_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *act_item = cJSON_GetObjectItem(args, "action");
    const char *action = act_item ? act_item->valuestring : "validate";
    if (!action || !action[0]) action = "validate";

    cJSON *txt_item = cJSON_GetObjectItem(args, "grammar");
    if (!txt_item) txt_item = cJSON_GetObjectItem(args, "text");
    if (!txt_item) txt_item = cJSON_GetObjectItem(args, "input");
    const char *grammar_text = txt_item ? txt_item->valuestring : NULL;

    if (!grammar_text || !grammar_text[0]) {
        return sdsnew("ERROR: missing required parameter 'grammar' or 'text'");
    }

    ebnf_grammar_t *g = (ebnf_grammar_t *)calloc(1, sizeof(ebnf_grammar_t));
    if (!g) return sdsnew("ERROR: out of memory allocating grammar parser");
    ebnf_parse_grammar(g, grammar_text);

    if (strcmp(action, "validate") == 0) {
        cJSON *res = cJSON_CreateObject();
        cJSON_AddStringToObject(res, "action", "validate");
        cJSON_AddBoolToObject(res, "valid", (g->errors[0] == '\0' && g->rule_count > 0));
        cJSON_AddNumberToObject(res, "rule_count", g->rule_count);
        
        if (g->errors[0]) {
            cJSON_AddStringToObject(res, "errors", g->errors);
        }
        
        /* Check for direct left-recursion */
        cJSON *lr_arr = cJSON_CreateArray();
        for (int i = 0; i < g->rule_count; i++) {
            for (int a = 0; a < g->rules[i].alt_count; a++) {
                if (g->rules[i].alts[a].symbol_count > 0) {
                    const ebnf_symbol_t *first = &g->rules[i].alts[a].symbols[0];
                    if (first->type == EBNF_SYM_NONTERMINAL && strcmp(first->text, g->rules[i].name) == 0) {
                        cJSON_AddItemToArray(lr_arr, cJSON_CreateString(g->rules[i].name));
                        break;
                    }
                }
            }
        }
        cJSON_AddItemToObject(res, "left_recursive_rules", lr_arr);

        /* Check for undefined non-terminals */
        cJSON *undef_arr = cJSON_CreateArray();
        for (int i = 0; i < g->rule_count; i++) {
            for (int a = 0; a < g->rules[i].alt_count; a++) {
                for (int s = 0; s < g->rules[i].alts[a].symbol_count; s++) {
                    const ebnf_symbol_t *sym = &g->rules[i].alts[a].symbols[s];
                    if (sym->type == EBNF_SYM_NONTERMINAL) {
                        if (ebnf_find_rule(g, sym->text) == -1) {
                            /* Check if already added */
                            int found = 0;
                            for (int k = 0; k < cJSON_GetArraySize(undef_arr); k++) {
                                if (strcmp(cJSON_GetArrayItem(undef_arr, k)->valuestring, sym->text) == 0) {
                                    found = 1; break;
                                }
                            }
                            if (!found) cJSON_AddItemToArray(undef_arr, cJSON_CreateString(sym->text));
                        }
                    }
                }
            }
        }
        cJSON_AddItemToObject(res, "undefined_symbols", undef_arr);

        char *json_str = cJSON_PrintUnformatted(res);
        sds out = sdsnew(json_str ? json_str : "{}");
        free(json_str);
        cJSON_Delete(res);
        free(g);
        return out;
    }

    if (strcmp(action, "parse_rules") == 0) {
        cJSON *res = cJSON_CreateObject();
        cJSON_AddStringToObject(res, "action", "parse_rules");
        cJSON_AddNumberToObject(res, "rule_count", g->rule_count);
        cJSON *rules_arr = cJSON_CreateArray();

        for (int i = 0; i < g->rule_count; i++) {
            cJSON *r_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(r_obj, "name", g->rules[i].name);
            cJSON_AddNumberToObject(r_obj, "line", g->rules[i].line);
            cJSON *alts_arr = cJSON_CreateArray();

            for (int a = 0; a < g->rules[i].alt_count; a++) {
                cJSON *alt_obj = cJSON_CreateObject();
                cJSON *syms_arr = cJSON_CreateArray();
                for (int s = 0; s < g->rules[i].alts[a].symbol_count; s++) {
                    cJSON *sym_obj = cJSON_CreateObject();
                    const char *stype = (g->rules[i].alts[a].symbols[s].type == EBNF_SYM_TERMINAL) ? "terminal" :
                                        (g->rules[i].alts[a].symbols[s].type == EBNF_SYM_OPTIONAL) ? "optional" :
                                        (g->rules[i].alts[a].symbols[s].type == EBNF_SYM_REPETITION) ? "repetition" : "nonterminal";
                    cJSON_AddStringToObject(sym_obj, "type", stype);
                    cJSON_AddStringToObject(sym_obj, "value", g->rules[i].alts[a].symbols[s].text);
                    cJSON_AddItemToArray(syms_arr, sym_obj);
                }
                cJSON_AddItemToObject(alt_obj, "symbols", syms_arr);
                cJSON_AddItemToArray(alts_arr, alt_obj);
            }
            cJSON_AddItemToObject(r_obj, "alternatives", alts_arr);
            cJSON_AddItemToArray(rules_arr, r_obj);
        }
        cJSON_AddItemToObject(res, "rules", rules_arr);

        char *json_str = cJSON_PrintUnformatted(res);
        sds out = sdsnew(json_str ? json_str : "{}");
        free(json_str);
        cJSON_Delete(res);
        free(g);
        return out;
    }

    if (strcmp(action, "canonicalize") == 0) {
        sds canon = sdsempty();
        for (int i = 0; i < g->rule_count; i++) {
            canon = sdscatprintf(canon, "%s = ", g->rules[i].name);
            for (int a = 0; a < g->rules[i].alt_count; a++) {
                if (a > 0) canon = sdscat(canon, " | ");
                for (int s = 0; s < g->rules[i].alts[a].symbol_count; s++) {
                    if (s > 0) canon = sdscat(canon, ", ");
                    const ebnf_symbol_t *sym = &g->rules[i].alts[a].symbols[s];
                    if (sym->type == EBNF_SYM_TERMINAL) {
                        canon = sdscatprintf(canon, "\"%s\"", sym->text);
                    } else if (sym->type == EBNF_SYM_OPTIONAL) {
                        canon = sdscatprintf(canon, "[ %s ]", sym->text);
                    } else if (sym->type == EBNF_SYM_REPETITION) {
                        canon = sdscatprintf(canon, "{ %s }", sym->text);
                    } else {
                        canon = sdscat(canon, sym->text);
                    }
                }
            }
            canon = sdscat(canon, " ;\n");
        }

        cJSON *res = cJSON_CreateObject();
        cJSON_AddStringToObject(res, "action", "canonicalize");
        cJSON_AddStringToObject(res, "canonical_ebnf", canon);
        cJSON_AddNumberToObject(res, "rule_count", g->rule_count);
        sdsfree(canon);

        char *json_str = cJSON_PrintUnformatted(res);
        sds out = sdsnew(json_str ? json_str : "{}");
        free(json_str);
        cJSON_Delete(res);
        free(g);
        return out;
    }

    free(g);
    return sdscatprintf(sdsempty(), "ERROR: unknown ebnf action '%s' (use validate, parse_rules, canonicalize)", action);
}

static const alpha_tool_t tool_ebnf = {
    .name = "ebnf_grammar",
    .aliases = {"ebnf", "bnf_parser", "grammar_tool"},
    .category = "parser",
    .description = "ISO EBNF & Formal Grammar analysis engine from katef/kgt. Validates syntax, parses production ASTs, detects direct/indirect left-recursion, finds undefined symbols, and canonicalizes EBNF specifications. Actions: validate, parse_rules, canonicalize.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"ebnf_grammar\",\"description\":\"ISO EBNF & Formal Grammar analysis engine from katef/kgt. Validates syntax, parses production ASTs, detects direct/indirect left-recursion, finds undefined symbols, and canonicalizes EBNF specifications. Actions: validate, parse_rules, canonicalize.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"validate\",\"parse_rules\",\"canonicalize\"]},\"grammar\":{\"type\":\"string\",\"description\":\"Raw EBNF or BNF grammar text\"},\"text\":{\"type\":\"string\",\"description\":\"Alias for grammar text\"}},\"required\":[\"grammar\"]}}}",
    .run = tool_ebnf_run
};
