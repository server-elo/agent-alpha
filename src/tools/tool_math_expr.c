/* tool_math_expr.c — Fast Recursive-Descent Math & Logic Evaluator from codeplea/tinyexpr */
#include <math.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    const char *expr;
    size_t len;
    size_t pos;
    cJSON *vars;
    int has_err;
    char err[128];
    int validate_mode;
} ExprState;

static void expr_skip_ws(ExprState *s) {
    while (s->pos < s->len && (s->expr[s->pos] == ' ' || s->expr[s->pos] == '\t' || s->expr[s->pos] == '\r' || s->expr[s->pos] == '\n'))
        s->pos++;
}

static double expr_parse_expression(ExprState *s);

static double expr_parse_primary(ExprState *s) {
    expr_skip_ws(s);
    if (s->has_err || s->pos >= s->len) {
        if (!s->has_err) {
            s->has_err = 1;
            snprintf(s->err, sizeof(s->err), "unexpected end of expression at pos %zu", s->pos);
        }
        return 0.0;
    }

    if (s->expr[s->pos] == '(') {
        s->pos++;
        double v = expr_parse_expression(s);
        expr_skip_ws(s);
        if (s->pos >= s->len || s->expr[s->pos] != ')') {
            s->has_err = 1;
            snprintf(s->err, sizeof(s->err), "missing closing parenthesis at pos %zu", s->pos);
            return 0.0;
        }
        s->pos++;
        return v;
    }

    if (s->expr[s->pos] == '+') {
        s->pos++;
        return expr_parse_primary(s);
    }
    if (s->expr[s->pos] == '-') {
        s->pos++;
        return -expr_parse_primary(s);
    }

    if ((s->expr[s->pos] >= '0' && s->expr[s->pos] <= '9') || s->expr[s->pos] == '.') {
        char *endptr = NULL;
        double v = strtod(&s->expr[s->pos], &endptr);
        if (endptr == &s->expr[s->pos]) {
            s->has_err = 1;
            snprintf(s->err, sizeof(s->err), "invalid number format at pos %zu", s->pos);
            return 0.0;
        }
        s->pos = (size_t)(endptr - s->expr);
        return v;
    }

    if ((s->expr[s->pos] >= 'a' && s->expr[s->pos] <= 'z') || (s->expr[s->pos] >= 'A' && s->expr[s->pos] <= 'Z') || s->expr[s->pos] == '_') {
        size_t start = s->pos;
        while (s->pos < s->len && ((s->expr[s->pos] >= 'a' && s->expr[s->pos] <= 'z') ||
                                   (s->expr[s->pos] >= 'A' && s->expr[s->pos] <= 'Z') ||
                                   (s->expr[s->pos] >= '0' && s->expr[s->pos] <= '9') ||
                                   s->expr[s->pos] == '_')) {
            s->pos++;
        }
        size_t id_len = s->pos - start;
        char id[64];
        if (id_len >= sizeof(id)) id_len = sizeof(id) - 1;
        memcpy(id, &s->expr[start], id_len);
        id[id_len] = '\0';

        expr_skip_ws(s);
        if (s->pos < s->len && s->expr[s->pos] == '(') {
            s->pos++;
            double a1 = expr_parse_expression(s);
            expr_skip_ws(s);
            double a2 = 0.0, a3 = 0.0;
            if (s->pos < s->len && s->expr[s->pos] == ',') {
                s->pos++;
                a2 = expr_parse_expression(s);
                expr_skip_ws(s);
            }
            if (s->pos < s->len && s->expr[s->pos] == ',') {
                s->pos++;
                a3 = expr_parse_expression(s);
                expr_skip_ws(s);
            }
            if (s->pos >= s->len || s->expr[s->pos] != ')') {
                s->has_err = 1;
                snprintf(s->err, sizeof(s->err), "missing ')' in function '%s' at pos %zu", id, s->pos);
                return 0.0;
            }
            s->pos++;

            if (strcmp(id, "sqrt") == 0) return a1 >= 0 ? sqrt(a1) : 0.0;
            if (strcmp(id, "cbrt") == 0) return cbrt(a1);
            if (strcmp(id, "sin") == 0) return sin(a1);
            if (strcmp(id, "cos") == 0) return cos(a1);
            if (strcmp(id, "tan") == 0) return tan(a1);
            if (strcmp(id, "asin") == 0) return asin(a1);
            if (strcmp(id, "acos") == 0) return acos(a1);
            if (strcmp(id, "atan") == 0) return atan(a1);
            if (strcmp(id, "atan2") == 0) return atan2(a1, a2);
            if (strcmp(id, "abs") == 0 || strcmp(id, "fabs") == 0) return fabs(a1);
            if (strcmp(id, "floor") == 0) return floor(a1);
            if (strcmp(id, "ceil") == 0) return ceil(a1);
            if (strcmp(id, "round") == 0) return round(a1);
            if (strcmp(id, "exp") == 0) return exp(a1);
            if (strcmp(id, "log") == 0 || strcmp(id, "ln") == 0) return a1 > 0 ? log(a1) : 0.0;
            if (strcmp(id, "log10") == 0) return a1 > 0 ? log10(a1) : 0.0;
            if (strcmp(id, "pow") == 0) return pow(a1, a2);
            if (strcmp(id, "min") == 0) return a1 < a2 ? a1 : a2;
            if (strcmp(id, "max") == 0) return a1 > a2 ? a1 : a2;
            if (strcmp(id, "hypot") == 0) return hypot(a1, a2);
            if (strcmp(id, "clamp") == 0) {
                if (a1 < a2) return a2;
                if (a1 > a3) return a3;
                return a1;
            }

            s->has_err = 1;
            snprintf(s->err, sizeof(s->err), "unknown function '%s'", id);
            return 0.0;
        }

        if (strcasecmp(id, "pi") == 0) return 3.14159265358979323846;
        if (strcasecmp(id, "e") == 0) return 2.71828182845904523536;
        if (strcasecmp(id, "true") == 0) return 1.0;
        if (strcasecmp(id, "false") == 0) return 0.0;

        if (s->vars && cJSON_IsObject(s->vars)) {
            cJSON *v = cJSON_GetObjectItem(s->vars, id);
            if (v && cJSON_IsNumber(v)) return v->valuedouble;
        }

        if (s->validate_mode) return 1.0;

        s->has_err = 1;
        snprintf(s->err, sizeof(s->err), "unknown variable or identifier '%s' at pos %zu", id, start);
        return 0.0;
    }

    s->has_err = 1;
    snprintf(s->err, sizeof(s->err), "unexpected character '%c' (0x%02X) at pos %zu", s->expr[s->pos], (unsigned char)s->expr[s->pos], s->pos);
    return 0.0;
}

static double expr_parse_power(ExprState *s) {
    double base = expr_parse_primary(s);
    expr_skip_ws(s);
    if (s->pos < s->len && s->expr[s->pos] == '^') {
        s->pos++;
        double exponent = expr_parse_power(s);
        return pow(base, exponent);
    }
    return base;
}

static double expr_parse_term(ExprState *s) {
    double left = expr_parse_power(s);
    while (1) {
        expr_skip_ws(s);
        if (s->pos >= s->len) break;
        char op = s->expr[s->pos];
        if (op != '*' && op != '/' && op != '%') break;
        s->pos++;
        double right = expr_parse_power(s);
        if (op == '*') {
            left *= right;
        } else if (op == '/') {
            if (fabs(right) < 1e-15) {
                s->has_err = 1;
                snprintf(s->err, sizeof(s->err), "division by zero");
                return 0.0;
            }
            left /= right;
        } else if (op == '%') {
            if (fabs(right) < 1e-15) {
                s->has_err = 1;
                snprintf(s->err, sizeof(s->err), "modulo by zero");
                return 0.0;
            }
            left = fmod(left, right);
        }
    }
    return left;
}

static double expr_parse_expression(ExprState *s) {
    double left = expr_parse_term(s);
    while (1) {
        expr_skip_ws(s);
        if (s->pos >= s->len) break;
        char op = s->expr[s->pos];
        if (op != '+' && op != '-') break;
        s->pos++;
        double right = expr_parse_term(s);
        if (op == '+') left += right;
        else left -= right;
    }
    return left;
}

static sds tool_math_expr_eval_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *expr = cJSON_GetStringValue(cJSON_GetObjectItem(args, "expression"));
    if (!expr) expr = cJSON_GetStringValue(cJSON_GetObjectItem(args, "expr"));
    if (!expr) expr = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    if (!expr) return sdsnew("ERROR: expression string required for math_expr_eval");

    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action) action = "eval";

    cJSON *vars = cJSON_GetObjectItem(args, "variables");
    if (!vars) vars = cJSON_GetObjectItem(args, "vars");

    if (strcmp(action, "tokenize") == 0) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "action", "tokenize");
        cJSON_AddStringToObject(resp, "expression", expr);
        cJSON *tokens = cJSON_CreateArray();
        size_t elen = strlen(expr);
        size_t p = 0;
        while (p < elen) {
            while (p < elen && (expr[p] == ' ' || expr[p] == '\t' || expr[p] == '\r' || expr[p] == '\n')) p++;
            if (p >= elen) break;
            cJSON *tok = cJSON_CreateObject();
            size_t start = p;
            if ((expr[p] >= '0' && expr[p] <= '9') || expr[p] == '.') {
                while (p < elen && ((expr[p] >= '0' && expr[p] <= '9') || expr[p] == '.' || expr[p] == 'e' || expr[p] == 'E' || (p > start && (expr[p-1] == 'e' || expr[p-1] == 'E') && (expr[p] == '+' || expr[p] == '-'))))
                    p++;
                char buf[64];
                size_t n = p - start;
                if (n >= sizeof(buf)) n = sizeof(buf) - 1;
                memcpy(buf, &expr[start], n);
                buf[n] = '\0';
                cJSON_AddStringToObject(tok, "type", "number");
                cJSON_AddStringToObject(tok, "value", buf);
            } else if ((expr[p] >= 'a' && expr[p] <= 'z') || (expr[p] >= 'A' && expr[p] <= 'Z') || expr[p] == '_') {
                while (p < elen && ((expr[p] >= 'a' && expr[p] <= 'z') || (expr[p] >= 'A' && expr[p] <= 'Z') || (expr[p] >= '0' && expr[p] <= '9') || expr[p] == '_'))
                    p++;
                char buf[64];
                size_t n = p - start;
                if (n >= sizeof(buf)) n = sizeof(buf) - 1;
                memcpy(buf, &expr[start], n);
                buf[n] = '\0';
                cJSON_AddStringToObject(tok, "type", "identifier");
                cJSON_AddStringToObject(tok, "value", buf);
            } else {
                char buf[4];
                buf[0] = expr[p++];
                buf[1] = '\0';
                cJSON_AddStringToObject(tok, "type", "symbol");
                cJSON_AddStringToObject(tok, "value", buf);
            }
            cJSON_AddNumberToObject(tok, "offset", (double)start);
            cJSON_AddItemToArray(tokens, tok);
        }
        cJSON_AddItemToObject(resp, "tokens", tokens);
        char *rendered = cJSON_PrintUnformatted(resp);
        sds out = sdsnew(rendered ? rendered : "{}");
        free(rendered);
        cJSON_Delete(resp);
        return out;
    }

    if (strcmp(action, "validate") == 0) {
        ExprState state;
        memset(&state, 0, sizeof(state));
        state.expr = expr;
        state.len = strlen(expr);
        state.pos = 0;
        state.vars = vars;
        state.validate_mode = 1;
        expr_parse_expression(&state);
        expr_skip_ws(&state);
        if (!state.has_err && state.pos < state.len) {
            state.has_err = 1;
            snprintf(state.err, sizeof(state.err), "unexpected trailing characters at pos %zu", state.pos);
        }

        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "action", "validate");
        cJSON_AddStringToObject(resp, "expression", expr);
        cJSON_AddBoolToObject(resp, "valid", !state.has_err);
        if (state.has_err) {
            cJSON_AddStringToObject(resp, "error", state.err);
            cJSON_AddNumberToObject(resp, "error_offset", (double)state.pos);
        }
        char *rendered = cJSON_PrintUnformatted(resp);
        sds out = sdsnew(rendered ? rendered : "{}");
        free(rendered);
        cJSON_Delete(resp);
        return out;
    }

    ExprState state;
    memset(&state, 0, sizeof(state));
    state.expr = expr;
    state.len = strlen(expr);
    state.pos = 0;
    state.vars = vars;
    state.validate_mode = 0;

    double val = expr_parse_expression(&state);
    expr_skip_ws(&state);
    if (!state.has_err && state.pos < state.len) {
        state.has_err = 1;
        snprintf(state.err, sizeof(state.err), "unexpected trailing characters '%c' at pos %zu", state.expr[state.pos], state.pos);
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "eval");
    cJSON_AddStringToObject(resp, "expression", expr);
    cJSON_AddBoolToObject(resp, "success", !state.has_err);
    if (!state.has_err) {
        cJSON_AddNumberToObject(resp, "value", val);
    } else {
        cJSON_AddStringToObject(resp, "error", state.err);
        cJSON_AddNumberToObject(resp, "error_offset", (double)state.pos);
    }
    char *rendered = cJSON_PrintUnformatted(resp);
    sds out = sdsnew(rendered ? rendered : "{}");
    free(rendered);
    cJSON_Delete(resp);
    return out;
}

static const alpha_tool_t tool_math_expr = {
    .name = "math_expr_eval",
    .aliases = {"tinyexpr", "calc", NULL},
    .category = "math",
    .description = "Fast Recursive-Descent Math & Logic Expression Evaluator from codeplea/tinyexpr. Supports arithmetic (+, -, *, /, %, ^), scientific functions (sqrt, cbrt, sin, cos, tan, abs, floor, ceil, round, exp, log, pow, min, max, hypot, clamp), constants (pi, e), variables bindings map, tokenization, and syntax validation.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"math_expr_eval\",\"description\":\"Fast Recursive-Descent Math & Logic Expression Evaluator from codeplea/tinyexpr. Supports arithmetic (+, -, *, /, %, ^), scientific functions (sqrt, cbrt, sin, cos, tan, abs, floor, ceil, round, exp, log, pow, min, max, hypot, clamp), constants (pi, e), variables bindings map, tokenization, and syntax validation.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"eval\",\"validate\",\"tokenize\"],\"description\":\"Action to perform (default eval)\"},\"expression\":{\"type\":\"string\",\"description\":\"Math expression string to evaluate, validate or tokenize\"},\"variables\":{\"type\":\"object\",\"description\":\"Optional key-value map of variable numeric bindings, e.g. {'x': 3, 'y': 4}\"}},\"required\":[\"expression\"]}}}",
    .run = tool_math_expr_eval_run
};
