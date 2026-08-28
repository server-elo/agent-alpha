/* test_ebnf.c — tests for ebnf_grammar tool (ISO EBNF & Formal Grammar Analysis) */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static cJSON *P(sds s) {
    if (!s) return NULL;
    return cJSON_Parse(s);
}

int main(void) {
    TEST_BEGIN("ebnf_grammar");

    // 1. Basic valid EBNF validation
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "validate");
        cJSON_AddStringToObject(a, "grammar", "expr = term , { \"+\" , term } ;\nterm = factor , { \"*\" , factor } ;\nfactor = [ \"-\" ] , \"x\" ;");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "valid grammar response non-null");
        cJSON *p = P(r);
        CHECK(p != NULL, "valid grammar parses as JSON");
        if (p) {
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p, "valid")), "grammar is marked valid");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p, "rule_count")), 3, "3 rules parsed");
            cJSON_Delete(p);
        }
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 2. Direct left-recursion detection
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "validate");
        cJSON_AddStringToObject(a, "grammar", "expr = expr , \"+\" , term | term ;\nterm = \"id\" ;");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "left-recursion response non-null");
        cJSON *p = P(r);
        CHECK(p != NULL, "left-recursion parses as JSON");
        if (p) {
            cJSON *lr = cJSON_GetObjectItem(p, "left_recursive_rules");
            CHECK(lr != NULL && cJSON_IsArray(lr), "left_recursive_rules array present");
            CHECK_EQ_INT(cJSON_GetArraySize(lr), 1, "detects 1 left-recursive rule");
            if (cJSON_GetArraySize(lr) > 0) {
                CHECK(strcmp(cJSON_GetArrayItem(lr, 0)->valuestring, "expr") == 0, "identified 'expr' as left-recursive");
            }
            cJSON_Delete(p);
        }
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 3. Undefined non-terminal detection
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "validate");
        cJSON_AddStringToObject(a, "grammar", "statement = \"if\" , condition , \"then\" , block ;\nblock = \"return\" ;");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "undefined check non-null");
        cJSON *p = P(r);
        CHECK(p != NULL, "undefined check json valid");
        if (p) {
            cJSON *undef = cJSON_GetObjectItem(p, "undefined_symbols");
            CHECK(undef != NULL && cJSON_IsArray(undef), "undefined_symbols array present");
            CHECK_EQ_INT(cJSON_GetArraySize(undef), 1, "flags 1 undefined symbol");
            if (cJSON_GetArraySize(undef) > 0) {
                CHECK(strcmp(cJSON_GetArrayItem(undef, 0)->valuestring, "condition") == 0, "identified 'condition' as undefined");
            }
            cJSON_Delete(p);
        }
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 4. Parse Rules AST structure
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "parse_rules");
        cJSON_AddStringToObject(a, "grammar", "identifier = letter , { letter | digit } ;");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "parse_rules response non-null");
        cJSON *p = P(r);
        CHECK(p != NULL, "parse_rules json valid");
        if (p) {
            cJSON *rules = cJSON_GetObjectItem(p, "rules");
            CHECK(rules != NULL && cJSON_IsArray(rules), "rules array present");
            CHECK_EQ_INT(cJSON_GetArraySize(rules), 1, "1 rule in AST");
            cJSON *r0 = cJSON_GetArrayItem(rules, 0);
            CHECK(strcmp(cJSON_GetObjectItem(r0, "name")->valuestring, "identifier") == 0, "rule name is identifier");
            cJSON_Delete(p);
        }
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 5. Canonicalize EBNF formatting
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "canonicalize");
        cJSON_AddStringToObject(a, "grammar", "ruleA ::= 'foo' | 'bar' ;\nruleB : [ 'opt' ] ruleA ;");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "canonicalize response non-null");
        cJSON *p = P(r);
        CHECK(p != NULL, "canonicalize json valid");
        if (p) {
            cJSON *canon = cJSON_GetObjectItem(p, "canonical_ebnf");
            CHECK(canon != NULL && cJSON_IsString(canon), "canonical_ebnf string present");
            CHECK(strstr(canon->valuestring, "ruleA = \"foo\" | \"bar\" ;") != NULL, "ruleA formatted to ISO EBNF");
            CHECK(strstr(canon->valuestring, "ruleB = ") != NULL && strstr(canon->valuestring, "ruleA ;") != NULL, "ruleB formatted to ISO EBNF");
            cJSON_Delete(p);
        }
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 6. Adversarial: Missing parameter rejection
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "validate");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "missing grammar returns error string");
        CHECK(strstr(r, "ERROR") != NULL, "error flagged for missing grammar parameter");
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 7. Adversarial: Unterminated string literal in grammar
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "validate");
        cJSON_AddStringToObject(a, "grammar", "broken = \"unterminated string ;");
        sds r = tools_run("ebnf_grammar", a, NULL);
        CHECK(r != NULL, "unterminated string handled");
        cJSON *p = P(r);
        CHECK(p != NULL, "unterminated string returns JSON report");
        if (p) {
            CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p, "valid")), "invalid grammar reported");
            CHECK(strstr(cJSON_GetObjectItem(p, "errors")->valuestring, "unterminated") != NULL, "reports unterminated string error");
            cJSON_Delete(p);
        }
        sdsfree(r);
        cJSON_Delete(a);
    }

    // 8. Alias verification
    {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddStringToObject(a, "action", "validate");
        cJSON_AddStringToObject(a, "grammar", "root = \"start\" ;");
        sds r1 = tools_run("ebnf", a, NULL);
        sds r2 = tools_run("bnf_parser", a, NULL);
        sds r3 = tools_run("grammar_tool", a, NULL);
        CHECK(r1 != NULL && strstr(r1, "\"valid\":true") != NULL, "alias 'ebnf' works");
        CHECK(r2 != NULL && strstr(r2, "\"valid\":true") != NULL, "alias 'bnf_parser' works");
        CHECK(r3 != NULL && strstr(r3, "\"valid\":true") != NULL, "alias 'grammar_tool' works");
        sdsfree(r1);
        sdsfree(r2);
        sdsfree(r3);
        cJSON_Delete(a);
    }

    // 9. Schema registration in master table
    {
        cJSON *schema = tools_schema();
        CHECK(schema != NULL, "tools_schema() non-null");
        char *str = cJSON_PrintUnformatted(schema);
        CHECK(str != NULL, "schema printed");
        CHECK(strstr(str, "ebnf_grammar") != NULL, "ebnf_grammar is present in tools_schema()");
        free(str);
        cJSON_Delete(schema);
    }

    return test_report("ebnf_grammar");
}
