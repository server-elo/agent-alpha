#include "alpha.h"
#include "test_util.h"
#include <string.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static cJSON *args(const char *pat, const char *inp){
    cJSON *a=cJSON_CreateObject();
    cJSON_AddStringToObject(a,"pattern",pat);
    cJSON_AddStringToObject(a,"input",inp);
    return a;
}

static cJSON *args_start(const char *pat, const char *inp, int s){
    cJSON *a=args(pat,inp);
    cJSON_AddNumberToObject(a,"start",s);
    return a;
}

static int is_matched(sds r){ return r && strstr(r,"\"matched\":true")!=NULL; }
static int has_err(sds r){ return r && strncmp(r,"ERROR",5)==0; }

static void test_peg_patterns(void) {
    TEST_BEGIN("peg_match: Packrat PEG Pattern Matching Engine from PackCC");

    // 1 literal
    { cJSON *a=args("\"hello\"","hello world"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "literal match"); CHECK(strstr(r,"\"length\":5")!=NULL, "literal len 5"); sdsfree(r); cJSON_Delete(a); }
    // 2 literal fail
    { cJSON *a=args("\"hello\"","hi"); sds r=tools_run("peg_match",a,"."); CHECK(!is_matched(r), "literal mismatch"); sdsfree(r); cJSON_Delete(a); }
    // 3 choice first
    { cJSON *a=args("\"ab\"/\"cd\"","ab"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "choice branch 1"); sdsfree(r); cJSON_Delete(a); }
    // 4 choice second
    { cJSON *a=args("\"ab\"/\"cd\"","cd"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "choice branch 2"); sdsfree(r); cJSON_Delete(a); }
    // 5 choice fail
    { cJSON *a=args("\"ab\"/\"cd\"","ef"); sds r=tools_run("peg_match",a,"."); CHECK(!is_matched(r), "choice failure"); sdsfree(r); cJSON_Delete(a); }
    // 6 sequence
    { cJSON *a=args("\"a\" \"b\"","ab"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "sequence ab"); CHECK(strstr(r,"\"length\":2")!=NULL, "seq len 2"); sdsfree(r); cJSON_Delete(a); }
    // 7 star zero
    { cJSON *a=args("\"a\"*",""); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "star zero"); CHECK(strstr(r,"\"length\":0")!=NULL, "star len 0"); sdsfree(r); cJSON_Delete(a); }
    // 8 star many
    { cJSON *a=args("\"a\"*","aaa"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "star many"); CHECK(strstr(r,"\"length\":3")!=NULL, "star len 3"); sdsfree(r); cJSON_Delete(a); }
    // 9 plus fail empty
    { cJSON *a=args("\"a\"+",""); sds r=tools_run("peg_match",a,"."); CHECK(!is_matched(r), "plus fail empty"); sdsfree(r); cJSON_Delete(a); }
    // 10 class
    { cJSON *a=args("[a-z]+","hello"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "class [a-z]+"); sdsfree(r); cJSON_Delete(a); }
    // 11 class neg
    { cJSON *a=args("[^0-9]+","abc"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "negated class [^0-9]+"); sdsfree(r); cJSON_Delete(a); }
    // 12 dot
    { cJSON *a=args(".","x"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "any dot ."); sdsfree(r); cJSON_Delete(a); }
    // 13 not predicate success
    { cJSON *a=args("!\"a\" .","b"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "not predicate success"); sdsfree(r); cJSON_Delete(a); }
    // 14 not predicate fail
    { cJSON *a=args("!\"a\" .","a"); sds r=tools_run("peg_match",a,"."); CHECK(!is_matched(r), "not predicate fail"); sdsfree(r); cJSON_Delete(a); }
    // 15 and predicate
    { cJSON *a=args("&\"a\" \"a\"","a"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "and predicate match"); sdsfree(r); cJSON_Delete(a); }
    // 16 group + choice
    { cJSON *a=args("(\"a\"/\"b\")+","abba"); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "group choice"); CHECK(strstr(r,"\"length\":4")!=NULL, "group len 4"); sdsfree(r); cJSON_Delete(a); }
    // 17 start offset
    { cJSON *a=args_start("\"b\"","ab",1); sds r=tools_run("peg_match",a,"."); CHECK(is_matched(r), "start offset match"); sdsfree(r); cJSON_Delete(a); }
    // 18 adversarial negative start
    { cJSON *a=args_start("\"a\"","a",-1); sds r=tools_run("peg_match",a,"."); CHECK(has_err(r), "negative start rejected"); sdsfree(r); cJSON_Delete(a); }
    // 19 adversarial out of bounds start
    { cJSON *a=args_start("\"a\"","a",5); sds r=tools_run("peg_match",a,"."); CHECK(has_err(r), "out of bounds start rejected"); sdsfree(r); cJSON_Delete(a); }
    // 20 adversarial missing pattern
    { cJSON *b=cJSON_CreateObject(); cJSON_AddStringToObject(b,"input","hi"); sds r=tools_run("peg_match",b,"."); CHECK(has_err(r), "missing pattern rejected"); sdsfree(r); cJSON_Delete(b); }
    // 21 unterminated string error
    { cJSON *a=args("\"hello","hello"); sds r=tools_run("peg_match",a,"."); CHECK(has_err(r), "unterminated literal rejected"); sdsfree(r); cJSON_Delete(a); }
    // 22 alias peg
    { cJSON *a=args("\"hi\"","hi"); sds r=tools_run("peg",a,"."); CHECK(is_matched(r), "alias peg works"); sdsfree(r); cJSON_Delete(a); }
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    test_peg_patterns();
    return test_report("test_peg_match");
}
