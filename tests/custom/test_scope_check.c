/* test_scope_check.c — tests for scope_check (comment/string-aware delimiter
 * balance checker) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

int main(void){
    TEST_BEGIN("scope_check");

    /* 1. balanced C with comment and string braces */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"text","int main(){ /* { */ char s[] = \"}\"; int x = (1+2); return x; }");
        sds r=tools_run("scope_check",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"balanced c parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"balanced")),"balanced true");
            CHECK(cJSON_GetObjectItem(p,"first_error")==NULL || cJSON_IsNull(cJSON_GetObjectItem(p,"first_error")),"no first_error");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. unbalanced ruby: close '}' where '(' expected */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"text","def foo { (1+2 }");
        cJSON_AddStringToObject(a,"lang","ruby");
        sds r=tools_run("scope_check",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"unbalanced ruby parses");
        if(p){
            CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"balanced")),"unbalanced false");
            cJSON *fe=cJSON_GetObjectItem(p,"first_error");
            CHECK(fe && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(fe,"type")),"mismatch")==0,"mismatch type");
            CHECK(fe && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(fe,"char")),"}")==0,"close char }");
            CHECK(fe && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(fe,"expected")),")")==0,"expected )");
            cJSON *unc=cJSON_GetObjectItem(p,"unclosed");
            CHECK(unc && cJSON_GetArraySize(unc)>=1,"unclosed listed");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. profiles listing */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","profiles");
        sds r=tools_run("scope_check",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"profiles parses");
        if(p){
            cJSON *pr=cJSON_GetObjectItem(p,"profiles");
            CHECK(pr && cJSON_GetArraySize(pr)==3,"three profiles");
            if(pr && cJSON_GetArraySize(pr)==3){
                cJSON *c0=cJSON_GetArrayItem(pr,0);
                CHECK(c0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(c0,"lang")),"c")==0,"profile c");
                CHECK(c0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(c0,"block_comment_start")),"/*")==0,"c block start");
            }
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. custom bracket pairs */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"text","<a><b>x</b></a>");
        cJSON_AddStringToObject(a,"pairs","<>");
        sds r=tools_run("scope_check",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"custom pairs parse");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"balanced")),"angle brackets balanced");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. missing text -> error */
    {
        cJSON *a=cJSON_CreateObject();
        sds r=tools_run("scope_check",a,NULL);
        CHECK(IS_ERR(r),"missing text errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. unclosed trailing bracket reported */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"text","int f(int a){ return (a; }");
        sds r=tools_run("scope_check",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"unclosed report parses");
        if(p){
            CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"balanced")),"unclosed unbalanced");
            cJSON *unc=cJSON_GetObjectItem(p,"unclosed");
            CHECK(unc && cJSON_GetArraySize(unc)>=1,"has unclosed entries");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. python triple-quote long string keeps braces out of scope */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"text","x = \"\"\"{(}\"\"\"\n");
        cJSON_AddStringToObject(a,"lang","python");
        sds r=tools_run("scope_check",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"python parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"balanced")),"braces in long string ignored");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("scope_check");
}
