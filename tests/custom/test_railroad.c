/* test_railroad.c — tests for railroad (EBNF ASCII diagram renderer) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

int main(void){
    TEST_BEGIN("railroad");

    /* 1. render simple repetition rule */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"grammar","expr = term { '+' term } ;");
        sds r=tools_run("railroad",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"render parses");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"rule_count")),1,"one rule");
            cJSON *rules=cJSON_GetObjectItem(p,"rules");
            cJSON *r0=cJSON_GetArrayItem(rules,0);
            CHECK(r0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(r0,"name")),"expr")==0,"rule name expr");
            cJSON *diag=r0?cJSON_GetObjectItem(r0,"diagram"):NULL;
            CHECK(diag && cJSON_GetStringValue(diag)!=NULL,"diagram present");
            if(diag && cJSON_GetStringValue(diag)){
                CHECK(strstr(cJSON_GetStringValue(diag),"(term)")!=NULL,"diagram mentions term");
            }
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. multiple rules */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"grammar","a = 'x' ;\nb = a 'y' ;");
        sds r=tools_run("railroad",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"multi-rule parses");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"rule_count")),2,"two rules");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. validate-only action accepts and reports */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","validate");
        cJSON_AddStringToObject(a,"grammar","x = [ 'a' \n ] ;");
        sds r=tools_run("railroad",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"validate action parses");
        if(p){ cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. malformed grammar -> error with position */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"grammar","a = ( b c ;");
        sds r=tools_run("railroad",a,NULL);
        CHECK(IS_ERR(r),"malformed grammar errors");
        CHECK(r && strstr(r,"col")!=NULL,"error reports a position");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. missing grammar -> error */
    {
        cJSON *a=cJSON_CreateObject();
        sds r=tools_run("railroad",a,NULL);
        CHECK(IS_ERR(r),"missing grammar is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. text alias works like grammar */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"text","g = 'x' ;");
        sds r=tools_run("railroad",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"text alias parses");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"rule_count")),1,"alias renders one rule");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. alternation renders */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"grammar","alt = 'a' | 'b' | 'c' ;");
        sds r=tools_run("railroad",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"alternation parses");
        if(p){
            cJSON *rules=cJSON_GetObjectItem(p,"rules");
            cJSON *r0=cJSON_GetArrayItem(rules,0);
            CHECK(r0 && cJSON_GetNumberValue(cJSON_GetObjectItem(r0,"height"))>=3,"alternation has height");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("railroad");
}
