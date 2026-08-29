/* test_tokenizer.c — tests for tokenizer (spec-driven longest-match lexing) */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

static cJSON *sp(const char *name, const char *pattern, int skip){
    cJSON *s=cJSON_CreateObject();
    cJSON_AddStringToObject(s,"name",name);
    cJSON_AddStringToObject(s,"pattern",pattern);
    if(skip) cJSON_AddBoolToObject(s,"skip",1);
    return s;
}

int main(void){
    TEST_BEGIN("tokenizer");

    /* 1. arithmetic token stream with skipped whitespace */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *specs=cJSON_CreateArray();
        cJSON_AddItemToArray(specs,sp("WS"," +",1));
        cJSON_AddItemToArray(specs,sp("INT","[0-9]+",0));
        cJSON_AddItemToArray(specs,sp("OP","[+-]",0));
        cJSON_AddItemToObject(a,"specs",specs);
        cJSON_AddStringToObject(a,"input","12 + 7-3");
        sds r=tools_run("tokenizer",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"arith tokenizes");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"count")),5,"five tokens");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"consumed")),8,"consumed 8");
            cJSON *toks=cJSON_GetObjectItem(p,"tokens");
            cJSON *t0=toks?cJSON_GetArrayItem(toks,0):NULL;
            CHECK(t0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(t0,"type")),"INT")==0,"tok0 INT");
            CHECK(t0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(t0,"value")),"12")==0,"tok0 value 12");
            CHECK(t0 && (int)cJSON_GetNumberValue(cJSON_GetObjectItem(t0,"col"))==1,"tok0 col 1");
            cJSON *t1=toks?cJSON_GetArrayItem(toks,1):NULL;
            CHECK(t1 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(t1,"value")),"+")==0,"tok1 is +");
            cJSON *t4=toks?cJSON_GetArrayItem(toks,4):NULL;
            CHECK(t4 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(t4,"type")),"INT")==0,"last INT 3");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. longest match wins over keyword */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *specs=cJSON_CreateArray();
        cJSON_AddItemToArray(specs,sp("KW","for",0));
        cJSON_AddItemToArray(specs,sp("ID","[a-z]+",0));
        cJSON_AddItemToObject(a,"specs",specs);
        cJSON_AddStringToObject(a,"input","format");
        sds r=tools_run("tokenizer",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"longest match tokenizes");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"count")),1,"one token");
            cJSON *toks=cJSON_GetObjectItem(p,"tokens");
            cJSON *t0=toks?cJSON_GetArrayItem(toks,0):NULL;
            CHECK(t0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(t0,"type")),"ID")==0,"ID not KW");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. tie (same length) goes to earlier spec */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *specs=cJSON_CreateArray();
        cJSON_AddItemToArray(specs,sp("KW","for",0));
        cJSON_AddItemToArray(specs,sp("ID","[a-z]+",0));
        cJSON_AddItemToObject(a,"specs",specs);
        cJSON_AddStringToObject(a,"input","for");
        sds r=tools_run("tokenizer",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"tie tokenizes");
        if(p){
            cJSON *toks=cJSON_GetObjectItem(p,"tokens");
            cJSON *t0=toks?cJSON_GetArrayItem(toks,0):NULL;
            CHECK(t0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(t0,"type")),"KW")==0,"KW on tie");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. validate action checks specs only */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","validate");
        cJSON *specs=cJSON_CreateArray();
        cJSON_AddItemToArray(specs,sp("INT","[0-9]+",0));
        cJSON_AddItemToObject(a,"specs",specs);
        sds r=tools_run("tokenizer",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"validate parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"specs valid");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"count")),1,"one spec");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. invalid spec -> error naming it */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *specs=cJSON_CreateArray();
        cJSON_AddItemToArray(specs,sp("BAD","[0-9",0));
        cJSON_AddItemToObject(a,"specs",specs);
        cJSON_AddStringToObject(a,"input","1");
        sds r=tools_run("tokenizer",a,NULL);
        CHECK(IS_ERR(r),"bad spec errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. unlexable input -> error with position */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *specs=cJSON_CreateArray();
        cJSON_AddItemToArray(specs,sp("INT","[0-9]+",0));
        cJSON_AddItemToObject(a,"specs",specs);
        cJSON_AddStringToObject(a,"input","x");
        sds r=tools_run("tokenizer",a,NULL);
        CHECK(IS_ERR(r),"unlexable errors");
        CHECK(r && strstr(r,"offset 0")!=NULL,"position reported");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. missing specs -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"input","1");
        sds r=tools_run("tokenizer",a,NULL);
        CHECK(IS_ERR(r),"missing specs error");
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("tokenizer");
}
