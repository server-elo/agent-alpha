/* test_linkage.c — tests for linkage (link-grammar validator) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

static cJSON *dw(const char *word, const char *left, const char *right){
    cJSON *w=cJSON_CreateObject();
    cJSON_AddStringToObject(w,"word",word);
    if(left){ cJSON *l=cJSON_CreateArray(); cJSON_AddItemToArray(l,cJSON_CreateString(left)); cJSON_AddItemToObject(w,"left",l); }
    if(right){ cJSON *r=cJSON_CreateArray(); cJSON_AddItemToArray(r,cJSON_CreateString(right)); cJSON_AddItemToObject(w,"right",r); }
    return w;
}

int main(void){
    TEST_BEGIN("linkage");

    /* 1. valid linkage: "dogs bark" with S- connector */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *d=cJSON_CreateArray();
        cJSON_AddItemToArray(d,dw("dogs",NULL,"S-"));
        cJSON_AddItemToArray(d,dw("bark","S-",NULL));
        cJSON_AddItemToObject(a,"dictionary",d);
        cJSON_AddStringToObject(a,"sentence","dogs bark");
        sds r=tools_run("linkage",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid linkage parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"valid true");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"link_count")),1,"one link");
            cJSON *links=cJSON_GetObjectItem(p,"links");
            cJSON *l0=cJSON_GetArrayItem(links,0);
            CHECK(l0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(l0,"connector")),"S-")==0,"connector S-");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. impossible linkage: two words, no way to connect */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *d=cJSON_CreateArray();
        cJSON_AddItemToArray(d,dw("dogs",NULL,"S-"));
        cJSON_AddItemToArray(d,dw("cats",NULL,"S-"));
        cJSON_AddItemToObject(a,"dictionary",d);
        cJSON_AddStringToObject(a,"sentence","dogs cats");
        sds r=tools_run("linkage",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"invalid linkage parses");
        if(p){
            CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"valid false");
            cJSON *reason=cJSON_GetObjectItem(p,"reason");
            CHECK(reason && cJSON_GetStringValue(reason)!=NULL,"reason present");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. sentence given as array of word strings */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *d=cJSON_CreateArray();
        cJSON_AddItemToArray(d,dw("dogs",NULL,"S-"));
        cJSON_AddItemToArray(d,dw("run","S-",NULL));
        cJSON_AddItemToObject(a,"dictionary",d);
        cJSON *s=cJSON_CreateArray();
        cJSON_AddItemToArray(s,cJSON_CreateString("dogs"));
        cJSON_AddItemToArray(s,cJSON_CreateString("run"));
        cJSON_AddItemToObject(a,"sentence",s);
        sds r=tools_run("linkage",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"array sentence parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"array sentence valid");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. missing dictionary -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"sentence","dogs bark");
        sds r=tools_run("linkage",a,NULL);
        CHECK(IS_ERR(r),"missing dictionary is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. missing sentence -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *d=cJSON_CreateArray();
        cJSON_AddItemToArray(d,dw("dogs",NULL,"S-"));
        cJSON_AddItemToObject(a,"dictionary",d);
        sds r=tools_run("linkage",a,NULL);
        CHECK(IS_ERR(r),"missing sentence is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. word absent from dictionary -> invalid */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *d=cJSON_CreateArray();
        cJSON_AddItemToArray(d,dw("dogs",NULL,"S-"));
        cJSON_AddItemToObject(a,"dictionary",d);
        cJSON_AddStringToObject(a,"sentence","dogs");
        sds r=tools_run("linkage",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"unknown word parses");
        if(p){ CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"unknown word invalid"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. three-word chain, two links */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON *d=cJSON_CreateArray();
        cJSON_AddItemToArray(d,dw("the",NULL,"D-"));
        cJSON_AddItemToArray(d,dw("dog","D-","V-"));
        cJSON_AddItemToArray(d,dw("barks","V-",NULL));
        cJSON_AddItemToObject(a,"dictionary",d);
        cJSON_AddStringToObject(a,"sentence","the dog barks");
        sds r=tools_run("linkage",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"chain parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"three-word chain valid");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"link_count")),2,"two links");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("linkage");
}
