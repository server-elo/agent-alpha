/* test_wildmatch.c — tests for wildmatch (gitignore-style matcher) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

static cJSON *match_req(const char *pat, const char *path){
    cJSON *a=cJSON_CreateObject();
    cJSON_AddStringToObject(a,"action","match");
    cJSON_AddStringToObject(a,"pattern",pat);
    cJSON_AddStringToObject(a,"path",path);
    return a;
}

int main(void){
    TEST_BEGIN("wildmatch");

    /* 1. ** spans directories */
    {
        cJSON *a=match_req("**/doc/*.md","a/b/doc/x.md");
        sds r=tools_run("wildmatch",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"** match parses");
        if(p){ CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"match")),"** matches"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. plain * never crosses '/' */
    {
        cJSON *a=match_req("*.js","a/b.js");
        sds r=tools_run("wildmatch",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"* no-slash-match parses");
        if(p){ CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"match")),"star does not cross slash"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. character class range */
    {
        cJSON *a=match_req("fo[a-c]","fob");
        sds r=tools_run("wildmatch",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"range parses");
        if(p){ CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"match")),"class range matches"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. negated class */
    {
        cJSON *a=match_req("fo[^a-c]","foz");
        sds r=tools_run("wildmatch",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"negated class parses");
        if(p){ CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"match")),"negated class matches"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. '?' single char */
    {
        cJSON *a=match_req("ab?","abc");
        sds r=tools_run("wildmatch",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"? parses");
        if(p){ CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"match")),"? matches one char"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. gitignore filter: negation, dir-only, basename rules */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","filter");
        cJSON_AddStringToObject(a,"rules","*.log\n!keep.log\nbuild/\n");
        cJSON *paths=cJSON_CreateArray();
        cJSON_AddItemToArray(paths,cJSON_CreateString("a.log"));
        cJSON_AddItemToArray(paths,cJSON_CreateString("keep.log"));
        cJSON_AddItemToArray(paths,cJSON_CreateString("build/x.c"));
        cJSON_AddItemToArray(paths,cJSON_CreateString("src/b.log"));
        cJSON_AddItemToObject(a,"paths",paths);
        sds r=tools_run("wildmatch",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"filter parses");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"count")),4,"four paths");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"ignored_count")),3,"three ignored");
            cJSON *ign=cJSON_GetObjectItem(p,"ignored_paths");
            CHECK(ign && cJSON_GetArraySize(ign)==3,"ignored_paths length");
            cJSON *res=cJSON_GetObjectItem(p,"results");
            cJSON *r1=res?cJSON_GetArrayItem(res,1):NULL;
            CHECK(r1 && !cJSON_IsTrue(cJSON_GetObjectItem(r1,"ignored")),"keep.log survives negation");
            CHECK(r1 && cJSON_IsTrue(cJSON_GetObjectItem(r1,"negated")),"keep.log flagged negated");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. match with missing pattern -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","match");
        cJSON_AddStringToObject(a,"path","x.js");
        sds r=tools_run("wildmatch",a,NULL);
        CHECK(IS_ERR(r),"missing pattern errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. filter with missing rules -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","filter");
        cJSON *paths=cJSON_CreateArray();
        cJSON_AddItemToArray(paths,cJSON_CreateString("a.log"));
        cJSON_AddItemToObject(a,"paths",paths);
        sds r=tools_run("wildmatch",a,NULL);
        CHECK(IS_ERR(r),"missing rules errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 9. unknown action -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","wombat");
        sds r=tools_run("wildmatch",a,NULL);
        CHECK(IS_ERR(r),"unknown action errors");
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("wildmatch");
}
