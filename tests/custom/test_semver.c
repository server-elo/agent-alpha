/* test_semver.c — tests for semver (Semantic Versioning 2.0.0) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }

int main(void){
    TEST_BEGIN("semver");

    /* 1. parse simple */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"version","1.2.3");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"parse 1.2.3 JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"major")),1,"major 1");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"minor")),2,"minor 2");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"patch")),3,"patch 3");
            CHECK(cJSON_IsNull(cJSON_GetObjectItem(p,"prerelease")),"no prerelease");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. parse with prerelease and build */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"version","2.0.0-alpha.1+001");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"parse prerelease+build JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"major")),2,"major 2");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"prerelease")),"alpha.1")==0,"prerelease alpha.1");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"build")),"001")==0,"build 001");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. valid true */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","valid");
        cJSON_AddStringToObject(a,"version","0.1.0");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid true JSON");
        if(p){ CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"0.1.0 valid"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. valid false: leading zero */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","valid");
        cJSON_AddStringToObject(a,"version","01.2.3");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"valid")),"01.2.3 invalid false"); cJSON_Delete(p); }
        else CHECK(0,"valid false parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. valid false: missing patch */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","valid");
        cJSON_AddStringToObject(a,"version","1.2");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"valid")),"1.2 invalid"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. compare equal */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"v1","1.2.3");
        cJSON_AddStringToObject(a,"v2","1.2.3");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"cmp")),0,"compare equal 0"); CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"equal")),"equal true"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. compare less */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"v1","1.0.0");
        cJSON_AddStringToObject(a,"v2","2.0.0");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"cmp")),-1,"1.0.0 < 2.0.0"); CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"less")),"less true"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. compare prerelease precedence */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"v1","1.0.0-alpha");
        cJSON_AddStringToObject(a,"v2","1.0.0");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"cmp")),-1,"prerelease < release"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 9. compare prerelease numeric vs alphanumeric */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"v1","1.0.0-alpha.1");
        cJSON_AddStringToObject(a,"v2","1.0.0-alpha.beta");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"cmp")),-1,"numeric prerelease < alphanumeric"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 10. inc patch */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","inc");
        cJSON_AddStringToObject(a,"version","1.2.3");
        cJSON_AddStringToObject(a,"bump","patch");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"version")),"1.2.4")==0,"patch bump 1.2.3->1.2.4"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 11. inc minor */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","inc");
        cJSON_AddStringToObject(a,"version","1.2.3");
        cJSON_AddStringToObject(a,"bump","minor");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"version")),"1.3.0")==0,"minor bump"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 12. inc major */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","inc");
        cJSON_AddStringToObject(a,"version","1.2.3");
        cJSON_AddStringToObject(a,"bump","major");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"version")),"2.0.0")==0,"major bump"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 13. inc clears prerelease */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","inc");
        cJSON_AddStringToObject(a,"version","1.2.3-alpha+001");
        cJSON_AddStringToObject(a,"bump","patch");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"version")),"1.2.4")==0,"inc clears prerelease/build"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 14. sort asc */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sort");
        cJSON *arr=cJSON_CreateArray();
        cJSON_AddItemToArray(arr,cJSON_CreateString("1.0.0"));
        cJSON_AddItemToArray(arr,cJSON_CreateString("2.0.0-alpha"));
        cJSON_AddItemToArray(arr,cJSON_CreateString("1.0.1"));
        cJSON_AddItemToArray(arr,cJSON_CreateString("2.0.0"));
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *v=cJSON_GetObjectItem(p,"versions");
            CHECK(v && cJSON_GetArraySize(v)==4,"sort asc size 4");
            if(v && cJSON_GetArraySize(v)==4){
                CHECK(strcmp(cJSON_GetArrayItem(v,0)->valuestring,"1.0.0")==0,"sort asc first 1.0.0");
                CHECK(strcmp(cJSON_GetArrayItem(v,1)->valuestring,"1.0.1")==0,"sort asc second 1.0.1");
                CHECK(strcmp(cJSON_GetArrayItem(v,2)->valuestring,"2.0.0-alpha")==0,"sort asc third prerelease");
                CHECK(strcmp(cJSON_GetArrayItem(v,3)->valuestring,"2.0.0")==0,"sort asc last 2.0.0");
            }
            cJSON_Delete(p);
        } else CHECK(0,"sort asc parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 15. sort desc */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sort");
        cJSON *arr=cJSON_CreateArray();
        cJSON_AddItemToArray(arr,cJSON_CreateString("1.0.0"));
        cJSON_AddItemToArray(arr,cJSON_CreateString("2.0.0"));
        cJSON_AddItemToArray(arr,cJSON_CreateString("1.5.0"));
        cJSON_AddItemToObject(a,"data",arr);
        cJSON_AddStringToObject(a,"order","desc");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *v=cJSON_GetObjectItem(p,"versions");
            if(v && cJSON_GetArraySize(v)==3){
                CHECK(strcmp(cJSON_GetArrayItem(v,0)->valuestring,"2.0.0")==0,"sort desc first 2.0.0");
                CHECK(strcmp(cJSON_GetArrayItem(v,2)->valuestring,"1.0.0")==0,"sort desc last 1.0.0");
            } else CHECK(0,"sort desc size");
            cJSON_Delete(p);
        } else CHECK(0,"sort desc parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 16. v prefix handling */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"version","v1.2.3");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"major")),1,"v prefix major 1"); cJSON_Delete(p); }
        else CHECK(0,"v prefix parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 17. alias version -> semver_compare */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"v1","1.0.0");
        cJSON_AddStringToObject(a,"v2","1.0.0");
        sds r=tools_run("version",a,NULL);
        CHECK(r!=NULL,"alias version works");
        if(r){ cJSON *p=P(r); if(p) cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 18. invalid prerelease leading zero */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","valid");
        cJSON_AddStringToObject(a,"version","1.0.0-alpha.01");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"valid")),"prerelease numeric leading zero invalid"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 19. build metadata does not affect precedence */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"v1","1.0.0+001");
        cJSON_AddStringToObject(a,"v2","1.0.0+20130313144700");
        sds r=tools_run("semver",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"cmp")),0,"build metadata equal"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 20. schema includes semver */
    {
        cJSON *schema=tools_schema();
        CHECK(schema!=NULL,"tools_schema non-null");
        if(schema){
            int found=0;
            int n=cJSON_GetArraySize(schema);
            for(int i=0;i<n;i++){
                cJSON *item=cJSON_GetArrayItem(schema,i);
                cJSON *func=cJSON_GetObjectItem(item,"function");
                if(!func) func=item;
                cJSON *nm=cJSON_GetObjectItem(func,"name");
                if(nm && cJSON_IsString(nm) && strcmp(nm->valuestring,"semver")==0) found=1;
            }
            CHECK(found,"schema contains semver");
            cJSON_Delete(schema);
        }
    }

    return test_report("semver");
}
