/* test_stats.c — tests for stats tool (describe/histogram/correlation/normalize/percentile) */
#include "alpha.h"
#include "test_util.h"

sds tools_run(const char *name, cJSON *args, const char *cwd);

int main(void){
    TEST_BEGIN("stats_tool");

    /* 1. describe basic */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","describe");
        cJSON_AddStringToObject(a,"data","[1,2,3,4,5]");
        sds r=tools_run("stats",a,NULL);
        CHECK(r!=NULL,"describe returned non-NULL");
        CHECK(strstr(r,"\"count\":5")!=NULL,"describe count 5");
        CHECK(strstr(r,"\"mean\":3")!=NULL,"describe mean 3");
        CHECK(strstr(r,"\"median\":3")!=NULL,"describe median 3");
        CHECK(strstr(r,"\"min\":1")!=NULL,"describe min 1");
        CHECK(strstr(r,"\"max\":5")!=NULL,"describe max 5");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. describe variance/stdev */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","describe");
        cJSON_AddStringToObject(a,"data","[2,4,4,4,5,5,7,9]");
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"count\":8")!=NULL,"describe count 8");
        CHECK(strstr(r,"\"mean\":5")!=NULL,"describe mean 5 for classic dataset");
        CHECK(strstr(r,"variance")!=NULL,"describe has variance");
        CHECK(strstr(r,"stdev")!=NULL,"describe has stdev");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. histogram default bins */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","histogram");
        cJSON_AddStringToObject(a,"data","[1,2,2,3,3,3,4,4,5]");
        cJSON_AddNumberToObject(a,"bins",5);
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"bins\":5")!=NULL,"histogram bins 5");
        CHECK(strstr(r,"\"counts\"")!=NULL,"histogram has counts");
        CHECK(strstr(r,"\"edges\"")!=NULL,"histogram has edges");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. histogram counts sum equals n */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","histogram");
        cJSON_AddStringToObject(a,"data","[0,0,10,10]");
        cJSON_AddNumberToObject(a,"bins",2);
        sds r=tools_run("stats",a,NULL);
        /* should have 2 bins, counts [2,2] */
        CHECK(strstr(r,"\"counts\":[2,2]")!=NULL,"histogram counts [2,2] for 2 bins");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. correlation perfect positive */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","correlation");
        cJSON *x=cJSON_CreateArray(); cJSON_AddItemToArray(x,cJSON_CreateNumber(1)); cJSON_AddItemToArray(x,cJSON_CreateNumber(2)); cJSON_AddItemToArray(x,cJSON_CreateNumber(3));
        cJSON *y=cJSON_CreateArray(); cJSON_AddItemToArray(y,cJSON_CreateNumber(2)); cJSON_AddItemToArray(y,cJSON_CreateNumber(4)); cJSON_AddItemToArray(y,cJSON_CreateNumber(6));
        cJSON_AddItemToObject(a,"x",x);
        cJSON_AddItemToObject(a,"y",y);
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"r\":1")!=NULL,"correlation r=1 perfect positive");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. correlation negative */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","correlation");
        cJSON_AddStringToObject(a,"x","[1,2,3,4,5]");
        cJSON_AddStringToObject(a,"y","[5,4,3,2,1]");
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"r\":-1")!=NULL,"correlation r=-1 perfect negative");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. correlation with string-encoded arrays */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","correlation");
        cJSON_AddStringToObject(a,"x","[1,2,3]");
        cJSON_AddStringToObject(a,"y","[1,2,3]");
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"n\":3")!=NULL,"correlation n=3 via string arrays");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. normalize zscore */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","normalize");
        cJSON_AddStringToObject(a,"data","[1,2,3,4,5]");
        cJSON_AddStringToObject(a,"method","zscore");
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"method\":\"zscore\"")!=NULL,"normalize zscore method");
        CHECK(strstr(r,"\"mean\":3")!=NULL,"normalize zscore mean 3");
        CHECK(strstr(r,"\"data\":[")!=NULL,"normalize has data array");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 9. normalize minmax */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","normalize");
        cJSON_AddStringToObject(a,"data","[0,5,10]");
        cJSON_AddStringToObject(a,"method","minmax");
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"method\":\"minmax\"")!=NULL,"normalize minmax method");
        CHECK(strstr(r,"\"min\":0")!=NULL,"normalize minmax min 0");
        CHECK(strstr(r,"\"max\":10")!=NULL,"normalize minmax max 10");
        CHECK(strstr(r,"0,0.5,1")!=NULL,"normalize minmax data 0,0.5,1");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 10. percentile median = 50th */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","percentile");
        cJSON_AddStringToObject(a,"data","[1,2,3,4,5]");
        cJSON_AddNumberToObject(a,"p",50);
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"p\":50")!=NULL,"percentile p 50");
        CHECK(strstr(r,"\"value\":3")!=NULL,"percentile 50 -> 3");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 11. percentile 0 and 100 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","percentile");
        cJSON_AddStringToObject(a,"data","[10,20,30]");
        cJSON_AddNumberToObject(a,"p",0);
        sds r=tools_run("stats",a,NULL);
        CHECK(strstr(r,"\"value\":10")!=NULL,"percentile 0 -> min 10");
        sdsfree(r); cJSON_Delete(a);
        cJSON *b=cJSON_CreateObject();
        cJSON_AddStringToObject(b,"action","percentile");
        cJSON_AddStringToObject(b,"data","[10,20,30]");
        cJSON_AddNumberToObject(b,"p",100);
        sds r2=tools_run("stats",b,NULL);
        CHECK(strstr(r2,"\"value\":30")!=NULL,"percentile 100 -> max 30");
        sdsfree(r2); cJSON_Delete(b);
    }
    /* 12. error handling: missing data */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","describe");
        sds r=tools_run("stats",a,NULL);
        CHECK(strncmp(r,"ERROR",5)==0,"describe missing data -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 13. alias via describe (tool alias) */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","describe");
        cJSON_AddStringToObject(a,"data","[7,7,7]");
        sds r=tools_run("describe",a,NULL);
        CHECK(strstr(r,"\"mean\":7")!=NULL,"alias 'describe' works");
        sdsfree(r); cJSON_Delete(a);
    }

    return test_report("stats_tool");
}
