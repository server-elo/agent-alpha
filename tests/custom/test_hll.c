#include "alpha.h"
#include "test_util.h"
#include <math.h>
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("hll");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","count");
        cJSON *items=cJSON_CreateArray();
        cJSON_AddItemToArray(items,cJSON_CreateString("apple"));
        cJSON_AddItemToArray(items,cJSON_CreateString("banana"));
        cJSON_AddItemToArray(items,cJSON_CreateString("apple"));
        cJSON_AddItemToArray(items,cJSON_CreateString("cherry"));
        cJSON_AddItemToArray(items,cJSON_CreateString("banana"));
        cJSON_AddItemToArray(items,cJSON_CreateString("date"));
        cJSON_AddItemToArray(items,cJSON_CreateString("elderberry"));
        cJSON_AddItemToObject(a,"items",items);
        sds r=tools_run("hll",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            CHECK(cJSON_GetObjectItem(p,"raw_items_processed")->valueint==7,"processed 7 items");
            CHECK(cJSON_GetObjectItem(p,"estimated_cardinality")->valueint==5,"exact 5 unique items estimated");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","count");
        cJSON *items=cJSON_CreateArray();
        for(int i=0;i<2000;i++){ char buf[32]; snprintf(buf,sizeof(buf),"user_%d",i); cJSON_AddItemToArray(items,cJSON_CreateString(buf)); }
        cJSON_AddItemToObject(a,"items",items);
        sds r=tools_run("hll",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            double est=cJSON_GetObjectItem(p,"estimated_cardinality")->valuedouble;
            CHECK(fabs(est-2000.0)<60.0,"2000 items estimated within <3% standard error");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","count");
        sds r=tools_run("hll",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"missing items rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("hll");
}
