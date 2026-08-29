#include "alpha.h"
#include "test_util.h"
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("gorilla");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","encode_timestamps");
        cJSON *ts=cJSON_CreateArray();
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1000));
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1010));
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1020));
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1030));
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1042));
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1052));
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(1062));
        cJSON_AddItemToObject(a,"timestamps",ts);
        sds r=tools_run("gorilla",a,NULL);
        CHECK(r!=NULL,"encode response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            CHECK(cJSON_GetObjectItem(p,"t0")->valuedouble==1000.0,"t0 matches");
            CHECK(cJSON_GetObjectItem(p,"initial_delta")->valuedouble==10.0,"initial_delta matches 10");
            CHECK(cJSON_GetObjectItem(p,"perfect_cadence_count")->valueint==3,"3 zero double-deltas detected");
            cJSON *dec=cJSON_CreateObject();
            cJSON_AddStringToObject(dec,"action","decode_timestamps");
            cJSON_AddNumberToObject(dec,"t0",cJSON_GetObjectItem(p,"t0")->valuedouble);
            cJSON_AddNumberToObject(dec,"initial_delta",cJSON_GetObjectItem(p,"initial_delta")->valuedouble);
            cJSON_AddItemToObject(dec,"double_deltas",cJSON_Duplicate(cJSON_GetObjectItem(p,"double_deltas"),1));
            sds dr=tools_run("gorilla",dec,NULL);
            CHECK(dr!=NULL,"decode response returned");
            cJSON *dp=P(dr);
            CHECK(dp!=NULL,"valid decode json");
            if(dp){
                cJSON *dts=cJSON_GetObjectItem(dp,"timestamps");
                CHECK(cJSON_GetArraySize(dts)==7,"all 7 timestamps recovered");
                CHECK(cJSON_GetArrayItem(dts,0)->valuedouble==1000.0,"ts[0] matches");
                CHECK(cJSON_GetArrayItem(dts,4)->valuedouble==1042.0,"ts[4] matches 1042");
                CHECK(cJSON_GetArrayItem(dts,6)->valuedouble==1062.0,"ts[6] matches 1062");
                cJSON_Delete(dp);
            }
            sdsfree(dr); cJSON_Delete(dec);
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","encode_timestamps");
        cJSON *ts=cJSON_CreateArray();
        cJSON_AddItemToArray(ts,cJSON_CreateNumber(100));
        cJSON_AddItemToObject(a,"timestamps",ts);
        sds r=tools_run("gorilla",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"single timestamp rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("gorilla");
}
