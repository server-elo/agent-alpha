#include "alpha.h"
#include "test_util.h"
#include <math.h>
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("bezier_easing");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"preset","linear");
        cJSON_AddNumberToObject(a,"x",0.5);
        sds r=tools_run("bezier_easing",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            CHECK(fabs(cJSON_GetObjectItem(p,"y")->valuedouble-0.5)<1e-4,"linear at 0.5 is 0.5");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"preset","ease-in");
        cJSON_AddNumberToObject(a,"x",0.5);
        sds r=tools_run("bezier_easing",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(cJSON_GetObjectItem(p,"y")->valuedouble<0.4,"ease-in at 0.5 is slow"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"preset","ease-out");
        cJSON_AddNumberToObject(a,"x",0.5);
        sds r=tools_run("bezier_easing",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(cJSON_GetObjectItem(p,"y")->valuedouble>0.6,"ease-out at 0.5 is fast"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON_AddStringToObject(a,"preset","ease-in-out");
        cJSON_AddNumberToObject(a,"samples",11);
        sds r=tools_run("bezier_easing",a,NULL);
        CHECK(r!=NULL,"sample response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            cJSON *pts=cJSON_GetObjectItem(p,"points");
            CHECK(cJSON_GetArraySize(pts)==11,"11 sample points returned");
            cJSON *first=cJSON_GetArrayItem(pts,0);
            cJSON *last=cJSON_GetArrayItem(pts,10);
            CHECK(fabs(cJSON_GetObjectItem(first,"x")->valuedouble-0.0)<1e-4,"first x is 0");
            CHECK(fabs(cJSON_GetObjectItem(first,"y")->valuedouble-0.0)<1e-4,"first y is 0");
            CHECK(fabs(cJSON_GetObjectItem(last,"x")->valuedouble-1.0)<1e-4,"last x is 1");
            CHECK(fabs(cJSON_GetObjectItem(last,"y")->valuedouble-1.0)<1e-4,"last y is 1");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"preset","invalid_preset");
        sds r=tools_run("bezier_easing",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"invalid preset rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("bezier_easing");
}
