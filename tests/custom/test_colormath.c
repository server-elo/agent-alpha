#include "alpha.h"
#include "test_util.h"
#include <math.h>
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("colormath");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","convert");
        cJSON_AddStringToObject(a,"color","#38bdf8");
        sds r=tools_run("colormath",a,NULL);
        CHECK(r!=NULL,"colormath returns response");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            cJSON *rgb=cJSON_GetObjectItem(p,"rgb");
            CHECK(cJSON_GetObjectItem(rgb,"r")->valueint==56,"r matches");
            CHECK(cJSON_GetObjectItem(rgb,"g")->valueint==189,"g matches");
            CHECK(cJSON_GetObjectItem(rgb,"b")->valueint==248,"b matches");
            cJSON *hsl=cJSON_GetObjectItem(p,"hsl");
            CHECK(fabs(cJSON_GetObjectItem(hsl,"h")->valuedouble-198.4)<1.0,"hue matches");
            cJSON *ok=cJSON_GetObjectItem(p,"oklab");
            CHECK(cJSON_GetObjectItem(ok,"L")->valuedouble>0.6 && cJSON_GetObjectItem(ok,"L")->valuedouble<0.8,"oklab L in range");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","delta_e");
        cJSON_AddStringToObject(a,"color1","#FF0000");
        cJSON_AddStringToObject(a,"color2","#FE0201");
        sds r=tools_run("colormath",a,NULL);
        CHECK(r!=NULL,"delta_e response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            CHECK(cJSON_GetObjectItem(p,"delta_e_2000")->valuedouble<1.5,"delta_e_2000 is small for near-identical colors");
            CHECK(cJSON_GetObjectItem(p,"delta_e_76")->valuedouble<2.5,"delta_e_76 is small");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","delta_e");
        cJSON_AddStringToObject(a,"color1","#FF0000");
        cJSON_AddStringToObject(a,"color2","#00FFFF");
        r=tools_run("colormath",a,NULL);
        p=P(r);
        CHECK(p!=NULL,"opposites valid json");
        if(p){
            CHECK(cJSON_GetObjectItem(p,"delta_e_2000")->valuedouble>40.0,"delta_e_2000 is large for opposites");
            CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"perceptually_identical")),"not identical");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","kelvin");
        cJSON_AddNumberToObject(a,"kelvin",6500.0);
        sds r=tools_run("colormath",a,NULL);
        CHECK(r!=NULL,"kelvin response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            CHECK(cJSON_GetObjectItem(p,"kelvin")->valuedouble==6500.0,"kelvin matches");
            cJSON *rgb=cJSON_GetObjectItem(p,"rgb");
            CHECK(cJSON_GetObjectItem(rgb,"r")->valueint==255,"r at 6500K is 255");
            CHECK(cJSON_GetObjectItem(rgb,"b")->valueint>200,"b at 6500K is white/cool");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","kelvin");
        cJSON_AddNumberToObject(a,"kelvin",2000.0);
        r=tools_run("colormath",a,NULL);
        p=P(r);
        if(p){
            cJSON *rgb=cJSON_GetObjectItem(p,"rgb");
            CHECK(cJSON_GetObjectItem(rgb,"r")->valueint==255,"candlelight red 255");
            CHECK(cJSON_GetObjectItem(rgb,"b")->valueint<50,"candlelight blue is low");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","convert");
        cJSON_AddStringToObject(a,"color","not_a_color");
        sds r=tools_run("colormath",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"invalid color hex error"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","kelvin");
        cJSON_AddNumberToObject(a,"kelvin",500.0);
        sds r=tools_run("colormath",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"kelvin < 1000 rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("colormath");
}
