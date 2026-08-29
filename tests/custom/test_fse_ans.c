#include "alpha.h"
#include "test_util.h"
#include <math.h>
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("fse_ans");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","entropy");
        cJSON_AddStringToObject(a,"text","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        sds r=tools_run("fse_ans",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            CHECK(cJSON_GetObjectItem(p,"shannon_entropy_bits_per_byte")->valuedouble==0.0,"zero entropy for constant string");
            CHECK(cJSON_GetObjectItem(p,"unique_symbols_count")->valueint==1,"1 unique symbol");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","rle_encode");
        cJSON_AddStringToObject(a,"text","Hello WWWWWWWWWW World");
        sds r=tools_run("fse_ans",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            CHECK(strstr(cJSON_GetStringValue(cJSON_GetObjectItem(p,"compressed")),"[10:W]")!=NULL,"RLE run encoded as [10:W]");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","entropy");
        sds r=tools_run("fse_ans",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"missing text rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("fse_ans");
}
