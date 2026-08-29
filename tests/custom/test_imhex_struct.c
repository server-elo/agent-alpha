#include "alpha.h"
#include "test_util.h"
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("imhex_struct");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","unpack");
        cJSON_AddStringToObject(a,"data","42 E8 03 00 01 E2 40 41 4C 50 48 41");
        cJSON *schema=cJSON_CreateArray();
        cJSON *f1=cJSON_CreateObject(); cJSON_AddStringToObject(f1,"name","magic"); cJSON_AddStringToObject(f1,"type","u8"); cJSON_AddItemToArray(schema,f1);
        cJSON *f2=cJSON_CreateObject(); cJSON_AddStringToObject(f2,"name","count"); cJSON_AddStringToObject(f2,"type","u16_le"); cJSON_AddItemToArray(schema,f2);
        cJSON *f3=cJSON_CreateObject(); cJSON_AddStringToObject(f3,"name","flags"); cJSON_AddStringToObject(f3,"type","u32_be"); cJSON_AddItemToArray(schema,f3);
        cJSON *f4=cJSON_CreateObject(); cJSON_AddStringToObject(f4,"name","tag"); cJSON_AddStringToObject(f4,"type","string[5]"); cJSON_AddItemToArray(schema,f4);
        cJSON_AddItemToObject(a,"schema",schema);
        sds r=tools_run("imhex_struct",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            cJSON *fields=cJSON_GetObjectItem(p,"fields");
            CHECK(cJSON_GetObjectItem(fields,"magic")->valueint==0x42,"magic u8 matches 0x42");
            CHECK(cJSON_GetObjectItem(fields,"count")->valueint==1000,"count u16_le matches 1000");
            CHECK(cJSON_GetObjectItem(fields,"flags")->valueint==123456,"flags u32_be matches 123456");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(fields,"tag")),"ALPHA")==0,"tag string[5] matches ALPHA");
            CHECK(cJSON_GetObjectItem(p,"bytes_read")->valueint==12,"read all 12 bytes");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","unpack");
        cJSON_AddStringToObject(a,"data","42 E8 03");
        sds r=tools_run("imhex_struct",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"missing schema rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","unpack");
        cJSON_AddStringToObject(a,"data","ZZ XX YY");
        cJSON_AddItemToObject(a,"schema",cJSON_CreateArray());
        sds r=tools_run("imhex_struct",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"invalid hex rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("imhex_struct");
}
