/* test_resp.c — tests for resp (REdis Serialization Protocol codec) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

int main(void){
    TEST_BEGIN("resp");

    /* 1. parse RESP2 simple string */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","+OK\r\n");
        sds r=tools_run("resp",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"simple string parses");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"type")),"simple")==0,"type simple");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"value")),"OK")==0,"value OK");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"consumed")),5,"consumed 5");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"trailing")),0,"no trailing");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. parse array with bulk and int */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","*2\r\n$4\r\nPING\r\n:1\r\n");
        sds r=tools_run("resp",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"array parses");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"type")),"array")==0,"type array");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"count")),2,"count 2");
            cJSON *v=cJSON_GetObjectItem(p,"value");
            cJSON *v0=v?cJSON_GetArrayItem(v,0):NULL;
            cJSON *v1=v?cJSON_GetArrayItem(v,1):NULL;
            CHECK(v0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(v0,"type")),"bulk")==0,"elem0 bulk");
            CHECK(v0 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(v0,"value")),"PING")==0,"elem0 PING");
            CHECK(v1 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(v1,"type")),"int")==0,"elem1 int");
            CHECK(v1 && (int)cJSON_GetNumberValue(cJSON_GetObjectItem(v1,"value"))==1,"elem1 value 1");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. parse integer, error and null forms */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","$-1\r\n");
        sds r=tools_run("resp",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"null bulk parses");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"type")),"null")==0,"null bulk type");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. encode explicit bulk type */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","encode");
        cJSON_AddStringToObject(a,"type","bulk");
        cJSON_AddStringToObject(a,"value","PING");
        sds r=tools_run("resp",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"encode bulk parses");
        if(p){
            const char *wire=cJSON_GetStringValue(cJSON_GetObjectItem(p,"resp"));
            CHECK(wire && strcmp(wire,"$4\r\nPING\r\n")==0,"wire text check");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"bytes")),10,"bytes 10");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. encode array inferred from JSON */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","encode");
        cJSON *v=cJSON_CreateArray();
        cJSON_AddItemToArray(v,cJSON_CreateString("PING"));
        cJSON_AddItemToArray(v,cJSON_CreateNumber(1));
        cJSON_AddItemToObject(a,"value",v);
        sds r=tools_run("resp",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"encode array parses");
        if(p){
            const char *wire=cJSON_GetStringValue(cJSON_GetObjectItem(p,"resp"));
        CHECK(wire && strncmp(wire,"*2\r\n",4)==0,"array header wire");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. malformed wire -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","%(broken)");
        sds r=tools_run("resp",a,NULL);
        CHECK(IS_ERR(r),"bad wire errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. missing data for parse -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        sds r=tools_run("resp",a,NULL);
        CHECK(IS_ERR(r),"missing data errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. truncated bulk length -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","$5\r\nab");
        sds r=tools_run("resp",a,NULL);
        CHECK(IS_ERR(r),"truncated bulk errors");
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("resp");
}
