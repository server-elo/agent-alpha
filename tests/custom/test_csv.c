/* test_csv.c — tests for csv tool (parse / stringify RFC4180) */
#include "alpha.h"
#include "test_util.h"
extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ cJSON *j=cJSON_Parse(s); return j; }

int main(void){
    TEST_BEGIN("csv_tool");

    // 1. parse simple without header
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a,b,c\n1,2,3");
        sds r=tools_run("csv",a,NULL);
        CHECK(r!=NULL,"parse simple non-null");
        cJSON *p=P(r);
        CHECK(p!=NULL,"parse simple valid json");
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            CHECK(rows && cJSON_IsArray(rows),"parse rows array");
            CHECK_EQ_INT(cJSON_GetArraySize(rows),2,"parse 2 rows");
            cJSON *r0=cJSON_GetArrayItem(rows,0);
            CHECK(cJSON_GetArraySize(r0)==3,"parse row0 3 cols");
            cJSON *c0=cJSON_GetArrayItem(r0,0);
            CHECK(c0 && strcmp(c0->valuestring,"a")==0,"parse r0c0 a");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 2. parse with header -> objects
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","name,age\nAlice,30\nBob,25");
        cJSON_AddBoolToObject(a,"header",1);
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"parse header valid json");
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            CHECK_EQ_INT(cJSON_GetArraySize(rows),2,"header 2 objects");
            cJSON *o0=cJSON_GetArrayItem(rows,0);
            cJSON *nm=cJSON_GetObjectItem(o0,"name");
            CHECK(nm && strcmp(nm->valuestring,"Alice")==0,"header Alice");
            cJSON *ag=cJSON_GetObjectItem(o0,"age");
            CHECK(ag && strcmp(ag->valuestring,"30")==0,"header age 30");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 3. quoted field with comma
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a,\"b,c\",d\n1,2,3");
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            cJSON *r0=cJSON_GetArrayItem(rows,0);
            cJSON *c1=cJSON_GetArrayItem(r0,1);
            CHECK(c1 && strcmp(c1->valuestring,"b,c")==0,"quoted comma preserved");
            cJSON_Delete(p);
        } else CHECK(0,"quoted comma parse valid");
        sdsfree(r); cJSON_Delete(a);
    }
    // 4. escaped quote "" inside quoted field
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a,\"b\"\"c\",d");
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            cJSON *r0=cJSON_GetArrayItem(rows,0);
            cJSON *c1=cJSON_GetArrayItem(r0,1);
            CHECK(c1 && strcmp(c1->valuestring,"b\"c")==0,"escaped quote -> b\"c");
            cJSON_Delete(p);
        } else CHECK(0,"escaped quote valid");
        sdsfree(r); cJSON_Delete(a);
    }
    // 5. empty fields
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a,,c\n,,");
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            CHECK_EQ_INT(cJSON_GetArraySize(rows),2,"empty fields 2 rows");
            cJSON *r0=cJSON_GetArrayItem(rows,0);
            CHECK(cJSON_GetArraySize(r0)==3,"empty row0 3 cols");
            cJSON *c1=cJSON_GetArrayItem(r0,1);
            CHECK(c1 && c1->valuestring[0]=='\0',"empty field is \"\"");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 6. custom delimiter ;
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a;b;c\n1;2;3");
        cJSON_AddStringToObject(a,"delimiter",";");
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            CHECK_EQ_INT(cJSON_GetArraySize(rows),2,"delim ; 2 rows");
            cJSON *r0=cJSON_GetArrayItem(rows,0);
            CHECK(strcmp(cJSON_GetArrayItem(r0,0)->valuestring,"a")==0,"delim a");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 7. stringify array of arrays
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","stringify");
        cJSON *data=cJSON_CreateArray();
        cJSON *row0=cJSON_CreateArray(); cJSON_AddItemToArray(row0,cJSON_CreateString("a")); cJSON_AddItemToArray(row0,cJSON_CreateString("b")); cJSON_AddItemToArray(row0,cJSON_CreateString("c"));
        cJSON *row1=cJSON_CreateArray(); cJSON_AddItemToArray(row1,cJSON_CreateString("1")); cJSON_AddItemToArray(row1,cJSON_CreateString("2")); cJSON_AddItemToArray(row1,cJSON_CreateString("3"));
        cJSON_AddItemToArray(data,row0); cJSON_AddItemToArray(data,row1);
        cJSON_AddItemToObject(a,"data",data);
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"stringify arrays valid json");
        if(p){
            cJSON *csv=cJSON_GetObjectItem(p,"csv");
            CHECK(csv && strstr(csv->valuestring,"a,b,c")!=NULL,"stringify header a,b,c");
            CHECK(strstr(csv->valuestring,"1,2,3")!=NULL,"stringify row 1,2,3");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 8. stringify quoting needed (field with comma)
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","stringify");
        cJSON *data=cJSON_CreateArray();
        cJSON *row=cJSON_CreateArray(); cJSON_AddItemToArray(row,cJSON_CreateString("a")); cJSON_AddItemToArray(row,cJSON_CreateString("b,c")); cJSON_AddItemToArray(row,cJSON_CreateString("d"));
        cJSON_AddItemToArray(data,row);
        cJSON_AddItemToObject(a,"data",data);
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *csv=cJSON_GetObjectItem(p,"csv");
            CHECK(csv && strstr(csv->valuestring,"\"b,c\"")!=NULL,"stringify quotes b,c");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 9. roundtrip parse(stringify)
    {
        cJSON *sa=cJSON_CreateObject();
        cJSON_AddStringToObject(sa,"action","stringify");
        cJSON *data=cJSON_CreateArray();
        cJSON *r0=cJSON_CreateArray(); cJSON_AddItemToArray(r0,cJSON_CreateString("x")); cJSON_AddItemToArray(r0,cJSON_CreateString("y"));
        cJSON *r1=cJSON_CreateArray(); cJSON_AddItemToArray(r1,cJSON_CreateString("hello, world")); cJSON_AddItemToArray(r1,cJSON_CreateString("say \"hi\""));
        cJSON_AddItemToArray(data,r0); cJSON_AddItemToArray(data,r1);
        cJSON_AddItemToObject(sa,"data",data);
        sds sr=tools_run("csv",sa,NULL);
        cJSON *pj=cJSON_Parse(sr);
        cJSON *csvj=cJSON_GetObjectItem(pj,"csv");
        const char *csv_str = csvj ? csvj->valuestring : "";
        cJSON *pa=cJSON_CreateObject();
        cJSON_AddStringToObject(pa,"action","parse");
        cJSON_AddStringToObject(pa,"data",csv_str);
        sds pr=tools_run("csv",pa,NULL);
        cJSON *pp=P(pr);
        if(pp){
            cJSON *rows=cJSON_GetObjectItem(pp,"rows");
            CHECK_EQ_INT(cJSON_GetArraySize(rows),2,"roundtrip 2 rows");
            cJSON *rr1=cJSON_GetArrayItem(rows,1);
            CHECK(strcmp(cJSON_GetArrayItem(rr1,0)->valuestring,"hello, world")==0,"roundtrip hello, world");
            CHECK(strcmp(cJSON_GetArrayItem(rr1,1)->valuestring,"say \"hi\"")==0,"roundtrip say hi");
            cJSON_Delete(pp);
        } else CHECK(0,"roundtrip parse valid");
        cJSON_Delete(pj); sdsfree(sr); cJSON_Delete(sa);
        sdsfree(pr); cJSON_Delete(pa);
    }
    // 10. CRLF handling
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a,b\r\n1,2\r\n3,4");
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *rows=cJSON_GetObjectItem(p,"rows");
            CHECK_EQ_INT(cJSON_GetArraySize(rows),3,"CRLF 3 rows");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 11. error missing data
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        sds r=tools_run("csv",a,NULL);
        CHECK(r && strstr(r,"ERROR")!=NULL,"parse missing data error");
        sdsfree(r); cJSON_Delete(a);
    }
    // 12. unterminated quote error
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","a,\"b,c");
        sds r=tools_run("csv",a,NULL);
        CHECK(r && strstr(r,"ERROR")!=NULL,"unterminated quote error");
        sdsfree(r); cJSON_Delete(a);
    }
    // 13. alias csv_parse
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","a,b\n1,2");
        sds r=tools_run("csv_parse",a,NULL);
        CHECK(r && strstr(r,"\"rows\"")!=NULL,"alias csv_parse works");
        sdsfree(r); cJSON_Delete(a);
    }
    // 14. stringify with custom delimiter
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","stringify");
        cJSON_AddStringToObject(a,"delimiter",";");
        cJSON *data=cJSON_CreateArray();
        cJSON *row=cJSON_CreateArray(); cJSON_AddItemToArray(row,cJSON_CreateString("a")); cJSON_AddItemToArray(row,cJSON_CreateString("b"));
        cJSON_AddItemToArray(data,row);
        cJSON_AddItemToObject(a,"data",data);
        sds r=tools_run("csv",a,NULL);
        cJSON *p=P(r);
        if(p){
            cJSON *csv=cJSON_GetObjectItem(p,"csv");
            CHECK(csv && strcmp(csv->valuestring,"a;b")==0,"stringify delim ;");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    // 15. schema registered
    {
        cJSON *s=tools_schema();
        char *js=cJSON_PrintUnformatted(s);
        CHECK(js && strstr(js,"\"csv\"")!=NULL,"schema contains csv");
        if(js) free(js);
        cJSON_Delete(s);
    }

    return test_report("csv");
}

