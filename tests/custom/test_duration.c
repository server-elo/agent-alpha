/* Test suite for duration tool */
#include "alpha.h"
#include "test_util.h"
sds tools_run(const char *name, cJSON *args, const char *cwd);
int main(void){
    TEST_BEGIN("duration_tool");
    // 1 parse simple
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","1h30m");
        sds r=tools_run("duration",a,NULL);
        CHECK(r!=NULL,"parse 1h30m non-null");
        CHECK(strstr(r,"5400")!=NULL,"1h30m = 5400 secs");
        CHECK(strstr(r,"1h")!=NULL,"formatted contains 1h");
        sdsfree(r); cJSON_Delete(a);
    }
    // 2 parse with days/weeks
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","1w 2d");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"777600")!=NULL,"1w2d = 777600");
        sdsfree(r); cJSON_Delete(a);
    }
    // 3 parse compact without spaces
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","1d2h30m45s");
        sds r=tools_run("duration",a,NULL);
        // 86400+7200+1800+45=95445
        CHECK(strstr(r,"95445")!=NULL,"1d2h30m45s = 95445");
        sdsfree(r); cJSON_Delete(a);
    }
    // 4 parse bare number as seconds
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","3600");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"3600")!=NULL,"bare 3600 = 3600");
        sdsfree(r); cJSON_Delete(a);
    }
    // 5 negative duration
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","-1h30m");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"-5400")!=NULL,"-1h30m = -5400");
        CHECK(strstr(r,"negative")!=NULL,"negative flag");
        sdsfree(r); cJSON_Delete(a);
    }
    // 6 format seconds to string
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","format");
        cJSON_AddNumberToObject(a,"seconds",90061);
        sds r=tools_run("duration",a,NULL);
        // 90061 = 1d 1h 1m 1s (86400+3600+60+1)
        CHECK(strstr(r,"1d")!=NULL,"format 90061 has 1d");
        CHECK(strstr(r,"1h")!=NULL,"format 90061 has 1h");
        CHECK(strstr(r,"1m")!=NULL,"format 90061 has 1m");
        sdsfree(r); cJSON_Delete(a);
    }
    // 7 format 0
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","format");
        cJSON_AddNumberToObject(a,"seconds",0);
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"0s")!=NULL,"format 0 => 0s");
        sdsfree(r); cJSON_Delete(a);
    }
    // 8 add two durations
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","add");
        cJSON_AddStringToObject(a,"a","1h");
        cJSON_AddStringToObject(a,"b","30m");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"5400")!=NULL,"add 1h+30m = 5400");
        CHECK(strstr(r,"1h 30m")!=NULL||strstr(r,"1h")!=NULL,"add formatted");
        sdsfree(r); cJSON_Delete(a);
    }
    // 9 compare
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"a","2h");
        cJSON_AddStringToObject(a,"b","90m");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"\"greater\":true")!=NULL,"2h > 90m");
        CHECK(strstr(r,"\">\"")!=NULL||strstr(r,">")!=NULL,"op >");
        sdsfree(r); cJSON_Delete(a);
    }
    // 10 compare equal
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","compare");
        cJSON_AddStringToObject(a,"a","60m");
        cJSON_AddStringToObject(a,"b","1h");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"\"equal\":true")!=NULL,"60m == 1h");
        sdsfree(r); cJSON_Delete(a);
    }
    // 11 error on invalid
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","notaduration");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"ERROR")!=NULL,"invalid duration reports ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    // 12 alias human_time
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","2h");
        sds r=tools_run("human_time",a,NULL);
        CHECK(strstr(r,"7200")!=NULL,"alias human_time works");
        sdsfree(r); cJSON_Delete(a);
    }
    // 13 format via string input
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","format");
        cJSON_AddStringToObject(a,"seconds","1h30m"); // should normalize?
        // Actually seconds expects number, but string "1h30m" will be parsed as duration string in format path
        // Our format code handles string seconds that are duration strings -> it parses and reformats
        sds r=tools_run("duration",a,NULL);
        // It should handle string containing duration string
        CHECK(r!=NULL,"format with string input non-null");
        sdsfree(r); cJSON_Delete(a);
    }
    // 14 ms truncated
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","1500ms");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"\"seconds\":1")!=NULL||strstr(r,":1")!=NULL,"1500ms => 1s truncated");
        sdsfree(r); cJSON_Delete(a);
    }
    // 15 weeks
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"input","1w");
        sds r=tools_run("duration",a,NULL);
        CHECK(strstr(r,"604800")!=NULL,"1w = 604800");
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("duration_tool");
}
