/* test_tswindow.c — tests for tswindow (time-series window aggregation) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }

static void add_point(cJSON *arr, double ts, double value){
    cJSON *o=cJSON_CreateObject();
    cJSON_AddNumberToObject(o,"ts",ts);
    cJSON_AddNumberToObject(o,"value",value);
    cJSON_AddItemToArray(arr,o);
}

static int is_error(sds r){ return r && strncmp(r,"ERROR:",6)==0; }

static double win_num(cJSON *res, int wi, const char *field){
    cJSON *ws=cJSON_GetObjectItem(res,"windows");
    if(!ws) return -1e30;
    cJSON *w=cJSON_GetArrayItem(ws,wi);
    if(!w) return -1e30;
    return cJSON_GetNumberValue(cJSON_GetObjectItem(w,field));
}

int main(void){
    TEST_BEGIN("tswindow");

    /* 1. tumbling basic: 10 points, interval 5 -> 2 windows with full aggregates */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","aggregate");
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        for(int i=0;i<10;i++) add_point(arr,i,i+1);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"tumbling basic JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"windows_total")),2,"2 windows");
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"sorted_input")),"input sorted flag");
            CHECK_EQ_INT((int)win_num(p,0,"start"),0,"w0 start 0");
            CHECK_EQ_INT((int)win_num(p,0,"end"),5,"w0 end 5");
            CHECK_EQ_INT((int)win_num(p,0,"count"),5,"w0 count 5");
            CHECK_EQ_INT((int)win_num(p,0,"min"),1,"w0 min 1");
            CHECK_EQ_INT((int)win_num(p,0,"max"),5,"w0 max 5");
            CHECK_EQ_INT((int)win_num(p,0,"sum"),15,"w0 sum 15");
            CHECK_EQ_INT((int)win_num(p,0,"avg"),3,"w0 avg 3");
            CHECK_EQ_INT((int)win_num(p,0,"first"),1,"w0 first 1");
            CHECK_EQ_INT((int)win_num(p,0,"last"),5,"w0 last 5");
            CHECK_EQ_INT((int)win_num(p,1,"start"),5,"w1 start 5");
            CHECK_EQ_INT((int)win_num(p,1,"sum"),40,"w1 sum 40");
            CHECK_EQ_INT((int)win_num(p,1,"last"),10,"w1 last 10");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. unsorted input handled honestly: sorted_input=false, aggregates correct */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,5,6); add_point(arr,0,1); add_point(arr,7,8); add_point(arr,2,3);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"unsorted JSON");
        if(p){
            CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"sorted_input")),"sorted_input false reported");
            CHECK_EQ_INT((int)win_num(p,0,"count"),2,"w0 count 2 (ts 0,2)");
            CHECK_EQ_INT((int)win_num(p,0,"first"),1,"w0 first 1");
            CHECK_EQ_INT((int)win_num(p,0,"last"),3,"w0 last 3");
            CHECK_EQ_INT((int)win_num(p,1,"first"),6,"w1 first 6 (ts 5)");
            CHECK_EQ_INT((int)win_num(p,1,"last"),8,"w1 last 8 (ts 7)");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. duplicate ts: first/last follow input order among ties (stable sort) */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,10); add_point(arr,0,20); add_point(arr,4,30);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)win_num(p,0,"count"),3,"dup ts count 3");
            CHECK_EQ_INT((int)win_num(p,0,"first"),10,"dup ts first 10");
            CHECK_EQ_INT((int)win_num(p,0,"last"),30,"dup ts last 30");
            CHECK_EQ_INT((int)win_num(p,0,"min"),10,"dup ts min 10");
            cJSON_Delete(p);
        } else CHECK(0,"dup ts parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. negative timestamps: floor division anchors window at -10 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,-7,42);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)win_num(p,0,"start"),-10,"neg ts window start -10");
            CHECK_EQ_INT((int)win_num(p,0,"end"),-5,"neg ts window end -5");
            CHECK_EQ_INT((int)win_num(p,0,"count"),1,"neg ts count 1");
            cJSON_Delete(p);
        } else CHECK(0,"neg ts parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. offset alignment shifts window grid */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON_AddNumberToObject(a,"offset",2);
        cJSON *arr=cJSON_CreateArray();
        for(int i=0;i<10;i++) add_point(arr,i,i);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"windows_total")),3,"offset 3 windows");
            CHECK_EQ_INT((int)win_num(p,0,"start"),-3,"offset w0 start -3");
            CHECK_EQ_INT((int)win_num(p,0,"end"),2,"offset w0 end 2");
            CHECK_EQ_INT((int)win_num(p,0,"count"),2,"offset w0 count 2");
            CHECK_EQ_INT((int)win_num(p,2,"start"),7,"offset w2 start 7");
            CHECK_EQ_INT((int)win_num(p,2,"count"),3,"offset w2 count 3");
            cJSON_Delete(p);
        } else CHECK(0,"offset parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. gaps: empty windows are skipped */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",10);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1); add_point(arr,1,2); add_point(arr,100,3);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"windows_total")),2,"gaps: only 2 non-empty windows");
            CHECK_EQ_INT((int)win_num(p,1,"start"),100,"gaps w1 start 100");
            CHECK_EQ_INT((int)win_num(p,1,"count"),1,"gaps w1 count 1");
            cJSON_Delete(p);
        } else CHECK(0,"gaps parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. sliding windows: interval 10 slide 5, overlapping windows */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"mode","sliding");
        cJSON_AddNumberToObject(a,"interval",10);
        cJSON_AddNumberToObject(a,"slide",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1); add_point(arr,5,2); add_point(arr,10,3); add_point(arr,15,4);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"sliding JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"windows_total")),5,"sliding 5 windows");
            CHECK_EQ_INT((int)win_num(p,0,"start"),-5,"sliding w0 start -5");
            CHECK_EQ_INT((int)win_num(p,0,"count"),1,"sliding w0 count 1");
            CHECK_EQ_INT((int)win_num(p,1,"start"),0,"sliding w1 start 0");
            CHECK_EQ_INT((int)win_num(p,1,"count"),2,"sliding w1 count 2");
            CHECK_EQ_INT((int)win_num(p,2,"count"),2,"sliding w2 count 2");
            CHECK_EQ_INT((int)win_num(p,2,"sum"),5,"sliding w2 sum 5 (2+3)");
            CHECK_EQ_INT((int)win_num(p,4,"start"),15,"sliding w4 start 15");
            CHECK_EQ_INT((int)win_num(p,4,"count"),1,"sliding w4 count 1");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. shorthand action "sliding" selects mode */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sliding");
        cJSON_AddNumberToObject(a,"interval",10);
        cJSON_AddNumberToObject(a,"slide",10);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1); add_point(arr,5,2);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"mode")),"sliding")==0,"shorthand mode sliding");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"windows_total")),1,"slide==interval equals tumbling");
            cJSON_Delete(p);
        } else CHECK(0,"shorthand parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 9. data as JSON string is accepted */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",100);
        cJSON_AddStringToObject(a,"data","[{\"ts\":1,\"value\":2},{\"ts\":2,\"value\":4}]");
        sds r=tools_run("tswindow",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)win_num(p,0,"count"),2,"string data count 2");
            CHECK_EQ_INT((int)win_num(p,0,"avg"),3,"string data avg 3");
            cJSON_Delete(p);
        } else CHECK(0,"string data parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 10. negative: missing data */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"missing data -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 11. negative: empty array */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON_AddItemToObject(a,"data",cJSON_CreateArray());
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"empty data -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 12. negative: point missing value */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        cJSON *o=cJSON_CreateObject();
        cJSON_AddNumberToObject(o,"ts",1);
        cJSON_AddItemToArray(arr,o);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"missing value -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 13. negative: non-integer ts rejected */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,1.5,10);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"fractional ts -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 14. negative: interval zero / negative / missing */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",0);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"interval 0 -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",-5);
        arr=cJSON_CreateArray();
        add_point(arr,0,1);
        cJSON_AddItemToObject(a,"data",arr);
        r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"interval -5 -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        arr=cJSON_CreateArray();
        add_point(arr,0,1);
        cJSON_AddItemToObject(a,"data",arr);
        r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"interval missing -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 15. negative: sliding without slide */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"mode","sliding");
        cJSON_AddNumberToObject(a,"interval",10);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"sliding w/o slide -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 16. negative: non-finite value rejected (inf) */
    {
        volatile double z=0.0;
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        cJSON *o=cJSON_CreateObject();
        cJSON_AddNumberToObject(o,"ts",0);
        cJSON_AddNumberToObject(o,"value",1.0/z);
        cJSON_AddItemToArray(arr,o);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"infinite value -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 17. negative: unknown action */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","explode");
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"unknown action -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 18. negative: sliding scan-range explosion rejected */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"mode","sliding");
        cJSON_AddNumberToObject(a,"interval",10);
        cJSON_AddNumberToObject(a,"slide",1);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,1); add_point(arr,1000000000000.0,2);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"huge sliding scan -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 19. negative: ts beyond 2^53 rejected */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,9007199254740992.0,1); /* 2^53 */
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("tswindow",a,NULL);
        CHECK(is_error(r),"ts > 2^53-1 -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 20. alias ts_window resolves */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddNumberToObject(a,"interval",5);
        cJSON *arr=cJSON_CreateArray();
        add_point(arr,0,7);
        cJSON_AddItemToObject(a,"data",arr);
        sds r=tools_run("ts_window",a,NULL);
        CHECK(r!=NULL && !is_error(r),"alias ts_window works");
        if(r){ cJSON *p=P(r); if(p) cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }

    return test_report("tswindow");
}
