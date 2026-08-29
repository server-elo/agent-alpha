#include "alpha.h"
#include "test_util.h"
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("scc_dag");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","toposort");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("compile")); cJSON_AddItemToArray(e1,cJSON_CreateString("link")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("link")); cJSON_AddItemToArray(e2,cJSON_CreateString("test")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("test")); cJSON_AddItemToArray(e3,cJSON_CreateString("deploy")); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("scc_dag",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"is_dag")),"is a clean DAG");
            CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"has_cycle")),"no cycle");
            cJSON *order=cJSON_GetObjectItem(p,"order");
            CHECK(cJSON_GetArraySize(order)==4,"4 tasks ordered");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetArrayItem(order,0)),"compile")==0,"compile is first");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetArrayItem(order,3)),"deploy")==0,"deploy is last");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","tarjan_scc");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("B")); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("C")); cJSON_AddItemToArray(e3,cJSON_CreateString("A")); cJSON_AddItemToArray(edges,e3);
        cJSON *e4=cJSON_CreateArray(); cJSON_AddItemToArray(e4,cJSON_CreateString("C")); cJSON_AddItemToArray(e4,cJSON_CreateString("D")); cJSON_AddItemToArray(edges,e4);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("scc_dag",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"has_cycle")),"cycle detected");
            CHECK(!cJSON_IsTrue(cJSON_GetObjectItem(p,"is_dag")),"not a DAG");
            cJSON *comps=cJSON_GetObjectItem(p,"components");
            CHECK(cJSON_GetArraySize(comps)==2,"2 strongly connected components found");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","toposort");
        sds r=tools_run("scc_dag",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"missing edges error"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("scc_dag");
}
