/* test_graph.c — tests for graph analysis tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }

int main(void){
    TEST_BEGIN("graph");

    /* 1. analyze simple DAG */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","analyze");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("B")); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("A")); cJSON_AddItemToArray(e3,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        CHECK(r!=NULL,"analyze DAG non-null");
        cJSON *p=P(r);
        CHECK(p!=NULL,"analyze parses JSON");
        if(p){
            CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"has_cycle")),"DAG has no cycle");
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"is_dag")),"is_dag true");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"node_count")),3,"3 nodes");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"edge_count")),3,"3 edges");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 2. has_cycle true */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","has_cycle");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("X")); cJSON_AddItemToArray(e1,cJSON_CreateString("Y")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("Y")); cJSON_AddItemToArray(e2,cJSON_CreateString("Z")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("Z")); cJSON_AddItemToArray(e3,cJSON_CreateString("X")); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        CHECK(r!=NULL,"has_cycle cycle non-null");
        cJSON *p=P(r);
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"has_cycle")),"detects cycle");
            cJSON_Delete(p);
        } else { CHECK(0,"has_cycle JSON parse"); }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 3. topo_sort valid */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","topo_sort");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("A")); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("B")); cJSON_AddItemToArray(e3,cJSON_CreateString("D")); cJSON_AddItemToArray(edges,e3);
        cJSON *e4=cJSON_CreateArray(); cJSON_AddItemToArray(e4,cJSON_CreateString("C")); cJSON_AddItemToArray(e4,cJSON_CreateString("D")); cJSON_AddItemToArray(edges,e4);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"topo_sort valid JSON");
        if(p){
            cJSON *order=cJSON_GetObjectItem(p,"order");
            CHECK(order && cJSON_IsArray(order),"order array present");
            CHECK_EQ_INT(cJSON_GetArraySize(order),4,"order size 4");
            /* A must be first, D last */
            if(order && cJSON_GetArraySize(order)==4){
                CHECK(strcmp(cJSON_GetArrayItem(order,0)->valuestring,"A")==0,"A first in topo");
                CHECK(strcmp(cJSON_GetArrayItem(order,3)->valuestring,"D")==0,"D last in topo");
            }
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 4. topo_sort cycle error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","topo_sort");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("B")); cJSON_AddItemToArray(e2,cJSON_CreateString("A")); cJSON_AddItemToArray(edges,e2);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        CHECK(r!=NULL,"topo cycle non-null");
        cJSON *p=P(r);
        CHECK(p!=NULL,"topo cycle JSON");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"has_cycle")),"cycle flagged in topo response");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 5. shortest_path unweighted */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","shortest_path");
        cJSON_AddStringToObject(a,"source","A");
        cJSON_AddStringToObject(a,"target","C");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("B")); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("A")); cJSON_AddItemToArray(e3,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"shortest unweighted JSON");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"reachable")),"reachable true");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),1,"distance 1 via direct edge");
            cJSON *path=cJSON_GetObjectItem(p,"path");
            CHECK(path && cJSON_IsArray(path),"path array");
            CHECK_EQ_INT(cJSON_GetArraySize(path),2,"path length 2");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 6. shortest_path weighted (Dijkstra) */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","shortest_path");
        cJSON_AddStringToObject(a,"source","A");
        cJSON_AddStringToObject(a,"target","C");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateObject(); cJSON_AddStringToObject(e1,"from","A"); cJSON_AddStringToObject(e1,"to","B"); cJSON_AddNumberToObject(e1,"weight",1); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateObject(); cJSON_AddStringToObject(e2,"from","B"); cJSON_AddStringToObject(e2,"to","C"); cJSON_AddNumberToObject(e2,"weight",1); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateObject(); cJSON_AddStringToObject(e3,"from","A"); cJSON_AddStringToObject(e3,"to","C"); cJSON_AddNumberToObject(e3,"weight",10); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"weighted shortest JSON");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"reachable")),"weighted reachable");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),2,"weighted distance 2 via B");
            cJSON *path=cJSON_GetObjectItem(p,"path");
            CHECK(path && cJSON_GetArraySize(path)==3,"weighted path via B has 3 nodes");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 7. bfs traversal */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","bfs");
        cJSON_AddStringToObject(a,"source","A");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("A")); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("B")); cJSON_AddItemToArray(e3,cJSON_CreateString("D")); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"bfs JSON");
        if(p){
            cJSON *ord=cJSON_GetObjectItem(p,"order");
            CHECK(ord && cJSON_IsArray(ord),"bfs order array");
            CHECK(strcmp(cJSON_GetArrayItem(ord,0)->valuestring,"A")==0,"bfs starts at A");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"visited_count")),4,"bfs visited 4");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 8. components undirected */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","components");
        cJSON_AddBoolToObject(a,"directed",0);
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(e2,cJSON_CreateString("D")); cJSON_AddItemToArray(edges,e2);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"components undirected JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"component_count")),2,"2 components");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 9. components directed SCC */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","components");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("B")); cJSON_AddItemToArray(e2,cJSON_CreateString("A")); cJSON_AddItemToArray(edges,e2);
        cJSON *e3=cJSON_CreateArray(); cJSON_AddItemToArray(e3,cJSON_CreateString("C")); cJSON_AddItemToArray(e3,cJSON_CreateString("D")); cJSON_AddItemToArray(edges,e3);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"SCC JSON");
        if(p){
            /* A<->B is one SCC, C and D are separate => 3 components */
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"component_count")),3,"3 SCCs");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 10. unreachable shortest_path */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","shortest_path");
        cJSON_AddStringToObject(a,"source","A");
        cJSON_AddStringToObject(a,"target","Z");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON_AddItemToObject(a,"edges",edges);
        cJSON_AddItemToObject(a,"nodes",cJSON_CreateArray()); /* also add Z via nodes */
        /* need Z node: add via nodes array */
        cJSON *nodes=cJSON_GetObjectItem(a,"nodes");
        cJSON_AddItemToArray(nodes,cJSON_CreateString("A"));
        cJSON_AddItemToArray(nodes,cJSON_CreateString("B"));
        cJSON_AddItemToArray(nodes,cJSON_CreateString("Z"));
        sds r=tools_run("graph",a,NULL);
        CHECK(r!=NULL,"unreachable non-null");
        cJSON *p=P(r);
        if(p){
            CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"reachable")),"unreachable false");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 11. error handling: missing edges */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","analyze");
        sds r=tools_run("graph",a,NULL);
        CHECK(r!=NULL,"missing edges error non-null");
        CHECK(strstr(r,"ERROR")!=NULL,"missing edges flagged");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 12. aliases */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","has_cycle");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r1=tools_run("dag",a,NULL);
        sds r2=tools_run("graph_analysis",a,NULL);
        CHECK(r1!=NULL && strstr(r1,"ERROR")==NULL,"alias dag works");
        CHECK(r2!=NULL && strstr(r2,"ERROR")==NULL,"alias graph_analysis works");
        sdsfree(r1); sdsfree(r2); cJSON_Delete(a);
    }

    /* 13. schema registration */
    {
        cJSON *schema=tools_schema();
        CHECK(schema!=NULL,"tools_schema non-null");
        char *str=cJSON_PrintUnformatted(schema);
        CHECK(str!=NULL,"schema printed");
        CHECK(strstr(str,"\"graph\"")!=NULL,"graph in schema");
        free(str); cJSON_Delete(schema);
    }

    /* 14. dfs traversal */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","dfs");
        cJSON_AddStringToObject(a,"source","A");
        cJSON *edges=cJSON_CreateArray();
        cJSON *e1=cJSON_CreateArray(); cJSON_AddItemToArray(e1,cJSON_CreateString("A")); cJSON_AddItemToArray(e1,cJSON_CreateString("B")); cJSON_AddItemToArray(edges,e1);
        cJSON *e2=cJSON_CreateArray(); cJSON_AddItemToArray(e2,cJSON_CreateString("B")); cJSON_AddItemToArray(e2,cJSON_CreateString("C")); cJSON_AddItemToArray(edges,e2);
        cJSON_AddItemToObject(a,"edges",edges);
        sds r=tools_run("graph",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"dfs JSON");
        if(p){
            cJSON *ord=cJSON_GetObjectItem(p,"order");
            CHECK(ord && cJSON_GetArraySize(ord)==3,"dfs visits 3");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    return test_report("graph");
}
