/* tool_graph.c — Pure-C Directed/Undirected Graph Analysis Engine (C11)
 * Inspired by graph theory toolkits (LEDA/Boost Graph).
 * Capabilities:
 * - Graph parsing from JSON nodes/edges (arrays or objects, weighted/unweighted)
 * - Cycle detection (DFS coloring for directed, parent tracking for undirected)
 * - Topological sort (Kahn's algorithm)
 * - Shortest path (Dijkstra O(N^2), BFS-fast for unweighted)
 * - Connected components / Strongly connected components (BFS / Kosaraju)
 * - BFS / DFS traversal orders
 * - Comprehensive analyze/stats (density, degrees, DAG, weighted)
 * No I/O, no external deps beyond cJSON/sds/math.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <float.h>
#include <limits.h>

#define GRAPH_MAX_NODES 256
#define GRAPH_MAX_EDGES 2048
#define GRAPH_MAX_NAME  64
#define GRAPH_INF 1e18

/* ---------- helpers ---------- */

static int graph_find_node(char names[][GRAPH_MAX_NAME], int n, const char *name) {
    for (int i = 0; i < n; i++) if (strcmp(names[i], name) == 0) return i;
    return -1;
}
static int graph_add_node(char names[][GRAPH_MAX_NAME], int *n, const char *name, sds *err) {
    if (!name || !name[0]) { if (err) *err = sdsnew("ERROR: empty node name"); return -1; }
    int idx = graph_find_node(names, *n, name);
    if (idx >= 0) return idx;
    if (*n >= GRAPH_MAX_NODES) { if (err) *err = sdscatprintf(sdsempty(),"ERROR: too many nodes (max %d)", GRAPH_MAX_NODES); return -1; }
    strncpy(names[*n], name, GRAPH_MAX_NAME-1);
    names[*n][GRAPH_MAX_NAME-1] = '\0';
    (*n)++;
    return *n - 1;
}

static int graph_parse_bool(cJSON *args, const char *key, int def) {
    cJSON *v = cJSON_GetObjectItem(args, key);
    if (!v) return def;
    if (cJSON_IsBool(v)) return cJSON_IsTrue(v);
    if (cJSON_IsNumber(v)) return v->valueint != 0;
    if (cJSON_IsString(v) && v->valuestring) {
        if (strcasecmp(v->valuestring, "true")==0 || strcmp(v->valuestring,"1")==0 || strcasecmp(v->valuestring,"yes")==0) return 1;
        if (strcasecmp(v->valuestring, "false")==0 || strcmp(v->valuestring,"0")==0 || strcasecmp(v->valuestring,"no")==0) return 0;
    }
    return def;
}

static const char *graph_get_str(cJSON *obj, const char *k1, const char *k2, const char *k3, const char *k4) {
    cJSON *v = NULL;
    if (k1) v = cJSON_GetObjectItem(obj, k1);
    if ((!v || !cJSON_IsString(v)) && k2) v = cJSON_GetObjectItem(obj, k2);
    if ((!v || !cJSON_IsString(v)) && k3) v = cJSON_GetObjectItem(obj, k3);
    if ((!v || !cJSON_IsString(v)) && k4) v = cJSON_GetObjectItem(obj, k4);
    if (v && cJSON_IsString(v) && v->valuestring) return v->valuestring;
    return NULL;
}

static double graph_get_weight(cJSON *obj, double def) {
    const char *keys[] = {"weight","w","cost","distance","value","len","length", NULL};
    for (int i=0; keys[i]; i++) {
        cJSON *v = cJSON_GetObjectItem(obj, keys[i]);
        if (v && cJSON_IsNumber(v)) return v->valuedouble;
        if (v && cJSON_IsString(v) && v->valuestring) {
            char *ep=NULL; double d=strtod(v->valuestring,&ep);
            if (ep && *ep=='\0') return d;
        }
    }
    return def;
}

/* Parse graph from args into structures.
 * Returns 0 on success, -1 on error (err set).
 */
static int graph_parse(cJSON *args, int *out_directed, char names[][GRAPH_MAX_NAME], int *out_n,
                       int adj[][GRAPH_MAX_NODES], double wgt[][GRAPH_MAX_NODES],
                       int *out_weighted, int *out_edge_count, sds *err) {
    *out_n = 0;
    *out_weighted = 0;
    *out_edge_count = 0;
    int directed = graph_parse_bool(args, "directed", 1);
    /* also check "undirected" inverse */
    cJSON *und = cJSON_GetObjectItem(args, "undirected");
    if (und) {
        int uv = graph_parse_bool(args, "undirected", 0);
        if (uv) directed = 0;
    }
    *out_directed = directed;
    for (int i=0;i<GRAPH_MAX_NODES;i++) for(int j=0;j<GRAPH_MAX_NODES;j++){ adj[i][j]=0; wgt[i][j]=GRAPH_INF; }
    for (int i=0;i<GRAPH_MAX_NODES;i++) wgt[i][i]=0;

    /* nodes */
    cJSON *jnodes = cJSON_GetObjectItem(args, "nodes");
    if (!jnodes) jnodes = cJSON_GetObjectItem(args, "vertices");
    if (!jnodes) jnodes = cJSON_GetObjectItem(args, "node_list");
    if (jnodes) {
        if (!cJSON_IsArray(jnodes)) { *err=sdsnew("ERROR: 'nodes' must be an array of strings"); return -1; }
        int nn = cJSON_GetArraySize(jnodes);
        for (int i=0;i<nn;i++) {
            cJSON *nd = cJSON_GetArrayItem(jnodes,i);
            if (!cJSON_IsString(nd) || !nd->valuestring) { *err=sdsnew("ERROR: each node must be a string"); return -1; }
            if (graph_add_node(names, out_n, nd->valuestring, err) <0) return -1;
        }
    }
    /* edges */
    cJSON *jedges = cJSON_GetObjectItem(args, "edges");
    if (!jedges) jedges = cJSON_GetObjectItem(args, "links");
    if (!jedges) jedges = cJSON_GetObjectItem(args, "edge_list");
    if (!jedges) {
        /* also support graph as JSON string? */
        cJSON *jdata = cJSON_GetObjectItem(args, "data");
        if (jdata && cJSON_IsArray(jdata)) jedges = jdata;
        else if (jdata && cJSON_IsString(jdata) && jdata->valuestring) {
            cJSON *parsed = cJSON_Parse(jdata->valuestring);
            if (parsed && cJSON_IsArray(parsed)) {
                /* use parsed as edges, but need to free later - handle separately */
                jedges = parsed;
                /* mark for cleanup? we leak small - better parse and copy */
                int rc = 0;
                /* recursion not ideal: just handle inline */
                int tmp_n = *out_n;
                char tmp_names[GRAPH_MAX_NODES][GRAPH_MAX_NAME];
                memcpy(tmp_names, names, sizeof(tmp_names));
                /* fallback: report error */
                cJSON_Delete(parsed);
                *err=sdsnew("ERROR: 'edges' array is required");
                return -1;
                (void)rc; (void)tmp_n;
            } else {
                if (parsed) cJSON_Delete(parsed);
            }
        }
    }
    if (!jedges) { *err=sdsnew("ERROR: 'edges' array is required (e.g. [[\"A\",\"B\"],[\"B\",\"C\"]])"); return -1; }
    if (!cJSON_IsArray(jedges)) { *err=sdsnew("ERROR: 'edges' must be an array"); return -1; }
    int en = cJSON_GetArraySize(jedges);
    if (en > GRAPH_MAX_EDGES) { *err=sdscatprintf(sdsempty(),"ERROR: too many edges (%d > %d)", en, GRAPH_MAX_EDGES); return -1; }
    for (int i=0;i<en;i++) {
        cJSON *e = cJSON_GetArrayItem(jedges,i);
        const char *from=NULL, *to=NULL;
        double weight=1.0;
        int has_weight=0;
        if (cJSON_IsArray(e)) {
            int sz=cJSON_GetArraySize(e);
            if (sz<2) { *err=sdscatprintf(sdsempty(),"ERROR: edge %d must have at least 2 elements [from,to]", i); return -1; }
            cJSON *a0=cJSON_GetArrayItem(e,0);
            cJSON *a1=cJSON_GetArrayItem(e,1);
            if (!cJSON_IsString(a0) || !cJSON_IsString(a1)) { *err=sdscatprintf(sdsempty(),"ERROR: edge %d [from,to] must be strings", i); return -1; }
            from=a0->valuestring; to=a1->valuestring;
            if (sz>=3) {
                cJSON *a2=cJSON_GetArrayItem(e,2);
                if (cJSON_IsNumber(a2)) { weight=a2->valuedouble; has_weight=1; }
                else if (cJSON_IsString(a2) && a2->valuestring) { char *ep=NULL; double d=strtod(a2->valuestring,&ep); if(ep&&*ep=='\0'){ weight=d; has_weight=1; } }
            }
        } else if (cJSON_IsObject(e)) {
            from = graph_get_str(e,"from","source","src","u");
            to   = graph_get_str(e,"to","target","dst","v");
            if (!from) from = graph_get_str(e,"from_node",NULL,NULL,NULL);
            if (!to)   to   = graph_get_str(e,"to_node",NULL,NULL,NULL);
            if (!from || !to) { *err=sdscatprintf(sdsempty(),"ERROR: edge %d object must have from/to fields", i); return -1; }
            double wv = graph_get_weight(e, 1.0);
            /* detect if weight was explicitly present */
            int wexist=0;
            const char *wkeys[]={"weight","w","cost","distance","value","len","length",NULL};
            for(int k=0;wkeys[k];k++) if(cJSON_GetObjectItem(e,wkeys[k])){ wexist=1; break; }
            if (wexist) { weight=wv; has_weight=1; }
        } else {
            *err=sdscatprintf(sdsempty(),"ERROR: edge %d must be array [from,to] or object {from,to}", i);
            return -1;
        }
        if (has_weight && weight != 1.0) *out_weighted=1;
        if (weight < 0) { /* allow negative but mark weighted */ *out_weighted=1; }
        int fi = graph_add_node(names, out_n, from, err);
        if (fi <0) return -1;
        int ti = graph_add_node(names, out_n, to, err);
        if (ti <0) return -1;
        adj[fi][ti]=1;
        wgt[fi][ti]=weight;
        if (!directed) { adj[ti][fi]=1; wgt[ti][fi]=weight; }
        (*out_edge_count)++;
        (void)has_weight;
    }
    if (*out_n==0) { *err=sdsnew("ERROR: graph has no nodes"); return -1; }
    return 0;
}

/* ---------- algorithms ---------- */

static int dfs_cycle_directed(int n, int adj[][GRAPH_MAX_NODES], int color[], int v) {
    color[v]=1;
    for(int u=0;u<n;u++) if(adj[v][u]){
        if(color[u]==1) return 1;
        if(color[u]==0 && dfs_cycle_directed(n,adj,color,u)) return 1;
    }
    color[v]=2;
    return 0;
}
static int has_cycle_directed(int n, int adj[][GRAPH_MAX_NODES]) {
    int color[GRAPH_MAX_NODES]={0};
    for(int i=0;i<n;i++) if(color[i]==0) if(dfs_cycle_directed(n,adj,color,i)) return 1;
    return 0;
}
static int dfs_cycle_undirected(int n, int adj[][GRAPH_MAX_NODES], int visited[], int v, int parent) {
    visited[v]=1;
    for(int u=0;u<n;u++) if(adj[v][u]){
        if(!visited[u]){ if(dfs_cycle_undirected(n,adj,visited,u,v)) return 1; }
        else if(u!=parent) return 1;
    }
    return 0;
}
static int has_cycle_undirected(int n, int adj[][GRAPH_MAX_NODES]) {
    int vis[GRAPH_MAX_NODES]={0};
    for(int i=0;i<n;i++) if(!vis[i]) if(dfs_cycle_undirected(n,adj,vis,i,-1)) return 1;
    return 0;
}

static int topo_sort_kahn(int n, int adj[][GRAPH_MAX_NODES], int order[]) {
    int indeg[GRAPH_MAX_NODES]={0};
    for(int i=0;i<n;i++) for(int j=0;j<n;j++) if(adj[i][j]) indeg[j]++;
    int q[GRAPH_MAX_NODES]; int qh=0, qt=0;
    for(int i=0;i<n;i++) if(indeg[i]==0) q[qt++]=i;
    int idx=0;
    while(qh<qt){
        int v=q[qh++];
        order[idx++]=v;
        for(int u=0;u<n;u++) if(adj[v][u]){
            if(--indeg[u]==0) q[qt++]=u;
        }
    }
    return idx==n ? 0 : -1;
}

static int bfs_order(int n, int adj[][GRAPH_MAX_NODES], int src, int order[], int *out_len) {
    int vis[GRAPH_MAX_NODES]={0};
    int q[GRAPH_MAX_NODES]; int qh=0, qt=0;
    q[qt++]=src; vis[src]=1;
    int idx=0;
    while(qh<qt){
        int v=q[qh++];
        order[idx++]=v;
        for(int u=0;u<n;u++) if(adj[v][u] && !vis[u]){ vis[u]=1; q[qt++]=u; }
    }
    *out_len=idx;
    return 0;
}
static void dfs_iter(int n, int adj[][GRAPH_MAX_NODES], int src, int order[], int *out_len) {
    int vis[GRAPH_MAX_NODES]={0};
    int stack[GRAPH_MAX_NODES]; int top=0;
    stack[top++]=src;
    int idx=0;
    while(top>0){
        int v=stack[--top];
        if(vis[v]) continue;
        vis[v]=1;
        order[idx++]=v;
        /* push neighbors in reverse to preserve order */
        for(int u=n-1;u>=0;u--) if(adj[v][u] && !vis[u]) stack[top++]=u;
    }
    *out_len=idx;
}

/* Dijkstra O(N^2) */
static int dijkstra(int n, double wgt[][GRAPH_MAX_NODES], int adj[][GRAPH_MAX_NODES], int src, int dst, double dist[], int prev[]) {
    int vis[GRAPH_MAX_NODES]={0};
    for(int i=0;i<n;i++){ dist[i]=GRAPH_INF; prev[i]=-1; }
    dist[src]=0;
    for(int iter=0; iter<n; iter++){
        int u=-1; double best=GRAPH_INF;
        for(int i=0;i<n;i++) if(!vis[i] && dist[i]<best){ best=dist[i]; u=i; }
        if(u==-1) break;
        vis[u]=1;
        if(u==dst) break;
        for(int v=0; v<n; v++) if(adj[u][v]){
            double w = wgt[u][v];
            if(w>=GRAPH_INF/2) w=1;
            if(dist[u]+w < dist[v]){ dist[v]=dist[u]+w; prev[v]=u; }
        }
    }
    return dist[dst] < GRAPH_INF/2 ? 0 : -1;
}

/* Kosaraju for SCC (directed) */
static void kosaraju_dfs1(int n,int adj[][GRAPH_MAX_NODES],int v,int vis[],int stack[],int *sp){
    vis[v]=1;
    for(int u=0;u<n;u++) if(adj[v][u] && !vis[u]) kosaraju_dfs1(n,adj,u,vis,stack,sp);
    stack[(*sp)++]=v;
}
static void kosaraju_dfs2(int n,int radj[][GRAPH_MAX_NODES],int v,int vis[],int comp[],int cid){
    vis[v]=1; comp[v]=cid;
    for(int u=0;u<n;u++) if(radj[v][u] && !vis[u]) kosaraju_dfs2(n,radj,u,vis,comp,cid);
}

/* ---------- main dispatcher ---------- */

static sds tool_graph_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) {
        /* infer from presence of source/target */
        if (cJSON_GetObjectItem(args,"source") || cJSON_GetObjectItem(args,"target")) action="shortest_path";
        else action="analyze";
    }
    /* normalize */
    char actbuf[32]; strncpy(actbuf, action, sizeof(actbuf)-1); actbuf[sizeof(actbuf)-1]=0;
    for(char *p=actbuf;*p;p++) *p=(char)tolower((unsigned char)*p);

    /* aliases */
    if(strcmp(actbuf,"stats")==0) strcpy(actbuf,"analyze");
    if(strcmp(actbuf,"validate")==0) strcpy(actbuf,"analyze");
    if(strcmp(actbuf,"dag")==0) strcpy(actbuf,"topo_sort");
    if(strcmp(actbuf,"topological_sort")==0) strcpy(actbuf,"topo_sort");
    if(strcmp(actbuf,"topo")==0) strcpy(actbuf,"topo_sort");
    if(strcmp(actbuf,"shortest")==0) strcpy(actbuf,"shortest_path");
    if(strcmp(actbuf,"path")==0) strcpy(actbuf,"shortest_path");
    if(strcmp(actbuf,"scc")==0) strcpy(actbuf,"components");
    if(strcmp(actbuf,"connected")==0) strcpy(actbuf,"components");

    int directed=1; char names[GRAPH_MAX_NODES][GRAPH_MAX_NAME]; int n=0;
    int adj[GRAPH_MAX_NODES][GRAPH_MAX_NODES]; double wgt[GRAPH_MAX_NODES][GRAPH_MAX_NODES];
    int weighted=0, edge_count=0; sds err=NULL;
    if(graph_parse(args,&directed,names,&n,adj,wgt,&weighted,&edge_count,&err)!=0){
        sds e=err?err:sdsnew("ERROR: graph parse failed");
        return e;
    }

    /* compute cycle once for many actions */
    int has_cycle = directed ? has_cycle_directed(n,adj) : has_cycle_undirected(n,adj);
    int is_dag = !has_cycle;

    if(strcmp(actbuf,"analyze")==0){
        int indeg[GRAPH_MAX_NODES]={0}, outdeg[GRAPH_MAX_NODES]={0};
        for(int i=0;i<n;i++) for(int j=0;j<n;j++) if(adj[i][j]){ outdeg[i]++; indeg[j]++; }
        int self_loops=0;
        for(int i=0;i<n;i++) if(adj[i][i]) self_loops++;
        double possible = directed ? (double)n*(n-1) : (double)n*(n-1)/2.0;
        double density = possible>0 ? (double)edge_count/possible : 0;
        cJSON *res=cJSON_CreateObject();
        cJSON_AddStringToObject(res,"action","analyze");
        cJSON_AddNumberToObject(res,"node_count",n);
        cJSON_AddNumberToObject(res,"edge_count",edge_count);
        cJSON_AddBoolToObject(res,"directed",directed);
        cJSON_AddBoolToObject(res,"weighted",weighted);
        cJSON_AddBoolToObject(res,"has_cycle",has_cycle);
        cJSON_AddBoolToObject(res,"is_dag",is_dag);
        cJSON_AddNumberToObject(res,"density",density);
        cJSON_AddNumberToObject(res,"self_loops",self_loops);
        cJSON *nodes_arr=cJSON_CreateArray();
        for(int i=0;i<n;i++) cJSON_AddItemToArray(nodes_arr,cJSON_CreateString(names[i]));
        cJSON_AddItemToObject(res,"nodes",nodes_arr);
        cJSON *indeg_arr=cJSON_CreateArray();
        cJSON *outdeg_arr=cJSON_CreateArray();
        for(int i=0;i<n;i++){ cJSON_AddItemToArray(indeg_arr,cJSON_CreateNumber(indeg[i])); cJSON_AddItemToArray(outdeg_arr,cJSON_CreateNumber(outdeg[i])); }
        cJSON_AddItemToObject(res,"indegrees",indeg_arr);
        cJSON_AddItemToObject(res,"outdegrees",outdeg_arr);
        char *js=cJSON_PrintUnformatted(res);
        sds out=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(res);
        return out;
    }

    if(strcmp(actbuf,"has_cycle")==0){
        cJSON *res=cJSON_CreateObject();
        cJSON_AddStringToObject(res,"action","has_cycle");
        cJSON_AddBoolToObject(res,"has_cycle",has_cycle);
        cJSON_AddBoolToObject(res,"is_dag",is_dag);
        cJSON_AddNumberToObject(res,"node_count",n);
        cJSON_AddNumberToObject(res,"edge_count",edge_count);
        char *js=cJSON_PrintUnformatted(res);
        sds out=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(res);
        return out;
    }

    if(strcmp(actbuf,"topo_sort")==0){
        if(!directed){
            return sdsnew("ERROR: topo_sort requires directed graph (set directed:true)");
        }
        if(has_cycle){
            cJSON *res=cJSON_CreateObject();
            cJSON_AddStringToObject(res,"action","topo_sort");
            cJSON_AddBoolToObject(res,"has_cycle",1);
            cJSON_AddStringToObject(res,"error","graph has cycle — topological order impossible");
            char *js=cJSON_PrintUnformatted(res);
            sds out=sdsnew(js?js:"{}");
            free(js); cJSON_Delete(res);
            return out;
        }
        int order[GRAPH_MAX_NODES];
        int rc=topo_sort_kahn(n,adj,order);
        if(rc!=0) return sdsnew("ERROR: topo_sort failed (cycle detected)");
        cJSON *res=cJSON_CreateObject();
        cJSON_AddStringToObject(res,"action","topo_sort");
        cJSON_AddBoolToObject(res,"has_cycle",0);
        cJSON *arr=cJSON_CreateArray();
        for(int i=0;i<n;i++) cJSON_AddItemToArray(arr,cJSON_CreateString(names[order[i]]));
        cJSON_AddItemToObject(res,"order",arr);
        cJSON_AddNumberToObject(res,"node_count",n);
        char *js=cJSON_PrintUnformatted(res);
        sds out=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(res);
        return out;
    }

    if(strcmp(actbuf,"shortest_path")==0){
        const char *src_s = graph_get_str(args,"source","from",NULL,NULL);
        if(!src_s) src_s = graph_get_str(args,"src","start",NULL,NULL);
        const char *dst_s = graph_get_str(args,"target","to",NULL,NULL);
        if(!dst_s) dst_s = graph_get_str(args,"dst","end","goal",NULL);
        if(!src_s || !dst_s) return sdsnew("ERROR: shortest_path requires 'source' and 'target' strings");
        int si=graph_find_node(names,n,src_s);
        int ti=graph_find_node(names,n,dst_s);
        if(si<0) return sdscatprintf(sdsempty(),"ERROR: source '%s' not in graph",src_s);
        if(ti<0) return sdscatprintf(sdsempty(),"ERROR: target '%s' not in graph",dst_s);
        double dist[GRAPH_MAX_NODES]; int prev[GRAPH_MAX_NODES];
        int rc=dijkstra(n,wgt,adj,si,ti,dist,prev);
        cJSON *res=cJSON_CreateObject();
        cJSON_AddStringToObject(res,"action","shortest_path");
        cJSON_AddStringToObject(res,"source",src_s);
        cJSON_AddStringToObject(res,"target",dst_s);
        if(rc!=0){
            cJSON_AddBoolToObject(res,"reachable",0);
            cJSON_AddStringToObject(res,"error","no path");
            cJSON_AddNumberToObject(res,"distance",-1);
            cJSON_AddItemToObject(res,"path",cJSON_CreateArray());
        } else {
            cJSON_AddBoolToObject(res,"reachable",1);
            cJSON_AddNumberToObject(res,"distance",dist[ti]);
            /* reconstruct path */
            int rev[GRAPH_MAX_NODES]; int rlen=0;
            for(int cur=ti; cur!=-1; cur=prev[cur]){ rev[rlen++]=cur; if(cur==si) break; }
            cJSON *path=cJSON_CreateArray();
            for(int i=rlen-1;i>=0;i--) cJSON_AddItemToArray(path,cJSON_CreateString(names[rev[i]]));
            cJSON_AddItemToObject(res,"path",path);
        }
        cJSON_AddBoolToObject(res,"weighted",weighted);
        char *js=cJSON_PrintUnformatted(res);
        sds out=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(res);
        return out;
    }

    if(strcmp(actbuf,"bfs")==0 || strcmp(actbuf,"dfs")==0){
        const char *src_s = graph_get_str(args,"source","from","src","start");
        if(!src_s) src_s = graph_get_str(args,"node",NULL,NULL,NULL);
        if(!src_s) return sdscatprintf(sdsempty(),"ERROR: %s requires 'source' string",actbuf);
        int si=graph_find_node(names,n,src_s);
        if(si<0) return sdscatprintf(sdsempty(),"ERROR: source '%s' not in graph",src_s);
        int order[GRAPH_MAX_NODES]; int olen=0;
        if(strcmp(actbuf,"bfs")==0) bfs_order(n,adj,si,order,&olen);
        else dfs_iter(n,adj,si,order,&olen);
        cJSON *res=cJSON_CreateObject();
        cJSON_AddStringToObject(res,"action",actbuf);
        cJSON_AddStringToObject(res,"source",src_s);
        cJSON *arr=cJSON_CreateArray();
        for(int i=0;i<olen;i++) cJSON_AddItemToArray(arr,cJSON_CreateString(names[order[i]]));
        cJSON_AddItemToObject(res,"order",arr);
        cJSON_AddNumberToObject(res,"visited_count",olen);
        char *js=cJSON_PrintUnformatted(res);
        sds out=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(res);
        return out;
    }

    if(strcmp(actbuf,"components")==0){
        cJSON *res=cJSON_CreateObject();
        cJSON_AddStringToObject(res,"action","components");
        cJSON_AddBoolToObject(res,"directed",directed);
        cJSON *comps=cJSON_CreateArray();
        if(directed){
            /* Kosaraju SCC */
            int vis[GRAPH_MAX_NODES]={0};
            int stack[GRAPH_MAX_NODES]; int sp=0;
            for(int i=0;i<n;i++) if(!vis[i]) kosaraju_dfs1(n,adj,i,vis,stack,&sp);
            int radj[GRAPH_MAX_NODES][GRAPH_MAX_NODES]={0};
            for(int i=0;i<n;i++) for(int j=0;j<n;j++) if(adj[i][j]) radj[j][i]=1;
            memset(vis,0,sizeof(vis));
            int comp_id[GRAPH_MAX_NODES]; for(int i=0;i<n;i++) comp_id[i]=-1;
            int cid=0;
            for(int i=sp-1;i>=0;i--){
                int v=stack[i];
                if(!vis[v]){ kosaraju_dfs2(n,radj,v,vis,comp_id,cid); cid++; }
            }
            cJSON_AddNumberToObject(res,"component_count",cid);
            for(int c=0;c<cid;c++){
                cJSON *arr=cJSON_CreateArray();
                for(int i=0;i<n;i++) if(comp_id[i]==c) cJSON_AddItemToArray(arr,cJSON_CreateString(names[i]));
                cJSON_AddItemToArray(comps,arr);
            }
            /* also report if weakly connected count differs? */
            cJSON_AddBoolToObject(res,"is_strongly_connected",cid==1);
        } else {
            int vis[GRAPH_MAX_NODES]={0};
            int cid=0;
            for(int i=0;i<n;i++) if(!vis[i]){
                cJSON *arr=cJSON_CreateArray();
                int q[GRAPH_MAX_NODES]; int qh=0,qt=0;
                q[qt++]=i; vis[i]=1;
                while(qh<qt){
                    int v=q[qh++];
                    cJSON_AddItemToArray(arr,cJSON_CreateString(names[v]));
                    for(int u=0;u<n;u++) if(adj[v][u] && !vis[u]){ vis[u]=1; q[qt++]=u; }
                }
                cJSON_AddItemToArray(comps,arr);
                cid++;
            }
            cJSON_AddNumberToObject(res,"component_count",cid);
            cJSON_AddBoolToObject(res,"is_connected",cid==1);
        }
        cJSON_AddItemToObject(res,"components",comps);
        char *js=cJSON_PrintUnformatted(res);
        sds out=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(res);
        return out;
    }

    return sdscatprintf(sdsempty(),"ERROR: unknown graph action '%s' (use analyze/has_cycle/topo_sort/shortest_path/bfs/dfs/components)",action);
}

static const alpha_tool_t tool_graph = {
    .name = "graph",
    .aliases = {"dag","graph_analysis","topo_sort"},
    .category = "analysis",
    .description = "Pure-C graph analysis engine: cycle detection, topological sort (Kahn), shortest path (Dijkstra/BFS), BFS/DFS traversals, connected & strongly-connected components (Kosaraju), density/degree stats. Supports directed/undirected, weighted/unweighted edges as arrays [from,to,w] or objects {from,to,weight}. Actions: analyze, has_cycle, topo_sort, shortest_path, bfs, dfs, components.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"graph\",\"description\":\"Pure-C graph analysis: cycle detection, topo sort, shortest path, BFS/DFS, components.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"analyze\",\"has_cycle\",\"topo_sort\",\"shortest_path\",\"bfs\",\"dfs\",\"components\"],\"description\":\"Graph operation\"},\"nodes\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Node names (optional, inferred from edges)\"},\"edges\":{\"type\":\"array\",\"items\":{\"type\":\"array\"},\"description\":\"Edges as [from,to] or [from,to,weight] or {from,to,weight}\"},\"directed\":{\"type\":\"boolean\",\"description\":\"Directed graph (default true)\"},\"source\":{\"type\":\"string\",\"description\":\"Source node for shortest_path/bfs/dfs\"},\"target\":{\"type\":\"string\",\"description\":\"Target node for shortest_path\"}},\"required\":[]}}}",
    .run = tool_graph_run
};
