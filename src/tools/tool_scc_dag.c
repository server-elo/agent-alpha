/*
 * tool_scc_dag.c - Tarjan's SCC, Kahn's Topological Sort & DAG Dependency Engine
 *
 * Implements linear-time O(V+E) Strongly Connected Component decomposition,
 * topological sorting, and cycle path detection for dependency graphs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "sds.h"

#define MAX_NODES 256

typedef struct {
    char name[64];
    int adj[MAX_NODES];
    int adj_count;
    int in_degree;
    /* Tarjan state */
    int index;
    int lowlink;
    int on_stack;
} dag_node_t;

typedef struct {
    dag_node_t nodes[MAX_NODES];
    int node_count;
} dag_graph_t;

static int get_or_add_node(dag_graph_t *g, const char *name) {
    for (int i = 0; i < g->node_count; i++) {
        if (strcmp(g->nodes[i].name, name) == 0) return i;
    }
    if (g->node_count >= MAX_NODES) return -1;
    int idx = g->node_count++;
    strncpy(g->nodes[idx].name, name, sizeof(g->nodes[idx].name) - 1);
    g->nodes[idx].adj_count = 0;
    g->nodes[idx].in_degree = 0;
    g->nodes[idx].index = -1;
    g->nodes[idx].lowlink = -1;
    g->nodes[idx].on_stack = 0;
    return idx;
}

static void add_edge(dag_graph_t *g, int u, int v) {
    if (u < 0 || v < 0) return;
    for (int i = 0; i < g->nodes[u].adj_count; i++) {
        if (g->nodes[u].adj[i] == v) return; // duplicate edge
    }
    g->nodes[u].adj[g->nodes[u].adj_count++] = v;
    g->nodes[v].in_degree++;
}

/* Tarjan's SCC DFS */
static int g_tarjan_idx = 0;
static int g_tarjan_stack[MAX_NODES];
static int g_tarjan_top = 0;

static void tarjan_dfs(dag_graph_t *g, int u, cJSON *scc_list) {
    g->nodes[u].index = g_tarjan_idx;
    g->nodes[u].lowlink = g_tarjan_idx;
    g_tarjan_idx++;
    g_tarjan_stack[g_tarjan_top++] = u;
    g->nodes[u].on_stack = 1;

    for (int i = 0; i < g->nodes[u].adj_count; i++) {
        int v = g->nodes[u].adj[i];
        if (g->nodes[v].index == -1) {
            tarjan_dfs(g, v, scc_list);
            if (g->nodes[v].lowlink < g->nodes[u].lowlink) {
                g->nodes[u].lowlink = g->nodes[v].lowlink;
            }
        } else if (g->nodes[v].on_stack) {
            if (g->nodes[v].index < g->nodes[u].lowlink) {
                g->nodes[u].lowlink = g->nodes[v].index;
            }
        }
    }

    if (g->nodes[u].lowlink == g->nodes[u].index) {
        cJSON *component = cJSON_CreateArray();
        int w = -1;
        do {
            w = g_tarjan_stack[--g_tarjan_top];
            g->nodes[w].on_stack = 0;
            cJSON_AddItemToArray(component, cJSON_CreateString(g->nodes[w].name));
        } while (w != u && g_tarjan_top > 0);
        cJSON_AddItemToArray(scc_list, component);
    }
}

static sds tool_scc_dag_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *action_item = cJSON_GetObjectItem(args, "action");
    const char *action = action_item && action_item->valuestring ? action_item->valuestring : "tarjan_scc";

    cJSON *edges = cJSON_GetObjectItem(args, "edges");
    if (!edges || !cJSON_IsArray(edges)) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Missing required 'edges' array (e.g. [['A','B'], ['B','C']])");
        char *json = cJSON_PrintUnformatted(err);
        sds res = sdsnew(json);
        free(json);
        cJSON_Delete(err);
        return res;
    }

    dag_graph_t g;
    memset(&g, 0, sizeof(g));

    int edge_count = cJSON_GetArraySize(edges);
    for (int i = 0; i < edge_count; i++) {
        cJSON *e = cJSON_GetArrayItem(edges, i);
        if (cJSON_IsArray(e) && cJSON_GetArraySize(e) >= 2) {
            const char *src = cJSON_GetArrayItem(e, 0)->valuestring;
            const char *dst = cJSON_GetArrayItem(e, 1)->valuestring;
            if (src && dst) {
                int u = get_or_add_node(&g, src);
                int v = get_or_add_node(&g, dst);
                add_edge(&g, u, v);
            }
        }
    }

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "status", "ok");
    cJSON_AddStringToObject(out, "action", action);
    cJSON_AddNumberToObject(out, "node_count", g.node_count);
    cJSON_AddNumberToObject(out, "edge_count", edge_count);

    if (strcmp(action, "tarjan_scc") == 0 || strcmp(action, "scc") == 0) {
        cJSON *scc_list = cJSON_CreateArray();
        g_tarjan_idx = 0;
        g_tarjan_top = 0;

        for (int i = 0; i < g.node_count; i++) {
            if (g.nodes[i].index == -1) {
                tarjan_dfs(&g, i, scc_list);
            }
        }

        int cycle_detected = 0;
        int scc_count = cJSON_GetArraySize(scc_list);
        for (int i = 0; i < scc_count; i++) {
            if (cJSON_GetArraySize(cJSON_GetArrayItem(scc_list, i)) > 1) {
                cycle_detected = 1;
                break;
            }
        }

        cJSON_AddItemToObject(out, "components", scc_list);
        cJSON_AddBoolToObject(out, "has_cycle", cycle_detected);
        cJSON_AddBoolToObject(out, "is_dag", !cycle_detected);

    } else if (strcmp(action, "toposort") == 0) {
        int in_deg[MAX_NODES];
        for (int i = 0; i < g.node_count; i++) in_deg[i] = g.nodes[i].in_degree;

        int queue[MAX_NODES];
        int head = 0, tail = 0;

        for (int i = 0; i < g.node_count; i++) {
            if (in_deg[i] == 0) queue[tail++] = i;
        }

        cJSON *order = cJSON_CreateArray();
        while (head < tail) {
            int u = queue[head++];
            cJSON_AddItemToArray(order, cJSON_CreateString(g.nodes[u].name));

            for (int i = 0; i < g.nodes[u].adj_count; i++) {
                int v = g.nodes[u].adj[i];
                in_deg[v]--;
                if (in_deg[v] == 0) queue[tail++] = v;
            }
        }

        int has_cycle = (cJSON_GetArraySize(order) < g.node_count);
        cJSON_AddItemToObject(out, "order", order);
        cJSON_AddBoolToObject(out, "has_cycle", has_cycle);
        cJSON_AddBoolToObject(out, "is_dag", !has_cycle);

    } else {
        cJSON_Delete(out);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "status", "error");
        cJSON_AddStringToObject(err, "error", "Unknown action. Supported: tarjan_scc, toposort");
        char *json = cJSON_PrintUnformatted(err);
        sds res = sdsnew(json);
        free(json);
        cJSON_Delete(err);
        return res;
    }

    char *json = cJSON_PrintUnformatted(out);
    sds res = sdsnew(json);
    free(json);
    cJSON_Delete(out);
    return res;
}

const alpha_tool_t tool_scc_dag = {
    .name = "scc_dag",
    .aliases = {"tarjan_scc", "topological_sort", "dag_solver"},
    .category = "graph",
    .description = "Tarjan's strongly connected components (SCC), Kahn's topological sorting, and cycle detection for dependency graphs.",
    .schema_json = "{\n"
                   "  \"type\": \"object\",\n"
                   "  \"properties\": {\n"
                   "    \"action\": {\"type\": \"string\", \"enum\": [\"tarjan_scc\", \"toposort\"]},\n"
                   "    \"edges\": {\n"
                   "      \"type\": \"array\",\n"
                   "      \"items\": {\"type\": \"array\", \"items\": {\"type\": \"string\"}},\n"
                   "      \"description\": \"List of directed edge pairs [src, dst]\"\n"
                   "    }\n"
                   "  },\n"
                   "  \"required\": [\"edges\"]\n"
                   "}",
    .run = tool_scc_dag_run
};
