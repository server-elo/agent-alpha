/* tool_toolsearch.c — tool discovery meta-tools (BM25 search + schema fetch)
 *
 * These are how the model reaches tools outside its visible window: search_tools
 * finds candidates by keywords and returns each hit WITH its full schema, so the
 * tool can be called immediately without a second hop; describe_tools fetches
 * schemas for exact names. Discovery quality therefore depends entirely on each
 * tool's description text — synonyms matter. */

static sds tool_search_tools_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *q = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
    cJSON *kj = cJSON_GetObjectItem(args, "k");
    int k = cJSON_IsNumber(kj) ? kj->valueint : 8;
    int n = 0;
    alpha_tool_hit_t *hits = tools_search(q, k, &n);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        const alpha_tool_t *t = hits[i].tool;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", t->name);
        if (t->category) cJSON_AddStringToObject(o, "category", t->category);
        if (t->description) cJSON_AddStringToObject(o, "description", t->description);
        cJSON_AddNumberToObject(o, "score", hits[i].score);
        /* The full OpenAI-format schema rides along so a found tool can be
         * called on the very next turn — no describe_tools round trip. */
        cJSON *schema = t->schema_json ? cJSON_Parse(t->schema_json) : NULL;
        if (schema) cJSON_AddItemToObject(o, "schema", schema);
        cJSON_AddItemToArray(arr, o);
    }
    free(hits);
    char *s = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    sds out = sdsnew(s ? s : "[]");
    free(s);
    return out;
}

static const alpha_tool_t tool_search_tools = {
    .name = "search_tools",
    .aliases = {"find_tool", "tool_search", NULL},
    .category = "core",
    .description = "Search the tool catalog by keywords when the tool you need is "
        "not in your visible tool list. BM25 full-text search over tool names, "
        "aliases, categories and descriptions; returns the best matches with "
        "their full schemas, ready to call immediately. Synonyms: find tool, "
        "discover tool, look up a capability, which tool can do X.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"search_tools\",\"description\":\"Search the tool catalog by keywords when the tool you need is not in your visible tool list. Returns matching tools with their full schemas, ready to call immediately.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Keywords describing the capability you need (synonyms help)\"},\"k\":{\"type\":\"integer\",\"description\":\"Maximum results to return (default 8)\"}},\"required\":[\"query\"]}}}",
    .run = tool_search_tools_run
};

static sds tool_describe_tools_run(cJSON *args, const char *cwd) {
    (void)cwd;
    cJSON *names = cJSON_GetObjectItem(args, "names");
    cJSON *arr = cJSON_CreateArray();
    cJSON *nj = NULL;
    cJSON_ArrayForEach(nj, names) {
        const char *nm = cJSON_GetStringValue(nj);
        if (!nm) continue;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", nm);
        const alpha_tool_t *t = tools_find(nm);
        cJSON *schema = (t && t->schema_json) ? cJSON_Parse(t->schema_json) : NULL;
        if (schema) cJSON_AddItemToObject(o, "schema", schema);
        else cJSON_AddStringToObject(o, "error", "unknown tool");
        cJSON_AddItemToArray(arr, o);
    }
    char *s = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    sds out = sdsnew(s ? s : "[]");
    free(s);
    return out;
}

static const alpha_tool_t tool_describe_tools = {
    .name = "describe_tools",
    .aliases = {"tool_schema", NULL},
    .category = "core",
    .description = "Fetch the full schemas of tools by exact name (e.g. names "
        "returned by search_tools). Synonyms: tool details, tool schema, "
        "inspect tool, what arguments does a tool take.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"describe_tools\",\"description\":\"Fetch the full schemas of tools by exact name (e.g. names returned by search_tools).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"names\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Tool names to describe\"}},\"required\":[\"names\"]}}}",
    .run = tool_describe_tools_run
};
