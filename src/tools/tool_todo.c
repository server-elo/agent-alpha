/* tool_todo.c — Session Todo Task Management */

#define ALPHA_MAX_TODO_ITEMS 256
#define ALPHA_MAX_TODO_CONTENT 4000

typedef struct {
    char id[64];
    char content[ALPHA_MAX_TODO_CONTENT];
    char status[16]; /* pending, in_progress, completed, cancelled */
} todo_item_t;

typedef struct {
    todo_item_t items[ALPHA_MAX_TODO_ITEMS];
    int count;
} todo_store_t;

static todo_store_t g_todo_store = { .count = 0 };
static pthread_mutex_t g_todo_lock = PTHREAD_MUTEX_INITIALIZER;

static int todo_valid_status(const char *st) {
    if (!st) return 0;
    return strcmp(st, "pending") == 0 ||
           strcmp(st, "in_progress") == 0 ||
           strcmp(st, "completed") == 0 ||
           strcmp(st, "cancelled") == 0;
}

static sds tool_todo_run(cJSON *args, const char *cwd) {
    (void)cwd;
    pthread_mutex_lock(&g_todo_lock);

    cJSON *todos = cJSON_GetObjectItem(args, "todos");
    cJSON *merge_item = cJSON_GetObjectItem(args, "merge");
    int merge = (merge_item && cJSON_IsBool(merge_item)) ? cJSON_IsTrue(merge_item) : 0;

    if (todos && cJSON_IsArray(todos)) {
        if (!merge) {
            /* Replace mode */
            g_todo_store.count = 0;
            int n = cJSON_GetArraySize(todos);
            for (int i = 0; i < n && g_todo_store.count < ALPHA_MAX_TODO_ITEMS; i++) {
                cJSON *item = cJSON_GetArrayItem(todos, i);
                if (!cJSON_IsObject(item)) continue;
                const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(item, "id"));
                const char *cnt = cJSON_GetStringValue(cJSON_GetObjectItem(item, "content"));
                const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(item, "status"));
                if (!id || !id[0]) continue;
                todo_item_t *t = &g_todo_store.items[g_todo_store.count++];
                snprintf(t->id, sizeof(t->id), "%s", id);
                snprintf(t->content, sizeof(t->content), "%s", cnt ? cnt : "(no description)");
                snprintf(t->status, sizeof(t->status), "%s", todo_valid_status(st) ? st : "pending");
            }
        } else {
            /* Merge mode: update existing by ID, append new */
            int n = cJSON_GetArraySize(todos);
            for (int i = 0; i < n; i++) {
                cJSON *item = cJSON_GetArrayItem(todos, i);
                if (!cJSON_IsObject(item)) continue;
                const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(item, "id"));
                const char *cnt = cJSON_GetStringValue(cJSON_GetObjectItem(item, "content"));
                const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(item, "status"));
                if (!id || !id[0]) continue;

                int found = -1;
                for (int j = 0; j < g_todo_store.count; j++) {
                    if (strcmp(g_todo_store.items[j].id, id) == 0) {
                        found = j;
                        break;
                    }
                }
                if (found >= 0) {
                    if (cnt && cnt[0]) snprintf(g_todo_store.items[found].content, sizeof(g_todo_store.items[found].content), "%s", cnt);
                    if (st && todo_valid_status(st)) snprintf(g_todo_store.items[found].status, sizeof(g_todo_store.items[found].status), "%s", st);
                } else if (g_todo_store.count < ALPHA_MAX_TODO_ITEMS) {
                    todo_item_t *t = &g_todo_store.items[g_todo_store.count++];
                    snprintf(t->id, sizeof(t->id), "%s", id);
                    snprintf(t->content, sizeof(t->content), "%s", cnt ? cnt : "(no description)");
                    snprintf(t->status, sizeof(t->status), "%s", todo_valid_status(st) ? st : "pending");
                }
            }
        }
    }

    /* Build JSON summary response */
    cJSON *res = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    int pending = 0, in_prog = 0, comp = 0, canc = 0;

    for (int i = 0; i < g_todo_store.count; i++) {
        todo_item_t *t = &g_todo_store.items[i];
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", t->id);
        cJSON_AddStringToObject(obj, "content", t->content);
        cJSON_AddStringToObject(obj, "status", t->status);
        cJSON_AddItemToArray(arr, obj);

        if (strcmp(t->status, "pending") == 0) pending++;
        else if (strcmp(t->status, "in_progress") == 0) in_prog++;
        else if (strcmp(t->status, "completed") == 0) comp++;
        else if (strcmp(t->status, "cancelled") == 0) canc++;
    }

    cJSON_AddItemToObject(res, "todos", arr);
    cJSON *sum = cJSON_CreateObject();
    cJSON_AddNumberToObject(sum, "total", g_todo_store.count);
    cJSON_AddNumberToObject(sum, "pending", pending);
    cJSON_AddNumberToObject(sum, "in_progress", in_prog);
    cJSON_AddNumberToObject(sum, "completed", comp);
    cJSON_AddNumberToObject(sum, "cancelled", canc);
    cJSON_AddItemToObject(res, "summary", sum);

    pthread_mutex_unlock(&g_todo_lock);

    char *json_s = cJSON_PrintUnformatted(res);
    sds out = sdsnew(json_s ? json_s : "{}");
    if (json_s) free(json_s);
    cJSON_Delete(res);
    return out;
}

static const alpha_tool_t tool_todo = {
    .name = "todo",
    .aliases = {NULL},
    .category = "planning",
    .description = "Manage task list for current session. Omit todos to read, provide todos array to create/update items. Each item: {id, content, status: pending|in_progress|completed|cancelled}. merge=true updates by id.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"todo\",\"description\":\"Manage task list for current session. Omit todos to read, provide todos array to create/update items. Each item: {id, content, status: pending|in_progress|completed|cancelled}. merge=true updates by id.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"todos\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"},\"status\":{\"type\":\"string\"}},\"required\":[\"id\",\"content\",\"status\"]}},\"merge\":{\"type\":\"boolean\"}},\"required\":[]}}}",
    .run = tool_todo_run
};
