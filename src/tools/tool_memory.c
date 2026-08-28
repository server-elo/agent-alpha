/* tool_memory.c — Persistent curated memory across sessions */

#define ALPHA_MEMORY_DIR       ".alpha/memory"
#define ALPHA_MEMORY_ENTRY_SEP "\n§\n"
#define ALPHA_MEMORY_MAX_ENTRIES 64
#define ALPHA_MEMORY_CHAR_LIMIT   2200
#define ALPHA_USER_CHAR_LIMIT     1375
#define ALPHA_MEMORY_ARENA_SIZE 4096

typedef struct {
    char buf[ALPHA_MEMORY_ARENA_SIZE];
    size_t offset;
} arena_t;

static void arena_init(arena_t *a) {
    a->offset = 0;
}

static void arena_reset(arena_t *a) {
    a->offset = 0;
}

static char *arena_alloc(arena_t *a, size_t sz) {
    size_t aligned = (sz + 7) & ~(size_t)7;
    if (a->offset + aligned > sizeof(a->buf)) return NULL;
    char *p = a->buf + a->offset;
    a->offset += aligned;
    return p;
}

typedef struct {
    char *entries[ALPHA_MEMORY_MAX_ENTRIES];
    int count;
    int char_limit;
    arena_t arena;
} memory_store_t;

static memory_store_t g_memory_store = { .count = 0, .char_limit = ALPHA_MEMORY_CHAR_LIMIT };
static memory_store_t g_user_store    = { .count = 0, .char_limit = ALPHA_USER_CHAR_LIMIT };
static pthread_mutex_t g_memory_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *memory_dir(void) {
    static char dir[PATH_MAX];
    const char *env = getenv("ALPHA_MEMORY_DIR");
    if (env && env[0]) {
        snprintf(dir, sizeof(dir), "%s", env);
        mkdir_p(dir);
        return dir;
    }
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = "/tmp";
    snprintf(dir, sizeof(dir), "%s/" ALPHA_MEMORY_DIR, home);
    mkdir_p(dir);
    return dir;
}

static const char *memory_path(const char *target) {
    static char path[PATH_MAX];
    const char *dir = memory_dir();
    if (strcmp(target, "user") == 0)
        snprintf(path, sizeof(path), "%s/USER.md", dir);
    else
        snprintf(path, sizeof(path), "%s/MEMORY.md", dir);
    return path;
}

static int memory_parse_into_store(const char *raw, memory_store_t *store) {
    if (!raw || !raw[0]) return 0;
    char *copy = strdup(raw);
    if (!copy) return 0;

    char *save = NULL;
    char *tok = strtok_r(copy, ALPHA_MEMORY_ENTRY_SEP, &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t' || *tok == '\n' || *tok == '\r') tok++;
        char *end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t' ||
                             end[-1] == '\n' || end[-1] == '\r')) end--;
        *end = 0;
        if (tok[0] && store->count < ALPHA_MEMORY_MAX_ENTRIES) {
            int dup = 0;
            for (int i = 0; i < store->count; i++) {
                if (strcmp(store->entries[i], tok) == 0) { dup = 1; break; }
            }
            if (!dup) {
                size_t len = strlen(tok);
                char *p = arena_alloc(&store->arena, len + 1);
                if (!p) break;
                memcpy(p, tok, len + 1);
                store->entries[store->count++] = p;
            }
        }
        tok = strtok_r(NULL, ALPHA_MEMORY_ENTRY_SEP, &save);
    }
    free(copy);
    return store->count;
}

static int memory_load(const char *target, memory_store_t *store) {
    const char *path = memory_path(target);
    FILE *f = fopen(path, "rb");
    if (!f) {
        store->count = 0;
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1048576) { fclose(f); store->count = 0; return 0; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;

    arena_reset(&store->arena);
    store->count = 0;
    memory_parse_into_store(buf, store);
    free(buf);
    return 0;
}

static int memory_save(const char *target, memory_store_t *store) {
    const char *path = memory_path(target);
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    for (int i = 0; i < store->count; i++) {
        if (i > 0) fputs(ALPHA_MEMORY_ENTRY_SEP, f);
        fputs(store->entries[i], f);
    }
    int ok = (fflush(f) == 0);
    if (ok) ok = (fsync(fileno(f)) == 0);
    fclose(f);
    if (ok) ok = (rename(tmp, path) == 0);
    else unlink(tmp);
    return ok ? 0 : -1;
}

static int memory_char_count(memory_store_t *store) {
    if (store->count == 0) return 0;
    int total = 0;
    for (int i = 0; i < store->count; i++) {
        if (i > 0) total += (int)strlen(ALPHA_MEMORY_ENTRY_SEP);
        total += (int)strlen(store->entries[i]);
    }
    return total;
}

void memory_free_store(memory_store_t *store) {
    arena_reset(&store->arena);
    store->count = 0;
}

void memory_init(void) {
    pthread_mutex_lock(&g_memory_lock);
    arena_init(&g_memory_store.arena);
    arena_init(&g_user_store.arena);
    g_memory_store.count = 0;
    g_user_store.count = 0;
    memory_load("memory", &g_memory_store);
    memory_load("user", &g_user_store);
    pthread_mutex_unlock(&g_memory_lock);
}

sds memory_format_for_prompt(const char *target) {
    pthread_mutex_lock(&g_memory_lock);
    memory_store_t *store = (strcmp(target, "user") == 0) ? &g_user_store : &g_memory_store;
    if (store->count == 0) {
        pthread_mutex_unlock(&g_memory_lock);
        return sdsempty();
    }
    const char *header = (strcmp(target, "user") == 0)
        ? "USER PROFILE (who the user is)"
        : "MEMORY (your personal notes)";
    int current = memory_char_count(store);
    int limit = store->char_limit;
    int pct = limit > 0 ? (current * 100 / limit) : 0;
    if (pct > 100) pct = 100;

    sds out = sdscatprintf(sdsempty(),
        "══════════════════════════════════════════════\n"
        "%s [%d%% — %d/%d chars]\n"
        "══════════════════════════════════════════════\n",
        header, pct, current, limit);
    for (int i = 0; i < store->count; i++) {
        if (i > 0) out = sdscat(out, ALPHA_MEMORY_ENTRY_SEP);
        out = sdscat(out, store->entries[i]);
    }
    pthread_mutex_unlock(&g_memory_lock);
    return out;
}

static memory_store_t *memory_store_for(const char *target) {
    return (strcmp(target, "user") == 0) ? &g_user_store : &g_memory_store;
}

static sds memory_tool_add(memory_store_t *store, const char *content) {
    if (!content || !content[0])
        return sdsnew("ERROR: content cannot be empty");

    for (int i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i], content) == 0)
            return sdsnew("ERROR: entry already exists (no duplicate added)");
    }

    int current = memory_char_count(store);
    int new_total = current;
    if (store->count > 0) new_total += (int)strlen(ALPHA_MEMORY_ENTRY_SEP);
    new_total += (int)strlen(content);
    if (new_total > store->char_limit) {
        return sdscatprintf(sdsempty(),
            "ERROR: memory at %d/%d chars. Adding this entry (%zu chars) would "
            "exceed the limit. Use 'replace' to merge overlapping entries or "
            "'remove' to delete stale ones, then retry.",
            current, store->char_limit, strlen(content));
    }

    if (store->count >= ALPHA_MEMORY_MAX_ENTRIES)
        return sdsnew("ERROR: maximum number of entries reached");

    char *p = arena_alloc(&store->arena, strlen(content) + 1);
    if (!p)
        return sdsnew("ERROR: arena full — use 'remove' to free space");
    strcpy(p, content);
    store->entries[store->count++] = p;
    return sdscatprintf(sdsempty(), "OK added entry (%d/%d chars now)",
                        new_total, store->char_limit);
}

static sds memory_tool_replace(memory_store_t *store, const char *old_text,
                               const char *new_content) {
    if (!old_text || !old_text[0])
        return sdsnew("ERROR: old_text cannot be empty");
    if (!new_content || !new_content[0])
        return sdsnew("ERROR: new_content cannot be empty (use 'remove' to delete)");

    int matches[ALPHA_MEMORY_MAX_ENTRIES];
    int nmatch = 0;
    for (int i = 0; i < store->count; i++) {
        if (strstr(store->entries[i], old_text))
            matches[nmatch++] = i;
    }
    if (nmatch == 0)
        return sdsnew("ERROR: no entry matched old_text");
    if (nmatch > 1) {
        int same = 1;
        for (int i = 1; i < nmatch; i++) {
            if (strcmp(store->entries[matches[0]], store->entries[matches[i]]) != 0) {
                same = 0;
                break;
            }
        }
        if (!same)
            return sdsnew("ERROR: multiple distinct entries matched — be more specific");
    }

    int idx = matches[0];
    int current = memory_char_count(store);
    int new_total = current
        - (int)strlen(store->entries[idx])
        + (int)strlen(new_content);
    if (new_total > store->char_limit) {
        return sdscatprintf(sdsempty(),
            "ERROR: replacement would put memory at %d/%d chars. "
            "Shorten the new content or remove other entries first.",
            new_total, store->char_limit);
    }

    char *p = arena_alloc(&store->arena, strlen(new_content) + 1);
    if (!p)
        return sdsnew("ERROR: arena full — use 'remove' to free space");
    strcpy(p, new_content);
    store->entries[idx] = p;
    return sdscatprintf(sdsempty(), "OK replaced entry (%d/%d chars now)",
                        new_total, store->char_limit);
}

static sds memory_tool_remove(memory_store_t *store, const char *old_text) {
    if (!old_text || !old_text[0])
        return sdsnew("ERROR: old_text cannot be empty");

    int matches[ALPHA_MEMORY_MAX_ENTRIES];
    int nmatch = 0;
    for (int i = 0; i < store->count; i++) {
        if (strstr(store->entries[i], old_text))
            matches[nmatch++] = i;
    }
    if (nmatch == 0)
        return sdsnew("ERROR: no entry matched old_text");
    if (nmatch > 1) {
        int same = 1;
        for (int i = 1; i < nmatch; i++) {
            if (strcmp(store->entries[matches[0]], store->entries[matches[i]]) != 0) {
                same = 0;
                break;
            }
        }
        if (!same)
            return sdsnew("ERROR: multiple distinct entries matched — be more specific");
    }

    int idx = matches[0];
    for (int i = idx; i < store->count - 1; i++)
        store->entries[i] = store->entries[i + 1];
    store->count--;

    int current = memory_char_count(store);
    return sdscatprintf(sdsempty(), "OK removed entry (%d/%d chars now)",
                        current, store->char_limit);
}

static sds tool_memory_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    const char *target = cJSON_GetStringValue(cJSON_GetObjectItem(args, "target"));
    const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(args, "content"));
    const char *old_text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_text"));

    if (!target) target = "memory";
    if (strcmp(target, "memory") != 0 && strcmp(target, "user") != 0)
        return sdsnew("ERROR: target must be 'memory' or 'user'");

    if (!action) {
        pthread_mutex_lock(&g_memory_lock);
        memory_store_t *store = memory_store_for(target);
        cJSON *res = cJSON_CreateObject();
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < store->count; i++)
            cJSON_AddItemToArray(arr, cJSON_CreateString(store->entries[i]));
        cJSON_AddItemToObject(res, "entries", arr);
        int current = memory_char_count(store);
        cJSON_AddNumberToObject(res, "char_count", current);
        cJSON_AddNumberToObject(res, "char_limit", store->char_limit);
        cJSON_AddNumberToObject(res, "entry_count", store->count);
        pthread_mutex_unlock(&g_memory_lock);

        char *json_s = cJSON_PrintUnformatted(res);
        sds out = sdsnew(json_s ? json_s : "{}");
        if (json_s) free(json_s);
        cJSON_Delete(res);
        return out;
    }

    pthread_mutex_lock(&g_memory_lock);
    memory_store_t *store = memory_store_for(target);
    sds result = NULL;

    if (strcmp(action, "add") == 0) {
        result = memory_tool_add(store, content);
    } else if (strcmp(action, "replace") == 0) {
        result = memory_tool_replace(store, old_text, content);
    } else if (strcmp(action, "remove") == 0) {
        result = memory_tool_remove(store, old_text);
    } else {
        result = sdsnew("ERROR: unknown action — use add, replace, or remove");
    }

    if (result && strncmp(result, "OK", 2) == 0)
        memory_save(target, store);

    pthread_mutex_unlock(&g_memory_lock);
    return result;
}

static const alpha_tool_t tool_memory = {
    .name = "memory",
    .aliases = {NULL},
    .category = "memory",
    .description = "Persistent curated memory that survives across sessions. Two stores: 'memory' for your notes (environment facts, conventions, lessons) and 'user' for user profile (preferences, style). Entries are §-delimited. Actions: add (append), replace (substring match), remove (substring match). Omit action to read current entries. Character limits: 2200 (memory), 1375 (user).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"memory\",\"description\":\"Persistent curated memory that survives across sessions. Two stores: 'memory' for your notes (environment facts, conventions, lessons) and 'user' for user profile (preferences, style). Entries are §-delimited. Actions: add (append), replace (substring match), remove (substring match). Omit action to read current entries. Character limits: 2200 (memory), 1375 (user).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"add\",\"replace\",\"remove\"]},\"target\":{\"type\":\"string\",\"enum\":[\"memory\",\"user\"],\"description\":\"Which store: 'memory' (default) or 'user'\"},\"content\":{\"type\":\"string\",\"description\":\"Entry content for add/replace\"},\"old_text\":{\"type\":\"string\",\"description\":\"Substring identifying the entry for replace/remove\"}},\"required\":[]}}}",
    .run = tool_memory_run
};
