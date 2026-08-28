/* tool_fs.c — Filesystem manipulation tools (read, write, edit, list) */

static sds tool_read_file_run(cJSON *args, const char *cwd) {
    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    if (!path) return sdsnew("ERROR: path required");
    char full[PATH_MAX];
    resolve_path(full, path, cwd);
    if (has_binary_extension(full))
        return sdscatprintf(sdsempty(),
            "ERROR: %s has a binary extension (%s). "
            "Use execute_bash with xxd, strings, or file instead.",
            full, strrchr(full, '.') ? strrchr(full, '.') : "unknown");
    sds body = read_file_all(full, 250000);
    if (has_nul(body, sdslen(body))) {
        sdsfree(body);
        return sdscatprintf(sdsempty(),
            "ERROR: %s is binary (contains NUL bytes) and cannot be read as text. "
            "Use execute_bash with xxd, strings or file instead.", full);
    }
    return body;
}

static const alpha_tool_t tool_read_file = {
    .name = "read_file",
    .aliases = {NULL},
    .category = "filesystem",
    .description = "Read a file (any path).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"description\":\"Read a file (any path).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}}}",
    .run = tool_read_file_run
};

static sds tool_write_file_run(cJSON *args, const char *cwd) {
    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    const char *content = cJSON_GetStringValue(cJSON_GetObjectItem(args, "content"));
    if (!path) return sdsnew("ERROR: path required");
    if (!content) content = "";
    char full[PATH_MAX];
    resolve_path(full, path, cwd);
    if (write_file_all(full, content, strlen(content)) != 0)
        return sdscatprintf(sdsempty(), "ERROR write %s: %s", full, strerror(errno));
    return sdscatprintf(sdsempty(), "OK wrote %zu bytes → %s", strlen(content), full);
}

static const alpha_tool_t tool_write_file = {
    .name = "write_file",
    .aliases = {NULL},
    .category = "filesystem",
    .description = "Write full file contents (creates parents).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"write_file\",\"description\":\"Write full file contents (creates parents).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"}},\"required\":[\"path\",\"content\"]}}}",
    .run = tool_write_file_run
};

static sds tool_edit_file_run(cJSON *args, const char *cwd) {
    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    const char *old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_str"));
    if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_text"));
    if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "old_string"));
    if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "find"));
    if (!old_s) old_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "target"));

    const char *new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_str"));
    if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_text"));
    if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "new_string"));
    if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "replace"));
    if (!new_s) new_s = cJSON_GetStringValue(cJSON_GetObjectItem(args, "replacement"));

    if (!path || !old_s) return sdsnew("ERROR: path + old_str required");
    if (!new_s) new_s = "";
    char full[PATH_MAX];
    resolve_path(full, path, cwd);
    struct stat est;
    if (stat(full, &est) == 0 && (size_t)est.st_size > ALPHA_EDIT_MAX_BYTES)
        return sdscatprintf(sdsempty(),
            "ERROR: %s is %lld bytes, over the %zu byte edit limit. "
            "Editing it would truncate the file.",
            full, (long long)est.st_size, (size_t)ALPHA_EDIT_MAX_BYTES);
    sds body = read_file_all(full, ALPHA_EDIT_MAX_BYTES);
    if (strncmp(body, "ERROR", 5) == 0) return body;
    if (has_nul(body, sdslen(body))) {
        sdsfree(body);
        return sdscatprintf(sdsempty(),
            "ERROR: %s is binary (contains NUL bytes). Editing it as text "
            "would discard everything after the first NUL.", full);
    }
    {
        const char *ns = new_s;
        while (*ns == ' ' || *ns == '\t' || *ns == '\n' || *ns == '\r') ns++;
        size_t ns_len = strlen(ns);
        while (ns_len > 0 && (ns[ns_len - 1] == ' ' || ns[ns_len - 1] == '\t' ||
                              ns[ns_len - 1] == '\n' || ns[ns_len - 1] == '\r'))
            ns_len--;
        if (ns_len >= 8 && strstr(body, new_s)) {
            if (strcmp(old_s, new_s) == 0) {
                sdsfree(body);
                return sdsnew("OK (no change): old_str and new_str are identical, "
                              "and the file already contains this text.");
            }
            if (!strstr(body, old_s)) {
                sdsfree(body);
                return sdsnew("OK (no change): the edit appears to be already "
                              "applied — new_str is present and old_str is gone. "
                              "Do not re-send this patch.");
            }
        }
    }

    char *pos = strstr(body, old_s);
    if (!pos) {
        sdsfree(body);
        return sdsnew("ERROR: old_str not found");
    }
    if (strstr(pos + 1, old_s)) {
        sdsfree(body);
        return sdsnew("ERROR: old_str not unique");
    }
    size_t pre = (size_t)(pos - body);
    sds out = sdsnewlen(body, pre);
    out = sdscat(out, new_s);
    out = sdscat(out, pos + strlen(old_s));
    sdsfree(body);
    if (write_file_all(full, out, sdslen(out)) != 0) {
        sdsfree(out);
        return sdscatprintf(sdsempty(), "ERROR write %s", full);
    }
    sds msg = sdscatprintf(sdsempty(), "OK edited %s (%zu bytes now)", full, sdslen(out));
    sdsfree(out);
    return msg;
}

static const alpha_tool_t tool_edit_file = {
    .name = "edit_file",
    .aliases = {NULL},
    .category = "filesystem",
    .description = "Replace unique old_str with new_str in file.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"edit_file\",\"description\":\"Replace unique old_str with new_str in file.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"old_str\":{\"type\":\"string\"},\"new_str\":{\"type\":\"string\"}},\"required\":[\"path\",\"old_str\",\"new_str\"]}}}",
    .run = tool_edit_file_run
};

static sds tool_list_dir_run(cJSON *args, const char *cwd) {
    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    char full[PATH_MAX];
    resolve_path(full, path, cwd);
    return list_dir(full);
}

static const alpha_tool_t tool_list_dir = {
    .name = "list_dir",
    .aliases = {"ls", NULL},
    .category = "filesystem",
    .description = "List directory entries (any path).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"list_dir\",\"description\":\"List directory entries (any path).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}}}",
    .run = tool_list_dir_run
};
