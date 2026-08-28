/* tool_shell.c — Shell execution tools (bash & powershell) */

static sds tool_bash_run(cJSON *args, const char *cwd) {
    const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
    if (!cmd) cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "cmd"));
#ifdef ALPHA_PT_DARWIN
    if (cmd && (strstr(cmd, "/Desktop") || strstr(cmd, " ~/Desktop") ||
                strstr(cmd, "Desktop/") || strstr(cmd, "ls Desktop"))) {
        return sdsnew(
            "ERROR: command touches Desktop, which is served by the macOS File "
            "Provider and can block indefinitely.\n"
            "Copy what you need to a local directory first.\n");
    }
#endif
    sds out = shell_run(cmd, cwd);
    size_t nuls = 0;
    for (size_t i = 0; i < sdslen(out); i++)
        if (out[i] == 0) { out[i] = '.'; nuls++; }
    if (nuls)
        out = sdscatprintf(out, "\n[%zu NUL byte%s replaced with '.']",
                           nuls, nuls == 1 ? "" : "s");
    return out;
}

static const alpha_tool_t tool_bash = {
    .name = "execute_bash",
    .aliases = {"bash", "sh", NULL},
    .category = "system",
    .description = "Run any shell command (open; no sandbox).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"execute_bash\",\"description\":\"Run any shell command (open; no sandbox).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}},\"required\":[\"command\"]}}}",
    .run = tool_bash_run
};

static sds tool_powershell_run(cJSON *args, const char *cwd) {
    const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
    if (!cmd) cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "script"));
    if (!cmd || !cmd[0]) return sdsnew("ERROR: empty PowerShell command");
    if (access("/opt/homebrew/bin/pwsh", X_OK) != 0 && system("command -v pwsh >/dev/null 2>&1") != 0)
        return sdsnew("ERROR: pwsh (PowerShell 7+) is not installed. Install it with: brew install --cask powershell");
    sds pwsh_cmd = sdscatprintf(sdsempty(),
        "command -v pwsh >/dev/null 2>&1 && pwsh -NoProfile -NonInteractive -Command %s 2>&1 || /opt/homebrew/bin/pwsh -NoProfile -NonInteractive -Command %s 2>&1",
        shell_quote(cmd), shell_quote(cmd));
    sds out = shell_run(pwsh_cmd, cwd);
    sdsfree(pwsh_cmd);
    return out;
}

static const alpha_tool_t tool_powershell = {
    .name = "execute_powershell",
    .aliases = {"pwsh", NULL},
    .category = "system",
    .description = "Execute PowerShell 7+ via pwsh (pipelines, objects, scripts). macOS.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"execute_powershell\",\"description\":\"Execute PowerShell 7+ via pwsh (pipelines, objects, scripts). macOS.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"PowerShell command or script to run\"}},\"required\":[\"command\"]}}}",
    .run = tool_powershell_run
};
