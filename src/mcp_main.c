#include "../include/alpha.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Agent Alpha 4-Tool MCP Server (C Language)
 * Exposes exactly 4 core tools:
 * 1. execute_powershell
 * 2. execute_bash
 * 3. read_file
 * 4. write_file
 */

static void json_print_escaped(FILE *out, const char *s) {
    if (!s) return;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '\"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\b': fputs("\\b", out); break;
            case '\f': fputs("\\f", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    fprintf(out, "\\u%04x", (unsigned char)*p);
                } else {
                    fputc(*p, out);
                }
                break;
        }
    }
}

static cJSON *get_mcp_tools_schema(void) {
    /* Same 4-tool surface as before, but the schemas come from the tool
     * registry (tools_schema_window) instead of hand-built copies, so MCP and
     * the CLI can never drift apart. The registry speaks the OpenAI
     * {"type":"function","function":{...}} shape; MCP wants
     * {name, description, inputSchema}. */
    static const char *names[] = {
        "execute_powershell", "execute_bash", "read_file", "write_file"
    };
    cJSON *window = tools_schema_window(names, 4);
    cJSON *tools = cJSON_CreateArray();
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, window) {
        cJSON *fn = cJSON_GetObjectItem(item, "function");
        if (!fn) continue;
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "name"));
        const char *desc = cJSON_GetStringValue(cJSON_GetObjectItem(fn, "description"));
        cJSON *params = cJSON_GetObjectItem(fn, "parameters");
        cJSON *t = cJSON_CreateObject();
        if (name) cJSON_AddStringToObject(t, "name", name);
        if (desc) cJSON_AddStringToObject(t, "description", desc);
        if (params) cJSON_AddItemToObject(t, "inputSchema", cJSON_Duplicate(params, 1));
        cJSON_AddItemToArray(tools, t);
    }
    cJSON_Delete(window);
    return tools;
}

static sds run_powershell_cmd(const char *cmd, const char *cwd) {
    if (!cmd || !cmd[0]) return sdsnew("ERROR: empty PowerShell command");
    
    // Build invocation to pwsh on macOS
    sds pwsh_script = sdscatprintf(sdsempty(),
        "/opt/homebrew/bin/pwsh -NoProfile -NonInteractive -Command \"%s\" 2>&1 || pwsh -NoProfile -NonInteractive -Command \"%s\" 2>&1",
        cmd, cmd);
    
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", pwsh_script);
    sds res = tools_run("execute_bash", args, cwd);
    cJSON_Delete(args);
    sdsfree(pwsh_script);
    return res;
}

int main(void) {
    // Unbuffered I/O for instant JSON-RPC 2.0 stdio
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    while ((linelen = getline(&line, &linecap, stdin)) > 0) {
        if (linelen <= 1) continue;

        cJSON *req = cJSON_Parse(line);
        if (!req) continue;

        cJSON *id_item = cJSON_GetObjectItem(req, "id");
        cJSON *method_item = cJSON_GetObjectItem(req, "method");
        const char *method = cJSON_GetStringValue(method_item);

        if (!method) {
            cJSON_Delete(req);
            continue;
        }

        // 1. initialize
        if (strcmp(method, "initialize") == 0) {
            cJSON *res = cJSON_CreateObject();
            cJSON_AddStringToObject(res, "jsonrpc", "2.0");
            if (id_item) cJSON_AddItemToObject(res, "id", cJSON_Duplicate(id_item, 1));
            
            cJSON *result = cJSON_CreateObject();
            cJSON_AddStringToObject(result, "protocolVersion", "2024-11-05");
            cJSON *caps = cJSON_CreateObject();
            cJSON_AddItemToObject(caps, "tools", cJSON_CreateObject());
            cJSON_AddItemToObject(result, "capabilities", caps);
            
            cJSON *server_info = cJSON_CreateObject();
            cJSON_AddStringToObject(server_info, "name", "agent-alpha-4-tools-mcp");
            cJSON_AddStringToObject(server_info, "version", "1.0.0");
            cJSON_AddItemToObject(result, "serverInfo", server_info);
            
            cJSON_AddItemToObject(res, "result", result);
            char *json_str = cJSON_PrintUnformatted(res);
            printf("%s\n", json_str);
            free(json_str);
            cJSON_Delete(res);
        }
        // 2. notifications/initialized
        else if (strcmp(method, "notifications/initialized") == 0) {
            // Notification: no response
        }
        // 3. ping
        else if (strcmp(method, "ping") == 0) {
            cJSON *res = cJSON_CreateObject();
            cJSON_AddStringToObject(res, "jsonrpc", "2.0");
            if (id_item) cJSON_AddItemToObject(res, "id", cJSON_Duplicate(id_item, 1));
            cJSON_AddItemToObject(res, "result", cJSON_CreateObject());
            char *json_str = cJSON_PrintUnformatted(res);
            printf("%s\n", json_str);
            free(json_str);
            cJSON_Delete(res);
        }
        // 4. tools/list (EXACTLY 4 TOOLS)
        else if (strcmp(method, "tools/list") == 0) {
            cJSON *res = cJSON_CreateObject();
            cJSON_AddStringToObject(res, "jsonrpc", "2.0");
            if (id_item) cJSON_AddItemToObject(res, "id", cJSON_Duplicate(id_item, 1));
            
            cJSON *result = cJSON_CreateObject();
            cJSON_AddItemToObject(result, "tools", get_mcp_tools_schema());
            cJSON_AddItemToObject(res, "result", result);
            
            char *json_str = cJSON_PrintUnformatted(res);
            printf("%s\n", json_str);
            free(json_str);
            cJSON_Delete(res);
        }
        // 5. tools/call
        else if (strcmp(method, "tools/call") == 0) {
            cJSON *params = cJSON_GetObjectItem(req, "params");
            const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(params, "name"));
            cJSON *args = cJSON_GetObjectItem(params, "arguments");

            char cwd[PATH_MAX];
            if (!getcwd(cwd, sizeof(cwd))) {
                /* Portable fallback: $HOME, else the filesystem root — never a
                 * hardcoded user path. */
                const char *home = getenv("HOME");
                snprintf(cwd, sizeof(cwd), "%s", (home && home[0]) ? home : "/");
            }

            sds output = NULL;
            if (name && strcmp(name, "execute_powershell") == 0) {
                const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
                output = run_powershell_cmd(cmd, cwd);
            } else if (name) {
                output = tools_run(name, args, cwd);
            } else {
                output = sdsnew("ERROR: missing tool name");
            }

            printf("{\"jsonrpc\":\"2.0\",");
            if (id_item) {
                char *id_str = cJSON_PrintUnformatted(id_item);
                printf("\"id\":%s,", id_str);
                free(id_str);
            } else {
                printf("\"id\":1,");
            }
            printf("\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"");
            json_print_escaped(stdout, output ? output : "");
            printf("\"}]}}\n");

            if (output) sdsfree(output);
        }

        cJSON_Delete(req);
    }

    if (line) free(line);
    return 0;
}
