/* tool_phone.c — Android ADB phone controller */

static int args_num(cJSON *args, const char *key, int def) {
    cJSON *v = cJSON_GetObjectItem(args, key);
    if (cJSON_IsNumber(v)) return v->valueint;
    const char *s = cJSON_GetStringValue(v);
    if (s && s[0]) return atoi(s);
    return def;
}

static sds adb_run(sds cmd, const char *cwd) {
    sds wrapped = sdscatprintf(sdsempty(),
        "command -v adb >/dev/null 2>&1 || { echo 'ERROR: adb not found. "
        "Termux: pkg install android-tools'; exit 127; }; %s", cmd);
    sdsfree(cmd);
    sds out = shell_run(wrapped, cwd);
    sdsfree(wrapped);
    return out;
}

static sds tool_phone_run(cJSON *args, const char *cwd) {
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0])
        return sdsnew("ERROR: action required (see/shot/tap/swipe/type/key/open/apps)");

    if (strcmp(action, "see") == 0) {
        sds out = adb_run(sdscatprintf(sdsempty(),
            "adb shell uiautomator dump /sdcard/alpha-ui.xml >/dev/null && "
            "adb shell cat /sdcard/alpha-ui.xml"), cwd);
        if (sdslen(out) > 60000) {
            sds head = sdsnewlen(out, 60000);
            sdsfree(out);
            out = sdscat(head, "\n...[UI tree truncated at 60000 bytes]");
        }
        return out;
    }
    if (strcmp(action, "shot") == 0) {
        sds path = sdscatprintf(sdsempty(), "%s/alpha-screen.png", alpha_tmpdir());
        sds out = adb_run(sdscatprintf(sdsempty(),
            "adb exec-out screencap -p > %s", shell_quote(path)), cwd);
        struct stat st;
        if (stat(path, &st) == 0 && st.st_size > 0)
            out = sdscatprintf(out, "\nOK screenshot saved: %s (%lld bytes)",
                               path, (long long)st.st_size);
        sdsfree(path);
        return out;
    }
    if (strcmp(action, "tap") == 0) {
        int x = args_num(args, "x", -1), y = args_num(args, "y", -1);
        if (x < 0 || y < 0)
            return sdsnew("ERROR: tap needs numeric x and y (take them from the bounds in 'see')");
        return adb_run(sdscatprintf(sdsempty(), "adb shell input tap %d %d", x, y), cwd);
    }
    if (strcmp(action, "swipe") == 0) {
        int x1 = args_num(args, "x1", -1), y1 = args_num(args, "y1", -1);
        int x2 = args_num(args, "x2", -1), y2 = args_num(args, "y2", -1);
        int ms = args_num(args, "ms", 300);
        if (x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0)
            return sdsnew("ERROR: swipe needs x1 y1 x2 y2 (screen centre out to the edge scrolls)");
        return adb_run(sdscatprintf(sdsempty(),
            "adb shell input swipe %d %d %d %d %d", x1, y1, x2, y2, ms), cwd);
    }
    if (strcmp(action, "type") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!text) return sdsnew("ERROR: text required");
        sds cmd = sdsempty();
        int first = 1;
        for (const char *p = text;;) {
            const char *nl = strchr(p, '\n');
            size_t seglen = nl ? (size_t)(nl - p) : strlen(p);
            sds seg = sdsempty();
            for (size_t i = 0; i < seglen; i++) {
                if (p[i] == '%') seg = sdscat(seg, "%25");
                else if (p[i] == ' ') seg = sdscat(seg, "%s");
                else seg = sdscatlen(seg, p + i, 1);
            }
            if (seglen)
                cmd = sdscatprintf(cmd, "%sadb shell input text %s",
                                   first ? "" : " && ", shell_quote(seg));
            sdsfree(seg);
            first = 0;
            if (!nl) break;
            cmd = sdscat(cmd, " && adb shell input keyevent KEYCODE_ENTER");
            p = nl + 1;
        }
        if (!cmd[0]) return sdsnew("ERROR: text is empty");
        return adb_run(cmd, cwd);
    }
    if (strcmp(action, "key") == 0) {
        const char *k = cJSON_GetStringValue(cJSON_GetObjectItem(args, "key"));
        if (!k) k = cJSON_GetStringValue(cJSON_GetObjectItem(args, "name"));
        if (!k || !k[0])
            return sdsnew("ERROR: key required (back/home/enter/recents/tab/del/power, or a raw KEYCODE_* name)");
        if (strcmp(k, "recents") == 0) k = "APP_SWITCH";
        char code[80];
        int n = 0;
        const char *prefix = strncmp(k, "KEYCODE_", 8) == 0 ? "" : "KEYCODE_";
        for (const char *p = prefix; *p && n < (int)sizeof(code) - 1; p++) code[n++] = *p;
        for (const char *p = k; *p && n < (int)sizeof(code) - 1; p++) {
            char c = *p;
            if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
                return sdscatprintf(sdsempty(), "ERROR: invalid key name '%s'", k);
            code[n++] = c;
        }
        code[n] = 0;
        return adb_run(sdscatprintf(sdsempty(), "adb shell input keyevent %s", code), cwd);
    }
    if (strcmp(action, "open") == 0) {
        const char *pkg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "package"));
        if (!pkg) pkg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!pkg || !pkg[0]) return sdsnew("ERROR: package required (see action 'apps')");
        for (const char *p = pkg; *p; p++)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '.' || *p == '_'))
                return sdscatprintf(sdsempty(), "ERROR: invalid package name '%s'", pkg);
        return adb_run(sdscatprintf(sdsempty(),
            "adb shell monkey -p %s -c android.intent.category.LAUNCHER 1", pkg), cwd);
    }
    if (strcmp(action, "apps") == 0) {
        return adb_run(sdsnew(
            "adb shell pm list packages -3 | sed 's/^package://' | sort"), cwd);
    }
    return sdscatprintf(sdsempty(), "ERROR: unknown phone action '%s'", action);
}

static const alpha_tool_t tool_phone = {
    .name = "phone",
    .aliases = {NULL},
    .category = "device",
    .description = "Control an Android phone over ADB. Actions: see, shot, tap, swipe, type, key, open, apps.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"phone\",\"description\":\"Control an Android phone over ADB (Termux: adb connect localhost:<port> after enabling wireless debugging). Loop: see -> tap/type/swipe -> see again. 'see' returns the screen's UI tree as XML — pick tap coordinates from the centre of an element's bounds=\\\"[l,t][r,b]\\\". Actions: see, shot (PNG screenshot, returns path), tap x y, swipe x1 y1 x2 y2 [ms], type text (newlines = ENTER), key back|home|enter|recents|tab|del|power, open package, apps (list user apps).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\"},\"text\":{\"type\":\"string\"},\"package\":{\"type\":\"string\"},\"key\":{\"type\":\"string\"},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"},\"x1\":{\"type\":\"number\"},\"y1\":{\"type\":\"number\"},\"x2\":{\"type\":\"number\"},\"y2\":{\"type\":\"number\"},\"ms\":{\"type\":\"number\"}},\"required\":[\"action\"]}}}",
    .run = tool_phone_run
};
