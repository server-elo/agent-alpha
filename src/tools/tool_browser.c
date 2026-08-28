/* tool_browser.c — Pure-C Browser tool */

static sds tool_browser_run(cJSON *args, const char *cwd) {
    (void)cwd;
    return browser_tool_run(args);
}

static const alpha_tool_t tool_browser = {
    .name = "browser",
    .aliases = {"web_browser", NULL},
    .category = "web",
    .description = "Pure-C browser. ONE sticky CDP tab. Loop: status/tabs -> open/navigate -> snapshot -> click/type/press/eval. close_others cleans junk. NEVER bash for click. Login/OAuth: snapshot+one click then stop. PROOF required.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"browser\",\"description\":\"Pure-C browser. ONE sticky CDP tab. Loop: status/tabs -> open/navigate -> snapshot -> click/type/press/eval. close_others cleans junk. NEVER bash for click. Login/OAuth: snapshot+one click then stop. PROOF required.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\"},\"url\":{\"type\":\"string\"},\"selector\":{\"type\":\"string\"},\"text\":{\"type\":\"string\"},\"expression\":{\"type\":\"string\"},\"tab_id\":{\"type\":\"string\"},\"x\":{\"type\":\"number\"},\"y\":{\"type\":\"number\"}},\"required\":[]}}}",
    .run = tool_browser_run
};
