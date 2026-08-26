/* Regression tests for the code_search tool (generation 211 shipped it with
 * zero coverage). Goes through the public tools_run() entry point — custom
 * tests link tools.o, so statics are not reachable here. Fixtures are created
 * by this test in a private mkdtemp dir and removed afterwards. */
#include "alpha.h"
#include "test_util.h"

static char fixture_dir[PATH_MAX];
static char fixture_c[PATH_MAX];
static char fixture_txt[PATH_MAX];

static void write_fixture(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) { perror("fixture"); _exit(2); }
    fputs(content, f);
    fclose(f);
}

static void fixtures_create(void) {
    char tmpl[PATH_MAX];
    const char *td = getenv("TMPDIR");
    if (!td || !td[0] || access(td, W_OK) != 0) td = "/tmp";
    snprintf(tmpl, sizeof(tmpl), "%s/alpha-cs-test-XXXXXX", td);
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); _exit(2); }
    snprintf(fixture_dir, sizeof(fixture_dir), "%s", tmpl);
    snprintf(fixture_c, sizeof(fixture_c), "%s/auth.c", fixture_dir);
    snprintf(fixture_txt, sizeof(fixture_txt), "%s/notes.txt", fixture_dir);
    write_fixture(fixture_c,
        "#include <stdio.h>\n"
        "static int authenticate_user(const char *token) {\n"
        "    return token != 0;\n"
        "}\n"
        "int main(void) { return authenticate_user(\"x\"); }\n");
    write_fixture(fixture_txt,
        "remember to authenticate before release\n");
}

static void fixtures_remove(void) {
    unlink(fixture_c);
    unlink(fixture_txt);
    rmdir(fixture_dir);
}

static sds search(const char *query, long max_results) {
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "query", query);
    cJSON_AddStringToObject(a, "path", fixture_dir);
    if (max_results > 0) cJSON_AddNumberToObject(a, "max_results", (double)max_results);
    sds r = tools_run("code_search", a, ".");
    cJSON_Delete(a);
    return r;
}

int main(void) {
    TEST_BEGIN("code_search");

    fixtures_create();

    /* --- argument validation --------------------------------------------- */
    {
        cJSON *a = cJSON_CreateObject();
        sds r = tools_run("code_search", a, ".");
        CHECK(strstr(r, "query required") != NULL, "missing query is rejected");
        sdsfree(r); cJSON_Delete(a);
    }
    {
        sds r = search("authenticate(", 0);   /* unbalanced paren: bad regex */
        CHECK(strstr(r, "invalid search text") != NULL, "invalid regex is rejected");
        sdsfree(r);
    }

    /* --- free-text search across the fixture dir -------------------------- */
    {
        sds r = search("authenticate", 0);
        CHECK(strstr(r, "authenticate_user") != NULL, "text match found in .c file");
        CHECK(strstr(r, "notes.txt") != NULL, "text match found in .txt file");
        sdsfree(r);
    }

    /* --- kind + name filters narrow line matches -------------------------- */
    {
        sds r = search("kind:function name:auth", 0);
        CHECK(strstr(r, "authenticate_user") != NULL, "kind:function name:auth finds the function");
        CHECK(strstr(r, "notes.txt") == NULL, "kind:function excludes plain prose lines");
        sdsfree(r);
    }

    /* --- language filter excludes non-matching files ----------------------- */
    {
        sds r = search("lang:python authenticate", 0);
        CHECK(strstr(r, "No matches") != NULL, "lang:python excludes the .c and .txt fixtures");
        sdsfree(r);
    }

    /* --- max_results is honoured ------------------------------------------- */
    {
        sds r = search("authenticate", 1);
        CHECK(strstr(r, "(1 result)") != NULL, "max_results caps the output");
        sdsfree(r);
    }

    /* --- unknown field prefixes pass through as literal text --------------- */
    {
        sds r = search("TODO:authenticate", 0);
        CHECK(strstr(r, "No matches") != NULL, "unknown prefix becomes literal search text");
        sdsfree(r);
    }

    fixtures_remove();
    return test_report("code_search");
}
