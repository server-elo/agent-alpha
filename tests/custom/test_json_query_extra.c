/* Extra certification for json_query tool — extended edge cases */
#include "alpha.h"
#include "test_util.h"

sds tools_run(const char *name, cJSON *args, const char *cwd);

int main(void) {
    TEST_BEGIN("json_query_extra");

    /* 1. Alias jq works identically to json_query */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"name\":\"Alice\"}");
        cJSON_AddStringToObject(args, "path", "name");
        sds r1 = tools_run("json_query", args, NULL);
        sds r2 = tools_run("jq", args, NULL);
        CHECK(r1 != NULL && r2 != NULL, "jq alias returns non-NULL like json_query");
        CHECK(strstr(r1, "Alice") != NULL, "json_query alias jq extracts Alice");
        CHECK(strstr(r2, "Alice") != NULL, "jq alias extracts Alice");
        CHECK(strcmp(r1, r2) == 0, "jq and json_query return identical output");
        sdsfree(r1); sdsfree(r2);
        cJSON_Delete(args);
    }

    /* 2. Query with no path returns whole document */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"a\":1,\"b\":2}");
        // no path
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "query no path returns non-NULL");
        CHECK(strstr(r, "\"a\"") != NULL, "query no path contains a");
        CHECK(strstr(r, "\"b\"") != NULL, "query no path contains b");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 3. Query array out of bounds -> error */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "[1,2,3]");
        cJSON_AddStringToObject(args, "path", "5");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "query OOB returns non-NULL");
        CHECK(strstr(r, "ERROR") != NULL, "query OOB reports ERROR");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 4. Filter with path navigation */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "filter");
        cJSON_AddStringToObject(args, "data", "{\"users\":[{\"name\":\"Alice\",\"age\":30},{\"name\":\"Bob\",\"age\":25}]}");
        cJSON_AddStringToObject(args, "path", "users");
        cJSON_AddStringToObject(args, "filter_key", "age");
        cJSON_AddNumberToObject(args, "filter_min", 28);
        cJSON_AddNumberToObject(args, "filter_max", 40);
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "filter with path returns non-NULL");
        CHECK(strstr(r, "Alice") != NULL, "filter with path includes Alice");
        CHECK(strstr(r, "Bob") == NULL, "filter with path excludes Bob age 25");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 5. Project with spaces around comma */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "project");
        cJSON_AddStringToObject(args, "data", "[{\"name\":\"Alice\",\"age\":30,\"city\":\"NYC\"}]");
        cJSON_AddStringToObject(args, "fields", "name , city");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "project with spaced fields returns non-NULL");
        CHECK(strstr(r, "Alice") != NULL, "project spaced fields includes Alice");
        CHECK(strstr(r, "NYC") != NULL, "project spaced fields includes NYC");
        CHECK(strstr(r, "\"age\"") == NULL, "project spaced fields excludes age");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 6. Aggregate exact numeric values */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "aggregate");
        cJSON_AddStringToObject(args, "data", "[{\"v\":10},{\"v\":20},{\"v\":30}]");
        cJSON_AddStringToObject(args, "value_key", "v");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "aggregate exact values non-NULL");
        CHECK(strstr(r, "\"count\":3") != NULL, "aggregate count 3");
        CHECK(strstr(r, "\"sum\":60.00") != NULL, "aggregate sum 60.00");
        CHECK(strstr(r, "\"avg\":20.00") != NULL, "aggregate avg 20.00");
        CHECK(strstr(r, "\"min\":10.00") != NULL, "aggregate min 10.00");
        CHECK(strstr(r, "\"max\":30.00") != NULL, "aggregate max 30.00");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 7. Aggregate with key alias "key" instead of value_key */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "aggregate");
        cJSON_AddStringToObject(args, "data", "[{\"score\":5},{\"score\":15}]");
        cJSON_AddStringToObject(args, "key", "score");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "aggregate alias key returns non-NULL");
        CHECK(strstr(r, "\"count\":2") != NULL, "aggregate alias key count 2");
        CHECK(strstr(r, "\"sum\":20.00") != NULL, "aggregate alias key sum 20.00");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 8. Unknown action -> error */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "bogus");
        cJSON_AddStringToObject(args, "data", "{\"a\":1}");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "unknown action returns non-NULL");
        CHECK(strstr(r, "ERROR") != NULL, "unknown action reports ERROR");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 9. Missing data parameter -> error */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        // no data
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "missing data returns non-NULL");
        CHECK(strstr(r, "ERROR") != NULL, "missing data reports ERROR");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 10. Filter on non-array -> error */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "filter");
        cJSON_AddStringToObject(args, "data", "{\"a\":1}");
        cJSON_AddStringToObject(args, "filter_key", "a");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "filter non-array returns non-NULL");
        CHECK(strstr(r, "ERROR") != NULL, "filter non-array reports ERROR");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 11. Nested query with array index in middle of path */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"a\":{\"b\":[{\"c\":99},{\"c\":100}]}}");
        cJSON_AddStringToObject(args, "path", "a.b.1.c");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "nested array middle path non-NULL");
        CHECK(strstr(r, "100") != NULL, "nested array middle extracts 100");
        sdsfree(r);
        cJSON_Delete(args);
    }

    /* 12. Query numeric value */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"count\":42}");
        cJSON_AddStringToObject(args, "path", "count");
        sds r = tools_run("json_query", args, NULL);
        CHECK(r != NULL, "query numeric returns non-NULL");
        CHECK(strstr(r, "42") != NULL, "query numeric extracts 42");
        sdsfree(r);
        cJSON_Delete(args);
    }

    return test_report("json_query_extra");
}
