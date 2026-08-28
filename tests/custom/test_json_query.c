/* Test suite for the JSON query tool (json_query).
 *
 * Tests the query, filter, project, and aggregate operations on JSON data
 * using the embedded cJSON parser — no shelling out to jq. */

#include "alpha.h"
#include "test_util.h"

/* Forward declarations from tools.c */
sds tools_run(const char *name, cJSON *args, const char *cwd);

int main(void) {
    TEST_BEGIN("json_query_tool");

    /* 1. Basic query: extract a value by path */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"name\":\"Alice\",\"age\":30,\"city\":\"NYC\"}");
        cJSON_AddStringToObject(args, "path", "name");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query basic query returned non-NULL");
        CHECK(strstr(result, "Alice") != NULL, "json_query extracted name=Alice");
        CHECK(strstr(result, "\"action\":\"query\"") != NULL, "json_query result has action field");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 2. Nested path extraction */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"user\":{\"profile\":{\"display_name\":\"Bob\",\"age\":25}}}");
        cJSON_AddStringToObject(args, "path", "user.profile.display_name");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query nested path returned non-NULL");
        CHECK(strstr(result, "Bob") != NULL, "json_query extracted nested display_name=Bob");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 3. Array index access */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"items\":[10,20,30,40,50]}");
        cJSON_AddStringToObject(args, "path", "items.2");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query array index returned non-NULL");
        CHECK(strstr(result, "30") != NULL, "json_query extracted items[2]=30");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 4. Filter operation: select objects matching a condition */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "filter");
        cJSON_AddStringToObject(args, "data", "[{\"name\":\"Alice\",\"age\":30},{\"name\":\"Bob\",\"age\":25},{\"name\":\"Charlie\",\"age\":35}]");
        cJSON_AddStringToObject(args, "path", "");
        cJSON_AddStringToObject(args, "filter_key", "age");
        cJSON_AddNumberToObject(args, "filter_min", 28);
        cJSON_AddNumberToObject(args, "filter_max", 40);
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query filter returned non-NULL");
        CHECK(strstr(result, "Alice") != NULL, "filter includes Alice (age 30)");
        CHECK(strstr(result, "Charlie") != NULL, "filter includes Charlie (age 35)");
        CHECK(strstr(result, "Bob") == NULL, "filter excludes Bob (age 25 < 28)");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 5. Project operation: select specific fields */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "project");
        cJSON_AddStringToObject(args, "data", "[{\"name\":\"Alice\",\"age\":30,\"city\":\"NYC\"},{\"name\":\"Bob\",\"age\":25,\"city\":\"LA\"}]");
        cJSON_AddStringToObject(args, "fields", "name,city");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query project returned non-NULL");
        CHECK(strstr(result, "Alice") != NULL, "project includes name=Alice");
        CHECK(strstr(result, "NYC") != NULL, "project includes city=NYC");
        CHECK(strstr(result, "\"age\"") == NULL, "project excludes age field");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 6. Aggregate: count and sum */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "aggregate");
        cJSON_AddStringToObject(args, "data", "[{\"name\":\"Alice\",\"score\":90},{\"name\":\"Bob\",\"score\":80},{\"name\":\"Charlie\",\"score\":95}]");
        cJSON_AddStringToObject(args, "value_key", "score");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query aggregate returned non-NULL");
        CHECK(strstr(result, "\"count\":3") != NULL, "aggregate count=3");
        CHECK(strstr(result, "\"sum\"") != NULL, "aggregate has sum field");
        CHECK(strstr(result, "\"avg\"") != NULL, "aggregate has avg field");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 7. Error handling: invalid JSON */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{invalid json}");
        cJSON_AddStringToObject(args, "path", "name");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query invalid JSON returned non-NULL");
        CHECK(strstr(result, "ERROR") != NULL, "json_query reports error on invalid JSON");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 8. Error handling: missing path */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"name\":\"Alice\"}");
        cJSON_AddStringToObject(args, "path", "nonexistent");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query missing path returned non-NULL");
        CHECK(strstr(result, "ERROR") != NULL, "json_query reports error on missing path");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 9. Empty array handling */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "aggregate");
        cJSON_AddStringToObject(args, "data", "[]");
        cJSON_AddStringToObject(args, "value_key", "score");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query empty array returned non-NULL");
        CHECK(strstr(result, "\"count\":0") != NULL, "aggregate empty array count=0");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 10. Deeply nested path with array */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "query");
        cJSON_AddStringToObject(args, "data", "{\"store\":{\"books\":[{\"title\":\"C Programming\",\"price\":45},{\"title\":\"Data Structures\",\"price\":55}],\"count\":2}}");
        cJSON_AddStringToObject(args, "path", "store.books.0.title");
        sds result = tools_run("json_query", args, NULL);
        CHECK(result != NULL, "json_query deep nested path returned non-NULL");
        CHECK(strstr(result, "C Programming") != NULL, "json_query extracted deeply nested title");
        sdsfree(result);
        cJSON_Delete(args);
    }

    return test_report("json_query_tool");
}
