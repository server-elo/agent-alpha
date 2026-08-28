/* Custom test: memory tool + benchmark tool integration.
 *
 * Validates the memory tool's add/read/replace/remove cycle and the benchmark
 * tool's basic timing and failure detection. Both tools are defined in
 * tools.c and reachable through tools_run().
 *
 * The memory tool is tested with a throwaway directory (ALPHA_MEMORY_DIR)
 * so the test never touches the user's real ~/.alpha/memory/ store. */
#include "alpha.h"
#include "test_util.h"

/* memory_init is declared in alpha.h; memory_store_t is internal to tools.c
 * and not needed here — we test exclusively through tools_run(). */

int main(void) {
    TEST_BEGIN("memory_bench");

    /* ── memory tool ──────────────────────────────────────────────────── */

    /* Point memory at a throwaway directory so the test never touches the
     * real store. The env var is read once inside memory_init() and again
     * inside memory_tool_run() → memory_dir(). */
    setenv("ALPHA_MEMORY_DIR", "/tmp/alpha-test-memory-XXXXXX", 1);
    /* mkdtemp is not available everywhere; use a fixed path under /tmp. */
    char memdir[128];
    snprintf(memdir, sizeof(memdir), "/tmp/alpha-test-memory-%d", (int)getpid());
    mkdir(memdir, 0755);
    setenv("ALPHA_MEMORY_DIR", memdir, 1);

    memory_init();

    /* 1. Read empty store */
    {
        cJSON *args = cJSON_CreateObject();
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory read (empty) returned non-NULL");
        CHECK(strstr(result, "\"entries\":[]") != NULL,
              "memory read (empty) has empty entries array");
        CHECK(strstr(result, "\"char_count\":0") != NULL,
              "memory read (empty) has char_count 0");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 2. Add an entry */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "add");
        cJSON_AddStringToObject(args, "content", "bench_before=val_before");
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory add returned non-NULL");
        CHECK(strncmp(result, "OK", 2) == 0,
              "memory add returned OK");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 3. Read back — should contain the entry */
    {
        cJSON *args = cJSON_CreateObject();
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory read (after add) returned non-NULL");
        CHECK(strstr(result, "bench_before") != NULL,
              "memory read contains 'bench_before'");
        CHECK(strstr(result, "val_before") != NULL,
              "memory read contains 'val_before'");
        CHECK(strstr(result, "\"char_count\":23") != NULL,
              "memory char_count is 23 (bench_before=val_before)");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 4. Replace the entry */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "replace");
        cJSON_AddStringToObject(args, "old_text", "bench_before");
        cJSON_AddStringToObject(args, "content", "bench_after=val_after");
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory replace returned non-NULL");
        CHECK(strncmp(result, "OK", 2) == 0,
              "memory replace returned OK");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 5. Verify replacement */
    {
        cJSON *args = cJSON_CreateObject();
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory read (after replace) returned non-NULL");
        CHECK(strstr(result, "bench_after") != NULL,
              "memory read contains 'bench_after'");
        CHECK(strstr(result, "val_after") != NULL,
              "memory read contains 'val_after'");
        CHECK(strstr(result, "bench_before") == NULL,
              "memory read no longer contains 'bench_before'");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 6. Remove the entry */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "remove");
        cJSON_AddStringToObject(args, "old_text", "bench_after");
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory remove returned non-NULL");
        CHECK(strncmp(result, "OK", 2) == 0,
              "memory remove returned OK");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 7. Verify empty after removal */
    {
        cJSON *args = cJSON_CreateObject();
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory read (after remove) returned non-NULL");
        CHECK(strstr(result, "\"entries\":[]") != NULL,
              "memory read (after remove) has empty entries array");
        CHECK(strstr(result, "\"char_count\":0") != NULL,
              "memory read (after remove) has char_count 0");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 8. User store — add and read */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "action", "add");
        cJSON_AddStringToObject(args, "target", "user");
        cJSON_AddStringToObject(args, "content", "user_pref=test");
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory user add returned non-NULL");
        CHECK(strncmp(result, "OK", 2) == 0,
              "memory user add returned OK");
        sdsfree(result);
        cJSON_Delete(args);
    }
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "target", "user");
        sds result = tools_run("memory", args, NULL);
        CHECK(result != NULL, "memory user read returned non-NULL");
        CHECK(strstr(result, "user_pref") != NULL,
              "memory user read contains 'user_pref'");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* ── benchmark tool ───────────────────────────────────────────────── */

    /* 9. Benchmark a trivial command */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "command", "echo hello");
        cJSON_AddNumberToObject(args, "iterations", 3);
        cJSON_AddNumberToObject(args, "warmup", 1);
        sds result = tools_run("benchmark", args, NULL);
        CHECK(result != NULL, "benchmark returned non-NULL");
        CHECK(strstr(result, "\"action\":\"benchmark\"") != NULL,
              "benchmark result has action field");
        CHECK(strstr(result, "\"iterations\":3") != NULL,
              "benchmark result shows 3 iterations");
        CHECK(strstr(result, "\"failures\":0") != NULL,
              "benchmark result shows 0 failures");
        CHECK(strstr(result, "\"avg_ms\"") != NULL,
              "benchmark result has avg_ms field");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* 10. Benchmark with a failing command */
    {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "command", "exit 42");
        cJSON_AddNumberToObject(args, "iterations", 2);
        sds result = tools_run("benchmark", args, NULL);
        CHECK(result != NULL, "benchmark (failing) returned non-NULL");
        CHECK(strstr(result, "\"failures\":2") != NULL,
              "benchmark (failing) shows 2 failures");
        sdsfree(result);
        cJSON_Delete(args);
    }

    /* ── Cleanup ──────────────────────────────────────────────────────── */

    /* Remove the throwaway directory */
    char rm_cmd[256];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", memdir);
    system(rm_cmd);

    return test_report("memory_bench");
}
