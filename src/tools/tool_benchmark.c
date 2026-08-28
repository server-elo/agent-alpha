/* tool_benchmark.c — Command execution benchmarking and timing suite */
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static sds tool_benchmark_run(cJSON *args, const char *cwd) {
    const char *cmd = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
    if (!cmd || !cmd[0])
        return sdsnew("ERROR: command required for benchmark");

    int iterations = 1;
    cJSON *iter_item = cJSON_GetObjectItem(args, "iterations");
    if (cJSON_IsNumber(iter_item)) {
        iterations = iter_item->valueint;
        if (iterations < 1) iterations = 1;
        if (iterations > 100) iterations = 100;
    }

    int warmup = 0;
    cJSON *warmup_item = cJSON_GetObjectItem(args, "warmup");
    if (cJSON_IsNumber(warmup_item)) {
        warmup = warmup_item->valueint;
        if (warmup < 0) warmup = 0;
        if (warmup > 20) warmup = 20;
    }

    /* Warmup runs (not timed) */
    for (int w = 0; w < warmup; w++) {
        sds r = shell_run(cmd, cwd);
        sdsfree(r);
    }

    /* Timed runs */
    double total_ms = 0.0;
    double min_ms = 1e18;
    double max_ms = 0.0;
    int failures = 0;

    for (int i = 0; i < iterations; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        sds r = shell_run(cmd, cwd);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (strncmp(r, "ERROR", 5) == 0) {
            failures++;
        } else {
            const char *exit_marker = strstr(r, "__ALPHA_EXIT:");
            if (exit_marker) {
                int ec = atoi(exit_marker + 13);
                if (ec != 0) failures++;
            }
        }

        double elapsed = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                         (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
        total_ms += elapsed;
        if (elapsed < min_ms) min_ms = elapsed;
        if (elapsed > max_ms) max_ms = elapsed;
        sdsfree(r);
    }

    double avg_ms = total_ms / (double)iterations;

    sds out = sdscatprintf(sdsempty(),
        "{\"action\":\"benchmark\",\"command\":\"%s\",\"iterations\":%d,"
        "\"warmup\":%d,\"failures\":%d,"
        "\"total_ms\":%.2f,\"avg_ms\":%.2f,\"min_ms\":%.2f,\"max_ms\":%.2f}",
        cmd, iterations, warmup, failures,
        total_ms, avg_ms, min_ms, max_ms);
    return out;
}

static const alpha_tool_t tool_benchmark = {
    .name = "benchmark",
    .aliases = {"bench", NULL},
    .category = "system",
    .description = "Measures the execution time of a shell command across multiple iterations with optional warmup. Reports total, average, minimum, and maximum elapsed milliseconds along with execution failure counts.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"benchmark\",\"description\":\"Measures the execution time of a shell command across multiple iterations with optional warmup. Reports total, average, minimum, and maximum elapsed milliseconds along with execution failure counts.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"Shell command to benchmark\"},\"iterations\":{\"type\":\"integer\",\"description\":\"Number of timed runs (1-100, default 1)\"},\"warmup\":{\"type\":\"integer\",\"description\":\"Number of untimed warmup runs (0-20, default 0)\"}},\"required\":[\"command\"]}}}",
    .run = tool_benchmark_run
};
