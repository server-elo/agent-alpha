#include "test_util.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    *out_len = rd;
    return buf;
}

static int count_tokens(sds res) {
    cJSON *p = cJSON_Parse(res);
    if (!p) return -1;
    cJSON *toks = cJSON_GetObjectItemCaseSensitive(p, "tokens");
    int n = (toks && cJSON_IsArray(toks)) ? cJSON_GetArraySize(toks) : 0;
    cJSON_Delete(p);
    return n;
}

static void test_real_file(void) {
    TEST_BEGIN("mdesk_tokenize: real messy source file");
    size_t len;
    char *src = read_file("src/tools.c", &len);
    CHECK(src != NULL, "read src/tools.c");
    if (!src) return;

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", src);
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    free(src);

    CHECK(res != NULL, "no crash on real file");
    int n = count_tokens(res);
    CHECK(n > 100, "produces many tokens from real file");
    CHECK(strstr(res, "\"action\":\"mdesk_tokenize\"") != NULL, "action confirmed");
    CHECK(strstr(res, "\"kind\":\"identifier\"") != NULL, "identifiers present");
    CHECK(strstr(res, "\"kind\":\"comment\"") != NULL, "comments present");
    CHECK(strstr(res, "\"kind\":\"string\"") != NULL, "strings present");
    sdsfree(res);
}

static void test_embedded_nulls(void) {
    TEST_BEGIN("mdesk_tokenize: embedded null bytes");
    const char *s = "int\x00\x00a = 1;\x00\x00";
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", s);
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "no crash on embedded nulls");
    CHECK(strstr(res, "\"action\":\"mdesk_tokenize\"") != NULL, "valid json returned");
    sdsfree(res);
}

static void test_unicode_identifiers(void) {
    TEST_BEGIN("mdesk_tokenize: UTF-8 identifiers");
    const char *s = "café = 1; naïve_ñ = 2; 日本語 = 3;";
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", s);
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "no crash on unicode");
    CHECK(strstr(res, "\"kind\":\"identifier\"") != NULL, "unicode identifiers recognized");
    sdsfree(res);
}

static void test_deeply_nested_triplets(void) {
    TEST_BEGIN("mdesk_tokenize: triple-quote nesting");
    const char *s = "'''outer '''inner''' outer''' + \"\"\"x\"\"\"";
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", s);
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "no crash on nested triplets");
    CHECK(strstr(res, "\"kind\":\"string\"") != NULL, "triplet strings recognized");
    sdsfree(res);
}

static void test_escape_sequences(void) {
    TEST_BEGIN("mdesk_tokenize: escape sequences in strings");
    const char *s = "line1\\nline2 \"tab\\tend\" 'it\\'s'";
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", s);
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "no crash on escapes");
    CHECK(strstr(res, "\"kind\":\"string\"") != NULL, "escaped strings recognized");
    sdsfree(res);
}

static void test_empty_input(void) {
    TEST_BEGIN("mdesk_tokenize: empty input");
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", "");
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    CHECK(res != NULL, "no crash on empty input");
    CHECK(strstr(res, "\"action\":\"mdesk_tokenize\"") != NULL, "valid json returned");
    sdsfree(res);
}

static void test_very_long_line(void) {
    TEST_BEGIN("mdesk_tokenize: very long line");
    char *s = malloc(200000);
    CHECK(s != NULL, "alloc long line buffer");
    if (!s) return;
    memset(s, 'a', 199999);
    s[199999] = '\0';
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "text", s);
    sds res = tools_run("mdesk_tokenize", args, ".");
    cJSON_Delete(args);
    free(s);
    CHECK(res != NULL, "no crash on 200KB line");
    CHECK(strstr(res, "\"action\":\"mdesk_tokenize\"") != NULL, "valid json returned");
    sdsfree(res);
}

int main(void) {
    test_real_file();
    test_embedded_nulls();
    test_unicode_identifiers();
    test_deeply_nested_triplets();
    test_escape_sequences();
    test_empty_input();
    test_very_long_line();
    return test_report("test_mdesk_fuzz");
}