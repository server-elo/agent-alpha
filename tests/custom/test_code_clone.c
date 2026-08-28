#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
extern cJSON *tools_schema(void);

static void test_minhash_fingerprint_deterministic(void) {
    TEST_BEGIN("code_clone_detector: deterministic 64-dimensional MinHash fingerprint");
    const char *code = "int compute_sum(int a, int b) { return a + b; }";
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "fingerprint");
    cJSON_AddStringToObject(args, "text", code);

    sds res1 = tools_run("code_clone_detector", args, ".");
    cJSON_Delete(args);

    CHECK(res1 != NULL, "response returned");
    cJSON *p1 = cJSON_Parse(res1);
    CHECK(p1 != NULL, "valid json returned");
    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p1, "action")), "fingerprint") == 0, "action confirmed");
    CHECK_EQ_INT(cJSON_GetNumberValue(cJSON_GetObjectItem(p1, "k")), 64, "k is 64");
    const char *hex1 = cJSON_GetStringValue(cJSON_GetObjectItem(p1, "hex"));
    CHECK(hex1 != NULL && strlen(hex1) == 512, "512-hex char fingerprint");

    /* Second identical run to assert determinism */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "fingerprint");
    cJSON_AddStringToObject(args2, "text", code);
    sds res2 = tools_run("code_clone_detector", args2, ".");
    cJSON_Delete(args2);

    cJSON *p2 = cJSON_Parse(res2);
    const char *hex2 = cJSON_GetStringValue(cJSON_GetObjectItem(p2, "hex"));
    CHECK(strcmp(hex1, hex2) == 0, "identical code produces identical 512-hex fingerprint");

    if (p1) cJSON_Delete(p1);
    if (p2) cJSON_Delete(p2);
    sdsfree(res1);
    sdsfree(res2);
}

static void test_jaccard_identical_and_clones(void) {
    TEST_BEGIN("code_clone_detector: Jaccard similarity on clones and near-clones");
    const char *code_orig = "static inline void process_packet(uint8_t *buf, size_t len) { for (size_t i = 0; i < len; i++) { buf[i] ^= 0xAA; } }";
    const char *code_clone = "static inline void process_packet(uint8_t *data, size_t length) { for (size_t i = 0; i < length; i++) { data[i] ^= 0xAA; } }";
    const char *code_disjoint = "struct Matrix4x4 { float m[4][4]; void identity() { memset(m, 0, sizeof(m)); m[0][0]=1; } };";

    /* Test 1: Identical code similarity must be 1.0 */
    cJSON *args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(args1, "action", "jaccard");
    cJSON_AddStringToObject(args1, "a", code_orig);
    cJSON_AddStringToObject(args1, "b", code_orig);
    sds res1 = tools_run("code_clone_detector", args1, ".");
    cJSON_Delete(args1);

    cJSON *p1 = cJSON_Parse(res1);
    CHECK(p1 != NULL, "valid json for identical comparison");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(p1, "similarity")) == 1.0, "identical code has 1.0 similarity");
    CHECK_EQ_INT(cJSON_GetNumberValue(cJSON_GetObjectItem(p1, "matching_slots")), 64, "all 64 slots match");
    CHECK_EQ_INT(cJSON_GetNumberValue(cJSON_GetObjectItem(p1, "lsh_bands_matched")), 32, "all 32 LSH bands match");

    /* Test 2: Near-clone similarity */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "jaccard");
    cJSON_AddStringToObject(args2, "a", code_orig);
    cJSON_AddStringToObject(args2, "b", code_clone);
    sds res2 = tools_run("code_clone_detector", args2, ".");
    cJSON_Delete(args2);

    cJSON *p2 = cJSON_Parse(res2);
    double sim_clone = cJSON_GetNumberValue(cJSON_GetObjectItem(p2, "similarity"));
    CHECK(sim_clone >= 0.70, "near clone has high Jaccard similarity (>= 0.70)");
    CHECK(cJSON_GetNumberValue(cJSON_GetObjectItem(p2, "lsh_bands_matched")) > 0, "near clone shares LSH bands");

    /* Test 3: Disjoint code */
    cJSON *args3 = cJSON_CreateObject();
    cJSON_AddStringToObject(args3, "action", "jaccard");
    cJSON_AddStringToObject(args3, "a", code_orig);
    cJSON_AddStringToObject(args3, "b", code_disjoint);
    sds res3 = tools_run("code_clone_detector", args3, ".");
    cJSON_Delete(args3);

    cJSON *p3 = cJSON_Parse(res3);
    double sim_disjoint = cJSON_GetNumberValue(cJSON_GetObjectItem(p3, "similarity"));
    CHECK(sim_disjoint < 0.30, "disjoint code has low Jaccard similarity (< 0.30)");

    if (p1) cJSON_Delete(p1);
    if (p2) cJSON_Delete(p2);
    if (p3) cJSON_Delete(p3);
    sdsfree(res1);
    sdsfree(res2);
    sdsfree(res3);
}

static void test_lsh_query_candidate_retrieval(void) {
    TEST_BEGIN("code_clone_detector: 32-band LSH candidate retrieval over corpus");
    cJSON *corpus = cJSON_CreateArray();

    cJSON *c1 = cJSON_CreateObject();
    cJSON_AddStringToObject(c1, "id", "math_add");
    cJSON_AddStringToObject(c1, "text", "int add(int a, int b) { return a + b; }");
    cJSON_AddItemToArray(corpus, c1);

    cJSON *c2 = cJSON_CreateObject();
    cJSON_AddStringToObject(c2, "id", "math_sum");
    cJSON_AddStringToObject(c2, "text", "int sum(int a, int b) { return a + b; }");
    cJSON_AddItemToArray(corpus, c2);

    cJSON *c3 = cJSON_CreateObject();
    cJSON_AddStringToObject(c3, "id", "graphics_draw");
    cJSON_AddStringToObject(c3, "text", "void render_pipeline_draw_quad(struct Context *ctx, float x, float y) { glDrawArrays(GL_TRIANGLES, 0, 6); }");
    cJSON_AddItemToArray(corpus, c3);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "lsh_match");
    cJSON_AddStringToObject(args, "query", "int add(int x, int y) { return x + y; }");
    cJSON_AddItemToObject(args, "corpus", corpus);
    cJSON_AddNumberToObject(args, "threshold", 0.60);

    sds res = tools_run("code_clone_detector", args, ".");
    cJSON_Delete(args);

    CHECK(res != NULL, "LSH query returns response");
    cJSON *p = cJSON_Parse(res);
    CHECK(p != NULL, "valid json result");
    cJSON *matches = cJSON_GetObjectItem(p, "matches");
    CHECK(matches != NULL && cJSON_IsArray(matches), "matches is an array");
    int count = cJSON_GetArraySize(matches);
    CHECK(count >= 1, "found candidate matches");

    int found_add = 0;
    for (int i = 0; i < count; i++) {
        cJSON *m = cJSON_GetArrayItem(matches, i);
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(m, "id"));
        if (id && strcmp(id, "math_add") == 0) found_add = 1;
    }
    CHECK(found_add == 1, "LSH retrieved true clone candidate 'math_add'");

    if (p) cJSON_Delete(p);
    sdsfree(res);
}

static void test_adversarial_and_schema(void) {
    TEST_BEGIN("code_clone_detector: adversarial rejection & schema registration");

    /* Test missing text */
    cJSON *args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(args1, "action", "fingerprint");
    sds res1 = tools_run("code_clone_detector", args1, ".");
    cJSON_Delete(args1);
    CHECK(strstr(res1, "ERROR: text or readable file path required") != NULL, "missing text rejected");
    sdsfree(res1);

    /* Test missing a or b in jaccard */
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "action", "jaccard");
    cJSON_AddStringToObject(args2, "a", "test string");
    sds res2 = tools_run("code_clone_detector", args2, ".");
    cJSON_Delete(args2);
    CHECK(strstr(res2, "ERROR: both 'a' and 'b' parameters required") != NULL, "missing b rejected");
    sdsfree(res2);

    /* Test unknown action */
    cJSON *args3 = cJSON_CreateObject();
    cJSON_AddStringToObject(args3, "action", "unsupported_action");
    sds res3 = tools_run("code_clone_detector", args3, ".");
    cJSON_Delete(args3);
    CHECK(strstr(res3, "ERROR: unknown code_clone_detector action") != NULL, "unknown action rejected");
    sdsfree(res3);

    /* Test schema presence */
    cJSON *schema = tools_schema();
    CHECK(schema != NULL, "schema parsed");
    char *s = cJSON_PrintUnformatted(schema);
    CHECK(s != NULL, "schema printed");
    CHECK(strstr(s, "\"name\":\"code_clone_detector\"") != NULL, "schema includes code_clone_detector");
    CHECK(strstr(s, "\"name\":\"intset\"") != NULL, "schema includes intset");
    free(s);
    if (schema) cJSON_Delete(schema);
}

int main(void) {
    test_minhash_fingerprint_deterministic();
    test_jaccard_identical_and_clones();
    test_lsh_query_candidate_retrieval();
    test_adversarial_and_schema();
    return test_report("test_code_clone");
}
