/* Minimal assertion helpers for the regression suite.
 *
 * Tests include the module under test directly (e.g. `#include "../src/tools.c"`)
 * because the functions they cover are `static`. That means a test compiles its
 * own copy of the module -- run `make test` after `make` so both are current.
 *
 * Every test must create the fixtures it needs. The original ad-hoc harnesses
 * read files left behind in /tmp and segfaulted once those were cleaned up. */
#ifndef ALPHA_TEST_UTIL_H
#define ALPHA_TEST_UTIL_H

#include <stdio.h>
#include <string.h>

static int alpha_checks, alpha_failures;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        alpha_checks++;                                                       \
        if (cond) {                                                           \
            printf("  ok   %s\n", (what));                                    \
        } else {                                                              \
            alpha_failures++;                                                 \
            printf("  FAIL %s   (%s:%d)\n", (what), __FILE__, __LINE__);      \
        }                                                                     \
    } while (0)

#define CHECK_EQ_INT(got, want, what)                                         \
    do {                                                                      \
        alpha_checks++;                                                       \
        long long g_ = (long long)(got), w_ = (long long)(want);              \
        if (g_ == w_) {                                                       \
            printf("  ok   %s\n", (what));                                    \
        } else {                                                              \
            alpha_failures++;                                                 \
            printf("  FAIL %s: got %lld want %lld   (%s:%d)\n",               \
                   (what), g_, w_, __FILE__, __LINE__);                       \
        }                                                                     \
    } while (0)

#define TEST_BEGIN(name) printf("%s\n", (name))

static int test_report(const char *suite) {
    printf("%s: %d checks, %d failed\n", suite, alpha_checks, alpha_failures);
    return alpha_failures == 0 ? 0 : 1;
}

#endif
