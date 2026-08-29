#ifndef ALPHA_TEST_FRAMEWORK_H
#define ALPHA_TEST_FRAMEWORK_H
#include <stdio.h>
#include <string.h>
static int g_checks, g_failed;
#define CHECK(cond, what) do { g_checks++; if (cond) { printf("  ok   %s\n", (what)); } else { g_failed++; printf("  FAIL %s   (%s:%d)\n", (what), __FILE__, __LINE__); } } while(0)
#define CHECK_EQ_INT(got, want, what) do { g_checks++; long long g_=(long long)(got), w_=(long long)(want); if(g_==w_) printf("  ok   %s\n",(what)); else { g_failed++; printf("  FAIL %s: got %lld want %lld (%s:%d)\n",(what),g_,w_,__FILE__,__LINE__);} } while(0)
#define TEST(name) void test_##name(void)
#define TEST_BEGIN(name) printf("%s\n",(name))
static int test_report(const char *suite){ printf("%s: %d checks, %d failed\n", suite, g_checks, g_failed); return g_failed==0?0:1; }
#endif
