/* Provider presets and terminal rendering.
 *
 * The presets decide which endpoint and key a user reaches with no flags at
 * all, so a wrong entry is a silent misconfiguration rather than a crash. The
 * UI helpers are here because width miscalculation is invisible in ASCII tests
 * and only shows up as ragged output on real, non-English text. */
#include "../src/provider.c"
#include "../src/ui.c"
#include "test_util.h"

static void test_lookup_by_name(void) {
    TEST_BEGIN("providers: lookup by name");
    const alpha_provider_t *p = alpha_provider_by_name("ollama");
    CHECK(p != NULL, "a known provider is found");
    CHECK(p && p->local == 1, "ollama is marked local");
    CHECK(p && p->key_env == NULL, "and needs no API key");

    /* Users type names in whatever case they like. */
    CHECK(alpha_provider_by_name("OpenAI") != NULL, "lookup is case insensitive");
    CHECK(alpha_provider_by_name("nope") == NULL, "an unknown name is not guessed at");
    CHECK(alpha_provider_by_name("") == NULL, "an empty name is not a match");
    CHECK(alpha_provider_by_name(NULL) == NULL, "NULL is handled");
}

/* Every hosted provider must name a key variable and every local one must not:
 * a hosted entry with no key var silently sends unauthenticated requests, and
 * a local entry demanding a key breaks the offline path this feature exists
 * for. Checking the whole table catches a bad row added later. */
static void test_table_is_internally_consistent(void) {
    TEST_BEGIN("providers: every entry is complete and consistent");
    int n = 0, bad = 0;
    for (int i = 0;; i++) {
        const alpha_provider_t *p = alpha_provider_at(i);
        if (!p) break;
        n++;
        if (!p->name || !p->name[0]) { printf("  (entry %d has no name)\n", i); bad++; }
        if (!p->base_url || strncmp(p->base_url, "http", 4) != 0) {
            printf("  (%s: base_url is not a URL)\n", p->name); bad++;
        }
        if (!p->default_model || !p->default_model[0]) {
            printf("  (%s: no default model)\n", p->name); bad++;
        }
        if (!p->local && !p->key_env) {
            printf("  (%s: hosted but names no key env var)\n", p->name); bad++;
        }
        if (p->local && p->key_env) {
            printf("  (%s: local but demands a key)\n", p->name); bad++;
        }
        /* A local preset pointing at a remote host would send the user's code
         * off the machine while claiming to be local. */
        if (p->local && !strstr(p->base_url, "localhost") && !strstr(p->base_url, "127.0.0.1")) {
            printf("  (%s: marked local but points off-machine)\n", p->name); bad++;
        }
    }
    CHECK(n >= 8, "the table has entries");
    CHECK_EQ_INT(bad, 0, "no entry is malformed");

    /* Duplicate names would make lookup order-dependent. */
    int dup = 0;
    for (int i = 0; alpha_provider_at(i); i++)
        for (int j = i + 1; alpha_provider_at(j); j++)
            if (strcasecmp(alpha_provider_at(i)->name, alpha_provider_at(j)->name) == 0) dup++;
    CHECK_EQ_INT(dup, 0, "provider names are unique");
}

/* Matching an explicit --url back to a preset is what lets a user pass only a
 * URL and still get the right key variable and default model. */
static void test_lookup_by_url(void) {
    TEST_BEGIN("providers: a base URL maps back to its preset");
    const alpha_provider_t *p = alpha_provider_by_url("http://localhost:11434/v1");
    CHECK(p && strcmp(p->name, "ollama") == 0, "exact URL matches");

    /* The forms a user actually types must all resolve to the same provider. */
    const char *variants[] = {
        "http://localhost:11434",
        "http://localhost:11434/",
        "http://localhost:11434/v1/",
        "https://localhost:11434/v1",
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        const alpha_provider_t *v = alpha_provider_by_url(variants[i]);
        if (!v || strcmp(v->name, "ollama") != 0) {
            printf("  (%s did not match ollama)\n", variants[i]);
            ok = 0;
        }
    }
    CHECK(ok, "scheme, port path and trailing slash variants all match");

    CHECK(alpha_provider_by_url("https://example.invalid/v1") == NULL,
          "an unknown endpoint matches nothing rather than the closest entry");
    CHECK(alpha_provider_by_url(NULL) == NULL, "NULL is handled");

    /* A different port is a different server: matching it to Ollama would hand
     * the wrong default model to whatever is really listening. */
    CHECK(alpha_provider_by_url("http://localhost:9999/v1") == NULL,
          "a different port does not match");
}

static void test_cfg_defaults(void) {
    TEST_BEGIN("providers: defaults only fill in what the caller left unset");
    alpha_cfg_t c = { 0 };
    alpha_cfg_defaults(&c);
    CHECK(c.max_turns > 0, "max_turns defaulted");
    CHECK(c.max_tokens > 0, "max_tokens defaulted");
    CHECK(c.temperature > 0.0, "temperature defaulted");

    alpha_cfg_t explicit_cfg = { .max_turns = 3, .max_tokens = 100, .temperature = 0.9 };
    alpha_cfg_defaults(&explicit_cfg);
    CHECK_EQ_INT(explicit_cfg.max_turns, 3, "an explicit max_turns is not overwritten");
    CHECK_EQ_INT(explicit_cfg.max_tokens, 100, "an explicit max_tokens is not overwritten");
    CHECK(explicit_cfg.temperature == 0.9, "an explicit temperature is not overwritten");

    alpha_cfg_defaults(NULL);   /* must not crash */
    CHECK(1, "NULL config is tolerated");
}

/* --- terminal rendering ---------------------------------------------------- */

/* Padding by strlen() is correct for ASCII and wrong for everything else, so
 * only non-ASCII input can catch it. */
static void test_display_width(void) {
    TEST_BEGIN("ui: display width counts columns, not bytes");
    CHECK_EQ_INT(ui_display_width("hello"), 5, "ASCII is one column per byte");
    CHECK_EQ_INT(ui_display_width(""), 0, "empty string is zero");
    /* "grün": 5 bytes, 4 columns. */
    CHECK_EQ_INT(ui_display_width("gr\xc3\xbcn"), 4, "a 2-byte character is one column");
    /* "—" U+2014: 3 bytes, 1 column. */
    CHECK_EQ_INT(ui_display_width("\xe2\x80\x94"), 1, "a 3-byte character is one column");
    /* CJK is double width. */
    CHECK_EQ_INT(ui_display_width("\xe4\xb8\xad\xe6\x96\x87"), 4, "CJK counts as two columns each");
    /* An emoji is double width: 4 bytes, 2 columns. */
    CHECK_EQ_INT(ui_display_width("\xf0\x9f\x9a\x80"), 2, "an emoji counts as two columns");
    /* Malformed input must terminate rather than run off the end. */
    CHECK_EQ_INT(ui_display_width("\xff\xfe"), 0, "stray bytes are skipped, not counted");
    CHECK_EQ_INT(ui_display_width("a\x80\x80" "b"), 2, "continuation bytes alone are ignored");
}

static void test_ellipsize(void) {
    TEST_BEGIN("ui: previews are shortened on a character boundary");
    sds s = ui_ellipsize("short", 20);
    CHECK(strcmp(s, "short") == 0, "text that fits is untouched");
    sdsfree(s);

    /* Tool arguments are JSON with embedded newlines; a raw one would break
     * the single-line layout. */
    s = ui_ellipsize("a\nb\tc   d", 20);
    CHECK(strcmp(s, "a b c d") == 0, "whitespace is collapsed to single spaces");
    sdsfree(s);

    s = ui_ellipsize("aaaaaaaaaaaaaaaaaaaaaaaaa", 10);
    CHECK(ui_display_width(s) <= 10, "a long string is cut to the limit");
    CHECK(strstr(s, "\xe2\x80\xa6") != NULL, "and marked with an ellipsis");
    sdsfree(s);

    /* Cutting mid-character would emit invalid UTF-8, which is exactly what
     * corrupted saved sessions elsewhere in this codebase. */
    s = ui_ellipsize("\xc3\xbc\xc3\xbc\xc3\xbc\xc3\xbc\xc3\xbc\xc3\xbc\xc3\xbc\xc3\xbc", 4);
    int valid = 1;
    for (size_t i = 0; i < sdslen(s); ) {
        unsigned char c = (unsigned char)s[i];
        int len = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3
                : (c & 0xF8) == 0xF0 ? 4 : 0;
        if (len == 0 || i + (size_t)len > sdslen(s)) { valid = 0; break; }
        for (int k = 1; k < len; k++)
            if (((unsigned char)s[i + k] & 0xC0) != 0x80) { valid = 0; break; }
        i += (size_t)len;
    }
    CHECK(valid, "a multi-byte character is never split by the cut");
    sdsfree(s);

    s = ui_ellipsize(NULL, 10);
    CHECK(sdslen(s) == 0, "NULL yields an empty string");
    sdsfree(s);
}

/* Colour codes in a pipe are noise, and NO_COLOR is the documented way to ask
 * for none. Both matter because this REPL is scriptable. */
static void test_color_is_suppressed_when_it_should_be(void) {
    TEST_BEGIN("ui: colour is off for pipes, NO_COLOR and dumb terminals");
    /* The suite's own stdout is a pipe under `make test`, which is the case
     * that matters: nothing may emit escapes. */
    if (!isatty(STDOUT_FILENO)) {
        CHECK(ui_use_color() == 0, "no colour when stdout is not a terminal");
        CHECK(strcmp(ui_c(UI_RED), "") == 0, "ui_c yields an empty string");
    } else {
        ui_color = -1;
        setenv("NO_COLOR", "1", 1);
        CHECK(ui_use_color() == 0, "NO_COLOR disables colour");
        CHECK(strcmp(ui_c(UI_RED), "") == 0, "ui_c yields an empty string");
        unsetenv("NO_COLOR");
    }
    ui_color = -1;
    CHECK(ui_width() >= 20, "a usable width is always reported");
}

int main(void) {
    test_lookup_by_name();
    test_table_is_internally_consistent();
    test_lookup_by_url();
    test_cfg_defaults();
    test_display_width();
    test_ellipsize();
    test_color_is_suppressed_when_it_should_be();
    return test_report("provider");
}
