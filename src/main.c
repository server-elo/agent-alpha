#include "alpha.h"
#include <curl/curl.h>

static void usage(const char *argv0) {
    fprintf(stderr,
        "Agent Alpha — open AI coding shell (no path security)\n"
        "Usage:\n"
        "  %s \"goal text\"              # one-shot CLI\n"
        "  %s --telegram                # Telegram long-poll\n"
        "  %s --repl                    # interactive stdin\n"
        "\nEnv:\n"
        "  ALPHA_BASE_URL   default http://127.0.0.1:8317/v1  (vibeproxy)\n"
        "  ALPHA_API_KEY    default none\n"
        "  ALPHA_MODEL      default vibeproxy/claude-opus-5\n"
        "  ALPHA_CWD        default $PWD\n"
        "  ALPHA_MAX_TURNS  default 24\n"
        "  TELEGRAM_BOT_TOKEN or ALPHA_TELEGRAM_BOT_TOKEN\n"
        "  ALPHA_TELEGRAM_ALLOW  default 5433551381 (* = open)\n",
        argv0, argv0, argv0);
}

static void load_dotenv(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0) continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char *key = p;
        char *val = eq + 1;
        /* trim key */
        char *ke = key + strlen(key);
        while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = 0;
        /* trim val newline + quotes */
        size_t n = strlen(val);
        while (n && (val[n - 1] == '\n' || val[n - 1] == '\r')) val[--n] = 0;
        if (n >= 2 && ((val[0] == '"' && val[n - 1] == '"') ||
                       (val[0] == '\'' && val[n - 1] == '\''))) {
            val[n - 1] = 0;
            val++;
        }
        if (!getenv(key)) setenv(key, val, 0);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    load_dotenv(".env");
    load_dotenv(".env.local");

    /* vibeproxy only — claude-opus-5, no model shopping. */
    const char *base = getenv("ALPHA_BASE_URL");
    if (!base || !base[0]) base = "http://127.0.0.1:8317/v1";

    const char *key = getenv("ALPHA_API_KEY");
    if (!key || !key[0]) key = getenv("OPENAI_API_KEY");
    if (!key || !key[0]) key = "none";

    const char *model = getenv("ALPHA_MODEL");
    if (!model || !model[0]) model = "claude-opus-5";

    const char *cwd = getenv("ALPHA_CWD");
    char pwd[PATH_MAX];
    if (!cwd || !cwd[0]) {
        if (getcwd(pwd, sizeof(pwd))) cwd = pwd;
        else cwd = ".";
    }

    int max_turns = 24;
    const char *mt = getenv("ALPHA_MAX_TURNS");
    if (mt && mt[0]) max_turns = atoi(mt);

    alpha_cfg_t cfg = {
        .base_url = base,
        .api_key = key,
        .model = model,
        .cwd = cwd,
        .max_turns = max_turns,
        .quiet = 0,
    };

    int telegram = 0, repl = 0;
    const char *goal = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--telegram") == 0 || strcmp(argv[i], "-t") == 0)
            telegram = 1;
        else if (strcmp(argv[i], "--repl") == 0)
            repl = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-q") == 0)
            cfg.quiet = 1;
        else if (argv[i][0] != '-')
            goal = argv[i];
    }

    if (telegram) {
        const char *tok = getenv("ALPHA_TELEGRAM_BOT_TOKEN");
        if (!tok || !tok[0]) tok = getenv("TELEGRAM_BOT_TOKEN");
        if (!tok || !tok[0]) tok = getenv("AGENT_TELEGRAM_BOT_TOKEN");
        const char *allow = getenv("ALPHA_TELEGRAM_ALLOW");
        if (!allow || !allow[0]) allow = getenv("AGENT_TELEGRAM_ALLOW");
        if (!allow || !allow[0]) allow = "5433551381";
        char root[PATH_MAX];
        if (getcwd(root, sizeof(root))) setenv("ALPHA_ROOT", root, 0);
        int rc = telegram_run(&cfg, tok, allow);
        curl_global_cleanup();
        return rc;
    }

    if (repl) {
        /* One session per working directory, so a terminal session actually
         * remembers the conversation (agent_run passes NULL and forgets
         * everything between prompts). */
        char spath[PATH_MAX];
        const char *home = getenv("HOME");
        char sdir[PATH_MAX];
        snprintf(sdir, sizeof(sdir), "%s/.alpha", home ? home : ".");
        mkdir(sdir, 0700);
        unsigned long h = 5381;
        for (const char *p = cfg.cwd; p && *p; p++) h = h * 33u + (unsigned char)*p;
        snprintf(spath, sizeof(spath), "%s/repl_%08lx.json", sdir, h & 0xffffffffUL);

        fprintf(stderr,
                "Agent Alpha REPL  model=%s  cwd=%s\n"
                "memory: %s\n"
                "commands: /new (reset)  /cwd <path>  exit\n",
                cfg.model, cfg.cwd, spath);
        char line[8192];
        while (fprintf(stderr, "alpha> ") && fgets(line, sizeof(line), stdin)) {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
            if (!n) continue;
            if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) break;
            if (strcmp(line, "/new") == 0 || strcmp(line, "/clear") == 0) {
                agent_session_clear(spath);
                fprintf(stderr, "memory cleared\n");
                continue;
            }
            if (strncmp(line, "/cwd ", 5) == 0) {
                const char *p = line + 5;
                while (*p == ' ') p++;
                static char newcwd[PATH_MAX];
                if (realpath(p, newcwd)) {
                    cfg.cwd = newcwd;
                    fprintf(stderr, "cwd = %s\n", newcwd);
                } else {
                    fprintf(stderr, "bad path\n");
                }
                continue;
            }
            sds ans = agent_run_session(&cfg, spath, line);
            printf("%s\n", ans);
            fflush(stdout);
            sdsfree(ans);
        }
        curl_global_cleanup();
        return 0;
    }

    if (!goal) {
        usage(argv[0]);
        curl_global_cleanup();
        return 1;
    }

    sds ans = agent_run(&cfg, goal);
    printf("%s\n", ans);
    sdsfree(ans);
    curl_global_cleanup();
    return 0;
}
