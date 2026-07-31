#include "alpha.h"
#include "ui.h"
#include <curl/curl.h>

static void usage(const char *argv0) {
    printf(
        "%sAgent Alpha%s — coding agent with shell, file and browser tools.\n"
        "Works with any OpenAI-compatible API, including local models.\n"
        "\n"
        "%sUsage%s\n"
        "  %s \"goal text\"          run one task and exit\n"
        "  %s                       interactive session\n"
        "  %s --telegram            Telegram bot\n"
        "  %s --providers           list known providers\n"
        "\n"
        "%sOptions%s\n"
        "  -p, --provider NAME      ollama, openai, anthropic, groq, ... (see --providers)\n"
        "  -m, --model NAME         model id\n"
        "  -u, --url URL            OpenAI-compatible base URL, e.g. http://localhost:11434/v1\n"
        "  -k, --key KEY            API key (prefer the env var)\n"
        "  -C, --cwd DIR            working directory for tools\n"
        "      --turns N            max tool-calling turns per request\n"
        "      --no-stream          wait for the whole reply instead of streaming\n"
        "  -q, --quiet              suppress progress output\n"
        "\n"
        "%sEnvironment%s\n"
        "  ALPHA_PROVIDER  ALPHA_BASE_URL  ALPHA_API_KEY  ALPHA_MODEL\n"
        "  ALPHA_CWD  ALPHA_MAX_TURNS  ALPHA_STREAM  NO_COLOR\n"
        "  Provider key vars (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) are picked up\n"
        "  automatically. Settings can also live in a .env file.\n"
        "\n"
        "%sWarning%s: tools run unsandboxed with your full permissions.\n",
        ui_c(UI_BOLD), ui_c(UI_RESET),
        ui_c(UI_BOLD), ui_c(UI_RESET),
        argv0, argv0, argv0, argv0,
        ui_c(UI_BOLD), ui_c(UI_RESET),
        ui_c(UI_BOLD), ui_c(UI_RESET),
        ui_c(UI_YELLOW), ui_c(UI_RESET));
}

static void list_providers(void) {
    printf("%s%-12s %-38s %s%s\n", ui_c(UI_BOLD), "NAME", "BASE URL", "KEY", ui_c(UI_RESET));
    for (int i = 0;; i++) {
        const alpha_provider_t *p = alpha_provider_at(i);
        if (!p) break;
        const char *keyed = p->local ? "not needed"
                          : (p->key_env && getenv(p->key_env) && getenv(p->key_env)[0])
                            ? "set" : (p->key_env ? p->key_env : "-");
        int have = p->local || (p->key_env && getenv(p->key_env) && getenv(p->key_env)[0]);
        printf("%s%-12s%s %-38s %s%s%s\n",
               ui_c(UI_CYAN), p->name, ui_c(UI_RESET),
               p->base_url,
               ui_c(have ? UI_GREEN : UI_DIM), keyed, ui_c(UI_RESET));
    }
    printf("\n%sAny other OpenAI-compatible endpoint works too: --url URL%s\n",
           ui_c(UI_DIM), ui_c(UI_RESET));
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
        char *ke = key + strlen(key);
        while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = 0;
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

/* --- live rendering -------------------------------------------------------- */

typedef struct {
    int streamed;       /* any text printed yet this turn */
    int quiet;
} render_t;

static void on_text(void *ud, const char *chunk) {
    render_t *r = ud;
    if (!r->streamed) {
        ui_spin_stop();
        r->streamed = 1;
    }
    fputs(chunk, stdout);
    fflush(stdout);
}

static void on_tool_start(void *ud, const char *name, const char *args_json) {
    render_t *r = ud;
    if (r->quiet) return;
    ui_spin_stop();
    sds preview = ui_ellipsize(args_json ? args_json : "", (size_t)ui_width() - 20);
    printf("  %s\u2022%s %s%s%s %s%s%s\n",
           ui_c(UI_YELLOW), ui_c(UI_RESET),
           ui_c(UI_BOLD), name, ui_c(UI_RESET),
           ui_c(UI_DIM), preview, ui_c(UI_RESET));
    fflush(stdout);
    sdsfree(preview);
    sds label = sdscatprintf(sdsempty(), "running %s", name);
    ui_spin_start(label);
    sdsfree(label);
}

static void on_tool_end(void *ud, const char *name, const char *result, double secs) {
    render_t *r = ud;
    (void)name;
    if (r->quiet) return;
    ui_spin_stop();
    int failed = result && strncmp(result, "ERROR", 5) == 0;
    /* Report size and duration rather than the output itself: a tool can
     * return 200 KB, and the model is the consumer, not the terminal. */
    size_t n = result ? strlen(result) : 0;
    printf("    %s%s %zu bytes in %.1fs%s\n",
           ui_c(failed ? UI_RED : UI_DIM),
           failed ? "\u2717" : "\u2713", n, secs, ui_c(UI_RESET));
    if (failed) {
        sds first = ui_ellipsize(result, (size_t)ui_width() - 8);
        printf("    %s%s%s\n", ui_c(UI_RED), first, ui_c(UI_RESET));
        sdsfree(first);
    }
    fflush(stdout);
    ui_spin_start("thinking");
}

static void on_turn(void *ud, int turn, int max_turns) {
    render_t *r = ud;
    if (r->quiet) return;
    r->streamed = 0;
    char label[64];
    if (turn == 0) snprintf(label, sizeof(label), "thinking");
    else snprintf(label, sizeof(label), "thinking (turn %d/%d)", turn + 1, max_turns);
    ui_spin_start(label);
}

/* --- interrupt -------------------------------------------------------------
 *
 * Ctrl-C cancels the current request and returns to the prompt; it only exits
 * when pressed with nothing running, so a runaway tool loop does not cost the
 * session. Async-signal-safe: sets a flag and writes nothing but a constant. */
static volatile sig_atomic_t g_in_request = 0;

static void on_sigint(int sig) {
    (void)sig;
    if (g_in_request) {
        alpha_cancel = 1;
        const char msg[] = "\n[interrupting…]\n";
        ssize_t w = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        (void)w;
    } else {
        ui_spin_shutdown();
        _exit(130);
    }
}

/* --- config ---------------------------------------------------------------- */

static void resolve_provider(alpha_cfg_t *cfg, const char *pname,
                             const char *url, const char *model, const char *key) {
    const alpha_provider_t *p = NULL;
    if (pname && pname[0]) {
        p = alpha_provider_by_name(pname);
        if (!p) {
            fprintf(stderr, "unknown provider '%s' — run --providers for the list, "
                            "or use --url for any OpenAI-compatible endpoint\n", pname);
            exit(2);
        }
    }
    /* An explicit URL still gets the matching preset's key var and default
     * model, so `--url http://localhost:11434/v1` alone is enough for Ollama. */
    if (!p && url && url[0]) p = alpha_provider_by_url(url);

    cfg->base_url = (url && url[0]) ? url : (p ? p->base_url : "http://localhost:11434/v1");
    cfg->model = (model && model[0]) ? model : (p ? p->default_model : "local");

    if (key && key[0]) {
        cfg->api_key = key;
    } else if (p && p->key_env) {
        const char *k = getenv(p->key_env);
        cfg->api_key = (k && k[0]) ? k : "";
    } else {
        cfg->api_key = "";
    }
}

int main(int argc, char **argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    load_dotenv(".env");
    load_dotenv(".env.local");

    const char *pname = getenv("ALPHA_PROVIDER");
    const char *url   = getenv("ALPHA_BASE_URL");
    const char *model = getenv("ALPHA_MODEL");
    const char *key   = getenv("ALPHA_API_KEY");
    const char *cwd   = getenv("ALPHA_CWD");
    int telegram = 0, quiet = 0, stream = 1, providers = 0;
    int max_turns = 0;
    const char *goal = NULL;

    const char *mt = getenv("ALPHA_MAX_TURNS");
    if (mt && mt[0]) max_turns = atoi(mt);
    const char *sv = getenv("ALPHA_STREAM");
    if (sv && (strcmp(sv, "0") == 0 || strcasecmp(sv, "false") == 0)) stream = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_next = (i + 1 < argc);
        if (!strcmp(a, "--telegram") || !strcmp(a, "-t")) telegram = 1;
        else if (!strcmp(a, "--providers")) providers = 1;
        else if (!strcmp(a, "--no-stream")) stream = 0;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) quiet = 1;
        else if ((!strcmp(a, "-p") || !strcmp(a, "--provider")) && has_next) pname = argv[++i];
        else if ((!strcmp(a, "-m") || !strcmp(a, "--model")) && has_next) model = argv[++i];
        else if ((!strcmp(a, "-u") || !strcmp(a, "--url")) && has_next) url = argv[++i];
        else if ((!strcmp(a, "-k") || !strcmp(a, "--key")) && has_next) key = argv[++i];
        else if ((!strcmp(a, "-C") || !strcmp(a, "--cwd")) && has_next) cwd = argv[++i];
        else if (!strcmp(a, "--turns") && has_next) max_turns = atoi(argv[++i]);
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (a[0] == '-') {
            fprintf(stderr, "unknown option '%s' (try --help)\n", a);
            return 2;
        }
        else goal = a;
    }

    if (providers) {
        list_providers();
        curl_global_cleanup();
        return 0;
    }

    char pwd[PATH_MAX];
    if (!cwd || !cwd[0]) {
        if (getcwd(pwd, sizeof(pwd))) cwd = pwd;
        else cwd = ".";
    }

    alpha_cfg_t cfg = {
        .cwd = cwd,
        .max_turns = max_turns,
        .quiet = quiet,
        .stream = stream,
        .parallel_tools = 1,
    };
    resolve_provider(&cfg, pname, url, model, key);
    alpha_cfg_defaults(&cfg);

    if (telegram) {
        const char *tok = getenv("ALPHA_TELEGRAM_BOT_TOKEN");
        if (!tok || !tok[0]) tok = getenv("TELEGRAM_BOT_TOKEN");
        const char *allow = getenv("ALPHA_TELEGRAM_ALLOW");
        /* No default allowlist: a bot token is a public endpoint, and shipping
         * one would mean anyone who found the bot got a shell on this machine.
         * "*" is available for the operator who really wants it. */
        if (!allow || !allow[0]) {
            fprintf(stderr,
                "ALPHA_TELEGRAM_ALLOW is not set. Tools run unsandboxed, so the bot\n"
                "refuses to start without an explicit allowlist of chat ids.\n"
                "Set ALPHA_TELEGRAM_ALLOW=<your chat id>, or \"*\" to allow everyone.\n");
            curl_global_cleanup();
            return 2;
        }
        int rc = telegram_run(&cfg, tok, allow);
        curl_global_cleanup();
        return rc;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    /* A pipe closed by the reader (`alpha ... | head`) must not kill the
     * process mid-write; the write error is handled where it happens. */
    signal(SIGPIPE, SIG_IGN);

    render_t rend = { .streamed = 0, .quiet = quiet };
    alpha_events_t events = {
        .on_text = on_text,
        .on_tool_start = on_tool_start,
        .on_tool_end = on_tool_end,
        .on_turn = on_turn,
        .ud = &rend,
    };
    /* Streaming callbacks print as they go. With --quiet or a pipe the reply is
     * printed once at the end instead, so output is not duplicated. */
    int live = cfg.stream && !quiet && ui_is_tty();
    if (live) cfg.events = &events;

    if (goal) {
        g_in_request = 1;
        sds ans = agent_run(&cfg, goal);
        g_in_request = 0;
        ui_spin_shutdown();
        if (!live) printf("%s\n", ans);
        else printf("\n");
        sdsfree(ans);
        curl_global_cleanup();
        return 0;
    }

    /* --- interactive ------------------------------------------------------- */

    /* One session per working directory, so a terminal session remembers the
     * conversation across invocations. */
    char spath[PATH_MAX];
    const char *home = getenv("HOME");
    char sdir[PATH_MAX];
    snprintf(sdir, sizeof(sdir), "%s/.alpha", home ? home : ".");
    mkdir(sdir, 0700);
    unsigned long h = 5381;
    for (const char *p = cfg.cwd; p && *p; p++) h = h * 33u + (unsigned char)*p;
    snprintf(spath, sizeof(spath), "%s/repl_%08lx.json", sdir, h & 0xffffffffUL);

    printf("\n%s%sAgent Alpha%s\n", ui_c(UI_BOLD), ui_c(UI_CYAN), ui_c(UI_RESET));
    ui_status("model", cfg.model);
    ui_status("endpoint", cfg.base_url);
    ui_status("cwd", cfg.cwd);
    if (!cfg.api_key[0]) ui_status("key", "none (local endpoint)");
    printf("\n%s/help for commands · Ctrl-C interrupts · Ctrl-D exits%s\n\n",
           ui_c(UI_DIM), ui_c(UI_RESET));

    char line[8192];
    for (;;) {
        printf("%s%s\u203a%s ", ui_c(UI_BOLD), ui_c(UI_CYAN), ui_c(UI_RESET));
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) {
            /* fgets also returns NULL when a signal interrupted it; that is not
             * end of input, and treating it as such quit the session on Ctrl-C. */
            if (ferror(stdin) && errno == EINTR) {
                clearerr(stdin);
                alpha_cancel = 0;
                printf("\n");
                continue;
            }
            printf("\n");
            break;
        }
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (!n) continue;

        if (!strcmp(line, "exit") || !strcmp(line, "quit") || !strcmp(line, "/exit")) break;
        if (!strcmp(line, "/help")) {
            printf("  %s/new%s      forget this conversation\n"
                   "  %s/cwd DIR%s  change the working directory for tools\n"
                   "  %s/model M%s  switch model\n"
                   "  %s/status%s   show the current settings\n"
                   "  %s/exit%s     quit\n",
                   ui_c(UI_CYAN), ui_c(UI_RESET), ui_c(UI_CYAN), ui_c(UI_RESET),
                   ui_c(UI_CYAN), ui_c(UI_RESET), ui_c(UI_CYAN), ui_c(UI_RESET),
                   ui_c(UI_CYAN), ui_c(UI_RESET));
            continue;
        }
        if (!strcmp(line, "/new") || !strcmp(line, "/clear")) {
            agent_session_clear(spath);
            ui_note("memory cleared");
            continue;
        }
        if (!strcmp(line, "/status")) {
            ui_status("model", cfg.model);
            ui_status("endpoint", cfg.base_url);
            ui_status("cwd", cfg.cwd);
            ui_status("session", spath);
            continue;
        }
        if (!strncmp(line, "/model ", 7)) {
            const char *p = line + 7;
            while (*p == ' ') p++;
            static char newmodel[256];
            snprintf(newmodel, sizeof(newmodel), "%s", p);
            cfg.model = newmodel;
            ui_status("model", cfg.model);
            continue;
        }
        if (!strncmp(line, "/cwd ", 5)) {
            const char *p = line + 5;
            while (*p == ' ') p++;
            static char newcwd[PATH_MAX];
            if (realpath(p, newcwd)) {
                cfg.cwd = newcwd;
                ui_status("cwd", newcwd);
            } else {
                ui_error("no such directory");
            }
            continue;
        }

        rend.streamed = 0;
        g_in_request = 1;
        sds ans = agent_run_session(&cfg, spath, line);
        g_in_request = 0;
        ui_spin_stop();

        if (!live) {
            printf("%s\n", ans);
        } else if (!rend.streamed) {
            /* Nothing streamed: an error, or a turn that only called tools. */
            printf("%s\n", ans);
        } else {
            printf("\n");
        }
        printf("\n");
        fflush(stdout);
        alpha_cancel = 0;
        sdsfree(ans);
    }

    ui_spin_shutdown();
    curl_global_cleanup();
    return 0;
}
