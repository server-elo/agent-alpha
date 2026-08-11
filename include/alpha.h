#ifndef ALPHA_H
#define ALPHA_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include "../deps/sds.h"
#include "../deps/cJSON.h"

/* Agent Alpha — open AI coding shell (no pin / path locks). */

/* Largest file edit_file will rewrite. Anything bigger is refused rather than
 * silently truncated to this size. */
#define ALPHA_EDIT_MAX_BYTES 2000000
/* Hard wall-clock cap for one user request (seconds). */
#define ALPHA_REQUEST_MAX_SECONDS 10800
/* Hard cap for shell_run (milliseconds). Overridable so the test suite can
 * prove timeout behaviour without waiting 60s per case. */
#ifndef ALPHA_SHELL_TIMEOUT_MS
#define ALPHA_SHELL_TIMEOUT_MS 60000
#endif

/* LLM replies are streamed, so there is no cap on how long a reply may take --
 * only on how long it may produce NOTHING. A fixed total timeout used to kill
 * long answers outright (a 16384-token reply measured 262s against a 300s cap)
 * and threw away every token already received. */
#ifndef ALPHA_LLM_STALL_SECONDS
#define ALPHA_LLM_STALL_SECONDS 120
#endif
/* Total cap for the non-streaming path only. Nothing arrives there until
 * generation has finished, so a stall timeout cannot distinguish a healthy
 * long reply from a dead connection and only a total cap is possible. */
#ifndef ALPHA_LLM_NOSTREAM_SECONDS
#define ALPHA_LLM_NOSTREAM_SECONDS 900
#endif
/* Cap on one voice transcription. It runs on the Telegram poll thread, so an
 * unbounded one stops every chat. Generous: the medium model takes ~11s for a
 * 15s note, and a first run may download the model. */
#ifndef ALPHA_VOICE_TIMEOUT_MS   /* overridable so tests need not wait 3 minutes */
#define ALPHA_VOICE_TIMEOUT_MS 180000
#endif
/* Largest voice note accepted for download (bytes). Telegram's own cap is
 * 20 MB; anything near that is minutes of transcription on the poll thread. */
#define ALPHA_VOICE_MAX_BYTES (8 * 1024 * 1024)

/* --- providers -------------------------------------------------------------
 *
 * Anything speaking the OpenAI /chat/completions shape works: hosted APIs and
 * local servers alike (Ollama, llama.cpp, LM Studio, vLLM, ...). A preset is
 * only a convenient way to fill in base_url, the key's env var and a default
 * model -- ALPHA_BASE_URL always wins, so an unlisted endpoint needs no code. */
/* Used when nothing at all is configured. Named once so the fallback endpoint
 * and the fallback model cannot drift apart. */
#define ALPHA_DEFAULT_PROVIDER "ollama"

typedef struct {
    const char *name;
    const char *base_url;
    const char *key_env;        /* env var holding the key, NULL if none */
    const char *default_model;
    int local;                  /* runs on this machine: no key required */
} alpha_provider_t;

const alpha_provider_t *alpha_provider_by_name(const char *name);
/* Best-effort match of a base URL back to a preset, so an explicit
 * ALPHA_BASE_URL still picks up that provider's key env var and default model. */
const alpha_provider_t *alpha_provider_by_url(const char *base_url);
const alpha_provider_t *alpha_provider_at(int i);   /* NULL past the end */

/* Streaming/tool progress, so a front end can render a reply as it arrives
 * instead of after it finishes. All fields optional. */
typedef struct {
    void (*on_text)(void *ud, const char *chunk);
    void (*on_reasoning)(void *ud, const char *chunk);
    void (*on_tool_start)(void *ud, const char *name, const char *args_json);
    void (*on_tool_end)(void *ud, const char *name, const char *result, double secs);
    void (*on_turn)(void *ud, int turn, int max_turns);
    void (*on_notice)(void *ud, const char *text);
    void *ud;
} alpha_events_t;

typedef struct {
    const char *base_url;   /* e.g. http://localhost:11434/v1 */
    const char *api_key;    /* optional; empty/"none" for local servers */
    const char *model;
    const char *cwd;        /* working directory for tools */
    int max_turns;
    int quiet;
    int stream;             /* 1 = SSE (default), 0 = single JSON response */
    int parallel_tools;     /* 1 = allow several tool calls per turn */
    int max_tokens;         /* 0 = provider default */
    double temperature;
    const alpha_events_t *events;
} alpha_cfg_t;

/* Defaults for fields a caller has left zeroed. */
void alpha_cfg_defaults(alpha_cfg_t *cfg);

/* Set from a signal handler to abort the in-flight request and any running
 * shell command. Cleared by the agent loop when it starts a new request. */
extern volatile sig_atomic_t alpha_cancel;

/* messages: cJSON array of chat messages (owned by caller).
 * with_tools=0 → plain chat completion (fast, no tool schema). */
/* out_failed (optional): set to 1 on transport/HTTP/parse failure.
 * Never infer failure from the text — a model may legitimately reply "ERROR: ...". */
sds llm_chat_ex(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message,
                int with_tools, int *out_failed);
sds llm_chat(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message, int with_tools);

/* Tool dispatch: name + args JSON object → result text (caller frees with sdsfree). */
sds tools_run(const char *name, cJSON *args, const char *cwd);

/* Caps on one CDP WebSocket reply. A snapshot of a large page is legitimately
 * hundreds of KB, and the old single-frame 500 KB limit silently dropped the
 * reply; these bound memory without rejecting real pages. */
#ifndef ALPHA_WS_MAX_FRAME
#define ALPHA_WS_MAX_FRAME   (8u * 1024 * 1024)
#endif
#ifndef ALPHA_WS_MAX_MESSAGE
#define ALPHA_WS_MAX_MESSAGE (16u * 1024 * 1024)
#endif

/* Pure-C browser tool (CDP, with a macOS open fallback). */
sds browser_tool_run(cJSON *args);

/* OpenAI-style tools array for request. Caller frees. */
cJSON *tools_schema(void);

/* One-shot (no memory). */
sds agent_run(alpha_cfg_t *cfg, const char *user_text);

/* Continuous chat. session_path = JSON history file (may be NULL). */
sds agent_run_session(alpha_cfg_t *cfg, const char *session_path, const char *user_text);

/* Clear session history file. */
void agent_session_clear(const char *session_path);

/* Telegram long-poll loop (blocking). */
int telegram_run(alpha_cfg_t *cfg, const char *token, const char *allow_csv);

/* Self-evolution loop: the agent edits its own source tree, then the driver
 * re-runs the gate (build, test suite, binary smoke test) and commits the
 * generation or reverts it with git reset --hard. reexec=1 replaces the
 * process with the freshly built binary after a kept generation. */
int evolve_run(alpha_cfg_t *cfg, const char *goal, int generations, int reexec);

#endif
