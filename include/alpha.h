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

#include "../deps/sds.h"
#include "../deps/cJSON.h"

/* Agent Alpha — open AI coding shell (no pin / path locks). */

/* Largest file edit_file will rewrite. Anything bigger is refused rather than
 * silently truncated to this size. */
#define ALPHA_EDIT_MAX_BYTES 2000000
/* Hard wall-clock cap for one user request (seconds). */
#define ALPHA_REQUEST_MAX_SECONDS 10800

/* LLM replies are streamed, so there is no cap on how long a reply may take --
 * only on how long it may produce NOTHING. A fixed total timeout used to kill
 * long answers outright (a 16384-token reply measured 262s against a 300s cap)
 * and threw away every token already received. */
#ifndef ALPHA_LLM_STALL_SECONDS
#define ALPHA_LLM_STALL_SECONDS 120
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

typedef struct {
    const char *base_url;   /* e.g. http://127.0.0.1:8317/v1 */
    const char *api_key;    /* optional; "none" ok for local proxy */
    const char *model;      /* e.g. grok-4.5 */
    const char *cwd;        /* working directory for tools */
    int max_turns;
    int quiet;
} alpha_cfg_t;

/* messages: cJSON array of chat messages (owned by caller).
 * with_tools=0 → plain chat completion (fast, no tool schema). */
/* out_failed (optional): set to 1 on transport/HTTP/parse failure.
 * Never infer failure from the text — a model may legitimately reply "ERROR: ...". */
sds llm_chat_ex(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message,
                int with_tools, int *out_failed);
sds llm_chat(const alpha_cfg_t *cfg, cJSON *messages, cJSON **out_message, int with_tools);

/* Tool dispatch: name + args JSON object → result text (caller frees with sdsfree). */
sds tools_run(const char *name, cJSON *args, const char *cwd);

/* Pure-C browser tool (OpenClaw-style CDP + macOS open fallback). */
sds browser_tool_run(cJSON *args);

/* OpenAI-style tools array for request. Caller frees. */
cJSON *tools_schema(void);

/* One-shot (no memory). */
sds agent_run(alpha_cfg_t *cfg, const char *user_text);

/* OpenClaw-style continuous chat. session_path = JSON history file (may be NULL). */
sds agent_run_session(alpha_cfg_t *cfg, const char *session_path, const char *user_text);

/* Clear session history file. */
void agent_session_clear(const char *session_path);

/* Telegram long-poll loop (blocking). */
int telegram_run(alpha_cfg_t *cfg, const char *token, const char *allow_csv);

#endif
