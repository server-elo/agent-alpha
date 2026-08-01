#include "alpha.h"

/* Lives here rather than in agent_loop.c because both the LLM layer and the
 * shell read it, and those are linked separately by the test binaries. */
volatile sig_atomic_t alpha_cancel = 0;

/* Presets for endpoints that speak the OpenAI /chat/completions shape.
 *
 * This table is a convenience, not a gate: ALPHA_BASE_URL overrides it, so an
 * endpoint that is not listed works without a code change. What a preset buys
 * is the right key env var and a sensible default model.
 *
 * `local` marks servers that run on this machine. They are the reason
 * api_key must stay optional: llama.cpp and Ollama reject nothing, and
 * demanding a key would make the offline path impossible.
 *
 * The local default must be a model that emits real tool_calls. Ollama lists
 * qwen2.5-coder:7b as tools-capable, but it in fact returns the call as JSON
 * text in `content` with tool_calls null (measured), so an agent driving it
 * never runs anything and prints the JSON at the user. qwen3:8b returns
 * proper tool_calls on the same request. */
static const alpha_provider_t PROVIDERS[] = {
    /* name         base_url                                  key_env             default_model              local */
    { "ollama",     "http://localhost:11434/v1",              NULL,               "qwen3:8b",                1 },
    { "llamacpp",   "http://localhost:8080/v1",               NULL,               "local",                   1 },
    { "lmstudio",   "http://localhost:1234/v1",               NULL,               "local-model",             1 },
    { "vllm",       "http://localhost:8000/v1",               NULL,               "local",                   1 },
    { "openai",     "https://api.openai.com/v1",              "OPENAI_API_KEY",   "gpt-4o",                  0 },
    { "anthropic",  "https://api.anthropic.com/v1",           "ANTHROPIC_API_KEY","claude-sonnet-4-20250514",0 },
    { "groq",       "https://api.groq.com/openai/v1",         "GROQ_API_KEY",     "llama-3.3-70b-versatile", 0 },
    { "together",   "https://api.together.xyz/v1",            "TOGETHER_API_KEY", "Qwen/Qwen2.5-Coder-32B-Instruct", 0 },
    { "openrouter", "https://openrouter.ai/api/v1",           "OPENROUTER_API_KEY","anthropic/claude-sonnet-4", 0 },
    { "mistral",    "https://api.mistral.ai/v1",              "MISTRAL_API_KEY",  "mistral-large-latest",    0 },
    { "deepseek",   "https://api.deepseek.com/v1",            "DEEPSEEK_API_KEY", "deepseek-chat",           0 },
    { "xai",        "https://api.x.ai/v1",                    "XAI_API_KEY",      "grok-2-latest",           0 },
};

#define NPROVIDERS ((int)(sizeof(PROVIDERS) / sizeof(PROVIDERS[0])))

const alpha_provider_t *alpha_provider_at(int i) {
    if (i < 0 || i >= NPROVIDERS) return NULL;
    return &PROVIDERS[i];
}

const alpha_provider_t *alpha_provider_by_name(const char *name) {
    if (!name || !name[0]) return NULL;
    for (int i = 0; i < NPROVIDERS; i++)
        if (strcasecmp(PROVIDERS[i].name, name) == 0) return &PROVIDERS[i];
    return NULL;
}

/* Compare hosts, ignoring scheme, trailing slash and any /v1 suffix, so
 * "http://localhost:11434" and "http://localhost:11434/v1/" both match Ollama.
 * Matching on the whole string would fail for exactly the URLs people type. */
static const char *strip_scheme(const char *u) {
    const char *p = strstr(u, "://");
    return p ? p + 3 : u;
}

static size_t host_len(const char *u) {
    const char *slash = strchr(u, '/');
    return slash ? (size_t)(slash - u) : strlen(u);
}

const alpha_provider_t *alpha_provider_by_url(const char *base_url) {
    if (!base_url || !base_url[0]) return NULL;
    const char *h = strip_scheme(base_url);
    size_t hn = host_len(h);
    for (int i = 0; i < NPROVIDERS; i++) {
        const char *ph = strip_scheme(PROVIDERS[i].base_url);
        size_t pn = host_len(ph);
        if (pn == hn && strncasecmp(ph, h, hn) == 0) return &PROVIDERS[i];
    }
    return NULL;
}

void alpha_cfg_defaults(alpha_cfg_t *cfg) {
    if (!cfg) return;
    if (cfg->max_turns <= 0) cfg->max_turns = 24;
    if (cfg->temperature <= 0.0) cfg->temperature = 0.2;
    if (cfg->max_tokens <= 0) cfg->max_tokens = 8192;
}
