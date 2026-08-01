# Agent Alpha

A coding agent in C. It reads and writes files, runs shell commands and drives
a browser, on your own machine, against **any OpenAI-compatible API** — hosted
or fully local.

![demo](assets/demo.gif)

Recorded unedited against a local `qwen3:8b`, no API key involved
(`vhs assets/demo.tape`). Small local models are weaker at tool discipline
than hosted ones — in the recording the model drifts into *describing* the
tools it would call rather than calling them. Point Alpha at a larger model
for real work; the local default is there so the first run needs nothing.

## Build

Needs a C compiler and libcurl. No other dependencies.

macOS and Linux. Process cleanup uses the kernel process table on macOS and
`/proc` on Linux; the shell is whichever of `zsh`/`bash`/`sh` exists.

```bash
make -j4
```

## Use

```bash
alpha                          # interactive session
alpha "fix the failing test"   # one task, then exit
alpha --providers              # what is configured
```

By default it talks to **Ollama on localhost** — nothing leaves your machine
and no API key is involved:

```bash
ollama serve && ollama pull qwen3:8b
alpha
```

### Any other backend

Presets fill in the endpoint, key variable and a default model:

```bash
alpha -p openai -m gpt-4o "..."      # uses $OPENAI_API_KEY
alpha -p groq "..."                  # uses $GROQ_API_KEY
alpha -p lmstudio "..."              # local, no key
```

A preset is only a shortcut. Anything that speaks `/chat/completions` works
without one:

```bash
alpha --url http://192.168.1.50:8000/v1 --model my-model "..."
```

| flag | meaning |
|---|---|
| `-p, --provider` | preset name (`--providers` lists them) |
| `-m, --model` | model id |
| `-u, --url` | OpenAI-compatible base URL |
| `-k, --key` | API key (prefer the env var) |
| `-C, --cwd` | working directory for tools |
| `--turns N` | max tool-calling turns per request |
| `--no-stream` | wait for the whole reply instead of streaming |
| `-q, --quiet` | no progress output |

Equivalent environment variables: `ALPHA_PROVIDER`, `ALPHA_BASE_URL`,
`ALPHA_API_KEY`, `ALPHA_MODEL`, `ALPHA_CWD`, `ALPHA_MAX_TURNS`, `ALPHA_STREAM`.
Provider key variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …) are picked up
automatically. Config is read from `~/.alpha/env` (or `ALPHA_ENV_FILE`); a
`.env` in the working directory is deliberately *not* loaded, so a checkout
cannot redirect the endpoint or the key.

Prefer the environment for `ALPHA_API_KEY`: `--key` is overwritten in `argv`
at startup so it does not sit in `ps`, but its length still leaks.

In the session: `/help`, `/new`, `/cwd DIR`, `/model M`, `/status`, `/exit`.
Ctrl-C interrupts the current request — including a running shell command —
without ending the session. Ctrl-D exits.

Colour and the spinner are disabled automatically when output is not a
terminal, and when `NO_COLOR` is set.

## Tools

`execute_bash`, `read_file`, `write_file`, `edit_file`, `list_dir`, `browser`.

The browser tool drives an existing Chrome over the DevTools protocol: one
sticky tab, `snapshot` before `click`. Start Chrome with
`--remote-debugging-port=9222`.

## Telegram

Optional. Run the agent as a Telegram bot with a continuous per-chat session.

```bash
ALPHA_TELEGRAM_BOT_TOKEN=...      # from @BotFather
ALPHA_TELEGRAM_ALLOW=123456789    # your chat id; "*" allows everyone
alpha --telegram
```

It **refuses to start without an allowlist**. A bot token is a public endpoint
and the tools are unsandboxed, so anyone who found the bot would get a shell.

`scripts/alpha-telegram.sh start|stop|status` runs it in the background. Only
one poller can run at a time — a second is refused, because Telegram hands each
update to whichever poller asks first and messages would vanish at random.

### Voice notes

Send a voice note and it is transcribed locally by Whisper
(`scripts/alpha-transcribe.py`) and used as the message. No API key, no
network: the audio never leaves the machine.

Requires `pip install openai-whisper` and `ffmpeg`. The `medium` model takes
about 11s for a 15s note on CPU; `ALPHA_VOICE_MODEL=small` is roughly 3× faster
and noticeably worse on technical words. `ALPHA_VOICE_LANG` sets the language
(default `en`) — auto-detect is deliberately not used, as it misfires badly on
short phone audio. `ALPHA_VOICE_PROMPT` biases transcription toward your own
jargon.

## Security

**Tools run unsandboxed with your full permissions.** There is no path
restriction: the agent can read, modify and delete anything your user can, and
`execute_bash` runs arbitrary commands. Run it on code you can afford to lose,
under a user account you are comfortable handing to a language model.

Two limits worth knowing:

- Shell commands are killed after 60s. A process that both calls `setsid()` and
  closes its inherited descriptors — the textbook daemonization sequence —
  survives that. It sheds every marker used to find it; closing the hole needs a
  per-command uid or a real sandbox.
- On macOS, paths served by the File Provider (Desktop, iCloud Drive) are
  refused rather than opened, because `opendir` on them can block forever.

## Tests

```bash
make test
```

463 checks over the tool layer, session handling, the SSE parser, provider
resolution, config loading, the CDP WebSocket client and the Telegram loop.
Both the macOS and Linux process-tracking paths are exercised on either host.
The suite discards its binaries before every
run: macOS `make` compares mtimes by whole seconds, and a source edited less
than a second after the previous build was silently re-tested as the old
binary — which is how three deliberately broken sources once reported all
checks passing.

## Licence

MIT. Vendored: [cJSON](https://github.com/DaveGamble/cJSON) (MIT),
[sds](https://github.com/antirez/sds) (BSD-2-Clause).
