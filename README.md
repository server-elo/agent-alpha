# Agent Alpha

Open AI coding shell in C. **No path pin / sandbox locks** — tools can read, write, and exec anywhere the process can.

## Features

- CLI one-shot, REPL, or Telegram long-poll
- Tools: `execute_bash`, `read_file`, `write_file`, `edit_file`, `list_dir`
- LLM: **vibeproxy `claude-opus-5`** (`http://127.0.0.1:8317/v1`)
- One tool per turn (`parallel_tool_calls: false`)

## Build

```bash
cd ~/projects/agent-alpha
make -j4
```

## CLI

```bash
./alpha "list files in /Users/lorenc/projects and summarize"
./alpha --repl
```

## Telegram

Put token in `.env`:

```bash
ALPHA_TELEGRAM_BOT_TOKEN=...
ALPHA_TELEGRAM_ALLOW=5433551381
ALPHA_BASE_URL=http://127.0.0.1:8317/v1
ALPHA_MODEL=claude-opus-5
```

```bash
./scripts/alpha-telegram.sh start
./scripts/alpha-telegram.sh status
./scripts/alpha-telegram.sh stop
```

Log: `/tmp/agent-alpha-telegram.log`

### Voice notes

Hold the mic in Telegram and talk; the note is transcribed locally by Whisper
(`scripts/alpha-transcribe.py`) and becomes the turn's text. No API key, no
network, audio never leaves the machine.

The `medium` model runs on CPU: measured 7s for a 3s note and 11s for a 15s
one. Polling pauses for that time, which Telegram tolerates.
`ALPHA_VOICE_MODEL=small` is about 3x faster and noticeably worse on jargon.

If a note comes back "could not transcribe", the reason is in the log --
usually a missing `ffmpeg`, which Whisper shells out to for decoding.

Transcription is biased with a list of project terms, since Whisper otherwise
spells them as ordinary English -- "Goldcrit" for buildcrit, "fan out" for
fanout, "Cargo Clippy" for cargo clippy. Override with `ALPHA_VOICE_PROMPT`,
or set it empty to disable. `ALPHA_VOICE_LANG` sets the language (default
`en`); auto-detect is deliberately not used, as it misfires badly on short
phone audio.

## Warning

Security is intentionally **off**. Do not expose this bot publicly. Allowlist chat ids.

### Known limitation: the 60s shell timeout does not catch full daemons

When a command hits the 60s cap, `shell_run` kills the process group, then
scans for descendants that left it — by parent chain, and by the output file
they still hold open. That covers processes that call `setsid()` (fds survive
setsid) and processes that close fds without detaching (still reachable by
ancestry).

A process that does **both** — `setsid()` *and* `close()` on its inherited
fds, i.e. the textbook daemonization sequence — sheds every marker and keeps
running. The timeout message says so when it fires. Fixing it properly needs a
per-command uid or a sandbox, which is more machinery than this tool warrants;
a process that deliberately daemonizes has asked to outlive the shell.
