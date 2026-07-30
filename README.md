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

## Warning

Security is intentionally **off**. Do not expose this bot publicly. Allowlist chat ids.
