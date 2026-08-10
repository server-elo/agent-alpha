#!/usr/bin/env bash
# Agent Alpha Telegram launcher (exclusive single poller)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PIDFILE="${ALPHA_PIDFILE:-/tmp/agent-alpha-telegram.pid}"
LOG="${ALPHA_LOG:-/tmp/agent-alpha-telegram.log}"
BIN="$ROOT/alpha"

load_env() {
  unset ALPHA_PROVIDER ALPHA_BASE_URL ALPHA_API_KEY ALPHA_MODEL ALPHA_CWD ALPHA_MAX_TURNS ALPHA_TELEGRAM_ALLOW ALPHA_TELEGRAM_BOT_TOKEN TELEGRAM_BOT_TOKEN
  if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
  fi
}

is_running() {
  if [[ -f "$PIDFILE" ]]; then
    local p
    p="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "${p:-}" ]] && kill -0 "$p" 2>/dev/null; then
      if ps -p "$p" -o command= 2>/dev/null | grep -q 'alpha --telegram'; then
        return 0
      fi
    fi
  fi
  pgrep -f "$BIN --telegram" >/dev/null 2>&1
}

cmd_stop() {
  if [[ -f "$PIDFILE" ]]; then
    local p
    p="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "${p:-}" ]] && kill -0 "$p" 2>/dev/null; then
      kill "$p" 2>/dev/null || true
      sleep 1
      kill -9 "$p" 2>/dev/null || true
      echo "stopped $p"
    fi
    rm -f "$PIDFILE"
  fi
  # belt: kill any alpha --telegram
  pkill -f "$BIN --telegram" 2>/dev/null || true
  pkill -f '/agent-alpha/alpha --telegram' 2>/dev/null || true
}

cmd_start() {
  load_env
  cmd_stop
  if [[ ! -x "$BIN" ]]; then
    make -C "$ROOT" -j4
  fi
  mkdir -p "$ROOT/sessions"
  nohup "$BIN" --telegram >>"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  sleep 1
  echo "started pid=$(cat "$PIDFILE") log=$LOG"
}

cmd_status() {
  if is_running; then
    ps -p "$(cat "$PIDFILE" 2>/dev/null || pgrep -f "$BIN --telegram" | head -1)" -o pid=,etime=,command= 2>/dev/null || true
  else
    echo "stopped"
  fi
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

case "${1:-status}" in
  start) start_ok=1; cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  *) echo "usage: $0 start|stop|restart|status"; exit 1 ;;
esac
