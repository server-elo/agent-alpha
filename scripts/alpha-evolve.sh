#!/usr/bin/env bash
# Agent Alpha evolution launcher (exclusive single run)
# usage: alpha-evolve.sh start "goal" [generations] | stop | restart | status | log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PIDFILE="${ALPHA_EVOLVE_PIDFILE:-/tmp/agent-alpha-evolve.pid}"
LOG="${ALPHA_EVOLVE_LOG:-/tmp/agent-alpha-evolve.log}"
BIN="$ROOT/alpha"

load_env() {
  unset ALPHA_PROVIDER ALPHA_BASE_URL ALPHA_API_KEY ALPHA_MODEL ALPHA_CWD ALPHA_MAX_TURNS
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
      if ps -p "$p" -o command= 2>/dev/null | grep -q 'alpha --evolve'; then
        return 0
      fi
    fi
  fi
  pgrep -f "$BIN --evolve" >/dev/null 2>&1
}

cmd_stop() {
  if [[ -f "$PIDFILE" ]]; then
    local p
    p="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "${p:-}" ]] && kill -0 "$p" 2>/dev/null; then
      # INT, not TERM: the driver treats it as "cancel the current generation"
      # and reverts cleanly instead of dying mid-git-reset.
      kill -INT "$p" 2>/dev/null || true
      sleep 2
      kill -9 "$p" 2>/dev/null || true
      echo "stopped $p"
    fi
    rm -f "$PIDFILE"
  fi
  pkill -f "$BIN --evolve" 2>/dev/null || true
}

cmd_start() {
  local goal="${1:-${ALPHA_EVOLVE_GOAL:-improve yourself}}"
  local gens="${2:-${ALPHA_EVOLVE_GENERATIONS:-3}}"
  load_env
  if is_running; then
    echo "already running ($(cat "$PIDFILE" 2>/dev/null)) — stop it first"
    exit 1
  fi
  if [[ ! -x "$BIN" ]]; then
    make -C "$ROOT" -j4
  fi
  nohup "$BIN" --evolve "$goal" --generations "$gens" >>"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  sleep 1
  echo "started pid=$(cat "$PIDFILE") goal='$goal' generations=$gens log=$LOG"
}

cmd_status() {
  if is_running; then
    ps -p "$(cat "$PIDFILE" 2>/dev/null || pgrep -f "$BIN --evolve" | head -1)" -o pid=,etime=,command= 2>/dev/null || true
  else
    echo "stopped"
  fi
}

case "${1:-status}" in
  start) shift; cmd_start "$@" ;;
  stop) cmd_stop ;;
  restart) cmd_stop; sleep 1; shift; cmd_start "$@" ;;
  status) cmd_status ;;
  log) tail -40 "$LOG" ;;
  *) echo "usage: $0 start \"goal\" [generations] | stop | restart | status | log"; exit 1 ;;
esac
