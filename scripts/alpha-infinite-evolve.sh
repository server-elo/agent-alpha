#!/bin/bash
# Continuous infinite evolution loop for Agent Alpha
# Each generation:
# 1. Runs BEFORE domain benchmark
# 2. Makes one small, gated improvement to the source
# 3. Runs 360° AFTER benchmark & quality comparison
# 4. Commits & pushes if the full gate passes, re-executes into new binary
#
# Safety: stops after MAX_CONSECUTIVE_REVERTS failed generations in a row so
# a broken model endpoint or a bad goal cannot burn GPU cycles forever.

ROOT="/Users/lorenc/projects/agent-alpha"
cd "$ROOT" || exit 1

set -a
source .env
set +a

export ALPHA_EVOLVE=1

# Direct Action C Tool Evolution Goal.
GOAL="Survey include/alpha.h and src/tools.c in Turn 1, then immediately choose ONE impactful capability to build (e.g. regex search, AST parser, fast JSON query, embedded KV index, diff-patching engine, process monitor). Write clean C11 in src/tools.c or src/, create rich unit tests in tests/custom/test_<name>.c, and verify with make -j4 && make test. Always invoke tools directly. Your final diff must be non-empty. Never edit sealed harness files (Makefile, src/evolve.c, src/warden.c, etc.)."

MAX_CONSECUTIVE_REVERTS=10
SLEEP_BETWEEN=10

echo "[alpha-loop] Starting continuous evolution daemon (stop after $MAX_CONSECUTIVE_REVERTS consecutive reverts)..."

reverts=0
while true; do
    echo "[alpha-loop] Launching evolution run at $(date)..."
    ./alpha --evolve "$GOAL" --generations 1

    # A kept generation is the last log entry with result "keep".
    last_result=$(tail -n 1 evolution/log.jsonl 2>/dev/null | grep -o '"result":"[a-z]*"' | cut -d'"' -f4)
    if [[ "$last_result" == "keep" ]]; then
        reverts=0
        git push origin main 2>/dev/null || true
    else
        reverts=$((reverts + 1))
        echo "[alpha-loop] generation reverted ($reverts/$MAX_CONSECUTIVE_REVERTS consecutive)"
    fi

    if (( reverts >= MAX_CONSECUTIVE_REVERTS )); then
        echo "[alpha-loop] $reverts consecutive reverts — stopping. Failure reasons are at the tail of evolution/log.jsonl."
        exit 1
    fi

    sleep $SLEEP_BETWEEN
done
