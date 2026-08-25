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

# Action-Oriented Full-Sovereignty Goal.
# Enforces fast reading (max 2 turns) followed immediately by writing C code and unit tests.
GOAL="You choose your own mission across Agent Alpha, but autonomy means SHIPPING REAL CODE. Follow this strict sequence: (1) In turns 1-2, read the target source files in include/ or src/; (2) In turns 3-5, write your C changes directly using write_file or patch_file; (3) Write new unit tests in tests/custom/test_<name>.c; (4) Run make -j4 && make test to certify all checks pass. Never spend all turns reading without writing code. Keep diffs focused and robust under -Wall -Wextra. Never touch sealed harness files (Makefile, src/evolve.c, src/warden.c, etc.)."

MAX_CONSECUTIVE_REVERTS=5
SLEEP_BETWEEN=15

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
