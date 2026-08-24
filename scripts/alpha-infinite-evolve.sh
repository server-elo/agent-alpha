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

# Small, landable changes only. The gate (build + full test suite + warden
# seal + benchmarks) rejects sweeping rewrites, and the sealed harness files
# listed in the goal can never be touched by a generation.
GOAL="Make ONE small, well-scoped improvement to Agent Alpha. Good candidates: fix a real bug you find by reading the code, handle a missing edge case, improve a tool's output or error message, or add a small, focused capability to src/tools.c, src/browser.c, src/provider.c, src/telegram.c, src/ui.c or src/main.c. Add unit tests for new logic in tests/custom/test_<name>.c. Verify with make -j4 && make test — every check must pass. Keep the diff minimal: a small change that passes the gate beats a grand redesign that gets reverted. NEVER touch the sealed harness files: Makefile, src/evolve.c, src/agent_loop.c, src/warden.c, src/llm.c, tests/test_evolve.c."

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
