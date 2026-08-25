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

# Ambitious C feature & tool evolution goal.
# Commands Agent Alpha to leverage the full 256k token context to reverse-engineer
# complete missing tools, build high-performance C modules, and write exhaustive unit tests.
GOAL="Leverage your full 256k token context window to build substantial new capabilities into Agent Alpha in native C11. Good goals: (1) Add complete, high-performance tools to src/tools.c (e.g., fast AST query, ripgrep/regex integration, structured memory indexes, embedded SQLite/KV cache, diff-patching engine, process supervisor); (2) Enhance core engine performance, latency, and memory throughput; (3) Add rich unit tests in tests/custom/test_<name>.c proving every new tool and edge case. Verify thoroughly with make -j4 && make test. Write clean, robust C11 (-Wall -Wextra clean). NEVER touch sealed harness files (Makefile, src/evolve.c, src/warden.c, src/agent_loop.c, src/llm.c, tests/test_evolve.c)."

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
