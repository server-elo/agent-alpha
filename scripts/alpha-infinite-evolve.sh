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

# Self-Directed Research Goal.
# The agent chooses its own mission each generation. Research is done by
# shallow-cloning reference repos into /tmp/alpha-research/ and reading the
# real source — cheap on tokens, high on signal. Strict step-by-step flow,
# one shipped port per generation.
GOAL="You choose your own mission each generation — but autonomy means SHIPPING, not exploring. Work strictly step by step: (1) SURVEY your own code (include/alpha.h, src/tools.c) to see what already exists; (2) RESEARCH: pick one best-in-class open-source project (ripgrep, sqlite, git internals, tree-sitter, stb-style single-file C libraries) and shallow-clone it: git clone --depth 1 <repo> /tmp/alpha-research/<name> — then read its real source, do not guess from memory; (3) DECIDE by yourself on ONE concrete, proven capability Agent Alpha lacks that fits this codebase; (4) PORT it yourself to clean, dependency-free C11 in src/ or include/, in the style of deps/cJSON and deps/sds; (5) write rich unit tests in tests/custom/test_<name>.c; (6) prove it with make -j4 && make test. Your final diff MUST be non-empty — a generation that only reads code and changes nothing is a failure. One shipped port beats ten grand unfinished designs. Never edit sealed harness files (Makefile, src/evolve.c, src/warden.c, src/agent_loop.c, src/llm.c, tests/test_evolve.c)."

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
