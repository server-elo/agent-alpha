#!/bin/bash
# Continuous infinite evolution loop for Agent Alpha
# Each generation:
# 1. Runs BEFORE domain benchmark
# 2. Inspects Hermes & external repos, ports logic to C, writes unit tests
# 3. Runs 360° AFTER benchmark & quality comparison
# 4. Commits & pushes if AFTER >= BEFORE, re-executes into new binary

ROOT="/Users/lorenc/projects/agent-alpha"
cd "$ROOT" || exit 1

set -a
source .env
set +a

export ALPHA_EVOLVE=1

GOAL="You have the full 256k token context window available on your local Metal GPU with quantized KV cache. Use this full capacity boldly — do not limit yourself to small tweaks. Ingest entire modules, deep-inspect /Users/lorenc/.hermes/hermes-agent/ and trending C repos, reverse-engineer complete missing tools and architectures into Agent Alpha in C (src/tools.c, include/alpha.h), write full unit tests in tests/, and ensure all 617+ checks and 360° benchmarks pass."

echo "[alpha-loop] Starting continuous infinite evolution daemon..."

while true; do
    echo "[alpha-loop] Launching evolution run at $(date)..."
    ./alpha --evolve "$GOAL" --generations 1
    
    # Push successful generation to GitHub if clean
    if [[ -z "$(git status --porcelain)" ]]; then
        git push origin main 2>/dev/null || true
    fi

    # Small delay between continuous iterations to prevent thrashing
    sleep 3
done
