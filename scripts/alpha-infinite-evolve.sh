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

GOAL="Perform systematic line-by-line inspection of /Users/lorenc/.hermes/hermes-agent/. Track inspected files in memory (target=memory). Reverse-engineer and implement missing tools or logic into Agent Alpha in C (src/tools.c). Re-execute into next generation until all files are thoroughly checked, then proceed to GitHub trending C repos."

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
