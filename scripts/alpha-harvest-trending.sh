#!/bin/bash
# ==============================================================================
# alpha-harvest-trending.sh — Autonomous GitHub Trending Harvester & Synthesizer
#
# Continuously discovers trending C, C++, and C# repositories on GitHub
# across daily, weekly, and monthly horizons. Clones them into staging,
# surveys all source files, and invokes agent-alpha's self-evolution engine
# to synthesize pure-C11 native capabilities with 360° Quality Gate verification.
# ==============================================================================

set -uo pipefail

ROOT_DIR="/Users/lorenc/projects/agent-alpha"
STAGING_BASE="/tmp/alpha_harvest"
HARVEST_LOG="$ROOT_DIR/evolution/harvested_repos.jsonl"

mkdir -p "$STAGING_BASE"
mkdir -p "$ROOT_DIR/evolution"
touch "$HARVEST_LOG"

LANGUAGES=("c" "cpp" "csharp")
TIMEFRAMES=("daily" "weekly" "monthly")

log() {
    echo -e "\033[1;34m[alpha-harvester]\033[0m $*" >&2
}

is_already_harvested() {
    local repo="$1"
    grep -F "\"repo\": \"$repo\"" "$HARVEST_LOG" > /dev/null 2>&1
}

fetch_trending_repos() {
    local lang="$1"
    local timeframe="$2"
    
    python3 - << PY "$lang" "$timeframe"
import sys, urllib.request, json, datetime

lang = sys.argv[1]
timeframe = sys.argv[2]
days = 2 if timeframe == 'daily' else (7 if timeframe == 'weekly' else 30)
d = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime('%Y-%m-%d')

url = f"https://api.github.com/search/repositories?q=language:{lang}+pushed:>{d}&sort=stars&order=desc&per_page=6"
req = urllib.request.Request(url, headers={'User-Agent': 'Agent-Alpha-Harvester'})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        for item in data.get('items', []):
            name = item.get('full_name', '')
            if name:
                print(name)
except Exception:
    pass
PY
}

harvest_repo() {
    local repo="$1"
    local lang="$2"
    local timeframe="$3"
    local clean_name
    clean_name=$(echo "$repo" | tr '/' '_')
    local stage_dir="$STAGING_BASE/$clean_name"

    if is_already_harvested "$repo"; then
        log "Skipping already-harvested repository: $repo"
        return 0
    fi

    log "Cloning $repo ($lang, $timeframe) into staging..."
    rm -rf "$stage_dir"
    if ! git clone --depth 1 "https://github.com/$repo.git" "$stage_dir" > /dev/null 2>&1; then
        log "Failed to clone $repo, skipping."
        return 1
    fi

    local file_count
    file_count=$(find "$stage_dir" -type f -not -path '*/.*' | wc -l | tr -d ' ')
    log "Cloned $repo ($file_count files) at $stage_dir"

    # Construct the deep-synthesis goal
    local goal="Autonomous Harvester Goal: Deeply survey the cloned $lang repository '$repo' at $stage_dir ($file_count files). Ingest its codebase step-by-step using list_dir, grep, and read_file across all header and source files. Identify ONE high-value capability, algorithm, parser, cryptographic utility, or data structure present in that repo that agent-alpha currently lacks. Implement a clean, pure-C11 native version in src/tools.c or src/, create rich unit tests in tests/custom/test_<name>.c, and verify with make -j4 && make test. Always invoke tools directly. Write at most ~150 lines per tool call. Your final diff must be non-empty. Never edit sealed harness files."

    log "Launching self-evolution synthesis for $repo..."
    cd "$ROOT_DIR" || exit 1

    local ts
    ts=$(date +%s)
    local evolve_out
    evolve_out=$(./alpha --evolve "$goal" --generations 1 2>&1)
    local rc=$?

    local outcome="revert"
    local last_log
    last_log=$(tail -n 1 "$ROOT_DIR/evolution/log.jsonl" 2>/dev/null || true)
    if [[ "$last_log" == *"\"result\":\"keep\""* ]] || [[ "$last_log" == *"\"result\": \"keep\""* ]]; then
        outcome="keep"
    fi

    echo "{\"ts\": $ts, \"repo\": \"$repo\", \"lang\": \"$lang\", \"timeframe\": \"$timeframe\", \"result\": \"$outcome\"}" >> "$HARVEST_LOG"
    log "Finished synthesis for $repo -> Outcome: $outcome"

    rm -rf "$stage_dir"
    return 0
}

# Main continuous harvesting loop
log "Starting Autonomous Cross-Repository Codebase Harvester..."
while true; do
    for tf in "${TIMEFRAMES[@]}"; do
        for lang in "${LANGUAGES[@]}"; do
            log "=== Scanning $lang ($tf) ==="
            while IFS= read -r repo; do
                if [ -n "$repo" ]; then
                    harvest_repo "$repo" "$lang" "$tf"
                    sleep 3
                fi
            done < <(fetch_trending_repos "$lang" "$tf")
        done
    done
    log "Completed full sweep across daily, weekly, monthly for C/C++/C#. Pausing 30 minutes before next sweep..."
    sleep 1800
done
