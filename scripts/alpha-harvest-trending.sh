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
STREAM_LOG="/tmp/alpha_harvester_stream.log"

mkdir -p "$STAGING_BASE"
mkdir -p "$ROOT_DIR/evolution"
touch "$HARVEST_LOG"
touch "$STREAM_LOG"

LANGUAGES=("c" "cpp" "csharp")
TIMEFRAMES=("daily" "weekly" "monthly")

BLOCKLIST=("torvalds/linux" "microsoft/PowerToys" "tensorflow/tensorflow" "electron/electron" "dotnet/aspnetcore")

log() {
    echo -e "\033[1;34m[alpha-harvester]\033[0m $(date '+%H:%M:%S') $*" | tee -a "$STREAM_LOG"
}

is_already_harvested() {
    local repo="$1"
    for b in "${BLOCKLIST[@]}"; do
        if [ "$repo" = "$b" ]; then return 0; fi
    done
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

url = f"https://api.github.com/search/repositories?q=language:{lang}+pushed:>{d}+size:<150000&sort=stars&order=desc&per_page=8"
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
        log "Skipping already-harvested or blocklisted repository: $repo"
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

    # Exact Generation 211 Gold-Standard Blueprint
    local goal="Autonomous Harvester Goal for '$repo' ($file_count files at $stage_dir):
Replicate the exact winning rhythm of Generation 211 (which shipped +501 lines of code_search):
1. [Turn 1 - Quick Survey]: Use list_dir and grep. Read 1 core algorithm file. Immediately pick ONE missing capability (e.g. data structure, parser, fast hashing, ring buffer, network packet queue, AST tokenizer, or binary inspector).
2. [Turn 2 - Plan with todo]: Call the todo tool with 4-6 small chunked tasks.
3. [Turns 3-6 - Chunked Pure-C11 Synthesis]: Write code in src/tools.c in small ~100-line chunks. Wire tools_run() dispatch and tools_schema(). NEVER touch src/evolve.c, Makefile, or warden files.
4. [Turns 7-9 - Dedicated Unit Test & Gate]: Write tests/custom/test_<name>.c with 6+ assertions. Run execute_bash with 'make -j4 && make test'. If compiler errors occur, fix them in the sandbox immediately.
Your final diff must be non-empty and must include tests/custom/test_<name>.c."

    log "Launching self-evolution synthesis for $repo..."
    cd "$ROOT_DIR" || exit 1

    local ts
    ts=$(date +%s)
    
    ./alpha --evolve "$goal" --generations 1 2>&1 | tee -a "$STREAM_LOG"

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
