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

BLOCKLIST=("torvalds/linux" "microsoft/PowerToys" "tensorflow/tensorflow" "electron/electron" "dotnet/aspnetcore" "php/php-src" "coolsnowwolf/lede" "git/git" "freebsd/freebsd" "netdata/netdata")

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
days = 3 if timeframe == 'daily' else (14 if timeframe == 'weekly' else 90)
d = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime('%Y-%m-%d')

queries = [
    f"language:{lang}+pushed:>{d}+stars:>50&sort=stars&order=desc&per_page=30",
    f"language:{lang}+stars:>200+topic:parser&sort=updated&order=desc&per_page=15",
    f"language:{lang}+stars:>200+topic:graphics&sort=updated&order=desc&per_page=15",
    f"language:{lang}+stars:>200+topic:compression&sort=updated&order=desc&per_page=15",
    f"language:{lang}+stars:>200+topic:cli&sort=updated&order=desc&per_page=15"
]

seen = set()
for q in queries:
    url = f"https://api.github.com/search/repositories?q={q}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Agent-Alpha-Harvester'})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get('items', []):
                name = item.get('full_name', '')
                if name and name not in seen:
                    seen.add(name)
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

    # Airtight non-cheating 3-phase execution blueprint
    local goal="Autonomous Harvester Goal for '$repo' ($file_count files staged at $stage_dir):
CRITICAL: You MUST call tools natively using the function-calling mechanism. NEVER write tool calls as plain text or pseudo-xml.
Follow the exact Generation 211 blueprint:
1. [Turn 1 - Quick Survey]: Use list_dir and grep. Read 1 core algorithm file. Immediately choose ONE missing capability (e.g. data structure, parser, fast hashing, ring buffer, network packet queue, AST tokenizer, or binary inspector).
2. [Turn 2 - Plan with todo]: Call the todo tool with 4-6 small chunked tasks.
3. [Turns 3-6 - Chunked Pure-C11 Synthesis]: Write code in src/tools.c in small ~100-line chunks. Wire tools_run() dispatch and tools_schema(). Enforce strict input validation (check for negative values on signed integers, validate character sets, and use overflow-safe bounds subtraction). NEVER touch src/evolve.c, Makefile, or warden files.
4. [Turns 7-9 - Real Unit Test & Verification]: Write a genuine unit test suite in tests/custom/test_<name>.c with 8+ rigorous assertions testing real edge cases AND mandatory adversarial negative tests (e.g. negative integers, invalid/corrupted strings, out-of-bounds checks). Run execute_bash with 'make -j4 && make test'. If any compiler warning or test fails, fix it immediately.
Your final diff must be non-empty and must include real working code + real tests."

    log "Launching self-evolution synthesis for $repo with BytePlus Ark Coding..."
    cd "$ROOT_DIR" || exit 1

    local ts
    ts=$(date +%s)
    export ALPHA_BASE_URL="${ALPHA_BASE_URL:-https://ark.ap-southeast.bytepluses.com/api/coding/v3}"
    export ALPHA_MODEL="${ALPHA_MODEL:-ark-code-latest}"
    if [ -z "${ALPHA_API_KEY:-}" ] && [ -f "$HOME/.openclaw/openclaw.json" ]; then
        ALPHA_API_KEY=$(grep -o '"apiKey": *"[^"]*"' "$HOME/.openclaw/openclaw.json" | head -n 1 | cut -d'"' -f4)
    fi
    export ALPHA_API_KEY
    ./alpha -u "$ALPHA_BASE_URL" -m "$ALPHA_MODEL" -k "$ALPHA_API_KEY" --evolve "$goal" --generations 1 2>&1 | tee -a "$STREAM_LOG"

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

# Main continuous harvesting loop (Runs 24/7 with zero artificial pauses)
log "Starting Autonomous Cross-Repository Codebase Harvester..."
while true; do
    for tf in "${TIMEFRAMES[@]}"; do
        for lang in "${LANGUAGES[@]}"; do
            log "=== Scanning $lang ($tf) ==="
            while IFS= read -r repo; do
                if [ -n "$repo" ]; then
                    harvest_repo "$repo" "$lang" "$tf"
                    sleep 2
                fi
            done < <(fetch_trending_repos "$lang" "$tf")
        done
    done
    log "Completed full sweep across daily, weekly, monthly for C/C++/C#. Cycling immediately into next sweep..."
    sleep 5
done
