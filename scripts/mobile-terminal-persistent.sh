#!/bin/bash
# Permanent 24/7 Mobile Web Terminal & SSH Tunnel Supervisor
# Keeps ttyd running and maintains an always-open, auto-reconnecting tunnel with keep-alive pings.

ROOT="/Users/lorenc/projects/agent-alpha"
PORT=7681
URL_FILE="/tmp/mobile_terminal_url.txt"

cleanup() {
    echo "[mobile-daemon] Stopping supervisor..."
    kill $(jobs -p) 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "[mobile-daemon] Starting persistent 24/7 mobile terminal service..."

# 1. Start ttyd if not already running
start_ttyd() {
    while true; do
        if ! pgrep -x "ttyd" > /dev/null; then
            echo "[mobile-daemon] Launching ttyd on port $PORT..."
            ttyd -p $PORT -W -t fontSize=16 -t theme='{"background": "#1e1e2e"}' zsh &
        fi
        sleep 5
    done
}
start_ttyd &

# 2. Start permanent auto-reconnecting tunnel with TCP keep-alives
while true; do
    echo "[mobile-daemon] Establishing permanent remote tunnel at $(date)..."
    
    # Run SSH reverse proxy to Pinggy with 10s keep-alives to prevent idle disconnects
    ssh -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=3 \
        -o TCPKeepAlive=yes \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=no \
        -p 443 \
        -R0:localhost:$PORT \
        a.pinggy.io > /tmp/tunnel_live.log 2>&1 &
    
    TUNNEL_PID=$!
    
    # Extract URL and save to fixed file
    for i in {1..30}; do
        URL=$(grep -o 'https://[-a-z0-9]*\.free\.pinggy\.net' /tmp/tunnel_live.log | tail -n 1)
        if [ -z "$URL" ]; then
            URL=$(grep -o 'https://[-a-z0-9]*\.run\.pinggy-free\.link' /tmp/tunnel_live.log | tail -n 1)
        fi
        if [ -n "$URL" ]; then
            echo "$URL" > "$URL_FILE"
            echo "[mobile-daemon] 24/7 Live URL: $URL"
            break
        fi
        sleep 1
    done
    
    # Supervise tunnel process
    wait $TUNNEL_PID 2>/dev/null || true
    echo "[mobile-daemon] Tunnel disconnected. Auto-reconnecting in 2s..."
    sleep 2
done
