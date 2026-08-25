#!/bin/bash
# Ensure the local vllm-mlx server can actually complete a request.
# /health can report "healthy" while the batched engine is wedged (every
# completion returns finish_reason "error" / empty stop), so this probes with
# a real tiny completion and restarts the server if it fails.
#
# Usage: scripts/alpha-server-ensure.sh   (exit 0 = server usable)

PORT="${ALPHA_SERVER_PORT:-8000}"
MODEL="${ALPHA_MODEL:-ornith-ai/Ornith-1.5-35B-A3B-MLX-6bit}"
BASE="http://127.0.0.1:$PORT"

probe() {
    curl -s -m 90 "$BASE/v1/chat/completions" \
        -H 'Content-Type: application/json' \
        -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":4,\"stream\":false}" \
    | grep -q '"content"'
}

if probe; then
    exit 0
fi

echo "[alpha-serve] server wedged — restarting vllm-mlx on port $PORT..."
pkill -f "vllm-mlx serve" 2>/dev/null
sleep 5
pkill -9 -f "vllm-mlx serve" 2>/dev/null
sleep 2

nohup "$HOME/mlx-env/bin/vllm-mlx" serve "$MODEL" --port "$PORT" \
    --continuous-batching \
    --kv-cache-quantization-bits 4 \
    --kv-cache-quantization-group-size 64 \
    --kv-cache-min-quantize-tokens 256 \
    --max-tokens 262144 \
    --max-request-tokens 262144 \
    --max-kv-size 262144 \
    --chunked-prefill-tokens 4096 \
    --prefill-step-size 4096 \
    --gpu-memory-utilization 0.90 \
    > /tmp/vllm-mlx.log 2>&1 &

for i in $(seq 1 60); do
    sleep 10
    if curl -s -m 2 "$BASE/health" 2>/dev/null | grep -q '"model_loaded":true' && probe; then
        echo "[alpha-serve] server back after ~$((i*10))s"
        exit 0
    fi
done

echo "[alpha-serve] ERROR: server did not recover"
exit 1
