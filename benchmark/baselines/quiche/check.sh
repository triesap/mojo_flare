#!/bin/bash
# Verify the quiche HTTP/3 baseline is up by probing with
# h2load --npn-list=h3 (the canonical h3 workload tool every h3
# baseline shares; see benchmark/scripts/bench_h3.sh). Exit 0
# on a successful 1-stream warm-up, else 1. Cargo's first build
# of quiche + boringssl-vendored can take 90-300s; wait up to
# 360s.
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8443}"
URL="https://127.0.0.1:$PORT/plaintext"

for _ in $(seq 1 720); do
    if h2load --npn-list=h3 -n 1 -c 1 \
            --connect-to "127.0.0.1:$PORT" "$URL" \
            > /dev/null 2>&1; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: quiche-h3 server did not answer after 360s at $URL"
exit 1
