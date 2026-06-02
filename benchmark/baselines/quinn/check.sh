#!/bin/bash
# Verify the quinn HTTP/3 baseline is up by probing it with
# h2load (which speaks h3 when called with --npn-list=h3 +
# --alpn-list=h3). Exit 0 once h2load completes a 1-stream
# warm-up request successfully, else 1. Cargo's first build of
# quinn + rustls + ring can take ~90-180s; wait up to 240s.
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8443}"
URL="https://127.0.0.1:$PORT/plaintext"

# h2load --h1 / --h3: we use h2load with --npn-list=h3 because
# it's the canonical workload tool every h3 baseline shares
# (see Track Q7-W commit 3/4 / benchmark/scripts/bench_h3.sh).
for _ in $(seq 1 480); do
    if h2load --npn-list=h3 -n 1 -c 1 \
            --connect-to "127.0.0.1:$PORT" "$URL" \
            > /dev/null 2>&1; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: quinn-h3 server did not answer after 240s at $URL"
exit 1
