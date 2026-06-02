#!/bin/bash
# Start the quinn HTTP/3 baseline on 127.0.0.1:$FLARE_BENCH_PORT.
# Writes PID to benchmark/results/.server.pid so the orchestrator
# can stop it after the run. Mirrors the contract of
# benchmark/baselines/hyper/run.sh.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8443}"

export FLARE_BENCH_PORT="$PORT"
export FLARE_BENCH_WORKERS="${FLARE_BENCH_WORKERS:-4}"

cd "$DIR"
# --locked enforces Cargo.lock so the bench numbers are
# reproducible across machines. cargo build is idempotent if
# cached; the first build can take 60-180s for the quinn +
# rustls + ring dependency tree.
cargo build --release --locked --quiet
./target/release/server &
echo $! > "$PID_FILE"
