#!/bin/bash
# Start the quiche HTTP/3 baseline on 127.0.0.1:$FLARE_BENCH_PORT.
# Writes PID to benchmark/results/.server.pid so the orchestrator
# can stop it after the run. Mirrors the contract of
# benchmark/baselines/quinn/run.sh.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8443}"

export FLARE_BENCH_PORT="$PORT"

cd "$DIR"
# --locked enforces Cargo.lock so bench numbers are reproducible
# across machines. cargo build is idempotent if cached; the
# first build can take 90-300s for the quiche + boringssl-
# vendored dependency tree.
cargo build --release --locked --quiet
./target/release/server &
echo $! > "$PID_FILE"
