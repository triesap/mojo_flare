#!/bin/bash
# Benchmark flare HTTP server with wrk.
# Usage: pixi run bench-server-wrk
#
# Requires: wrk (brew install wrk / apt install wrk)

set -e

echo "=== Building flare bench_server ==="
cd "$(dirname "$0")/.."
pixi run mojo build -I . benchmark/bench_server.mojo -o bench_server || exit 1

echo ""
echo "=== Starting server ==="
./bench_server &
SERVER_PID=$!
sleep 2

echo ""
echo "=== Running wrk: single thread, single connection, 10s ==="
wrk -t1 -c1 -d10s http://localhost:8080/ --header "User-Agent: wrk"

echo ""
echo "=== Running wrk: 4 threads, 100 connections, 10s ==="
wrk -t4 -c100 -d10s http://localhost:8080/ --header "User-Agent: wrk"

echo ""
echo "=== Running wrk: /json endpoint, single connection, 10s ==="
wrk -t1 -c1 -d10s http://localhost:8080/json --header "User-Agent: wrk"

echo ""
echo "=== Cleaning up ==="
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null
rm -f bench_server

echo "Done."
