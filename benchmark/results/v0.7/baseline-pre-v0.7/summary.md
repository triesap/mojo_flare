# Benchmark summary

- Run: 2026-05-06T0312-ehsan-dev-b20951e
- See env.json for hardware / toolchain versions.

| Target | Workload | Config | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| flare | plaintext | throughput | 70680 | 1.57 | 1.18 | 3.09 | 4.41 | 8.69 | true |
| go_nethttp | plaintext | throughput | 37850 | 1.58 | 1.34 | 3.19 | 3.64 | 4.32 | true |
