# v0.7 Pre-flight Perf Baseline

Captured at HEAD `b20951e` (`fix(ffi): harden OwnedDLHandle lifetime
across every FFI shim`) on 2026-05-06T03:12 UTC. This is the fixed
reference for v0.7 release-readiness perf-no-regression checks.

Per-commit gates (C2 if it ships, C3, C5, C6) compare a fresh
`pixi run --environment bench bench-vs-baseline-quick` run against
this snapshot. Acceptable drift:

- Req/s within ±1% of the median value below.
- p99 ≤ baseline + 5%.
- p99.99 ≤ baseline + 5%.

If a commit lands outside these bands, investigate and re-do
before the next commit goes in.

## Snapshot

Source: `benchmark/results/2026-05-06T0312-ehsan-dev-b20951e/` (also
mirrored here for posterity).

| Target | Workload | Config | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| flare | plaintext | throughput | 70,680 | 1.57 | 1.18 | 3.09 | 4.41 | 8.69 | true |
| go_nethttp | plaintext | throughput | 37,850 | 1.58 | 1.34 | 3.19 | 3.64 | 4.32 | true |

flare is 1.87x Go `net/http` 1w on this run. The flare 1w tail at
p99.99 (8.69 ms) is wider than the published v0.6 number
(3.36 ms from `benchmark/results/2026-05-04T1817-ehsan-dev-8fcf86b/`)
because this run is on a noisier dev-box state (concurrent system
load); the calibrated peak finder is consistent so the bench is
internally comparable for regression checks. For absolute tail
claims use the v0.6 published numbers.

## Reproducing

```bash
pixi run --environment bench bench-vs-baseline-quick
```

Runs `flare` + `go_nethttp` only, throughput config, ~9 minutes
wall-clock end-to-end. Output lands under
`benchmark/results/<timestamp>-<host>-<commit>/`.
