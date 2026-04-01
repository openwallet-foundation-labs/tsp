# Throughput Benchmarks

This document describes how to run and read the Throughput Suite for `tsp_sdk`.

See `benchmark-strategy.md` for benchmark IDs and policy requirements.

## Quickstart

Run the full Throughput Suite (recommended):

```sh
cargo bench -p tsp_sdk --bench throughput_report --features bench-criterion
```

Change output path:

```sh
cargo bench -p tsp_sdk --bench throughput_report --features bench-criterion -- --output target/bench-results/throughput.jsonl
```

Run a single variant:

```sh
# default (store/crypto/cesr/vid)
cargo bench -p tsp_sdk --bench throughput

# transport (tcp/tls/quic loopback)
cargo bench -p tsp_sdk --bench throughput_transport --features bench-criterion

# cli-level workflows
cargo bench -p tsp_sdk --bench throughput_cli

# store backends (askar sqlite)
cargo bench -p tsp_sdk --bench throughput_store_backend

# hpke (classic, no nacl)
cargo bench -p tsp_sdk --bench throughput_hpke --no-default-features --features resolve

# pq
cargo bench -p tsp_sdk --bench throughput_pq --no-default-features --features pq,resolve
```

Optional Postgres backend (manual; requires env):

```sh
export TSP_BENCH_PG_URL='postgres://...'
cargo bench -p tsp_sdk --bench throughput_store_backend_pg --features postgres
```

## Outputs

The suite produces:

- `target/bench-results/throughput.md`: human-readable summary (median time + ops/s + failures/total).
- `target/bench-results/throughput.jsonl`: canonical JSON Lines (mean in `value`, median under `stats.median.*`).
- `target/criterion/<benchmark_id>/new/estimates.json`: raw criterion estimates (source of mean/median).

## How to read

`throughput.md` is grouped by `variant` and includes:

- `benchmark_id`: stable ID from the strategy.
- `size_bytes`: parsed from the ID suffix when present (e.g. `1KiB` -> `1024`).
- `median_time`: per-iteration median wall-clock time (formatted from ns).
- `ops/s`: `1e9 / median_time_ns` (SI formatting, e.g. `4.12k`).
- `failures/total`: aggregated runtime failures over total attempts for the benchmark (`x/y`), or `-` when not collected for that benchmark target.

## Notes

- Criterion may print `Gnuplot not found...`; it does not affect results.
- Transport benches require `bench-criterion` to use repository-local dev certs for TLS/QUIC.
- CLI and transport benchmark harnesses follow SDK short-lived send behavior.
- Bench targets print one `failures/total` summary line per benchmark only when failures are non-zero.
