# Guardrail Benchmarks

The Guardrail Suite is the CI-oriented benchmark suite for `tsp_sdk`. It is designed for regression detection with stable metrics and is reported via Bencher.

## What it measures

- Metric: Callgrind `Ir` (instruction count)
- Coverage: the Guardrail benchmark IDs defined in `benchmark-strategy.md`
- Variants: multiple bench targets with different feature sets (e.g., default, classic HPKE, PQ)

## How to run

CI (recommended):

Guardrail runs are uploaded and compared in Bencher.

- Baseline tracking (`push` on `main`): `.github/workflows/bench-guardrail.yml`
- PR tracking (including fork PRs): `.github/workflows/bench-guardrail-pr.yml` (run/upload artifacts) + `.github/workflows/bench-guardrail-pr-track.yml` (upload to Bencher)
- Required repository variable: `BENCHER_PROJECT`
- Required repository secret: `BENCHER_API_TOKEN`
- Optional repository variable: `BENCHER_HOST` (set only for self-hosted Bencher; for bencher.dev leave this variable unset)

Linux (manual, no Bencher):

```bash
cargo bench -p tsp_sdk --bench guardrail --features resolve,bench-callgrind
cargo bench -p tsp_sdk --bench guardrail_hpke --no-default-features --features resolve,bench-callgrind
cargo bench -p tsp_sdk --bench guardrail_pq --no-default-features --features pq,resolve,bench-callgrind
```

macOS:

Callgrind/Valgrind is frequently unsupported or unstable on macOS. Prefer relying on CI.

If needed, use Docker to run the suite:

```bash
bash tsp_sdk/benches/guardrail/run_docker.sh
```

## Outputs

Primary results are stored in Bencher.

Local runs produce gungraun output, and Callgrind artifacts are produced under `target/gungraun/**`.

## How to read results

- `benchmark_id` identifies the benchmark case (stable across refactors).
- `value` is the `Ir` instruction count (lower is better).
- Variant-specific benchmarks include the crypto suite in their benchmark IDs (e.g., `*.hpke.*`, `*.hpke_pq.*`).
