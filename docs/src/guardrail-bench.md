# Guardrail Benchmarks

The Guardrail Suite is the CI-oriented benchmark suite for `tsp_sdk`. It is designed for regression detection with stable metrics.

## What it measures

- Metric: Callgrind `Ir` (instruction count)
- Coverage: the Guardrail benchmark IDs defined in `benchmark-strategy.md`
- Variants: the report runner may execute multiple bench targets with different feature sets (e.g., default, classic HPKE, PQ)

## How to run

Linux (recommended):

```bash
cargo bench -p tsp_sdk --bench guardrail_report
```

macOS:

Callgrind/Valgrind is frequently unsupported or unstable on macOS. Use Docker:

```bash
bash tsp_sdk/benches/guardrail/run_docker.sh
```

## Outputs

The Guardrail report runner writes:

- Canonical JSONL (one record per benchmark): `target/bench-results/guardrail.jsonl`
- Raw iai-callgrind summaries (for debugging/AI): `target/bench-results/guardrail.<variant>.iai.json`

Callgrind artifacts are produced under `target/iai/**` and referenced by relative paths in each JSONL record under `artifacts.*`.

## How to read results

- `benchmark_id` identifies the benchmark case (stable across refactors).
- `value` is the `Ir` instruction count (lower is better).
- `run.variant` indicates which Guardrail sub-run produced the record (e.g., `default`, `hpke`, `pq`).
