# Benchmark Strategy

This document defines benchmark standards for the TSP Rust SDK (`tsp_sdk`). It is a policy document: future benchmark implementations MUST follow it.

## Goals

- Detect performance regressions in PR review (CI + AI).
- Keep results actionable (benchmarks map to modules and paths).
- Produce stable, machine-readable outputs.

## Scope

In scope:

- SDK core: VID/DID, crypto, CESR, store
- transport and CLI benchmarks (local-only, non-gating by default)

Out of scope:

- external network performance (public internet / third-party services)
- absolute numbers comparable across arbitrary machines

## Benchmark suites

### Guardrail Suite (CI)

Purpose: regression detection with minimal CI time.

Metric: MUST gate on Callgrind `Ir` (instructions), not wall-clock time.

Required benchmark IDs:

- Store:
  - `guardrail.store.seal_open.direct.1KiB`
  - `guardrail.store.seal_open.direct.16KiB`
- Crypto:
  - `guardrail.crypto.seal_open.direct.1KiB`
  - `guardrail.crypto.seal_open.direct.16KiB`
- CESR:
  - `guardrail.cesr.decode_envelope.1KiB`
  - `guardrail.cesr.decode_envelope.16KiB`
  - Input MUST be a fixed, pre-generated message fixture (not generated inside the measured region).
- VID / DID:
  - `guardrail.vid.verify.did_peer.offline`
  - `guardrail.vid.verify.did_web.local`
  - `guardrail.vid.verify.did_webvh.local`
  - `did:web` and `did:webvh` MUST NOT depend on the public internet (use an in-process fixture resolver or a loopback HTTP server serving repository fixtures).

### Throughput Suite (manual / optional nightly)

Purpose: provide machine-specific throughput numbers (TPS) without slowing PR CI.

Required benchmark IDs:

- `throughput.sdk.blackbox.tps.seal_open.1KiB`
- `throughput.sdk.blackbox.tps.seal_open.16KiB`

Implementation requirements:

- SHOULD be an SDK example binary (release build).
- MUST use fixed fixtures/keys and fixed payloads.
- MUST use a fixed iteration count (large enough for stable results).
- MUST emit canonical JSON (below), including throughput (ops/s) and at least mean wall-clock time.

Optional (Throughput Suite):

- transport loopback benchmarks (TCP/TLS/QUIC/HTTP), separating setup vs steady-state
- CLI black-box scenarios (direct/nested/routed using local services only)

## Inputs

Benchmarks MUST define inputs explicitly.

Default payload sizes for message-like benchmarks:

- 0 B
- 32 B
- 256 B
- 1 KiB
- 16 KiB

Fixtures and keys:

- no randomness without a fixed seed (setup may generate; measured region must be deterministic)
- prefer repository fixtures (e.g., `examples/test/**`)
- no external network calls

Caching:

- if caches apply, define and label `cold` vs `warm`

## Benchmark IDs

IDs MUST be stable across refactors.

Format:

`<suite>.<area>.<case>[.<variant>][.<size>]`

Where:

- `suite`: `guardrail` or `throughput`
- `variant`: e.g., `direct`, `setup`, `steady`, `offline`, `local`
- `size`: e.g., `0B`, `32B`, `256B`, `1KiB`, `16KiB`

## Canonical JSON output (v1)

All benchmark implementations MUST be able to emit canonical JSON:

- UTF-8
- either a JSON array (`.json`) or JSON Lines (`.jsonl`)
- numeric fields MUST be numbers

Default output path convention:

- `target/bench-results/<suite>.json` (preferred)
- `target/bench-results/<suite>.jsonl` (allowed)

Each record MUST contain:

- `schema_version` (string, `"v1"`)
- `suite` (string, `guardrail` or `throughput`)
- `tool` (string, e.g., `callgrind`, `criterion`, `blackbox`, `cli`)
- `benchmark_id` (string)
- `metric` (string, e.g., `Ir`, `time_ns`, `throughput_ops_per_s`)
- `value` (number)
- `unit` (string)
- `git_sha` (string)
- `timestamp` (RFC 3339 / ISO 8601 string)
- `environment` (object; MUST exist)

`environment` MUST include:

- `os` (string)
- `arch` (string)
- `runner` (string; e.g., `github-actions`, `local`)
- `rustc` (string; `rustc -V`)

Standard metrics:

- Callgrind instructions: `metric="Ir"`, `unit="instructions"`
- Wall-clock time: `metric="time_ns"`, `unit="ns"`
- Throughput: `metric="throughput_ops_per_s"`, `unit="ops/s"`

Example record:

```json
{
  "schema_version": "v1",
  "suite": "guardrail",
  "tool": "callgrind",
  "benchmark_id": "guardrail.store.seal_open.direct.16KiB",
  "metric": "Ir",
  "value": 123456789,
  "unit": "instructions",
  "git_sha": "0123456789abcdef",
  "timestamp": "2026-01-27T12:34:56Z",
  "environment": {
    "os": "linux",
    "arch": "x86_64",
    "runner": "github-actions",
    "rustc": "rustc 1.88.0 (....)"
  }
}
```

### Callgrind output (CI)

CI MUST produce canonical JSON for the Guardrail Suite, even if the Callgrind runner emits its own JSON.

- raw tool output may be uploaded as an artifact for debugging
- normalization MUST inject `git_sha`, `timestamp`, and `environment.*` fields
- gating MUST be based on `Ir` unless this document is updated

## Baselines and thresholds

Baselines MUST come from the default branch (`main`); PRs compare against the latest baseline.

Default thresholds (tune after collecting baselines):

- Guardrail Suite: warn at +2% `Ir`
- Throughput Suite: warn-only by default; never PR-gating

## Manual profiling

This strategy is about comparability and regression detection. Deep performance debugging belongs in manual profiling workflows.

See `benchmark.md` for current profiling notes.
