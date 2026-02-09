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

Implementation note: Guardrail coverage MAY require multiple `cargo bench` invocations under different feature sets (e.g., default, no-`nacl`, `pq`).

Implementation note: Guardrail is reported via Bencher in CI. Running under different feature sets MAY require multiple `bencher run` invocations.

Required benchmark IDs:

- Store:
  - `guardrail.store.seal_open.direct.0B`
  - `guardrail.store.seal_open.direct.1KiB`
  - `guardrail.store.seal_open.direct.16KiB`
- Crypto:
  - `guardrail.crypto.seal_open.direct.0B`
  - `guardrail.crypto.seal_open.direct.1KiB`
  - `guardrail.crypto.seal_open.direct.16KiB`
  - Classic HPKE (no `nacl`):
    - `guardrail.crypto.seal_open.hpke.direct.0B`
    - `guardrail.crypto.seal_open.hpke.direct.1KiB`
    - `guardrail.crypto.seal_open.hpke.direct.16KiB`
    - `guardrail.crypto.sign_verify.ed25519.direct.0B`
    - `guardrail.crypto.sign_verify.ed25519.direct.1KiB`
    - `guardrail.crypto.sign_verify.ed25519.direct.16KiB`
  - Post-quantum (feature `pq`, no `nacl`):
    - `guardrail.crypto.seal_open.hpke_pq.direct.0B`
    - `guardrail.crypto.seal_open.hpke_pq.direct.1KiB`
    - `guardrail.crypto.seal_open.hpke_pq.direct.16KiB`
    - `guardrail.crypto.sign_verify.mldsa65.direct.0B`
    - `guardrail.crypto.sign_verify.mldsa65.direct.1KiB`
    - `guardrail.crypto.sign_verify.mldsa65.direct.16KiB`
  - Digest:
    - `guardrail.crypto.digest.sha256.0B`
    - `guardrail.crypto.digest.sha256.32B`
    - `guardrail.crypto.digest.sha256.1KiB`
    - `guardrail.crypto.digest.sha256.16KiB`
    - `guardrail.crypto.digest.blake2b256.0B`
    - `guardrail.crypto.digest.blake2b256.32B`
    - `guardrail.crypto.digest.blake2b256.1KiB`
    - `guardrail.crypto.digest.blake2b256.16KiB`
- CESR:
  - `guardrail.cesr.decode_envelope.0B`
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

Required benchmark IDs (mirror the Guardrail Suite under the `throughput.*` suite prefix):

- Store:
  - `throughput.store.seal_open.direct.0B`
  - `throughput.store.seal_open.direct.1KiB`
  - `throughput.store.seal_open.direct.16KiB`
- Crypto:
  - `throughput.crypto.seal_open.direct.0B`
  - `throughput.crypto.seal_open.direct.1KiB`
  - `throughput.crypto.seal_open.direct.16KiB`
  - Classic HPKE (no `nacl`):
    - `throughput.crypto.seal_open.hpke.direct.0B`
    - `throughput.crypto.seal_open.hpke.direct.1KiB`
    - `throughput.crypto.seal_open.hpke.direct.16KiB`
    - `throughput.crypto.sign_verify.ed25519.direct.0B`
    - `throughput.crypto.sign_verify.ed25519.direct.1KiB`
    - `throughput.crypto.sign_verify.ed25519.direct.16KiB`
  - Post-quantum (feature `pq`, no `nacl`):
    - `throughput.crypto.seal_open.hpke_pq.direct.0B`
    - `throughput.crypto.seal_open.hpke_pq.direct.1KiB`
    - `throughput.crypto.seal_open.hpke_pq.direct.16KiB`
    - `throughput.crypto.sign_verify.mldsa65.direct.0B`
    - `throughput.crypto.sign_verify.mldsa65.direct.1KiB`
    - `throughput.crypto.sign_verify.mldsa65.direct.16KiB`
  - Digest:
    - `throughput.crypto.digest.sha256.0B`
    - `throughput.crypto.digest.sha256.32B`
    - `throughput.crypto.digest.sha256.1KiB`
    - `throughput.crypto.digest.sha256.16KiB`
    - `throughput.crypto.digest.blake2b256.0B`
    - `throughput.crypto.digest.blake2b256.32B`
    - `throughput.crypto.digest.blake2b256.1KiB`
    - `throughput.crypto.digest.blake2b256.16KiB`
- CESR:
  - `throughput.cesr.decode_envelope.0B`
  - `throughput.cesr.decode_envelope.1KiB`
  - `throughput.cesr.decode_envelope.16KiB`
  - Input MUST be a fixed, pre-generated message fixture (not generated inside the measured region).
- VID / DID:
  - `throughput.vid.verify.did_peer.offline`
  - `throughput.vid.verify.did_web.local`
  - `throughput.vid.verify.did_webvh.local`
  - `did:web` and `did:webvh` MUST NOT depend on the public internet (use an in-process fixture resolver or a loopback HTTP server serving repository fixtures).

Additional required benchmark IDs:

- Transport (local loopback; setup vs steady-state separated by benchmark ID):
  - TCP:
    - `throughput.transport.tcp.oneway.deliver.1B`
    - `throughput.transport.tcp.oneway.deliver.1KiB`
    - `throughput.transport.tcp.oneway.deliver.16KiB`
    - `throughput.transport.tcp.roundtrip.echo.1B`
    - `throughput.transport.tcp.roundtrip.echo.1KiB`
    - `throughput.transport.tcp.roundtrip.echo.16KiB`
  - TLS (local dev cert; no public internet):
    - `throughput.transport.tls.oneway.deliver.1B`
    - `throughput.transport.tls.oneway.deliver.1KiB`
    - `throughput.transport.tls.oneway.deliver.16KiB`
    - `throughput.transport.tls.roundtrip.echo.1B`
    - `throughput.transport.tls.roundtrip.echo.1KiB`
    - `throughput.transport.tls.roundtrip.echo.16KiB`
  - QUIC (local dev cert; no public internet):
    - `throughput.transport.quic.oneway.deliver.1B`
    - `throughput.transport.quic.oneway.deliver.1KiB`
    - `throughput.transport.quic.roundtrip.echo.1B`
    - `throughput.transport.quic.roundtrip.echo.1KiB`
    - QUIC message size limits MAY restrict larger payload variants; if so, keep required sizes small and add larger sizes only when supported.

- CLI-level workflows (in-process; MUST NOT benchmark process startup):
  - Direct send+receive (relationship already established):
    - `throughput.cli.send_receive.direct.tcp.mem.0B`
    - `throughput.cli.send_receive.direct.tcp.mem.1KiB`
    - `throughput.cli.send_receive.direct.tcp.mem.16KiB`
    - `throughput.cli.send_receive.direct.tcp.sqlite.0B`
    - `throughput.cli.send_receive.direct.tcp.sqlite.1KiB`
    - `throughput.cli.send_receive.direct.tcp.sqlite.16KiB`
  - Relationship handshake (request -> accept):
    - `throughput.cli.relationship.roundtrip.tcp.mem`
    - `throughput.cli.relationship.roundtrip.tcp.sqlite`
  - Implementation note (stability): CLI `*.tcp.*` benchmarks SHOULD reuse a persistent loopback TCP connection with explicit message framing (e.g. length-delimited) and MUST NOT open a new TCP connection per message. This is a bench harness detail (the SDK's `tcp` transport may use 1-connection-per-message). These IDs are intended to measure steady-state throughput (seal/open + TCP I/O), not connect/accept setup costs.

- Store backends (persistence layer; local-only):
  - Askar SQLite:
    - `throughput.store.backend.askar.sqlite.persist.wallet_2vid`
    - `throughput.store.backend.askar.sqlite.read.wallet_2vid`

Implementation requirements:

- SHOULD be implemented using `criterion` benches.
- MUST use fixed fixtures/keys and fixed payloads.
- MUST report results in a stable, machine-readable way.
  - Throughput Suite: uses the repository-local report runner to emit canonical JSON (below), including throughput (ops/s) and at least mean wall-clock time.
  - Guardrail Suite: results are uploaded and compared in Bencher (CI), with optional Callgrind artifacts retained for debugging.
- Human-readable summaries SHOULD display median time/throughput (more robust to noise) when available.

Optional (Throughput Suite):

- SDK black-box TPS scenarios (example binary; release build)
- Askar Postgres (requires local DSN; never required):
  - `throughput.store.backend.askar.postgres.persist.wallet_2vid`
  - `throughput.store.backend.askar.postgres.read.wallet_2vid`
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

Transport loopback benchmarks use `1B` as the practical minimum (instead of `0B`) because some transport harnesses do not represent a 0-byte write as a meaningful per-message transfer.

Fixtures and keys:

- no randomness without a fixed seed (setup may generate)
- for cryptographic APIs which do not support injecting a deterministic RNG, measured regions MAY use OS RNG when gating on Callgrind `Ir`
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

## Canonical JSON output (v1, local / optional)

Repository-local report runners MAY emit canonical JSON:

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

Each record MAY include additional metadata fields (e.g., `run.variant`) as long as the required fields remain stable.

`environment` MUST include:

- `os` (string)
- `arch` (string)
- `runner` (string; e.g., `github-actions`, `local`)
- `rustc` (string; `rustc -V`)
- `tools` (object; toolchain versions used for the run)

If emitting canonical JSON, `environment.tools` MUST include:

- for `tool="callgrind"`:
  - `gungraun` (string; version, from `Cargo.lock`)
  - `gungraun_runner` (string; version)
  - `valgrind` (string; version)
- for `tool="criterion"`:
  - `criterion` (string; version, from `Cargo.lock`)

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
    "rustc": "rustc 1.88.0 (....)",
    "tools": {
      "gungraun": "0.17.0",
      "gungraun_runner": "0.17.0",
      "valgrind": "3.19.0"
    }
  }
}
```

### Callgrind output (CI)

CI SHOULD upload Guardrail results to Bencher and MAY also upload Callgrind artifacts for debugging.

- CI SHOULD upload `target/gungraun/**` as an artifact (Callgrind logs/out/flamegraphs)
- gating SHOULD be based on `Ir` unless this document is updated

### Artifacts

Guardrail runs MAY upload raw tool output and Callgrind debug files as artifacts (for debugging).

## Baselines and thresholds

Baselines MUST come from the default branch (`main`); PRs compare against the latest baseline.

Default thresholds (tune after collecting baselines):

- Guardrail Suite: warn at +2% `Ir`
- Throughput Suite: warn-only by default; never PR-gating

## Manual profiling

This strategy is about comparability and regression detection. Deep performance debugging belongs in manual profiling workflows.

See `benchmark.md` for current profiling notes.
