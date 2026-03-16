# TSP Test Vectors

`tsp_test_vectors` is the canonical home for:

- authoritative case packages under `assets/`
- spec-facing vector documents under `docs/spec/`
- generation, freezing, and validation tooling under `src/`

It exists to support two concrete workflows:

1. generate a complete case package or a single vector asset set
2. validate a frozen package and produce a replay/output report

## Recommended Workflow

For normal use, the preferred path is:

1. generate one complete case package
2. immediately run the dedicated case runner and print the report
3. if needed, run the package validator separately

Default build, `CC-001`:

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-generate -- \
  case --case cc001 --assets-root /tmp/tsp-tv-cc001 --report
```

`CC-002`:

```bash
cargo run -p tsp_test_vectors --features essr --bin tsp-vector-generate -- \
  case --case cc002 --assets-root /tmp/tsp-tv-cc002 --report
```

`CC-003`:

```bash
cargo run -p tsp_test_vectors --features nacl --bin tsp-vector-generate -- \
  case --case cc003 --assets-root /tmp/tsp-tv-cc003 --report
```

This one command:

- generates the complete case package
- seeds the canonical identity/private basis needed by the runner
- runs the dedicated case runner
- prints the current replay/output summary

No extra configuration or follow-up input is required.

## Layout

- `assets/artifact-set.cc-001/`
- `assets/artifact-set.cc-002/`
- `assets/artifact-set.cc-003/`
- `assets/review-set.cc-001/`
- `assets/review-set.cc-002/`
- `assets/review-set.cc-003/`
- `docs/spec/`
- `src/authoring/`
- `src/validator.rs`
- `src/case_runner.rs`

## Concepts

- `BV-*`
  byte-exact vectors
- `SV-*`
  semantic vectors
- `AV-*`
  mechanism or binding-level verification entries

- `case-level outcomes`
  structured expected outcomes for one complete case
  these are spec-facing outcome records, not new wire or fixture assets

Each complete case freezes its own case-local assets:

- `CC-001`: HPKE-Auth
- `CC-002`: HPKE-Base, build with `--features essr`
- `CC-003`: Sealed Box, build with `--features nacl`

## Commands

### Generate a complete case package

Default build, `CC-001`:

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-generate -- \
  case --case cc001 --assets-root /tmp/tsp-tv-cc001
```

`CC-002`:

```bash
cargo run -p tsp_test_vectors --features essr --bin tsp-vector-generate -- \
  case --case cc002 --assets-root /tmp/tsp-tv-cc002
```

`CC-003`:

```bash
cargo run -p tsp_test_vectors --features nacl --bin tsp-vector-generate -- \
  case --case cc003 --assets-root /tmp/tsp-tv-cc003
```

### Generate one vector

Example:

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-generate -- \
  vector --case cc001 --vector BV-001 --assets-root /tmp/tsp-tv-single
```

### Generate and immediately print a case report

This is the preferred end-to-end workflow.

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-generate -- \
  case --case cc001 --assets-root /tmp/tsp-tv-cc001 --report
```

The same pattern works for:

- `cc002` with `--features essr`
- `cc003` with `--features nacl`

Example report shape:

```text
CC-001 | vectors=17 fixtures=24 bindings=17 identity_reviews=11
  replay status: verified=12 failed=2 not-attempted=3
  case outputs: status=incomplete positive=6/6 negative(represented)=2/2 negative(actual)=0/2
```

Where:

- `verified` are vectors currently covered by SDK replay/output checks
- `failed` are vectors that were replayed but do not currently satisfy the expected behavior
- `not-attempted` are vectors intentionally kept out of replay, such as `AV-*`

### Validate canonical packages

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-validator -- all
```

Validate one manifest:

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-validator -- \
  case --manifest tsp_test_vectors/assets/artifact-set.cc-001/case-manifest.yaml
```

### Run the dedicated case runner

Report all cases:

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-case-runner -- all
```

Report one case:

```bash
cargo run -p tsp_test_vectors --bin tsp-vector-case-runner -- \
  case --case cc001
```

## Generated Package Shape

Generating one complete case creates a package root like:

```text
/tmp/tsp-tv-cc001/
  artifact-set.cc-001/
    case-manifest.yaml
    vectors/
    bindings/
    fixtures/
    private-fixtures/
  review-set.cc-001/
    vector-reviews/
    binding-reviews/
    fixture-reviews/
```

The generated package can be:

- validated with `tsp-vector-validator`
- reported with `tsp-vector-case-runner`
- consumed by `tsp_sdk` consumer tests

## What the validator checks

The validator does more than file-existence checks. It verifies:

- manifest, vector, fixture, and binding references resolve correctly
- review records exist and are marked `pass`
- reviewed values and binding/fixture alignment are self-consistent
- replay/output-equivalence coverage for the vectors currently under active
  replay verification
- case-level expected outcomes against actual replay-derived outcomes

The case runner consumes the same package and produces a report-oriented view of:

- replay coverage
- current verified/failed/not-attempted surface
- case-level outcome alignment state

It is a package validator and replay/report validator. It is not yet a full
implementation compliance harness for every vector.

## Current replay/output-equivalence scope

The canonical positive replay surface currently includes:

- `BV-001`
- `BV-002`
- `BV-003`
- `BV-004`
- `BV-005`
- `BV-006`
- `BV-007`
- `BV-008`
- `SV-001`
- `SV-002`
- `SV-003`
- `SV-005`

The current negative replay state is:

- `SV-004`
- `SV-006`

These are represented and attempted, but the current SDK still accepts them as
generic messages instead of rejecting them.

The current binding-level-only entries are:

- `AV-001`
- `AV-002`
- `AV-003`

These remain part of package validation and binding-level review, but they are
not currently treated as replayed message outputs.

## SDK consumer boundary

`tsp_sdk` is a consumer of this package. It is not the protocol-truth home.

The current PR boundary remains:

- no SDK protocol-logic changes
- only small helpers, consumer-side tests, and divergence probes

## Tests

Useful test commands:

```bash
cargo test -p tsp_test_vectors
cargo test -p tsp_sdk --test test_vectors
cargo test -p tsp_test_vectors --test generate_report -- --nocapture
cargo test -p tsp_test_vectors --features essr --test generate_report -- --nocapture
cargo test -p tsp_test_vectors --features nacl --test generate_report -- --nocapture
```

The feature-specific `generate_report` tests lock the one-command generation
and reporting workflow for:

- `CC-001`
- `CC-002`
- `CC-003`
