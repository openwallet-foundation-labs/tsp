# TSP Protocol Validation Design Package

This directory defines the documentation-first validation design for TSP protocol conformance.

The package is intentionally protocol-first:

- The protocol specification is the authority.
- Repository behavior is observational input only.
- A passing implementation must satisfy protocol-derived assertions, not implementation-derived expectations.

## Baseline

- Baseline specification: `v1.0 Experimental Implementor's Draft Rev 2`
- Baseline URL: `https://trustoverip.github.io/tswg-tsp-specification/`
- Baseline lock date: `2026-02-25`

## Contents

- `00-charter.md`: scope, goals, conformance model, evidence model
- `01-spec-clause-catalog.md`: clause IDs and normalized protocol requirements
- `02-conformance-matrix.md`: clause-to-test mapping and required evidence
- `03-test-taxonomy.md`: test families, coverage levels, and execution strategy
- `04-test-case-template.md`: standard test-case and test-vector templates
- `05-known-gaps-vs-current-impl.md`: observed protocol-vs-repo gap register
- `06-versioning-and-diff-policy.md`: baseline maintenance and spec diff process

## How To Use

1. Start from `01-spec-clause-catalog.md` to identify the clause ID.
2. Find its mapped test entry in `02-conformance-matrix.md`.
3. Instantiate the test with `04-test-case-template.md`.
4. Collect evidence as defined in `00-charter.md`.
5. Track uncertain semantics using `SPEC_GAP` as defined in the charter.

## Non-Goals For This Package

- No SDK/API changes.
- No executable test implementation.
- No conformance verdict for any current implementation.
