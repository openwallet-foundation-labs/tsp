# Charter: Protocol-First Validation Set for TSP

## 1. Objective

Define a decision-complete validation design that can be implemented as a conformance suite for TSP, with strict traceability from protocol clauses to verdicts.

## 2. Authority Model

- Source of truth: `https://trustoverip.github.io/tswg-tsp-specification/`
- Locked baseline: `v1.0 Experimental Implementor's Draft Rev 2`
- Lock date: `2026-02-25`
- Local codebase role: informative only, never normative

## 3. Scope

In scope:

- Message envelope and payload structure
- CESR framing and selectors used by protocol messages
- Cryptographic profile requirements (algorithm, mode, and signature semantics)
- Control-message semantics and state transitions
- Nested and routed mode semantics
- Transport interface obligations and behavior-level requirements
- Error handling and unsupported message behavior
- Cross-language interoperability vector format

Out of scope:

- Performance benchmarks and latency targets
- Production deployment topology
- UI/CLI usability
- Repository-specific internal architecture

## 4. Normative Strength

Each clause is tagged using protocol normative language:

- `MUST`: hard conformance requirement
- `SHOULD`: recommended requirement
- `MAY`: optional capability
- `INFO`: explanatory statement, not a conformance gate

## 5. Clause and Test Identity

- Clause ID format: `<DOMAIN>-<SUBDOMAIN>-<NNN>`
- Test ID format: `TC-<ClauseID>-<P|N|B>-<NNN>`
- Evidence ID format: `EV-<TestID>-<NNN>`

Domains are defined in `01-spec-clause-catalog.md`.

## 6. Verdict Model

- `PASS`: observed behavior satisfies the assertion
- `FAIL`: observed behavior violates the assertion
- `INCONCLUSIVE`: required evidence missing or corrupted
- `BLOCKED`: test cannot be executed due to external precondition

Rules:

- Any failed `MUST` clause fails conformance for that profile.
- Failed `SHOULD` clauses are reported separately and do not fail hard conformance by default.
- `MAY` clauses are scored as capability claims, not mandatory failures.

## 7. Evidence Model

Each executed test must provide a minimal evidence bundle:

- `packet_hex`: raw encoded input/output bytes
- `decoded_fields`: canonical decoded view used for assertions
- `error_code`: protocol error category or implementation error code
- `trace_ref`: transport/session trace identifier
- `timestamp_utc`: execution timestamp
- `implementation_profile`: tested build profile and feature flags

Optional fields:

- `key_material_ref`: reference only, never secret values
- `interop_peer_ref`: remote implementation identifier for interop tests

## 8. Ambiguity Policy

When specification language is ambiguous:

- Create an issue entry with tag `SPEC_GAP`.
- Do not silently infer behavior from implementation.
- Do not downgrade explicit `MUST` requirements.
- Keep test execution unblocked by marking the affected assertion as:
  - hard assertion if wording is explicit
  - pending assertion if wording is unresolved

## 9. Quality Gates

Design quality gates:

- 100% of normative clauses in baseline are assigned Clause IDs
- 100% of `MUST` and `SHALL` clauses have at least one positive and one negative test design
- Every test entry has a required evidence definition
- Every known implementation deviation is recorded in the gap register

Implementation quality gates (for future execution phase):

- Deterministic verdict for all mandatory tests
- Reproducible vector inputs and expected outputs
- Full traceability from failing test to clause and source anchor
