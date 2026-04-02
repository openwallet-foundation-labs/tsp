# Test Taxonomy and Coverage Levels

This document defines the test family model for converting clause requirements into executable validation sets.

## Family Definitions

1. `Identifier`
- VID format support (DID/URN)
- Uniqueness and metadata obligations
- Inner-identifier generation and correlation constraints

2. `MessageStructure`
- Envelope field presence and ordering
- Confidential vs non-confidential message shape
- Required signature and ciphertext groups

3. `ControlState`
- Control payload field validation
- Thread/digest linkage checks
- Relationship lifecycle transitions (request/accept/cancel/referral)

4. `NestedRouted`
- Nested message encapsulation invariants
- Routed message hop/route semantics
- Intermediary forwarding behavior and visibility boundaries

5. `Crypto`
- Algorithm profile support declarations
- Crypto mode compatibility
- Signature coverage and recipient binding

6. `Encoding`
- CESR framing, selectors, and length/group boundaries
- Unknown selector and malformed payload rejection
- Multi-signature parsing tolerance

7. `Transport`
- Send/receive contract behavior
- Endpoint binding requirements for receiving identities
- Binding-level error signaling behavior

8. `ErrorHandling`
- Unsupported message type behavior
- Parsing and validation failure handling
- Fail-closed guarantees on protected payload violations

## Case Types

- `P` (Positive): valid input and expected accept behavior
- `N` (Negative): invalid input and expected reject behavior
- `B` (Boundary): limits, empty values, repeated values, max-size, ordering

## Coverage Profiles

`TSP-REV2-CORE`:

- Includes all `P0` rows in `02-conformance-matrix.md`
- Mandatory for baseline conformance claim

`TSP-REV2-EXTENDED`:

- Includes all `P0` and `P1` rows
- Adds optional/capability profile checks

`TSP-REV2-FULL`:

- Includes `P0`, `P1`, and `P2`
- Includes stress and interop variants for each mandatory clause

## Execution Layers

Layer 1: Deterministic parser and structure validation

- No network dependencies
- Canonical encoded vectors only

Layer 2: Cryptographic and control-message semantic validation

- Requires key material and deterministic vector fixtures
- Includes tampering and mismatch cases

Layer 3: Transport and routing behavior validation

- Requires endpoint setup and trace collection
- Includes intermediary behavior checks

Layer 4: Interoperability validation

- Cross-language or cross-implementation vector replay
- Strict evidence capture and result normalization

## Priority Rules

1. Start with Layer 1 and Layer 2 for `P0` clauses.
2. Move to Layer 3 only after deterministic evidence formats are stable.
3. Layer 4 requires frozen vectors and versioned expected outcomes.

## Exit Criteria Per Family

- `Identifier`: all VID-format and metadata clauses mapped with `P/N/B`
- `MessageStructure`: all mandatory envelope/group rules have deterministic rejects
- `ControlState`: all control payload types include mismatch and replay negatives
- `NestedRouted`: all route and nested invariants include intermediary-focused negatives
- `Crypto`: each required profile has a valid and invalid fixture set
- `Encoding`: malformed CESR classes covered with fail-closed assertions
- `Transport`: send/receive contracts have endpoint and callback failure tests
- `ErrorHandling`: unsupported and malformed behavior never yields partial acceptance
