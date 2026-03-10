# TSP Test Vector Schema

This document defines a minimal schema for the TSP test-vector set. The schema supports:

- `byte-exact` vectors
- `semantic-only` vectors
- reusable identity and conversation fixtures

This schema is used in:

- [test-vector-instances.md](./test-vector-instances.md)
- [test-vector-fixtures.md](./test-vector-fixtures.md)

## Design Goals

- The schema should express only the minimum normative facts required by the spec, not SDK-internal storage shapes.
- The schema should support `decode/open`, `hop unwrap`, `state predicate`, and `expected rejection` within one coherent structure.
- The schema should make authoritative inputs explicit and should separately declare what is out of scope for comparison.

## Top-Level Fields

- `id`
  - stable vector ID such as `BV-001`
- `title`
  - short human-readable title
- `classification`
  - one of `byte-exact`, `semantic-only`, or `fixture-only`
- `profile`
  - the interoperability profile name targeted by the vector
- `spec_anchors`
  - one or more normative anchor names taken from the spec, not from SDK terminology
- `preconditions`
  - the minimum conditions that must already hold before the vector is applicable
- `input`
  - the authoritative input sample
- `expected`
  - the normatively required output, semantics, or rejection
- `not_compared`
  - explicit declarations of what does not participate in conformance judgment
- `fixture_definition`
  - used only by `fixture-only` entries to carry the structured fixture definition itself
- `notes`
  - non-normative review or generation notes

## Suggested `input` Subfields

- `artifact_format`
  - for example `hex`, `base64`, `json`, `yaml`, or `text`
- `wire_artifact`
  - the raw authoritative input sample
  - for confidential payloads, this field models the single ciphertext field on the wire, not an additional outer payload wrapper
- `fixture_refs`
  - identity fixture IDs or conversation fixture IDs required by the vector
- `runtime_context`
  - current hop, intended receiver, outer relationship context, and similar runtime conditions

## Suggested `expected` Subfields

- `decode_fields`
  - used when exact field equality is required, for example `Digest`, `Nonce`, or `VID_a`
- `semantic_assertions`
  - used when semantic agreement is required, for example “interpreted as bidirectional accept”
- `state_predicates`
  - minimum required state predicates, for example “must not establish a relationship”
- `forwarding_view`
  - used for routed hop cases, for example `next_hop_vid`, `remaining_route_ref`, and `opaque_payload_ref`
- `rejection`
  - used for negative vectors, for example `must_reject`, `must_reject_or_drop`, or `must_not_upgrade`

## Recommended Minimal YAML Shape

```yaml
id: BV-001
title: Direct RFI Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - receiver_vid is resolved
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 authoritative wire artifact>"
  fixture_refs:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  runtime_context:
    receiver_vid_expected: did:example:bob
expected:
  decode_fields:
    message_family: control
    control_type: TSP_RFI
    sender_vid: did:example:alice
    receiver_vid: did:example:bob
    digest: "<TBD hex request digest>"
  semantic_assertions:
    - interpreted as direct relationship request from alice to bob
  state_predicates:
    - accept must bind to the same digest
not_compared:
  - regenerated ciphertext bytes
notes:
  - authoritative sample is stored as inbound wire artifact only
```

## Minimum Supporting Fixtures

- identity fixture
  - `id`
  - `scope`
  - `identifier`
  - `public_material`
  - `private_material_ref`, if private material is retained for local sample generation only

- conversation fixture
  - `id`
  - `scope`
  - `related_identity_fixtures`
  - `binding_material`
  - `used_by_vectors`

## Fixture Naming Convention

- identity fixtures should follow:
  - `fixture.identity.<scope>.<alias>`
  - for example `fixture.identity.direct.alice`
  - for example `fixture.identity.outer.bob`
  - for example `fixture.identity.route.hop-1`
- conversation fixtures should follow:
  - `fixture.conversation.<scope>.<scenario>-<nn>`
  - for example `fixture.conversation.direct.request-01`
  - for example `fixture.conversation.nested.accept-01`
  - for example `fixture.conversation.negative.digest-mismatch-01`

## `runtime_context` Naming Convention

- for final-recipient contexts, prefer `sender_vid_expected` and `receiver_vid_expected`
- for nested contexts, prefer `outer_*` and `inner_*` prefixes, for example `outer_receiver_vid_expected`
- for intermediary contexts, prefer `current_hop_vid`
- only omit the `_expected` suffix when the field refers to the local runtime role context rather than a decoded expected value

## Constraints

- The set should use one shared schema.
- Creation should appear only as `fixture-only` material for now, not as formal conformance vectors.
- If the profile changes later, a new profile name should be introduced rather than silently rewriting existing samples.
