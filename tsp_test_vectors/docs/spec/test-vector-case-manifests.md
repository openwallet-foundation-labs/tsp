# TSP Test Vector Case Manifests

This document defines the case manifests for the complete cases.

A case manifest is the executable boundary between:

- one complete case
- one case-specific authoritative artifact set
- the shared abstract conformance intent
- the vectors and fixtures that the case explicitly realizes

The manifest does not redefine vector semantics. It declares how one mechanism-specific case realizes part of the vector set.

## Manifest-Level Fields

Each case manifest should define:

- `case_id`
  - stable complete-case identifier
- `case_profile`
  - the case profile name
- `confidentiality_mechanism`
  - the concrete protection mechanism used by the case
- `artifact_set_id`
  - the authoritative artifact-set identifier
- `abstract_intent_ref`
  - the shared vector-model intent referenced by the case
- `applicable_vector_refs`
  - the vector intents explicitly realized by the case
- `applicable_fixture_refs`
  - the fixtures explicitly required by the case
- `artifact_namespace_root`
  - the naming root for case-local artifacts
- `artifact_model`
  - the case-local model for protected outputs and bound values
- `output_boundary`
  - the explicit limits of cross-case comparison
- `realized_slice_refs`
  - the case-local slices already frozen as authoritative assets for that case
- `case_output_ref`
  - the case-level expected-outcome record summarized by the case
- `binding_artifact_refs`
  - case-local binding references such as digests, nonces, route references, and payload references
- `case_invariants`
  - the invariants that must hold for the case

## `CC-001` HPKE-Auth Manifest

```yaml
case_id: CC-001
case_profile: tsp-hpke-auth-complete-case-01
confidentiality_mechanism: HPKE-Auth
artifact_set_id: artifact-set.cc-001
abstract_intent_ref: vector-model.tsp-test-vectors-01
applicable_vector_refs:
  - BV-001
  - BV-002
  - BV-003
  - BV-004
  - BV-005
  - BV-006
  - BV-007
  - BV-008
  - SV-001
  - SV-002
  - SV-003
  - SV-004
  - SV-005
  - SV-006
  - AV-001
  - AV-002
  - AV-003
applicable_fixture_refs:
  - fixture.identity.direct.alice
  - fixture.identity.direct.bob
  - fixture.conversation.direct.request-01
  - fixture.conversation.direct.accept-01
  - fixture.conversation.direct.rfd-01
  - fixture.conversation.negative.digest-mismatch-01
  - fixture.identity.outer.alice
  - fixture.identity.outer.bob
  - fixture.identity.inner.alice-1
  - fixture.identity.inner.bob-1
  - fixture.conversation.nested.request-01
  - fixture.conversation.nested.accept-01
  - fixture.identity.route.alice
  - fixture.identity.route.bob
  - fixture.identity.route.hop-1
  - fixture.identity.route.hop-2
  - fixture.conversation.routed.path-01
  - fixture.conversation.routed.request-01
  - fixture.conversation.routed.accept-01
  - fixture.conversation.direct.message-01
  - fixture.conversation.nested.message-01
  - fixture.conversation.routed.message-01
  - fixture.conversation.negative.no-prior-relationship-01
  - fixture.conversation.negative.nested-without-outer-01
artifact_namespace_root: artifact.cc-001
artifact_model:
  protected_output_family: hpke-auth-case-local-artifacts
  bound_values_family: hpke-auth-case-local-bindings
  cross_case_output_identity: not-required
output_boundary:
  - outputs are authoritative only within artifact-set.cc-001
  - outputs are not assumed to be byte-equivalent to HPKE-Base or Sealed Box outputs
  - comparison is preserved only at the vector-assertion layer
realized_slice_refs:
  - slice.group-a.direct-confidential-control
  - slice.group-b.nested-confidential-control
  - slice.group-c.routed-confidential-control
  - slice.group-d.generic-confidential-messages
  - slice.group-e.negative-semantic-boundaries
case_output_ref: case-output.cc-001
binding_artifact_refs:
  - artifact.cc-001.binding.direct.request-01
  - artifact.cc-001.binding.direct.accept-01
  - artifact.cc-001.binding.direct.message-01
  - artifact.cc-001.binding.direct.rfd-01
  - artifact.cc-001.binding.negative.digest-mismatch-01
  - artifact.cc-001.binding.negative.no-prior-relationship-01
  - artifact.cc-001.binding.negative.nested-without-outer-01
  - artifact.cc-001.binding.nested.request-01
  - artifact.cc-001.binding.nested.accept-01
  - artifact.cc-001.binding.nested.message-01
  - artifact.cc-001.binding.routed.path-01
  - artifact.cc-001.binding.routed.request-01
  - artifact.cc-001.binding.routed.accept-01
  - artifact.cc-001.binding.routed.message-01
  - artifact.cc-001.binding.mechanism.confidential-control-sender-field
  - artifact.cc-001.binding.mechanism.ciphertext-family
  - artifact.cc-001.binding.mechanism.non-confidential-binding
case_invariants:
  - applicable vectors are declared explicitly
  - applicable fixtures are declared explicitly
  - all artifacts belong to artifact-set.cc-001
  - protocol meaning matches the realized vector intents
```

## `CC-002` HPKE-Base Manifest

```yaml
case_id: CC-002
case_profile: tsp-hpke-base-complete-case-01
confidentiality_mechanism: HPKE-Base
artifact_set_id: artifact-set.cc-002
abstract_intent_ref: vector-model.tsp-test-vectors-01
applicable_vector_refs:
  - BV-001
  - BV-002
  - BV-003
  - BV-004
  - BV-005
  - BV-006
  - BV-007
  - BV-008
  - SV-001
  - SV-002
  - SV-003
  - SV-004
  - SV-005
  - SV-006
  - AV-001
  - AV-002
  - AV-003
applicable_fixture_refs:
  - fixture.identity.direct.alice
  - fixture.identity.direct.bob
  - fixture.identity.outer.alice
  - fixture.identity.outer.bob
  - fixture.identity.inner.alice-1
  - fixture.identity.inner.bob-1
  - fixture.identity.route.alice
  - fixture.identity.route.bob
  - fixture.identity.route.hop-1
  - fixture.identity.route.hop-2
  - fixture.conversation.direct.request-01
  - fixture.conversation.direct.accept-01
  - fixture.conversation.direct.rfd-01
  - fixture.conversation.direct.message-01
  - fixture.conversation.nested.request-01
  - fixture.conversation.nested.accept-01
  - fixture.conversation.nested.message-01
  - fixture.conversation.routed.path-01
  - fixture.conversation.routed.request-01
  - fixture.conversation.routed.accept-01
  - fixture.conversation.routed.message-01
  - fixture.conversation.negative.digest-mismatch-01
  - fixture.conversation.negative.no-prior-relationship-01
  - fixture.conversation.negative.nested-without-outer-01
artifact_namespace_root: artifact.cc-002
artifact_model:
  protected_output_family: hpke-base-case-local-artifacts
  bound_values_family: hpke-base-case-local-bindings
  cross_case_output_identity: not-required
output_boundary:
  - outputs are authoritative only within artifact-set.cc-002
  - outputs are not assumed to be byte-equivalent to HPKE-Auth or Sealed Box outputs
  - comparison is preserved only at the vector-assertion layer
realized_slice_refs:
  - slice.group-a.direct-confidential-control
  - slice.group-b.nested-confidential-control
  - slice.group-c.routed-confidential-control
  - slice.group-d.generic-confidential-messages
  - slice.group-e.negative-semantic-boundaries
case_output_ref: case-output.cc-002
binding_artifact_refs:
  - artifact.cc-002.binding.direct.request-01
  - artifact.cc-002.binding.direct.accept-01
  - artifact.cc-002.binding.direct.rfd-01
  - artifact.cc-002.binding.direct.message-01
  - artifact.cc-002.binding.nested.request-01
  - artifact.cc-002.binding.nested.accept-01
  - artifact.cc-002.binding.nested.message-01
  - artifact.cc-002.binding.routed.path-01
  - artifact.cc-002.binding.routed.request-01
  - artifact.cc-002.binding.routed.accept-01
  - artifact.cc-002.binding.routed.message-01
  - artifact.cc-002.binding.negative.digest-mismatch-01
  - artifact.cc-002.binding.negative.no-prior-relationship-01
  - artifact.cc-002.binding.negative.nested-without-outer-01
  - artifact.cc-002.binding.mechanism.confidential-control-sender-field
  - artifact.cc-002.binding.mechanism.ciphertext-family
  - artifact.cc-002.binding.mechanism.non-confidential-binding
case_invariants:
  - applicable vectors are declared explicitly
  - applicable fixtures are declared explicitly
  - all artifacts belong to artifact-set.cc-002
  - protocol meaning matches the realized vector intents
```

## `CC-003` Sealed Box Manifest

```yaml
case_id: CC-003
case_profile: tsp-sealed-box-complete-case-01
confidentiality_mechanism: Sealed Box
artifact_set_id: artifact-set.cc-003
abstract_intent_ref: vector-model.tsp-test-vectors-01
applicable_vector_refs:
  - BV-001
  - BV-002
  - BV-003
  - BV-004
  - BV-005
  - BV-006
  - BV-007
  - BV-008
  - SV-001
  - SV-002
  - SV-003
  - SV-004
  - SV-005
  - SV-006
  - AV-001
  - AV-002
  - AV-003
applicable_fixture_refs:
  - fixture.identity.direct.alice
  - fixture.identity.direct.bob
  - fixture.identity.outer.alice
  - fixture.identity.outer.bob
  - fixture.identity.inner.alice-1
  - fixture.identity.inner.bob-1
  - fixture.identity.route.alice
  - fixture.identity.route.bob
  - fixture.identity.route.hop-1
  - fixture.identity.route.hop-2
  - fixture.conversation.direct.request-01
  - fixture.conversation.direct.accept-01
  - fixture.conversation.direct.rfd-01
  - fixture.conversation.nested.request-01
  - fixture.conversation.nested.accept-01
  - fixture.conversation.routed.path-01
  - fixture.conversation.routed.request-01
  - fixture.conversation.routed.accept-01
  - fixture.conversation.direct.message-01
  - fixture.conversation.nested.message-01
  - fixture.conversation.routed.message-01
  - fixture.conversation.negative.no-prior-relationship-01
  - fixture.conversation.negative.digest-mismatch-01
  - fixture.conversation.negative.nested-without-outer-01
artifact_namespace_root: artifact.cc-003
artifact_model:
  protected_output_family: sealed-box-case-local-artifacts
  bound_values_family: sealed-box-case-local-bindings
  cross_case_output_identity: not-required
output_boundary:
  - outputs are authoritative only within artifact-set.cc-003
  - outputs are not assumed to be byte-equivalent to HPKE-Auth or HPKE-Base outputs
  - comparison is preserved only at the vector-assertion layer
realized_slice_refs:
  - slice.group-a.direct-confidential-control
  - slice.group-b.nested-confidential-control
  - slice.group-c.routed-confidential-control
  - slice.group-d.generic-confidential-messages
  - slice.group-e.negative-semantic-boundaries
case_output_ref: case-output.cc-003
binding_artifact_refs:
  - artifact.cc-003.binding.direct.request-01
  - artifact.cc-003.binding.direct.accept-01
  - artifact.cc-003.binding.direct.rfd-01
  - artifact.cc-003.binding.negative.digest-mismatch-01
  - artifact.cc-003.binding.nested.request-01
  - artifact.cc-003.binding.nested.accept-01
  - artifact.cc-003.binding.routed.path-01
  - artifact.cc-003.binding.routed.request-01
  - artifact.cc-003.binding.routed.accept-01
  - artifact.cc-003.binding.direct.message-01
  - artifact.cc-003.binding.nested.message-01
  - artifact.cc-003.binding.routed.message-01
  - artifact.cc-003.binding.negative.no-prior-relationship-01
  - artifact.cc-003.binding.negative.nested-without-outer-01
  - artifact.cc-003.binding.mechanism.confidential-control-sender-field
  - artifact.cc-003.binding.mechanism.ciphertext-family
  - artifact.cc-003.binding.mechanism.non-confidential-binding
case_invariants:
  - applicable vectors are declared explicitly
  - applicable fixtures are declared explicitly
  - all artifacts belong to artifact-set.cc-003
  - protocol meaning matches the realized vector intents
```

## Manifest Invariants

- all case manifests should reference the same `abstract_intent_ref`
- the `artifact_set_id` must differ across cases
- each manifest should declare its own `applicable_vector_refs`
- each manifest should declare its own `applicable_fixture_refs`
- each manifest should use only case-local artifact references
- the field model is exercised by all three complete cases
- no manifest should imply cross-case byte identity or output identity
