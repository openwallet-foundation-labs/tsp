# TSP Test Vector Fixtures

This document defines the `fixture-only` entries referenced by the TSP test-vector set. These fixtures provide stable identity and conversation references for vectors. They do not define identity creation workflows, wallet layout, transport policy, or local SDK object models.

Fixture IDs are shared abstract references. Case-local fixture applicability is declared by the corresponding case manifest. `CC-001`, `CC-002`, and `CC-003` realize the full shared fixture set.

Authoritative fixture artifacts and bound values remain typed placeholders until the corresponding case-local asset set is frozen.

## Direct Scope

### `fixture.identity.direct.alice`

```yaml
id: fixture.identity.direct.alice
title: Direct Identity Fixture Alice
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Direct Relationship Forming
preconditions:
  - this fixture is used only as reviewed identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the direct-scope alice participant used by direct relationship vectors
  state_predicates:
    - this fixture alone does not establish any relationship state
fixture_definition:
  fixture_kind: identity
  scope: direct
  alias: alice
  identifier: "did:example:alice"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: direct_endpoint
  used_by_vectors:
    - BV-001
    - BV-002
    - BV-003
    - SV-001
    - SV-004
    - SV-005
not_compared:
  - SDK-local storage layout
  - non-normative metadata fields
```

### `fixture.identity.direct.bob`

```yaml
id: fixture.identity.direct.bob
title: Direct Identity Fixture Bob
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Direct Relationship Forming
preconditions:
  - this fixture is used only as reviewed identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the direct-scope bob participant used by direct relationship vectors
  state_predicates:
    - this fixture alone does not establish any relationship state
fixture_definition:
  fixture_kind: identity
  scope: direct
  alias: bob
  identifier: "did:example:bob"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: direct_endpoint
  used_by_vectors:
    - BV-001
    - BV-002
    - BV-003
    - SV-001
    - SV-004
    - SV-005
not_compared:
  - SDK-local storage layout
  - non-normative metadata fields
```

### `fixture.conversation.direct.request-01`

```yaml
id: fixture.conversation.direct.request-01
title: Direct Request Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - related reviewed identity fixtures are available
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed direct relationship request sample
  state_predicates:
    - vectors referencing this fixture must bind request semantics to this fixture's reviewed digest material
fixture_definition:
  fixture_kind: conversation
  scope: direct
  scenario: request
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  binding_material:
    request_digest: "<TBD hex request digest>"
    nonce: "<TBD hex request nonce>"
    thread_binding: "<TBD fixed thread binding or none>"
  used_by_vectors:
    - BV-001
    - BV-002
    - SV-005
not_compared:
  - SDK-generated local correlation IDs
  - storage-layer thread bookkeeping
```

### `fixture.conversation.direct.accept-01`

```yaml
id: fixture.conversation.direct.accept-01
title: Direct Accept Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - the reviewed direct request fixture already exists
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed positive direct accept sample
  state_predicates:
    - vectors referencing this fixture must bind the accept to the reviewed direct request fixture
fixture_definition:
  fixture_kind: conversation
  scope: direct
  scenario: accept
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  related_conversation_fixtures:
    - fixture.conversation.direct.request-01
  binding_material:
    request_digest: "<TBD hex request digest>"
    reply_digest: "<TBD hex reply digest>"
  used_by_vectors:
    - BV-002
not_compared:
  - SDK-local acceptance bookkeeping
  - transport delivery metadata
```

### `fixture.conversation.direct.rfd-01`

```yaml
id: fixture.conversation.direct.rfd-01
title: Direct RFD Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Relationship Forming Decline or Cancel
preconditions:
  - reviewed direct identity fixtures already exist
  - the reviewed context identifies the decline-or-cancel interpretation boundary
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed direct decline-or-cancel sample
  state_predicates:
    - vectors referencing this fixture must interpret the reviewed digest under the stated decline-or-cancel context
fixture_definition:
  fixture_kind: conversation
  scope: direct
  scenario: rfd
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  binding_material:
    digest: "<TBD hex reviewed decline-or-cancel digest>"
    reviewed_context: "<TBD decline-or-cancel interpretation reference>"
  used_by_vectors:
    - BV-003
not_compared:
  - SDK-local cleanup policy
  - local relationship bookkeeping
```

### `fixture.conversation.direct.message-01`

```yaml
id: fixture.conversation.direct.message-01
title: Direct Message Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Higher Layer Payload
preconditions:
  - a reviewed direct relationship context already exists
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the reviewed direct confidential generic-message context
  state_predicates:
    - vectors referencing this fixture must preserve the reviewed sender, receiver, and higher-layer payload semantics
fixture_definition:
  fixture_kind: conversation
  scope: direct
  scenario: message
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  binding_material:
    relationship_context_ref: "<TBD reviewed direct relationship reference>"
    payload_semantics_ref: "<TBD reviewed payload semantics reference>"
  used_by_vectors:
    - SV-001
not_compared:
  - regenerated confidential bytes
  - SDK-specific delivery buffering
```

## Negative Scope

### `fixture.conversation.negative.digest-mismatch-01`

```yaml
id: fixture.conversation.negative.digest-mismatch-01
title: Negative Digest Mismatch Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - the reviewed direct request fixture already exists
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml negative conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines an attempted direct accept with non-matching digest binding
  state_predicates:
    - vectors referencing this fixture must reject relationship establishment under the reviewed mismatch condition
fixture_definition:
  fixture_kind: conversation
  scope: negative
  scenario: digest-mismatch
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  related_conversation_fixtures:
    - fixture.conversation.direct.request-01
  binding_material:
    expected_request_digest: "<TBD hex expected request digest>"
    mismatching_request_digest: "<TBD hex mismatching request digest>"
  used_by_vectors:
    - SV-005
not_compared:
  - exact error wording
  - local cleanup policy after rejection
```

### `fixture.conversation.negative.no-prior-relationship-01`

```yaml
id: fixture.conversation.negative.no-prior-relationship-01
title: Negative No Prior Relationship Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Mode TSP Message
preconditions:
  - reviewed direct identity fixtures already exist
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml negative conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines a generic-message case where no prior relationship authorizes delivery
  state_predicates:
    - vectors referencing this fixture must reject or drop application delivery under the reviewed preconditions
fixture_definition:
  fixture_kind: conversation
  scope: negative
  scenario: no-prior-relationship
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
  binding_material:
    authorization_state: no-prior-relationship
  used_by_vectors:
    - SV-004
not_compared:
  - exact rejection wording
  - local telemetry or logging side effects
```

## Nested Scope

### `fixture.identity.outer.alice`

```yaml
id: fixture.identity.outer.alice
title: Outer Identity Fixture Alice
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Nested Relationship Forming
preconditions:
  - this fixture is used only as reviewed outer-relationship identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the outer-scope alice participant used by nested vectors
  state_predicates:
    - this fixture alone does not establish nested or direct relationship state
fixture_definition:
  fixture_kind: identity
  scope: outer
  alias: alice
  identifier: "did:example:alice"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: outer_endpoint
  used_by_vectors:
    - BV-004
    - BV-005
    - SV-002
    - SV-006
not_compared:
  - SDK-local storage layout
  - non-normative metadata fields
```

### `fixture.identity.outer.bob`

```yaml
id: fixture.identity.outer.bob
title: Outer Identity Fixture Bob
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Nested Relationship Forming
preconditions:
  - this fixture is used only as reviewed outer-relationship identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the outer-scope bob participant used by nested vectors
  state_predicates:
    - this fixture alone does not establish nested or direct relationship state
fixture_definition:
  fixture_kind: identity
  scope: outer
  alias: bob
  identifier: "did:example:bob"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: outer_endpoint
  used_by_vectors:
    - BV-004
    - BV-005
    - SV-002
    - SV-006
not_compared:
  - SDK-local storage layout
  - non-normative metadata fields
```

### `fixture.identity.inner.alice-1`

```yaml
id: fixture.identity.inner.alice-1
title: Inner Identity Fixture Alice-1
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Nested Relationship Forming
preconditions:
  - this fixture is used only as reviewed inner-relationship identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the inner-scope alice participant used by nested vectors
  state_predicates:
    - this fixture alone does not establish any inner relationship state
fixture_definition:
  fixture_kind: identity
  scope: inner
  alias: alice-1
  identifier: "did:example:alice-1"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: nested_inner_endpoint
  used_by_vectors:
    - BV-004
    - BV-005
    - SV-002
    - SV-006
not_compared:
  - SDK-local parent linkage layout
  - non-normative metadata fields
```

### `fixture.identity.inner.bob-1`

```yaml
id: fixture.identity.inner.bob-1
title: Inner Identity Fixture Bob-1
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Nested Relationship Forming
preconditions:
  - this fixture is used only as reviewed inner-relationship identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the inner-scope bob participant used by nested vectors
  state_predicates:
    - this fixture alone does not establish any inner relationship state
fixture_definition:
  fixture_kind: identity
  scope: inner
  alias: bob-1
  identifier: "did:example:bob-1"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: nested_inner_endpoint
  used_by_vectors:
    - BV-005
    - SV-002
    - SV-006
not_compared:
  - SDK-local parent linkage layout
  - non-normative metadata fields
```

### `fixture.conversation.nested.request-01`

```yaml
id: fixture.conversation.nested.request-01
title: Nested Request Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Nested Relationship Forming
  - Payload Nesting
preconditions:
  - reviewed outer and inner identity fixtures already exist
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml nested conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed nested relationship request sample
  state_predicates:
    - vectors referencing this fixture must treat nested request semantics as coupled to the reviewed outer context
fixture_definition:
  fixture_kind: conversation
  scope: nested
  scenario: request
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
  binding_material:
    request_digest: "<TBD hex nested request digest>"
    nonce: "<TBD hex nested request nonce>"
    outer_context_ref: "<TBD reviewed outer relationship reference>"
  used_by_vectors:
    - BV-004
    - BV-005
not_compared:
  - SDK-specific nested-thread bookkeeping
  - storage-layer parent linkage
```

### `fixture.conversation.nested.accept-01`

```yaml
id: fixture.conversation.nested.accept-01
title: Nested Accept Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Nested Relationship Forming
  - Payload Nesting
preconditions:
  - the reviewed nested request fixture already exists
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml nested conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed positive nested accept sample
  state_predicates:
    - vectors referencing this fixture must bind the nested accept to the reviewed nested request fixture
fixture_definition:
  fixture_kind: conversation
  scope: nested
  scenario: accept
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
    - fixture.identity.inner.bob-1
  related_conversation_fixtures:
    - fixture.conversation.nested.request-01
  binding_material:
    request_digest: "<TBD hex nested request digest>"
    reply_digest: "<TBD hex nested reply digest>"
    outer_context_ref: "<TBD reviewed outer relationship reference>"
  used_by_vectors:
    - BV-005
not_compared:
  - SDK-specific nested accept bookkeeping
  - transport delivery metadata
```

### `fixture.conversation.nested.message-01`

```yaml
id: fixture.conversation.nested.message-01
title: Nested Message Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Mode Nested TSP Message
  - Payload Nesting
preconditions:
  - reviewed outer and inner relationship fixtures already exist
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml nested message fixture artifact>"
expected:
  semantic_assertions:
    - defines the reviewed nested confidential-message context
  state_predicates:
    - vectors referencing this fixture must preserve inner semantics only within the reviewed outer context
fixture_definition:
  fixture_kind: conversation
  scope: nested
  scenario: message
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
    - fixture.identity.inner.bob-1
  related_conversation_fixtures:
    - fixture.conversation.nested.request-01
    - fixture.conversation.nested.accept-01
  binding_material:
    outer_context_ref: "<TBD reviewed outer relationship reference>"
    inner_context_ref: "<TBD reviewed inner relationship reference>"
    payload_semantics_ref: "<TBD reviewed payload semantics reference>"
  used_by_vectors:
    - SV-002
not_compared:
  - SDK-specific buffering or streaming behavior
  - regenerated nested confidential bytes
```

### `fixture.conversation.negative.nested-without-outer-01`

```yaml
id: fixture.conversation.negative.nested-without-outer-01
title: Negative Nested Without Outer Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Payload Nesting
  - Nested Relationships
preconditions:
  - reviewed inner nested identity fixtures already exist
  - the required coupled outer relationship context is intentionally absent
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml negative conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines a reviewed nested-traffic case without the required coupled outer context
  state_predicates:
    - vectors referencing this fixture must reject or drop the reviewed nested traffic under the missing-outer-context condition
fixture_definition:
  fixture_kind: conversation
  scope: negative
  scenario: nested-without-outer
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
    - fixture.identity.inner.bob-1
  binding_material:
    missing_outer_context: true
    inner_context_ref: "<TBD reviewed nested inner-context reference>"
  used_by_vectors:
    - SV-006
not_compared:
  - exact rejection wording
  - local cleanup behavior
```

## Routed Scope

### `fixture.identity.route.alice`

```yaml
id: fixture.identity.route.alice
title: Routed Identity Fixture Alice
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Routed Mode Message
preconditions:
  - this fixture is used only as reviewed routed-scope identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the routed-scope alice participant used by routed vectors
  state_predicates:
    - this fixture alone does not establish routed path semantics
fixture_definition:
  fixture_kind: identity
  scope: route
  alias: alice
  identifier: "did:example:alice"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: routed_endpoint
  used_by_vectors:
    - BV-006
    - BV-007
    - BV-008
    - SV-003
not_compared:
  - SDK-local storage layout
  - non-normative metadata fields
```

### `fixture.identity.route.bob`

```yaml
id: fixture.identity.route.bob
title: Routed Identity Fixture Bob
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Routed Mode Message
preconditions:
  - this fixture is used only as reviewed routed-scope identity material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the routed-scope bob participant used by routed vectors
  state_predicates:
    - this fixture alone does not establish routed path semantics
fixture_definition:
  fixture_kind: identity
  scope: route
  alias: bob
  identifier: "did:example:bob"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: routed_endpoint
  used_by_vectors:
    - BV-006
    - BV-007
    - BV-008
    - SV-003
not_compared:
  - SDK-local storage layout
  - non-normative metadata fields
```

### `fixture.identity.route.hop-1`

```yaml
id: fixture.identity.route.hop-1
title: Routed Identity Fixture Hop-1
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Routed Mode Message
preconditions:
  - this fixture is used only as reviewed routed intermediary material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the first intermediary hop used by routed vectors
  state_predicates:
    - this fixture alone does not establish final message semantics
fixture_definition:
  fixture_kind: identity
  scope: route
  alias: hop-1
  identifier: "did:example:hop-1"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: intermediary_hop
  used_by_vectors:
    - BV-006
    - BV-007
    - BV-008
    - SV-003
not_compared:
  - intermediary-local caches
  - non-normative metadata fields
```

### `fixture.identity.route.hop-2`

```yaml
id: fixture.identity.route.hop-2
title: Routed Identity Fixture Hop-2
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Verified Identifiers
  - Routed Mode Message
preconditions:
  - this fixture is used only as reviewed routed intermediary material
input:
  artifact_format: json
  wire_artifact: "<TBD json identity fixture artifact>"
expected:
  semantic_assertions:
    - identifies the second intermediary hop or next hop used by routed vectors
  state_predicates:
    - this fixture alone does not establish final message semantics
fixture_definition:
  fixture_kind: identity
  scope: route
  alias: hop-2
  identifier: "did:example:hop-2"
  public_material:
    verification_key: "<TBD json public verification key material>"
    encryption_key: "<TBD json public encryption key material>"
  private_material_ref: "<TBD reviewed private-material reference or none>"
  transport_or_route_role: intermediary_hop
  used_by_vectors:
    - BV-006
    - BV-007
    - BV-008
    - SV-003
not_compared:
  - intermediary-local caches
  - non-normative metadata fields
```

### `fixture.conversation.routed.path-01`

```yaml
id: fixture.conversation.routed.path-01
title: Routed Path Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
preconditions:
  - reviewed routed identity fixtures already exist
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml routed conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the reviewed hop-local routed path context
  state_predicates:
    - vectors referencing this fixture must expose only hop-local forwarding information at the intermediary
fixture_definition:
  fixture_kind: conversation
  scope: routed
  scenario: path
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.route.alice
    - fixture.identity.route.hop-1
    - fixture.identity.route.hop-2
    - fixture.identity.route.bob
  binding_material:
    next_hop_vid: "did:example:hop-2"
    remaining_route_ref: "<TBD json remaining-route reference>"
    opaque_payload_ref: "<TBD base64 opaque-payload reference>"
  used_by_vectors:
    - BV-006
    - SV-003
not_compared:
  - onward forwarding bytes
  - intermediary-local queueing or retry behavior
```

### `fixture.conversation.routed.request-01`

```yaml
id: fixture.conversation.routed.request-01
title: Routed Request Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
  - Direct Relationship Forming
preconditions:
  - reviewed routed identity fixtures already exist
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml routed conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed routed relationship request sample
  state_predicates:
    - vectors referencing this fixture must preserve final control semantics after routed unwrapping
fixture_definition:
  fixture_kind: conversation
  scope: routed
  scenario: request
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.route.alice
    - fixture.identity.route.hop-1
    - fixture.identity.route.hop-2
    - fixture.identity.route.bob
  binding_material:
    request_digest: "<TBD hex routed request digest>"
    nonce: "<TBD hex routed request nonce>"
    path_context_ref: "<TBD reviewed routed path reference>"
  used_by_vectors:
    - BV-007
not_compared:
  - intermediary implementation details
  - regenerated routed wrapper bytes
```

### `fixture.conversation.routed.accept-01`

```yaml
id: fixture.conversation.routed.accept-01
title: Routed Accept Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
  - Direct Relationship Forming
preconditions:
  - the reviewed routed request fixture already exists
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml routed conversation fixture artifact>"
expected:
  semantic_assertions:
    - defines the binding material for the reviewed routed relationship accept sample
  state_predicates:
    - vectors referencing this fixture must preserve final accept semantics after routed unwrapping
fixture_definition:
  fixture_kind: conversation
  scope: routed
  scenario: accept
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.route.alice
    - fixture.identity.route.hop-1
    - fixture.identity.route.hop-2
    - fixture.identity.route.bob
  related_conversation_fixtures:
    - fixture.conversation.routed.request-01
  binding_material:
    request_digest: "<TBD hex routed request digest>"
    reply_digest: "<TBD hex routed reply digest>"
    path_context_ref: "<TBD reviewed routed path reference>"
  used_by_vectors:
    - BV-008
not_compared:
  - intermediary implementation details
  - regenerated routed wrapper bytes
```

### `fixture.conversation.routed.message-01`

```yaml
id: fixture.conversation.routed.message-01
title: Routed Message Conversation Fixture 01
classification: fixture-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
  - Higher Layer Payload
preconditions:
  - the reviewed routed path fixture already exists
  - a reviewed authorized routed relationship context already exists
input:
  artifact_format: yaml
  wire_artifact: "<TBD yaml routed message fixture artifact>"
expected:
  semantic_assertions:
    - defines the reviewed routed confidential-message context
  state_predicates:
    - vectors referencing this fixture must preserve hop-local routing visibility and reviewed final payload semantics
fixture_definition:
  fixture_kind: conversation
  scope: routed
  scenario: message
  sequence: "01"
  related_identity_fixtures:
    - fixture.identity.route.alice
    - fixture.identity.route.hop-1
    - fixture.identity.route.hop-2
    - fixture.identity.route.bob
  related_conversation_fixtures:
    - fixture.conversation.routed.path-01
  binding_material:
    path_context_ref: "<TBD reviewed routed path reference>"
    payload_semantics_ref: "<TBD reviewed payload semantics reference>"
  used_by_vectors:
    - SV-003
not_compared:
  - regenerated confidential bytes
  - intermediary forwarding implementation details
```
