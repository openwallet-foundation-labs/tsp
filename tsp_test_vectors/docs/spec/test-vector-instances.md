# TSP Test Vector Instances

This document defines the shared abstract vector instances used by the TSP test-vector set.

Case-local applicability is declared by the corresponding case manifest.

The explicit realized slices across `CC-001`, `CC-002`, and `CC-003` are the confidential-control slices and the generic confidential-message slice:

- `BV-001`
- `BV-002`
- `BV-003`
- `SV-005`
- `AV-001`
- `AV-002`
- `AV-003`
- `BV-004`
- `BV-005`
- `BV-006`
- `BV-007`
- `BV-008`
- `SV-001`
- `SV-002`
- `SV-003`

In this shared abstract catalog, `wire_artifact` values and bound artifact fields remain typed placeholders.
Authoritative values are frozen only in the corresponding case-local vector assets.

## Vector Catalog

| Vector | Classification | Title |
| --- | --- | --- |
| `BV-001` | `byte-exact` | Direct RFI Decode |
| `BV-002` | `byte-exact` | Direct RFA Decode |
| `BV-003` | `byte-exact` | Direct RFD Decode |
| `BV-004` | `byte-exact` | Nested RFI Decode |
| `BV-005` | `byte-exact` | Nested RFA Decode |
| `BV-006` | `byte-exact` | Routed Hop Unwrap |
| `BV-007` | `byte-exact` | Routed RFI Final Decode |
| `BV-008` | `byte-exact` | Routed RFA Final Decode |
| `AV-002` | `byte-exact` | Ciphertext Encoding Family Decode |
| `SV-001` | `semantic-only` | Direct Confidential Generic Message Open |
| `SV-002` | `semantic-only` | Nested Confidential Generic Message Open |
| `SV-003` | `semantic-only` | Routed Confidential End-to-End Open |
| `SV-004` | `semantic-only` | Generic Message Without Prior Relationship |
| `SV-005` | `semantic-only` | RFA Digest Mismatch |
| `SV-006` | `semantic-only` | Nested Message Without Coupled Outer Relationship |
| `AV-001` | `semantic-only` | Confidential Control Sender-Field Presence |
| `AV-003` | `semantic-only` | Non-Confidential-Field Binding Review |

## Byte-Exact Vectors

### `BV-001` Direct RFI Decode

```yaml
id: BV-001
title: Direct RFI Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - receiver_vid is resolved
  - sender_vid is resolved
  - message is processed by the final intended receiver
  - no transport-specific behavior is required for interpretation
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 direct-rfi wire artifact>"
  fixture_refs:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
    - fixture.conversation.direct.request-01
  runtime_context:
    role: final_recipient
    receiver_vid_expected: "did:example:bob"
    sender_vid_expected: "did:example:alice"
expected:
  decode_fields:
    message_family: control
    control_type: TSP_RFI
    sender_vid: "did:example:alice"
    receiver_vid: "did:example:bob"
    digest: "<TBD hex request digest>"
    nonce: "<TBD hex request nonce>"
  semantic_assertions:
    - interpreted as a direct relationship-forming request from alice to bob
    - the request establishes pending relationship-forming semantics only
  state_predicates:
    - any future accept must bind to the same digest
    - the request alone must not be interpreted as an already established bidirectional relationship
not_compared:
  - regenerated ciphertext bytes
  - SDK-internal relationship storage layout
```

Relevant spec sections:

- `§7.1.2 Direct Relationship Forming`
- `§9.2.12.1 TSP_RFI`

### `BV-002` Direct RFA Decode

```yaml
id: BV-002
title: Direct RFA Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - receiver_vid is resolved
  - sender_vid is resolved
  - a reviewed direct relationship request digest is already fixed
  - message is processed by the final intended receiver
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 direct-rfa wire artifact>"
  fixture_refs:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
    - fixture.conversation.direct.request-01
    - fixture.conversation.direct.accept-01
  runtime_context:
    role: final_recipient
    receiver_vid_expected: "did:example:alice"
    sender_vid_expected: "did:example:bob"
expected:
  decode_fields:
    message_family: control
    control_type: TSP_RFA
    sender_vid: "did:example:bob"
    receiver_vid: "did:example:alice"
    digest: "<TBD hex request digest>"
    reply_digest: "<TBD hex reply digest>"
  semantic_assertions:
    - interpreted as a direct relationship-forming accept from bob to alice
    - the accept binds to the previously reviewed request digest
  state_predicates:
    - the accept must not be treated as valid if the bound request digest differs
    - under matching preconditions, the request/accept pair is sufficient to complete relationship formation semantics
not_compared:
  - regenerated accept wire bytes
  - SDK-internal thread or relationship identifiers
```

Relevant spec sections:

- `§7.1.2 Direct Relationship Forming`
- `§9.2.12.2 TSP_RFA`

### `BV-004` Nested RFI Decode

```yaml
id: BV-004
title: Nested RFI Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Nested Relationship Forming
  - Payload Nesting
preconditions:
  - a valid outer relationship already exists
  - sender and receiver outer VIDs are resolved
  - message is processed by the final intended receiver for the outer relationship
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 nested-rfi wire artifact>"
  fixture_refs:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
    - fixture.conversation.nested.request-01
  runtime_context:
    role: final_recipient
    outer_receiver_vid_expected: "did:example:bob"
    outer_sender_vid_expected: "did:example:alice"
expected:
  decode_fields:
    outer_message_family: nested
    inner_control_type: TSP_RFI
    inner_sender_vid: "did:example:alice-1"
    inner_receiver_vid: "<empty-or-unspecified-per-spec>"
    digest: "<TBD hex nested request digest>"
    nonce: "<TBD hex nested request nonce>"
  semantic_assertions:
    - interpreted as a private relationship-forming request coupled to the outer relationship
    - the inner request must not be interpreted as an independent direct relationship outside the outer context
  state_predicates:
    - any future nested accept must bind to the same nested request digest
    - the outer relationship remains a prerequisite context for the inner relationship semantics
not_compared:
  - regenerated nested wrapper bytes
  - SDK-specific parent-VID storage representation
```

Relevant spec sections:

- `§4.1 Payload Nesting`
- `§4.2 Nested Relationships`
- `§7.1.6 Nested Relationship Forming`
- `§9.2.12.5 TSP_RFI Nested`

### `BV-005` Nested RFA Decode

```yaml
id: BV-005
title: Nested RFA Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Nested Relationship Forming
  - Payload Nesting
preconditions:
  - a valid outer relationship already exists
  - a reviewed nested request digest is already fixed
  - sender and receiver outer VIDs are resolved
  - message is processed by the final intended receiver for the outer relationship
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 nested-rfa wire artifact>"
  fixture_refs:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
    - fixture.identity.inner.bob-1
    - fixture.conversation.nested.request-01
    - fixture.conversation.nested.accept-01
  runtime_context:
    role: final_recipient
    outer_receiver_vid_expected: "did:example:alice"
    outer_sender_vid_expected: "did:example:bob"
expected:
  decode_fields:
    outer_message_family: nested
    inner_control_type: TSP_RFA
    inner_sender_vid: "did:example:bob-1"
    inner_receiver_vid: "did:example:alice-1"
    digest: "<TBD hex nested request digest>"
    reply_digest: "<TBD hex nested reply digest>"
  semantic_assertions:
    - interpreted as a private relationship-forming accept coupled to the outer relationship
    - the accept binds to the previously reviewed nested request digest
  state_predicates:
    - the accept must not be valid outside the outer relationship context
    - under matching preconditions, the nested request/accept pair is sufficient to complete nested relationship formation semantics
not_compared:
  - regenerated nested accept wrapper bytes
  - SDK-specific storage for parent linkage or nested thread tracking
```

Relevant spec sections:

- `§4.1 Payload Nesting`
- `§4.2 Nested Relationships`
- `§7.1.6 Nested Relationship Forming`
- `§9.2.12.6 TSP_RFA Nested`

### `BV-006` Routed Hop Unwrap

```yaml
id: BV-006
title: Routed Hop Unwrap
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
preconditions:
  - current implementation is acting as an intermediary hop
  - current hop has the local context needed to unwrap one routed layer
  - next hop is resolved in the current routing context
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 routed-hop wire artifact>"
  fixture_refs:
    - fixture.identity.route.alice
    - fixture.identity.route.hop-1
    - fixture.identity.route.hop-2
    - fixture.identity.route.bob
    - fixture.conversation.routed.path-01
  runtime_context:
    role: intermediary_hop
    current_hop_vid: "did:example:hop-1"
expected:
  forwarding_view:
    next_hop_vid: "did:example:hop-2"
    remaining_route_ref: "<TBD json remaining-route reference>"
    opaque_payload_ref: "<TBD base64 opaque-payload reference>"
  semantic_assertions:
    - the intermediary learns only hop-local forwarding information
    - the intermediary does not learn final inner plaintext
    - the intermediary does not reinterpret the opaque payload as a final application message
  state_predicates:
    - no relationship-forming state is created solely by hop unwrap
not_compared:
  - bytes produced by onward forwarding
  - intermediary cache or queue implementation
```

Relevant spec sections:

- `§5.2 Routed Messages`
- `§5.3.4 The Destination Endpoint`

### `BV-007` Routed RFI Final Decode

```yaml
id: BV-007
title: Routed RFI Final Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
  - Direct Relationship Forming
preconditions:
  - the routed wrapper reaches the final intended recipient
  - routed path context is already fixed by a reviewed conversation fixture
  - sender and receiver final VIDs are resolved
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 routed-rfi-final wire artifact>"
  fixture_refs:
    - fixture.identity.route.alice
    - fixture.identity.route.hop-1
    - fixture.identity.route.hop-2
    - fixture.identity.route.bob
    - fixture.conversation.routed.request-01
  runtime_context:
    role: final_recipient
    receiver_vid_expected: "did:example:bob"
expected:
  decode_fields:
    message_family: control
    control_type: TSP_RFI
    sender_vid: "did:example:alice"
    receiver_vid: "did:example:bob"
    digest: "<TBD hex routed request digest>"
    nonce: "<TBD hex routed request nonce>"
  semantic_assertions:
    - after routed unwrapping, the final recipient interprets the message as a relationship-forming request
    - routed wrapping does not change the underlying control semantics
  state_predicates:
    - any future routed accept must bind to the same request digest
    - intermediary path handling must not be treated as final relationship acceptance
not_compared:
  - intermediary implementation details
  - regenerated routed wrapper bytes
```

Relevant spec sections:

- `§5.2 Routed Messages`
- `§5.4.2 Destination Endpoint`
- `§7.1.2 Direct Relationship Forming`
- `§9.2.12.1 TSP_RFI`

## Semantic-Only Vectors

### `SV-002` Nested Confidential Generic Message Open

```yaml
id: SV-002
title: Nested Confidential Generic Message Open
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Mode Nested TSP Message
  - Payload Nesting
preconditions:
  - a valid outer relationship already exists
  - a valid inner nested relationship already exists within that outer context
  - sender and receiver for both outer and inner contexts are resolved
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 nested-confidential-message wire artifact>"
  fixture_refs:
    - fixture.identity.outer.alice
    - fixture.identity.outer.bob
    - fixture.identity.inner.alice-1
    - fixture.identity.inner.bob-1
    - fixture.conversation.nested.message-01
  runtime_context:
    role: final_recipient
    outer_receiver_vid_expected: "did:example:bob"
    inner_receiver_vid_expected: "did:example:bob-1"
expected:
  semantic_assertions:
    - the implementation opens the outer protected layer before interpreting the inner message
    - the implementation recovers the reviewed inner sender, inner receiver, payload, and non-confidential data semantics
    - the inner message is treated as valid only within the reviewed outer relationship context
  state_predicates:
    - opening the nested confidential message must not create a new relationship
    - opening the nested confidential message must not detach the inner semantics from the outer context
not_compared:
  - regenerated nested confidential wire bytes
  - SDK-specific buffering or streaming details
```

Relevant spec sections:

- `§3.2.2 Ciphertext of the Confidential Payloads`
- `§4.1 Payload Nesting`
- `§4.2 Nested Relationships`
- `§9.2.8 Confidential Payload Ciphertext`

### `SV-004` Generic Message Without Prior Relationship

```yaml
id: SV-004
title: Generic Message Without Prior Relationship
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Mode TSP Message
preconditions:
  - receiver_vid is resolved
  - sender_vid is resolved
  - no valid prior relationship exists that would authorize this generic message
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 direct-generic-without-relationship wire artifact>"
  fixture_refs:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
    - fixture.conversation.negative.no-prior-relationship-01
  runtime_context:
    role: final_recipient
    receiver_vid_expected: "did:example:bob"
expected:
  semantic_assertions:
    - the sample is treated as unauthorized generic traffic under the stated preconditions
  state_predicates:
    - the message must not be accepted as a valid application message
    - the message must not establish a relationship
    - the message must not upgrade any relationship state
  rejection:
    must_reject_or_drop: true
    must_not_deliver_application_payload: true
    must_not_create_relationship: true
not_compared:
  - exact error wording
  - exact error type naming
  - logging side effects
```

Relevant spec sections:

- `§3.5 Sender Procedure`
- `§3.6 Receiver Procedure`
- `§9.2.3 Higher Layer Payload`

### `SV-005` RFA Digest Mismatch

```yaml
id: SV-005
title: RFA Digest Mismatch
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Direct Relationship Forming
preconditions:
  - sender_vid is resolved
  - receiver_vid is resolved
  - a reviewed earlier request exists in context
  - the accept sample intentionally contains a non-matching request digest
input:
  artifact_format: base64
  wire_artifact: "<TBD base64 direct-rfa-digest-mismatch wire artifact>"
  fixture_refs:
    - fixture.identity.direct.alice
    - fixture.identity.direct.bob
    - fixture.conversation.direct.request-01
    - fixture.conversation.negative.digest-mismatch-01
  runtime_context:
    role: final_recipient
    receiver_vid_expected: "did:example:alice"
expected:
  semantic_assertions:
    - the sample is recognized as an attempted relationship accept with invalid digest binding
  state_predicates:
    - the accept must not complete relationship establishment
    - the implementation must not upgrade the relationship to bidirectional
    - the mismatched accept must not overwrite the reviewed request binding
  rejection:
    must_reject: true
    must_not_create_relationship: true
    must_not_upgrade_relationship: true
    must_not_consume_valid_request_binding: true
not_compared:
  - exact rejection wording
  - exact rejection type naming
  - local cleanup strategy after rejection
```

Relevant spec sections:

- `§7.1.1 TSP Digest`
- `§7.1.2 Direct Relationship Forming`
- `§9.2.12.2 TSP_RFA`

## Additional Entries

The following entries are also defined in this document.
They do not yet freeze authoritative case-local artifacts.

### `BV-003` Direct RFD Decode

```yaml
id: BV-003
title: Direct RFD Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Relationship Forming Decline or Cancel
preconditions:
  - sender_vid is resolved
  - receiver_vid is resolved
  - the final recipient processes the reviewed direct TSP_RFD sample
  - the reviewed context identifies whether the sample expresses pending-request decline or established-relationship cancellation
expected:
  decode_fields:
    message_family: control
    control_type: TSP_RFD
    digest: "<TBD hex reviewed decline-or-cancel digest>"
  semantic_assertions:
    - the sample is interpreted as a reviewed direct relationship decline-or-cancel control outcome
    - the digest is interpreted according to the reviewed decline-or-cancel context
  state_predicates:
    - unknown relationships are ignored rather than accepted
not_compared:
  - local cleanup policy
  - SDK-local relationship bookkeeping
```

Relevant spec sections:

- `§7.1.7 Relationship Forming Decline or Cancel`
- `§9.2.12.7 TSP_RFD`

### `BV-008` Routed RFA Final Decode

```yaml
id: BV-008
title: Routed RFA Final Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Routed Mode Message
  - Direct Relationship Forming
preconditions:
  - the routed wrapper reaches the final intended recipient
  - the reviewed earlier routed request digest is already fixed
  - the destination endpoint has the local context needed to unwrap the reviewed routed sample
expected:
  decode_fields:
    message_family: control
    control_type: TSP_RFA
    digest: "<TBD hex routed request digest>"
  semantic_assertions:
    - final destination decoding exposes a reviewed routed relationship-forming accept
    - the accept binds to the earlier reviewed routed request
  state_predicates:
    - routed unwrapping preserves direct accept semantics
not_compared:
  - cross-case protected bytes
  - intermediary implementation details
```

Relevant spec sections:

- `§5.2 Routed Messages`
- `§5.4.2 Destination Endpoint`
- `§7.1.2 Direct Relationship Forming`
- `§9.2.12.2 TSP_RFA`

### `SV-001` Direct Confidential Generic Message Open

```yaml
id: SV-001
title: Direct Confidential Generic Message Open
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Ciphertext of the Confidential Payloads
  - Higher Layer Payload
preconditions:
  - a valid prior relationship exists
  - sender_vid is resolved
  - receiver_vid is resolved
  - the final recipient processes the reviewed direct confidential sample
expected:
  semantic_assertions:
    - opening yields the reviewed sender, receiver, higher-layer payload, and non-confidential data semantics
    - the message is interpreted as authorized generic traffic under the reviewed relationship context
  state_predicates:
    - the message does not create a new relationship
not_compared:
  - regenerated ciphertext bytes
```

Relevant spec sections:

- `§3.2.2 Ciphertext of the Confidential Payloads`
- `§3.5 Sender Procedure`
- `§3.6 Receiver Procedure`
- `§9.2.3 Higher Layer Payload`
- `§9.2.8 Confidential Payload Ciphertext`

### `SV-003` Routed Confidential End-to-End Open

```yaml
id: SV-003
title: Routed Confidential End-to-End Open
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Ciphertext of the Confidential Payloads
  - Routed Messages
preconditions:
  - the routed path context is fixed
  - the destination endpoint has the local context needed to unwrap the reviewed routed confidential sample
expected:
  semantic_assertions:
    - intermediary visibility remains limited to hop-local routing semantics
    - final recipient recovery yields the reviewed sender, receiver, and higher-layer payload semantics
  state_predicates:
    - routed confidential transport does not alter reviewed end-to-end payload meaning
not_compared:
  - regenerated ciphertext bytes
  - intermediary forwarding implementation details
```

Relevant spec sections:

- `§3.2.2 Ciphertext of the Confidential Payloads`
- `§5.2 Routed Messages`
- `§5.4.2 Destination Endpoint`
- `§9.2.8 Confidential Payload Ciphertext`

### `SV-006` Nested Message Without Coupled Outer Relationship

```yaml
id: SV-006
title: Nested Message Without Coupled Outer Relationship
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Payload Nesting
  - Nested Relationships
preconditions:
  - the reviewed sample represents nested traffic
  - the required coupled outer relationship context is absent
expected:
  semantic_assertions:
    - the nested message is not accepted as valid independent traffic
  state_predicates:
    - the reviewed rejection boundary is enforced when the outer context is missing
  rejection:
    must_reject_or_drop: true
    must_not_treat_as_independent_relationship: true
not_compared:
  - exact error wording
```

Relevant spec sections:

- `§4.1 Payload Nesting`
- `§4.2 Nested Relationships`
- `§7.1.6 Nested Relationship Forming`

### `AV-001` Confidential Control Sender-Field Presence

```yaml
id: AV-001
title: Confidential Control Sender-Field Presence
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - HPKE Auth Mode
  - HPKE Base Mode
  - TSP Use of Sealed Box for PKAE
preconditions:
  - reviewed mechanism-specific confidential control samples are available
expected:
  semantic_assertions:
    - HPKE-Auth realizes the reviewed control payload without requiring VID_sndr in the confidential control body
    - HPKE-Base requires the reviewed sender field
    - Sealed Box requires the reviewed sender field
not_compared:
  - unrelated payload fields
  - cross-mechanism protected bytes
```

Relevant spec sections:

- `§8 HPKE Auth Mode`
- `§8 HPKE Base Mode`
- `§8 TSP Use of Sealed Box for PKAE`

### `AV-002` Ciphertext Encoding Family Decode

```yaml
id: AV-002
title: Ciphertext Encoding Family Decode
classification: byte-exact
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - Confidential Payload Ciphertext
preconditions:
  - one reviewed confidential sample is available for each mechanism track
expected:
  semantic_assertions:
    - the ciphertext field decodes under the correct CESR family for each reviewed mechanism track
    - no reviewed sample is accepted under the wrong family interpretation
not_compared:
  - unrelated opened semantics
```

Relevant spec sections:

- `§9.2.8 Confidential Payload Ciphertext`

### `AV-003` Non-Confidential-Field Binding Review

```yaml
id: AV-003
title: Non-Confidential-Field Binding Review
classification: semantic-only
profile: tsp-initial-interoperability-profile-01
spec_anchors:
  - HPKE Auth Mode
  - HPKE Base Mode
  - TSP Use of Sealed Box for PKAE
preconditions:
  - reviewed confidential samples are available for HPKE and Sealed Box tracks
  - the reviewed test condition challenges non-confidential-field binding under a controlled interpretation boundary
expected:
  semantic_assertions:
    - HPKE realizes the reviewed binding semantics using non-confidential fields as AAD
    - Sealed Box follows the current reviewed spec behavior for the same fields
not_compared:
  - byte identity across mechanisms
```

Relevant spec sections:

- `§8 HPKE Auth Mode`
- `§8 HPKE Base Mode`
- `§8 TSP Use of Sealed Box for PKAE`
