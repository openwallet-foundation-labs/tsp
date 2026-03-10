# TSP Test Vector Spec Mapping

This document records the correspondence between the TSP test-vector set and the TSP specification.
It is non-normative reference material. It does not extend the vector schema.

Reference snapshot:

- Live spec consulted on March 11, 2026: <https://trustoverip.github.io/tswg-tsp-specification/>

## Vector To Spec Mapping

| Vector | Primary sections | Normative basis |
| --- | --- | --- |
| `BV-001` | `§7.1.2 Direct Relationship Forming`; `§9.2.12.1 TSP_RFI` | Direct request semantics are defined by the relationship-forming section, while exact control fields such as `Digest` and `Nonce` are fixed by the `TSP_RFI` encoding. |
| `BV-002` | `§7.1.2 Direct Relationship Forming`; `§9.2.12.2 TSP_RFA` | Direct accept semantics and request binding are defined by the direct relationship-forming flow; exact accept control fields are fixed by the `TSP_RFA` encoding. |
| `BV-003` | `§7.1.7 Relationship Forming Decline or Cancel`; `§9.2.12.7 TSP_RFD` | Decline/cancel semantics, including digest usage and the ignore-on-unknown rule, are defined here; exact control fields are fixed by the `TSP_RFD` encoding. |
| `BV-004` | `§4 Nested Messages`; `§4.1 Payload Nesting`; `§4.2 Nested Relationships`; `§7.1.6 Nested Relationship Forming`; `§9.2.12.5 TSP_RFI Nested` | Nested request semantics require an existing outer relationship and define the inner request as a private relationship coupled to that outer context. |
| `BV-005` | `§4 Nested Messages`; `§4.1 Payload Nesting`; `§4.2 Nested Relationships`; `§7.1.6 Nested Relationship Forming`; `§9.2.12.6 TSP_RFA Nested` | Nested accept semantics, including binding back to the nested request and preservation of the outer context, are defined by the nested relationship-forming flow. |
| `BV-006` | `§5.2 Routed Messages`; `§5.3.4 The Destination Endpoint` | Routed wrapping defines what is visible at one hop and how the current recipient strips one routed layer without learning the final protected payload. |
| `BV-007` | `§5.2 Routed Messages`; `§5.4.2 Destination Endpoint`; `§7.1.2 Direct Relationship Forming`; `§9.2.12.1 TSP_RFI` | Routed unwrapping must preserve the underlying direct request semantics and expose the same `TSP_RFI` control interpretation at the final endpoint. |
| `BV-008` | `§5.2 Routed Messages`; `§5.4.2 Destination Endpoint`; `§7.1.2 Direct Relationship Forming`; `§9.2.12.2 TSP_RFA` | Routed unwrapping must preserve the underlying direct accept semantics, including digest binding to the earlier request. |
| `SV-001` | `§3.2.2 Ciphertext of the Confidential Payloads`; `§3.5 Sender Procedure`; `§3.6 Receiver Procedure`; `§9.2.3 Higher Layer Payload`; `§9.2.8 Confidential Payload Ciphertext` | Direct generic confidential traffic is grounded in higher-layer payload structure, sender/receiver state preconditions, and the single-ciphertext-field wire interpretation. |
| `SV-002` | `§3.2.2 Ciphertext of the Confidential Payloads`; `§4.1 Payload Nesting`; `§4.2 Nested Relationships`; `§9.2.8 Confidential Payload Ciphertext` | Nested confidential traffic requires ordered outer/inner opening and remains valid only within the coupled outer relationship context. |
| `SV-003` | `§3.2.2 Ciphertext of the Confidential Payloads`; `§5.2 Routed Messages`; `§5.4.2 Destination Endpoint`; `§9.2.8 Confidential Payload Ciphertext` | Routed confidential traffic combines hop-local visibility with end-to-end protected payload recovery at the final destination. |
| `SV-004` | `§3.5 Sender Procedure`; `§3.6 Receiver Procedure`; `§9.2.3 Higher Layer Payload` | The receiver procedure permits dropping inbound generic traffic when no prior relationship exists or when the relationship is not bidirectional; this is the basis for the negative unauthorized-generic vector. |
| `SV-005` | `§7.1.1 TSP Digest`; `§7.1.2 Direct Relationship Forming`; `§9.2.12.2 TSP_RFA` | The accept is valid only when its digest binds to the earlier request; digest mismatch therefore blocks relationship completion. |
| `SV-006` | `§4.1 Payload Nesting`; `§4.2 Nested Relationships`; `§7.1.6 Nested Relationship Forming` | Inner nested semantics are not independently valid outside the outer relationship context; this is the basis for rejecting detached nested traffic. |
| `AV-001` | `§8 HPKE Auth Mode`; `§8 HPKE Base Mode`; `§8 TSP Use of Sealed Box for PKAE` | Confidential control payloads do not have one uniform sender-field requirement across `HPKE-Auth`, `HPKE-Base`, and `Sealed Box`; this distinction should be isolated explicitly. |
| `AV-002` | `§9.2.8 Confidential Payload Ciphertext` | Confidential payload ciphertext is encoded under different CESR families for `HPKE-Auth`, `HPKE-Base`, and `Sealed Box`, so family interpretation should be reviewed explicitly. |
| `AV-003` | `§8 HPKE Auth Mode`; `§8 HPKE Base Mode`; `§8 TSP Use of Sealed Box for PKAE` | HPKE and Sealed Box do not share the same non-confidential-field binding behavior in the current spec text; this interoperability distinction should be isolated explicitly. |
