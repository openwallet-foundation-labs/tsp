# Spec Clause Catalog (Rev 2 Baseline)

This file defines normalized clause IDs for the protocol baseline and records the clause-level requirement that must be validated.

Notes:

- Requirement text is intentionally normalized, not verbatim.
- Source anchor points to section-level locations in the specification site.
- Clause set in this revision focuses on baseline MUST/SHOULD requirements and key protocol nodes; additional clauses should be incrementally added via the diff process in `06-versioning-and-diff-policy.md`.

## Domain Codes

- `VID`: verified identifier requirements
- `MSG`: message structure and semantics
- `CTL`: control payload and relationship flow
- `NEST`: nested mode semantics
- `RTE`: routed mode semantics
- `CRY`: cryptographic profile
- `ENC`: CESR/framing encoding rules
- `TRN`: transport interfaces and endpoint obligations
- `ERR`: unsupported/error behavior

## Clause Records

| Clause ID | Strength | Normalized Requirement | Source Anchor | Status |
| --- | --- | --- | --- | --- |
| VID-FORM-001 | MUST | A TSP implementation MUST support VIDs using DID syntax. | `#verified-identifiers` | Mapped |
| VID-FORM-002 | MUST | A TSP implementation MUST support VIDs using URN syntax. | `#verified-identifiers` | Mapped |
| VID-FORM-003 | MUST | VIDs used in TSP MUST be globally unique. | `#verified-identifiers` | Mapped |
| VID-META-001 | MUST | A VID MUST expose transport address discovery via `VID.RESOLVEADDRESS` returning `VID_iaddr`. | `#verified-identifiers` | Mapped |
| VID-META-002 | MUST | A VID MUST expose encryption public key via `VID.PK_e`. | `#verified-identifiers` | Mapped |
| VID-META-003 | MUST | A VID MUST expose signature verification key via `VID.PK_v`. | `#verified-identifiers` | Mapped |
| VID-META-004 | MUST | A VID MUST support `VID.VERIFY` to validate the signature block given a message and VID types. | `#verified-identifiers` | Mapped |
| VID-META-005 | SHOULD | VID metadata SHOULD carry trust-policy-relevant attributes. | `#verified-identifiers` | Mapped |
| VID-DISC-001 | SHOULD | If a received TSP message uses unsupported VID types, the receiver SHOULD discard the message. | `#verified-identifiers` | Mapped |
| VID-INNER-001 | MUST | Correlatable identifiers MUST NOT be used for inner relationships. | `#verified-identifiers` | Mapped |
| VID-INNER-002 | SHOULD | Inner relationships SHOULD be based on a random and globally unique identifier. | `#verified-identifiers` | Mapped |
| MSG-GEN-001 | MUST | Every TSP message MUST include sender VID information. | `#messages` | Mapped |
| MSG-GEN-002 | MUST | Every TSP message MUST include an outer signature. | `#messages` | Mapped |
| MSG-CONF-001 | MUST | Confidential messages MUST identify sender and recipient VIDs in authenticated envelope data. | `#confidential-message` | Mapped |
| MSG-CONF-002 | MUST | Confidential messages MUST include exactly one encrypted content group. | `#confidential-message` | Mapped |
| MSG-CONF-003 | MUST | Confidential messages MUST include at least one signature group. | `#confidential-message` | Mapped |
| MSG-NONC-001 | MUST | Non-confidential messages MUST include sender VID and signature. | `#non-confidential-message` | Mapped |
| MSG-NONC-002 | MUST | In non-confidential messages, the recipient VID field is optional; implementations MUST accept messages with no recipient VID. | `#non-confidential-message` | Mapped |
| MSG-CTRL-001 | MUST | Control messages MUST be represented as protocol-defined payload types. | `#control-message-payload` | Mapped |
| MSG-SIG-001 | MUST | The signature block MUST be a signature over the concatenation of the Envelope and the Payload. | `#messages` | Mapped |
| CTL-TYPE-001 | MUST | Relationship request payload MUST carry nonce and optional hop list. | `#relationship-request-message` | Mapped |
| CTL-TYPE-002 | MUST | Relationship accept payload MUST carry reply digest referencing original request. | `#relationship-accept-message` | Mapped |
| CTL-TYPE-003 | MUST | Nested relationship request payload MUST carry nonce and nested message. | `#nested-relationship-request-message` | Mapped |
| CTL-TYPE-004 | MUST | Nested relationship accept payload MUST carry nested message and reply digest. | `#nested-relationship-accept-message` | Mapped |
| CTL-TYPE-005 | MUST | Relationship cancel payload MUST carry reply digest. | `#relationship-cancel-message` | Mapped |
| CTL-TYPE-006 | MUST | Relationship referral payload MUST carry referred VID. | `#relationship-referral-message` | Mapped |
| CTL-THRD-001 | MUST | Reply digest fields in control messages MUST reference the correct thread/request context. | `#control-message-payload` | Mapped |
| CTL-HOPS-001 | MUST | Hop list, when present, MUST contain only VID entries. | `#relationship-request-message` | Mapped |
| NEST-MODE-001 | MUST | Nested mode MUST encapsulate an inner TSP message as payload of an outer TSP message. | `#nested-mode-messages` | Mapped |
| NEST-MODE-002 | MUST | Nested payload semantics MUST preserve inner message integrity across forwarding. | `#nested-mode-messages` | Mapped |
| NEST-MODE-003 | MUST | Nested relationship setup MUST use control payload types defined for nested proposals/acceptance. | `#nested-relationship-request-message` | Mapped |
| RTE-MODE-001 | MUST | Routed mode messages MUST include route information as ordered VID list. | `#routed-mode-messages` | Mapped |
| RTE-MODE-002 | MUST | Routed payload MUST carry exactly one encrypted inner message plus route metadata. | `#routed-mode-messages` | Mapped |
| RTE-MODE-003 | MUST | Intermediary-visible data in routed mode MUST be limited to route processing information. | `#routed-mode-messages` | Mapped |
| RTE-MODE-004 | MUST | Intermediaries MUST forward routed/nested payloads without modifying protected inner content. | `#routed-mode-messages` | Mapped |
| RTE-MODE-006 | MUST | Route construction MUST be compatible with corresponding relationship request semantics. | `#relationship-request-message` | Mapped |
| CRY-HPKE-001 | MUST | Implementations MUST support HPKE in both Auth and Base modes (at least for the baseline profile). | `#message-crypto-type` | Mapped |
| CRY-HPKE-002 | MUST | Baseline HPKE MUST use KEM `0x0020` (DHKEM(X25519, HKDF-SHA256)), KDF `0x0001` (HKDF-SHA256), AEAD `0x0003` (ChaCha20Poly1305). | `#message-crypto-type` | Mapped |
| CRY-ALG-003 | MUST | Implementations MUST support Ed25519 signatures. | `#cryptography-requirements` | Mapped |
| CRY-SIG-001 | MUST | Signature verification MUST validate the signature block against `Concat(Envelope, Payload)`. | `#messages` | Mapped |
| ENC-CESR-001 | MUST | Protocol messages MUST be encoded using CESR as defined by the baseline encoding rules. | `#encoding` | Mapped |
| ENC-CESR-002 | MUST | Conformant implementations MUST support CESR interleaving scheme for JSON, CBOR, and MsgPak payload encodings. | `#encoding` | Mapped |
| ENC-PAY-001 | MUST | Generic payloads MUST use `XSCS` and include a CESR count field for the payload length. | `#encoding` | Mapped |
| ENC-PAY-002 | MUST | An outer message of a nested message MUST be encoded with payload type `XHOP`. | `#nested-mode-messages` | Mapped |
| ENC-PAY-003 | MUST | Control messages MUST be encoded with payload type `XRFI`, `XRFA`, or `XRFD` and follow the defined field order. | `#control-message-payload` | Mapped |
| ENC-PARSE-001 | MUST | Unknown or malformed mandatory selectors MUST trigger message rejection. | `#encoding` | Mapped |
| ENC-BOUND-001 | MUST | Length and group boundaries MUST be validated before semantic processing. | `#encoding` | Mapped |
| TRN-INTF-001 | MUST | Transport bindings MUST provide `TSP_TRANSPORT_SEND` and `TSP_TRANSPORT_RECEIVE`. | `#transport-layer-bindings` | Mapped |
| TRN-INTF-002 | MUST | Transport bindings MUST provide `TSP_TRANSPORT_SETUP`, `TSP_TRANSPORT_TEARDOWN`, and `TSP_TRANSPORT_EVENT`. | `#transport-layer-bindings` | Mapped |
| TRN-INTF-003 | MUST | Each VID used for receiving MUST have a transport endpoint binding. | `#transport-layer-bindings` | Mapped |
| TRN-INTF-004 | SHOULD | Implementations SHOULD support at least one standardized transport binding profile. | `#transport-layer-bindings` | Mapped |
| ERR-UNSP-001 | SHOULD | Unsupported message types from unknown senders SHOULD be safely discarded. | `#transport-layer-bindings` | Mapped |
| ERR-UNSP-002 | SHOULD | Unsupported message types from known senders SHOULD return an explicit error signal where feasible. | `#transport-layer-bindings` | Mapped |
| ERR-VAL-001 | MUST | Parsing or validation failure in protected message structures MUST not result in partial acceptance. | `#messages` | Mapped |

## Catalog Maintenance Rules

1. If a baseline clause changes wording but not behavior, keep the same Clause ID and update notes.
2. If behavior changes, create a new Clause ID and deprecate the old one in `06-versioning-and-diff-policy.md`.
3. If a section is unclear, add `SPEC_GAP` annotation instead of inferring behavior.
