# Observed Gaps: Protocol Baseline vs Current Repository

This register captures observed differences and uncertainty points between the protocol baseline and current repository behavior.

Important:

- This is an observation log, not a conformance verdict.
- Each item must be validated by protocol-derived tests before concluding pass/fail.

## Gap Register

| Gap ID | Observation | Protocol Impact | Evidence In Repo | Confidence | Planned Validation |
| --- | --- | --- | --- | --- | --- |
| GAP-001 | Current VID implementations appear focused on `did:web`, `did:peer`, and `did:webvh`; no obvious URN resolver path found. | Affects `VID-FORM-002` (MUST support URN syntax). | `tsp_sdk/src/vid/did/mod.rs`, `tsp_sdk/src/vid/resolve.rs`, `README.md` | Medium | Add positive URN parsing/resolution case and a capability profile check. |
| GAP-002 | HPKE base/auth support appears feature-controlled (`essr`) rather than guaranteed in all build profiles. | Affects `CRY-HPKE-001` (MUST support both HPKE modes in baseline profile). | `tsp_sdk/src/cesr/packet.rs`, `tsp_sdk/src/crypto/tsp_hpke.rs` | Medium | Add build-profile conformance matrix by feature set and profile claim. |
| GAP-003 | Optional NaCl/libsodium crypto support exists behind feature flags and may not be covered by the baseline spec profile. | Potentially affects extension claims; baseline should remain HPKE-focused (`CRY-HPKE-*`). | `tsp_sdk/src/crypto/tsp_nacl.rs`, `tsp_sdk/src/crypto/mod.rs` | Medium | Treat as capability-only until spec makes it normative; add profile metadata evidence. |
| GAP-004 | Additional temporary payload selectors exist (`X3RR`, `XRNI`, `XRNA`) and may not align with baseline control payload set. | Affects `MSG-CTRL-001` and control payload strictness. | `tsp_sdk/src/cesr/packet.rs` | High | Add strict unknown/extension selector behavior tests. |
| GAP-005 | Current parser/signature path appears centered on a single signature block in main verify/open flow. | Potentially impacts signature block parsing expectations (`MSG-SIG-001`) and any future multi-signature extensions (treat as `SPEC_GAP` until the spec is explicit). | `tsp_sdk/src/crypto/mod.rs`, `tsp_sdk/src/cesr/packet.rs` | Medium | Keep baseline tests single-signature; track multi-signature as future extension vectors if/when specified. |
| GAP-006 | Local technical spec and implementation docs are SDK-oriented and may not reflect all protocol-level transport obligations. | Affects `TRN-INTF-*` clause coverage completeness. | `docs/src/TSP-technical-specification.md`, `docs/src/transport.md` | High | Build transport-interface tests directly from protocol clauses, not SDK docs. |
| GAP-007 | Protocol baseline presents DID and URN as required VID formats, but CLI and examples emphasize DID-only workflows. | Affects end-to-end coverage of VID format MUSTs. | `examples/src/cli.rs`, `docs/src/cli/*.md` | Medium | Add explicit URN-path test fixtures at protocol layer (non-CLI if needed). |
| GAP-008 | Current test suite is scenario-heavy and not clause-traceable to baseline normative requirements. | Affects auditability and regression precision for all clause domains. | `tsp_sdk/src/test.rs`, `examples/tests/cli_tests.rs` | High | Introduce clause-tagged test IDs and evidence schema before expansion. |
| GAP-009 | Optional ML-DSA support exists, but conformance metadata for crypto capabilities is not formalized. | Affects how extension claims are expressed (baseline remains `CRY-ALG-003`, `CRY-HPKE-*`). | `tsp_sdk/src/definitions/mod.rs`, `tsp_sdk/src/cesr/packet.rs` | Medium | Require `implementation_profile` evidence to include declared capabilities and feature flags. |
| GAP-010 | Version signaling is present in encoding constants but not yet tied to a documented conformance profile matrix. | Affects future compatibility and versioned clause mapping. | `tsp_sdk/src/cesr/packet.rs` (`TSP_VERSION`) | Medium | Add baseline/profile/version mapping in versioning policy tests. |

## Risk Buckets

- High risk:
  - baseline clause omission due implementation-driven assumptions
  - extension selectors accepted without policy controls
  - non-traceable scenario tests masking normative gaps
- Medium risk:
  - feature-flag-dependent crypto mode conformance
  - optional profile claims without declaration discipline
  - DID-centric workflows under-covering URN requirements

## Resolution Workflow

1. Each gap maps to one or more clause IDs.
2. Add test design entries in `02-conformance-matrix.md`.
3. Create test vectors with `04-test-case-template.md`.
4. Resolve only through protocol-derived evidence.
