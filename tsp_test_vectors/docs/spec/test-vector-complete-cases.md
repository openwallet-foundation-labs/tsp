# TSP Test Vector Complete Cases

This document defines the case-level structure for the TSP test-vector set.

A complete case is a mechanism-specific realization of shared protocol assertions. It is not an additional vector class.

`HPKE-Auth`, `HPKE-Base`, and `Sealed Box` cases may share protocol intent while producing different protected outputs, different bound artifact values, and different case-local artifact structures.

`HPKE-Auth`, `HPKE-Base`, and `Sealed Box` are instantiated explicitly at manifest level.

Case manifests are defined in [test-vector-case-manifests.md](./test-vector-case-manifests.md).
Case-level expected outcomes are defined in
[test-vector-case-outputs.md](./test-vector-case-outputs.md).

## Shared Intent And Case Realization

This set distinguishes two layers:

- shared abstract conformance intent
  - the protocol assertions defined by the vector set
- case-specific realization
  - the concrete artifacts, bindings, and output structures produced under one confidentiality mechanism

Shared intent does not imply byte identity, artifact identity, or output-shape identity across cases.

The explicit realized slices across all three complete cases are:

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
- `SV-004`
- `SV-006`

## Case-Level Fields

Each complete case should define:

- `case_id`
  - stable case identifier such as `CC-001`
- `case_profile`
  - the cryptographic profile name used by the case
- `confidentiality_mechanism`
  - the concrete protection mechanism, such as `HPKE-Auth`, `HPKE-Base`, or `Sealed Box`
- `artifact_set_id`
  - the authoritative artifact-set identifier for the case
- `abstract_intent_ref`
  - the shared abstract conformance intent referenced by the case
- `applicability_boundary`
  - the vectors and fixtures this case explicitly realizes
- `output_boundary`
  - the class of artifacts this case produces and the limits of cross-case comparison
- `realized_slice_refs`
  - the case-local slices that are already frozen as authoritative assets for that case
- `case_output_ref`
  - the case-level expected-outcome record summarized by the case

## Complete Cases

| Case ID | Case profile | Confidentiality mechanism | Artifact set ID |
| --- | --- | --- | --- |
| `CC-001` | `tsp-hpke-auth-complete-case-01` | `HPKE-Auth` | `artifact-set.cc-001` |
| `CC-002` | `tsp-hpke-base-complete-case-01` | `HPKE-Base` | `artifact-set.cc-002` |
| `CC-003` | `tsp-sealed-box-complete-case-01` | `Sealed Box` | `artifact-set.cc-003` |

Case-output identifiers:

- `case-output.cc-001`
- `case-output.cc-002`
- `case-output.cc-003`

## Artifact Sets

Each case-specific artifact set should contain:

- one case manifest
- the case-local vector artifacts produced under that mechanism
- the case-local fixture artifacts required by that mechanism
- the case-local binding artifacts required to interpret the case outputs

Artifact-set identifiers:

- `artifact-set.cc-001`
- `artifact-set.cc-002`
- `artifact-set.cc-003`

## Minimum Artifact Categories

Each case-specific artifact set should provide at least:

- `case_manifest`
  - case metadata, case profile, confidentiality mechanism, applicability, and set references
- `vector_artifacts`
  - authoritative case-local `wire_artifact` values for vectors realized by that case
- `fixture_artifacts`
  - authoritative case-local fixture artifacts required by that case
- `binding_artifacts`
  - frozen case-local values referenced from vectors or fixtures, such as digests, nonces, route references, or payload references

## Applicability Boundary

No complete case automatically inherits the full vector set.

Each complete case should declare:

- which vector intents it realizes
- which fixtures it requires
- which bindings are specific to that case

These declarations define explicit vector applicability, explicit fixture applicability, and explicit binding applicability for the case.

Across `CC-001`, `CC-002`, and `CC-003`:

- shared intent may overlap
- realized vector subsets may overlap
- fixture use may overlap
- protected outputs are mechanism-specific
- case-local bound values are mechanism-specific

Applicability declarations are broader than frozen case-local realizations.

The current cross-case realized slices are the confidential-control slices, the generic confidential-message slice, and the negative semantic-boundary slice listed above.

## Output Boundary

- HPKE-Auth outputs are authoritative only within `artifact-set.cc-001`
- HPKE-Base outputs are authoritative only within `artifact-set.cc-002`
- Sealed Box outputs are authoritative only within `artifact-set.cc-003`
- cross-case byte equality is not required
- cross-case artifact identity is not required
- protocol meaning remains comparable only at the vector-assertion layer

## Case Invariants

- each complete case must identify its applicability boundary explicitly
- each complete case must bind only case-local artifacts from its own artifact set
- each complete case must preserve the comparison boundaries for the vector intents it realizes
- no case may claim cross-case byte equivalence without an explicit additional rule
- no case may add or remove protocol semantics beyond the vector set

## Case Profiles

- `tsp-hpke-auth-complete-case-01`
- `tsp-hpke-base-complete-case-01`
- `tsp-sealed-box-complete-case-01`
