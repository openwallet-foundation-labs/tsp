# TSP Test Vector Case Outputs

This document defines the case-level expected outcomes for the complete cases.

The detailed protocol assertions remain defined by the vector set.
The records below summarize what each complete case proves as a whole.

These records should be read as structured case-level outcome summaries.
They are not additional vector assets, additional binding assets, or final
message outputs.

`CC-001` and `CC-002` are written as HPKE-family cases.
`CC-003` is written as a separate Sealed Box case and is not treated as a
mechanically identical HPKE-family outcome record.

Each record below answers:

- what relationship outcomes are established
- what message-flow outcomes are demonstrated
- what negative boundaries are represented
- under which confidentiality family those conclusions hold

The case-output schema is defined in
[test-vector-case-output-schema.md](./test-vector-case-output-schema.md).

## `CC-001` HPKE-Auth Case Outcome

```yaml
case_output_id: case-output.cc-001
case_id: CC-001
case_profile: tsp-hpke-auth-complete-case-01
supported_vector_ids:
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
positive_outcomes:
  - HPKE-family direct relationship establishment is demonstrated
  - HPKE-family nested relationship establishment is demonstrated
  - HPKE-family routed control delivery is demonstrated
  - HPKE-family direct message replay succeeds
  - HPKE-family nested message replay succeeds
  - HPKE-family routed message replay succeeds
negative_outcomes:
  - HPKE-family no-prior-relationship traffic is represented as invalid
  - HPKE-family nested-without-outer traffic is represented as invalid
relationship_state_summary:
  - HPKE-family direct relationship reaches bidirectional state
  - HPKE-family nested relationship is coupled to an outer relationship
message_flow_summary:
  - HPKE-family direct message semantics are available after direct relationship forming
  - HPKE-family nested message semantics are available after nested relationship forming
  - HPKE-family routed message semantics are available after routed path and final delivery
family_summary:
  - HPKE-family case-level output
mechanism_summary:
  - confidentiality mechanism: HPKE-Auth
```

## `CC-002` HPKE-Base Case Outcome

```yaml
case_output_id: case-output.cc-002
case_id: CC-002
case_profile: tsp-hpke-base-complete-case-01
supported_vector_ids:
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
positive_outcomes:
  - HPKE-family direct relationship establishment is demonstrated
  - HPKE-family nested relationship establishment is demonstrated
  - HPKE-family routed control delivery is demonstrated
  - HPKE-family direct message replay succeeds
  - HPKE-family nested message replay succeeds
  - HPKE-family routed message replay succeeds
negative_outcomes:
  - HPKE-family no-prior-relationship traffic is represented as invalid
  - HPKE-family nested-without-outer traffic is represented as invalid
relationship_state_summary:
  - HPKE-family direct relationship reaches bidirectional state
  - HPKE-family nested relationship is coupled to an outer relationship
message_flow_summary:
  - HPKE-family direct message semantics are available after direct relationship forming
  - HPKE-family nested message semantics are available after nested relationship forming
  - HPKE-family routed message semantics are available after routed path and final delivery
family_summary:
  - HPKE-family case-level output
mechanism_summary:
  - confidentiality mechanism: HPKE-Base
```

## `CC-003` Sealed Box Case Outcome

```yaml
case_output_id: case-output.cc-003
case_id: CC-003
case_profile: tsp-sealed-box-complete-case-01
supported_vector_ids:
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
positive_outcomes:
  - direct relationship establishment is demonstrated under Sealed Box
  - nested relationship establishment is demonstrated under Sealed Box
  - routed control delivery is demonstrated under Sealed Box
  - direct message replay succeeds under Sealed Box
  - nested message replay succeeds under Sealed Box
  - routed message replay succeeds under Sealed Box
negative_outcomes:
  - no-prior-relationship traffic is represented as invalid under Sealed Box
  - nested-without-outer traffic is represented as invalid under Sealed Box
relationship_state_summary:
  - direct relationship reaches bidirectional state under Sealed Box
  - nested relationship is coupled to an outer relationship under Sealed Box
message_flow_summary:
  - direct message semantics are available after direct relationship forming under Sealed Box
  - nested message semantics are available after nested relationship forming under Sealed Box
  - routed message semantics are available after routed path and final delivery under Sealed Box
family_summary:
  - case output belongs to the Sealed Box case-level vocabulary
mechanism_summary:
  - confidentiality mechanism: Sealed Box
```
