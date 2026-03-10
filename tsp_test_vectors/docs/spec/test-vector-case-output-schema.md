# TSP Test Vector Case Output Schema

This document defines a minimal schema for case-level expected outcomes.

Case-level outcomes do not replace `BV`, `SV`, or `AV` assertions.
They summarize what a complete case proves at a higher protocol level.

This schema does not introduce a new wire-level or binding-level asset class.
It defines a structured, spec-facing outcome record that summarizes the
case-level meaning established by a complete case.

Case-level outcomes must not flatten confidentiality families that are not at the
same comparison level.

- `CC-001` and `CC-002` may share an HPKE-family outcome vocabulary where the
  protocol-level conclusion is genuinely the same and only the HPKE profile
  differs.
- `CC-003` must be written as a separate Sealed Box case-level record.
  It may describe similar demonstrated protocol capabilities, but it must not be
  treated as a mechanically identical HPKE-family output with only the
  mechanism label changed.

## Design Goal

The case-level outcome layer should answer:

- what high-level protocol outcomes a complete case establishes
- what final relationship and message semantics the case demonstrates
- what negative boundaries are represented by the case
- what mechanism-family scope those conclusions belong to

It should remain concise and should not duplicate every vector-level reviewed
field.

## Top-Level Fields

- `case_output_id`
  - stable identifier such as `case-output.cc-001`
- `case_id`
  - the complete-case identifier
- `case_profile`
  - the profile name used by the case
- `supported_vector_ids`
  - the vectors whose combined meaning is summarized by the case output
- `positive_outcomes`
  - the high-level protocol outcomes established by the case
- `negative_outcomes`
  - the high-level negative boundaries represented by the case
- `relationship_state_summary`
  - the final relationship-state meaning established by the case
- `message_flow_summary`
  - the final message-flow meaning established by the case
- `mechanism_summary`
  - a short mechanism-specific summary for the case
- `family_summary`
  - a short statement of whether the output belongs to an HPKE-family case or a
    separate non-HPKE case
- `notes`
  - non-normative notes when needed

## Interpretation Rule

The record defined here should be read as a structured expected-outcome summary.

It is not:

- a new ciphertext artifact
- a new fixture artifact
- a final store dump
- a single message output

Instead, it records the higher-level protocol outcomes that the complete case is
intended to establish.

## Recommended Minimal YAML Shape

```yaml
case_output_id: case-output.cc-001
case_id: CC-001
case_profile: tsp-hpke-auth-complete-case-01
supported_vector_ids:
  - BV-001
  - BV-002
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
positive_outcomes:
  - HPKE-family direct relationship establishment is demonstrated
  - HPKE-family nested relationship establishment is demonstrated
  - HPKE-family routed control delivery is demonstrated
  - HPKE-family direct, nested, and routed message semantics are demonstrated where applicable
negative_outcomes:
  - HPKE-family no-prior-relationship traffic is represented as invalid
  - HPKE-family nested-without-outer traffic is represented as invalid
relationship_state_summary:
  - HPKE-family direct relationship reaches bidirectional state
  - HPKE-family nested relationship is coupled to an outer relationship
message_flow_summary:
  - HPKE-family direct message semantics are available after direct relationship forming
  - HPKE-family nested message semantics are available after nested relationship forming
  - HPKE-family routed message semantics are available after routed path and delivery
family_summary:
  - case output belongs to the HPKE-family outcome vocabulary
mechanism_summary:
  - confidentiality mechanism: HPKE-Auth
```
