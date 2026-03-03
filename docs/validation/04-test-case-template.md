# Test Case Template

Use this template for every test in the validation set.

## 1. Metadata

- Test ID: `TC-<ClauseID>-<P|N|B>-<NNN>`
- Clause ID: `<DOMAIN>-<SUBDOMAIN>-<NNN>`
- Assertion ID: `AS-<ClauseID>-<NNN>`
- Priority: `P0 | P1 | P2`
- Family: `Identifier | MessageStructure | ControlState | NestedRouted | Crypto | Encoding | Transport | ErrorHandling`
- Baseline: `TSP Rev 2`

## 2. Objective

State one sentence describing what this test proves or disproves.

## 3. Inputs

- Input vector ID:
- Encoded payload source:
- Key material profile:
- Transport profile (if applicable):
- Feature flags/profile assumptions:

## 4. Preconditions

- Required local identities:
- Required verified identities:
- Required relationship state:
- Required transport bindings:

## 5. Procedure

1. Step 1
2. Step 2
3. Step 3

## 6. Expected Result

- Accept/Reject expectation:
- Expected decoded field invariants:
- Expected control-state transitions:
- Expected error category (if rejection expected):

## 7. Evidence Requirements

- `packet_hex`
- `decoded_fields`
- `error_code`
- `trace_ref`
- `timestamp_utc`
- `implementation_profile`

## 8. Verdict Rule

- `PASS` when all expected invariants match and no forbidden behavior appears.
- `FAIL` when any required invariant is violated.
- `INCONCLUSIVE` when required evidence keys are missing.
- `BLOCKED` when preconditions are unmet.

## 9. Security Notes

- Abuse case class:
- Replay relevance:
- Tampering relevance:
- Downgrade relevance:

## 10. Traceability

- Spec anchor:
- Related clause IDs:
- Related gap register IDs:

---

## Canonical YAML Skeleton

```yaml
test_id: TC-CRY-SIG-001-N-001
clause_id: CRY-SIG-001
assertion_id: AS-CRY-SIG-001-001
priority: P0
family: Crypto
baseline: tsp_rev2
objective: Reject message when outer signature does not cover protected envelope+ciphertext section.
inputs:
  vector_id: VEC-CRY-SIG-NEG-001
  encoded_payload_ref: vectors/cry_sig_neg_001.bin
  key_profile: ed25519_x25519
  transport_profile: none
  implementation_profile: default
preconditions:
  local_identity: receiver_vid_a
  verified_identity: sender_vid_b
  relationship_state: established
procedure:
  - load payload bytes
  - invoke open/verify path
  - capture result and decoded fields
expected:
  action: reject
  error_category: signature_verification_failed
evidence_required:
  - packet_hex
  - decoded_fields
  - error_code
  - trace_ref
  - timestamp_utc
verdict_rule:
  pass_if:
    - result.action == reject
    - result.error_category == signature_verification_failed
  fail_if:
    - result.action == accept
security_notes:
  abuse_class: forgery
  replay_relevance: medium
traceability:
  spec_anchor: "#confidential-message"
  related_clauses:
    - MSG-CONF-003
    - CRY-SIG-001
```
