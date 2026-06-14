# Conformance Matrix (Clause -> Assertion -> Tests)

This matrix links every baseline clause to executable assertion design.

Legend:

- Positive case marker: `P`
- Negative case marker: `N`
- Boundary case marker: `B`
- Priority: `P0` mandatory baseline, `P1` important, `P2` optional/capability

Evidence profile keys come from `00-charter.md`.

## Matrix

| Clause ID | Assertion ID | Family | Priority | Positive Cases | Negative Cases | Boundary Cases | Required Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| VID-FORM-001 | AS-VID-FORM-001-001 | Identifier | P0 | `TC-VID-FORM-001-P-001` | `TC-VID-FORM-001-N-001` | `TC-VID-FORM-001-B-001` | `decoded_fields,error_code` |
| VID-FORM-002 | AS-VID-FORM-002-001 | Identifier | P0 | `TC-VID-FORM-002-P-001` | `TC-VID-FORM-002-N-001` | `TC-VID-FORM-002-B-001` | `decoded_fields,error_code` |
| VID-FORM-003 | AS-VID-FORM-003-001 | Identifier | P0 | `TC-VID-FORM-003-P-001` | `TC-VID-FORM-003-N-001` | `TC-VID-FORM-003-B-001` | `decoded_fields,error_code` |
| VID-META-001 | AS-VID-META-001-001 | Identifier | P0 | `TC-VID-META-001-P-001` | `TC-VID-META-001-N-001` | `TC-VID-META-001-B-001` | `decoded_fields,error_code` |
| VID-META-002 | AS-VID-META-002-001 | Identifier | P0 | `TC-VID-META-002-P-001` | `TC-VID-META-002-N-001` | `TC-VID-META-002-B-001` | `decoded_fields,error_code` |
| VID-META-003 | AS-VID-META-003-001 | Identifier | P0 | `TC-VID-META-003-P-001` | `TC-VID-META-003-N-001` | `TC-VID-META-003-B-001` | `decoded_fields,error_code` |
| VID-META-004 | AS-VID-META-004-001 | Identifier | P0 | `TC-VID-META-004-P-001` | `TC-VID-META-004-N-001` | `TC-VID-META-004-B-001` | `decoded_fields,error_code` |
| VID-META-005 | AS-VID-META-005-001 | Identifier | P1 | `TC-VID-META-005-P-001` | `TC-VID-META-005-N-001` | `TC-VID-META-005-B-001` | `decoded_fields,error_code` |
| VID-DISC-001 | AS-VID-DISC-001-001 | Identifier | P1 | `TC-VID-DISC-001-P-001` | `TC-VID-DISC-001-N-001` | `TC-VID-DISC-001-B-001` | `error_code,trace_ref` |
| VID-INNER-001 | AS-VID-INNER-001-001 | Identifier | P0 | `TC-VID-INNER-001-P-001` | `TC-VID-INNER-001-N-001` | `TC-VID-INNER-001-B-001` | `decoded_fields,trace_ref` |
| VID-INNER-002 | AS-VID-INNER-002-001 | Identifier | P1 | `TC-VID-INNER-002-P-001` | `TC-VID-INNER-002-N-001` | `TC-VID-INNER-002-B-001` | `decoded_fields,error_code` |
| MSG-GEN-001 | AS-MSG-GEN-001-001 | MessageStructure | P0 | `TC-MSG-GEN-001-P-001` | `TC-MSG-GEN-001-N-001` | `TC-MSG-GEN-001-B-001` | `packet_hex,decoded_fields` |
| MSG-GEN-002 | AS-MSG-GEN-002-001 | MessageStructure | P0 | `TC-MSG-GEN-002-P-001` | `TC-MSG-GEN-002-N-001` | `TC-MSG-GEN-002-B-001` | `packet_hex,decoded_fields,error_code` |
| MSG-CONF-001 | AS-MSG-CONF-001-001 | MessageStructure | P0 | `TC-MSG-CONF-001-P-001` | `TC-MSG-CONF-001-N-001` | `TC-MSG-CONF-001-B-001` | `packet_hex,decoded_fields` |
| MSG-CONF-002 | AS-MSG-CONF-002-001 | MessageStructure | P0 | `TC-MSG-CONF-002-P-001` | `TC-MSG-CONF-002-N-001` | `TC-MSG-CONF-002-B-001` | `packet_hex,decoded_fields,error_code` |
| MSG-CONF-003 | AS-MSG-CONF-003-001 | MessageStructure | P0 | `TC-MSG-CONF-003-P-001` | `TC-MSG-CONF-003-N-001` | `TC-MSG-CONF-003-B-001` | `packet_hex,decoded_fields,error_code` |
| MSG-NONC-001 | AS-MSG-NONC-001-001 | MessageStructure | P0 | `TC-MSG-NONC-001-P-001` | `TC-MSG-NONC-001-N-001` | `TC-MSG-NONC-001-B-001` | `packet_hex,decoded_fields` |
| MSG-NONC-002 | AS-MSG-NONC-002-001 | MessageStructure | P0 | `TC-MSG-NONC-002-P-001` | `TC-MSG-NONC-002-N-001` | `TC-MSG-NONC-002-B-001` | `packet_hex,decoded_fields` |
| MSG-CTRL-001 | AS-MSG-CTRL-001-001 | ControlState | P0 | `TC-MSG-CTRL-001-P-001` | `TC-MSG-CTRL-001-N-001` | `TC-MSG-CTRL-001-B-001` | `packet_hex,decoded_fields,error_code` |
| MSG-SIG-001 | AS-MSG-SIG-001-001 | Crypto | P0 | `TC-MSG-SIG-001-P-001` | `TC-MSG-SIG-001-N-001` | `TC-MSG-SIG-001-B-001` | `packet_hex,decoded_fields,error_code` |
| CTL-TYPE-001 | AS-CTL-TYPE-001-001 | ControlState | P0 | `TC-CTL-TYPE-001-P-001` | `TC-CTL-TYPE-001-N-001` | `TC-CTL-TYPE-001-B-001` | `decoded_fields,error_code` |
| CTL-TYPE-002 | AS-CTL-TYPE-002-001 | ControlState | P0 | `TC-CTL-TYPE-002-P-001` | `TC-CTL-TYPE-002-N-001` | `TC-CTL-TYPE-002-B-001` | `decoded_fields,error_code` |
| CTL-TYPE-003 | AS-CTL-TYPE-003-001 | ControlState | P0 | `TC-CTL-TYPE-003-P-001` | `TC-CTL-TYPE-003-N-001` | `TC-CTL-TYPE-003-B-001` | `decoded_fields,error_code` |
| CTL-TYPE-004 | AS-CTL-TYPE-004-001 | ControlState | P0 | `TC-CTL-TYPE-004-P-001` | `TC-CTL-TYPE-004-N-001` | `TC-CTL-TYPE-004-B-001` | `decoded_fields,error_code` |
| CTL-TYPE-005 | AS-CTL-TYPE-005-001 | ControlState | P0 | `TC-CTL-TYPE-005-P-001` | `TC-CTL-TYPE-005-N-001` | `TC-CTL-TYPE-005-B-001` | `decoded_fields,error_code` |
| CTL-TYPE-006 | AS-CTL-TYPE-006-001 | ControlState | P0 | `TC-CTL-TYPE-006-P-001` | `TC-CTL-TYPE-006-N-001` | `TC-CTL-TYPE-006-B-001` | `decoded_fields,error_code` |
| CTL-THRD-001 | AS-CTL-THRD-001-001 | ControlState | P0 | `TC-CTL-THRD-001-P-001` | `TC-CTL-THRD-001-N-001` | `TC-CTL-THRD-001-B-001` | `decoded_fields,error_code,trace_ref` |
| CTL-HOPS-001 | AS-CTL-HOPS-001-001 | ControlState | P0 | `TC-CTL-HOPS-001-P-001` | `TC-CTL-HOPS-001-N-001` | `TC-CTL-HOPS-001-B-001` | `decoded_fields,error_code` |
| NEST-MODE-001 | AS-NEST-MODE-001-001 | NestedRouted | P0 | `TC-NEST-MODE-001-P-001` | `TC-NEST-MODE-001-N-001` | `TC-NEST-MODE-001-B-001` | `packet_hex,decoded_fields` |
| NEST-MODE-002 | AS-NEST-MODE-002-001 | NestedRouted | P0 | `TC-NEST-MODE-002-P-001` | `TC-NEST-MODE-002-N-001` | `TC-NEST-MODE-002-B-001` | `packet_hex,decoded_fields,error_code` |
| NEST-MODE-003 | AS-NEST-MODE-003-001 | NestedRouted | P0 | `TC-NEST-MODE-003-P-001` | `TC-NEST-MODE-003-N-001` | `TC-NEST-MODE-003-B-001` | `decoded_fields,error_code` |
| RTE-MODE-001 | AS-RTE-MODE-001-001 | NestedRouted | P0 | `TC-RTE-MODE-001-P-001` | `TC-RTE-MODE-001-N-001` | `TC-RTE-MODE-001-B-001` | `packet_hex,decoded_fields` |
| RTE-MODE-002 | AS-RTE-MODE-002-001 | NestedRouted | P0 | `TC-RTE-MODE-002-P-001` | `TC-RTE-MODE-002-N-001` | `TC-RTE-MODE-002-B-001` | `packet_hex,decoded_fields,error_code` |
| RTE-MODE-003 | AS-RTE-MODE-003-001 | NestedRouted | P0 | `TC-RTE-MODE-003-P-001` | `TC-RTE-MODE-003-N-001` | `TC-RTE-MODE-003-B-001` | `packet_hex,decoded_fields` |
| RTE-MODE-004 | AS-RTE-MODE-004-001 | NestedRouted | P0 | `TC-RTE-MODE-004-P-001` | `TC-RTE-MODE-004-N-001` | `TC-RTE-MODE-004-B-001` | `packet_hex,decoded_fields,trace_ref` |
| RTE-MODE-006 | AS-RTE-MODE-006-001 | NestedRouted | P0 | `TC-RTE-MODE-006-P-001` | `TC-RTE-MODE-006-N-001` | `TC-RTE-MODE-006-B-001` | `decoded_fields,error_code` |
| CRY-ALG-003 | AS-CRY-ALG-003-001 | Crypto | P0 | `TC-CRY-ALG-003-P-001` | `TC-CRY-ALG-003-N-001` | `TC-CRY-ALG-003-B-001` | `decoded_fields,error_code,packet_hex` |
| CRY-HPKE-001 | AS-CRY-HPKE-001-001 | Crypto | P0 | `TC-CRY-HPKE-001-P-001` | `TC-CRY-HPKE-001-N-001` | `TC-CRY-HPKE-001-B-001` | `decoded_fields,error_code,implementation_profile` |
| CRY-HPKE-002 | AS-CRY-HPKE-002-001 | Crypto | P0 | `TC-CRY-HPKE-002-P-001` | `TC-CRY-HPKE-002-N-001` | `TC-CRY-HPKE-002-B-001` | `decoded_fields,error_code,packet_hex` |
| CRY-SIG-001 | AS-CRY-SIG-001-001 | Crypto | P0 | `TC-CRY-SIG-001-P-001` | `TC-CRY-SIG-001-N-001` | `TC-CRY-SIG-001-B-001` | `packet_hex,decoded_fields,error_code` |
| ENC-CESR-001 | AS-ENC-CESR-001-001 | Encoding | P0 | `TC-ENC-CESR-001-P-001` | `TC-ENC-CESR-001-N-001` | `TC-ENC-CESR-001-B-001` | `packet_hex,error_code` |
| ENC-CESR-002 | AS-ENC-CESR-002-001 | Encoding | P0 | `TC-ENC-CESR-002-P-001` | `TC-ENC-CESR-002-N-001` | `TC-ENC-CESR-002-B-001` | `packet_hex,decoded_fields,error_code` |
| ENC-PAY-001 | AS-ENC-PAY-001-001 | Encoding | P0 | `TC-ENC-PAY-001-P-001` | `TC-ENC-PAY-001-N-001` | `TC-ENC-PAY-001-B-001` | `packet_hex,decoded_fields,error_code` |
| ENC-PAY-002 | AS-ENC-PAY-002-001 | Encoding | P0 | `TC-ENC-PAY-002-P-001` | `TC-ENC-PAY-002-N-001` | `TC-ENC-PAY-002-B-001` | `packet_hex,decoded_fields,error_code` |
| ENC-PAY-003 | AS-ENC-PAY-003-001 | Encoding | P0 | `TC-ENC-PAY-003-P-001` | `TC-ENC-PAY-003-N-001` | `TC-ENC-PAY-003-B-001` | `packet_hex,decoded_fields,error_code` |
| ENC-PARSE-001 | AS-ENC-PARSE-001-001 | Encoding | P0 | `TC-ENC-PARSE-001-P-001` | `TC-ENC-PARSE-001-N-001` | `TC-ENC-PARSE-001-B-001` | `packet_hex,error_code` |
| ENC-BOUND-001 | AS-ENC-BOUND-001-001 | Encoding | P0 | `TC-ENC-BOUND-001-P-001` | `TC-ENC-BOUND-001-N-001` | `TC-ENC-BOUND-001-B-001` | `packet_hex,error_code` |
| TRN-INTF-001 | AS-TRN-INTF-001-001 | Transport | P0 | `TC-TRN-INTF-001-P-001` | `TC-TRN-INTF-001-N-001` | `TC-TRN-INTF-001-B-001` | `trace_ref,error_code` |
| TRN-INTF-002 | AS-TRN-INTF-002-001 | Transport | P0 | `TC-TRN-INTF-002-P-001` | `TC-TRN-INTF-002-N-001` | `TC-TRN-INTF-002-B-001` | `trace_ref,error_code` |
| TRN-INTF-003 | AS-TRN-INTF-003-001 | Transport | P0 | `TC-TRN-INTF-003-P-001` | `TC-TRN-INTF-003-N-001` | `TC-TRN-INTF-003-B-001` | `trace_ref,error_code` |
| TRN-INTF-004 | AS-TRN-INTF-004-001 | Transport | P1 | `TC-TRN-INTF-004-P-001` | `TC-TRN-INTF-004-N-001` | `TC-TRN-INTF-004-B-001` | `implementation_profile,trace_ref` |
| ERR-UNSP-001 | AS-ERR-UNSP-001-001 | ErrorHandling | P1 | `TC-ERR-UNSP-001-P-001` | `TC-ERR-UNSP-001-N-001` | `TC-ERR-UNSP-001-B-001` | `error_code,trace_ref` |
| ERR-UNSP-002 | AS-ERR-UNSP-002-001 | ErrorHandling | P1 | `TC-ERR-UNSP-002-P-001` | `TC-ERR-UNSP-002-N-001` | `TC-ERR-UNSP-002-B-001` | `error_code,trace_ref` |
| ERR-VAL-001 | AS-ERR-VAL-001-001 | ErrorHandling | P0 | `TC-ERR-VAL-001-P-001` | `TC-ERR-VAL-001-N-001` | `TC-ERR-VAL-001-B-001` | `error_code,packet_hex` |

## Matrix Completion Rules

1. All `MUST` clauses require at least `P` and `N` cases before implementation starts.
2. `B` cases are required for every parser, framing, and cryptography clause.
3. A test cannot move to executable backlog without all required evidence keys defined.
4. Clause rows marked `P0` are mandatory for baseline conformance profile `TSP-REV2-CORE`.
