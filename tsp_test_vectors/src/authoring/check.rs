use crate::authoring::candidate::{
    CiphertextFamilyCandidate, DigestMismatchCandidate, DirectAcceptCandidate,
    DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate, NestedAcceptCandidate,
    NestedMessageCandidate, NestedRequestCandidate, NestedWithoutOuterCandidate,
    NoPriorRelationshipCandidate, NonConfidentialBindingCandidate, RoutedAcceptCandidate,
    RoutedMessageCandidate, RoutedPathCandidate, RoutedRequestCandidate,
    SenderFieldMechanismCandidate,
};

fn require_nonempty(field_name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field_name} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_case_vector_wire(
    case_id: &str,
    vector_id: &str,
    wire_base64: &str,
) -> Result<(), String> {
    require_nonempty("case_id", case_id)?;
    require_nonempty("vector_id", vector_id)?;
    require_nonempty("wire_base64", wire_base64)
}

pub fn check_direct_request_candidate(candidate: &DirectRequestCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("nonce", &candidate.nonce)
}

pub fn check_direct_accept_candidate(candidate: &DirectAcceptCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("reply_digest", &candidate.reply_digest)
}

pub fn check_direct_rfd_candidate(candidate: &DirectRfdCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("digest", &candidate.digest)?;
    require_nonempty("reviewed_context", &candidate.reviewed_context)
}

pub fn check_digest_mismatch_candidate(candidate: &DigestMismatchCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty(
        "expected_request_digest",
        &candidate.expected_request_digest,
    )?;
    require_nonempty(
        "mismatching_accept_digest",
        &candidate.mismatching_accept_digest,
    )?;
    if candidate.expected_request_digest == candidate.mismatching_accept_digest {
        Err("expected_request_digest must differ from mismatching_accept_digest".into())
    } else {
        Ok(())
    }
}

pub fn check_nonconfidential_binding_candidate(
    candidate: &NonConfidentialBindingCandidate,
) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("nonconfidential_data", &candidate.nonconfidential_data)
}

pub fn check_sender_field_mechanism_candidate(
    candidate: &SenderFieldMechanismCandidate,
) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty(
        "confidentiality_mechanism",
        &candidate.confidentiality_mechanism,
    )?;
    require_nonempty("sender_field_rule", &candidate.sender_field_rule)
}

pub fn check_ciphertext_family_candidate(
    candidate: &CiphertextFamilyCandidate,
) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty(
        "confidentiality_mechanism",
        &candidate.confidentiality_mechanism,
    )?;
    require_nonempty("cesr_ciphertext_family", &candidate.cesr_ciphertext_family)
}

pub fn check_direct_message_candidate(candidate: &DirectMessageCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty(
        "relationship_context_ref",
        &candidate.relationship_context_ref,
    )?;
    require_nonempty("payload_semantics_ref", &candidate.payload_semantics_ref)?;
    require_nonempty("sender", &candidate.sender)?;
    require_nonempty("receiver", &candidate.receiver)?;
    require_nonempty("nonconfidential_data", &candidate.nonconfidential_data)?;
    require_nonempty("payload", &candidate.payload)?;
    require_nonempty("crypto_type", &candidate.crypto_type)?;
    require_nonempty("signature_type", &candidate.signature_type)
}

pub fn check_nested_request_candidate(candidate: &NestedRequestCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("nonce", &candidate.nonce)?;
    require_nonempty("inner_vid", &candidate.inner_vid)?;
    require_nonempty(
        "inner_verification_key_jwk",
        &candidate.inner_verification_key_jwk,
    )?;
    require_nonempty(
        "inner_encryption_key_jwk",
        &candidate.inner_encryption_key_jwk,
    )?;
    require_nonempty("inner_private_vid_json", &candidate.inner_private_vid_json)?;
    require_nonempty("outer_context_ref", &candidate.outer_context_ref)
}

pub fn check_nested_accept_candidate(candidate: &NestedAcceptCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("reply_digest", &candidate.reply_digest)?;
    require_nonempty("inner_vid", &candidate.inner_vid)?;
    require_nonempty(
        "inner_verification_key_jwk",
        &candidate.inner_verification_key_jwk,
    )?;
    require_nonempty(
        "inner_encryption_key_jwk",
        &candidate.inner_encryption_key_jwk,
    )?;
    require_nonempty("inner_private_vid_json", &candidate.inner_private_vid_json)?;
    require_nonempty("outer_context_ref", &candidate.outer_context_ref)
}

pub fn check_routed_path_candidate(candidate: &RoutedPathCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("current_hop_vid", &candidate.current_hop_vid)?;
    require_nonempty("next_hop_vid", &candidate.next_hop_vid)?;
    require_nonempty("remaining_route_json", &candidate.remaining_route_json)?;
    require_nonempty("opaque_payload_base64", &candidate.opaque_payload_base64)
}

pub fn check_routed_request_candidate(candidate: &RoutedRequestCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("nonce", &candidate.nonce)?;
    require_nonempty("path_context_ref", &candidate.path_context_ref)?;
    require_nonempty("sender_vid", &candidate.sender_vid)?;
    require_nonempty("receiver_vid", &candidate.receiver_vid)
}

pub fn check_routed_accept_candidate(candidate: &RoutedAcceptCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("request_digest", &candidate.request_digest)?;
    require_nonempty("reply_digest", &candidate.reply_digest)?;
    require_nonempty("path_context_ref", &candidate.path_context_ref)
}

pub fn check_routed_message_candidate(candidate: &RoutedMessageCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("path_context_ref", &candidate.path_context_ref)?;
    require_nonempty("payload_semantics_ref", &candidate.payload_semantics_ref)?;
    require_nonempty("sender", &candidate.sender)?;
    require_nonempty("receiver", &candidate.receiver)?;
    require_nonempty("nonconfidential_data", &candidate.nonconfidential_data)?;
    require_nonempty("payload", &candidate.payload)?;
    require_nonempty("crypto_type", &candidate.crypto_type)?;
    require_nonempty("signature_type", &candidate.signature_type)
}

pub fn check_nested_message_candidate(candidate: &NestedMessageCandidate) -> Result<(), String> {
    require_case_vector_wire(
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    require_nonempty("outer_context_ref", &candidate.outer_context_ref)?;
    require_nonempty("inner_context_ref", &candidate.inner_context_ref)?;
    if candidate.outer_context_ref == candidate.inner_context_ref {
        return Err("outer_context_ref must differ from inner_context_ref".into());
    }
    require_nonempty("payload_semantics_ref", &candidate.payload_semantics_ref)?;
    require_nonempty(
        "inner_sender_owned_vid_json",
        &candidate.inner_sender_owned_vid_json,
    )?;
    require_nonempty(
        "inner_receiver_owned_vid_json",
        &candidate.inner_receiver_owned_vid_json,
    )?;
    require_nonempty("sender", &candidate.sender)?;
    require_nonempty("receiver", &candidate.receiver)?;
    require_nonempty("nonconfidential_data", &candidate.nonconfidential_data)?;
    require_nonempty("payload", &candidate.payload)?;
    require_nonempty("crypto_type", &candidate.crypto_type)?;
    require_nonempty("signature_type", &candidate.signature_type)
}

pub fn check_no_prior_relationship_candidate(
    candidate: &NoPriorRelationshipCandidate,
) -> Result<(), String> {
    require_nonempty("case_id", &candidate.case_id)?;
    require_nonempty("vector_id", &candidate.vector_id)?;
    require_nonempty("source_vector_ref", &candidate.source_vector_ref)?;
    require_nonempty("source_binding_ref", &candidate.source_binding_ref)?;
    require_nonempty("source_fixture_ref", &candidate.source_fixture_ref)?;
    require_nonempty("source_wire_base64", &candidate.source_wire_base64)?;
    if candidate.authorization_state != "no-prior-relationship" {
        return Err("authorization_state must be no-prior-relationship".into());
    }
    if candidate.relationship_context_ref != "absent" {
        return Err("relationship_context_ref must be absent".into());
    }
    require_nonempty("payload_semantics_ref", &candidate.payload_semantics_ref)?;
    Ok(())
}

pub fn check_nested_without_outer_candidate(
    candidate: &NestedWithoutOuterCandidate,
) -> Result<(), String> {
    require_nonempty("case_id", &candidate.case_id)?;
    require_nonempty("vector_id", &candidate.vector_id)?;
    require_nonempty("source_vector_ref", &candidate.source_vector_ref)?;
    require_nonempty("source_binding_ref", &candidate.source_binding_ref)?;
    require_nonempty("source_fixture_ref", &candidate.source_fixture_ref)?;
    require_nonempty("source_wire_base64", &candidate.source_wire_base64)?;
    if !candidate.missing_outer_context {
        return Err("missing_outer_context must be true".into());
    }
    if candidate.outer_context_ref != "absent" {
        return Err("outer_context_ref must be absent".into());
    }
    require_nonempty("inner_context_ref", &candidate.inner_context_ref)?;
    require_nonempty("payload_semantics_ref", &candidate.payload_semantics_ref)
}

#[cfg(test)]
mod tests {
    use super::{
        check_digest_mismatch_candidate, check_direct_request_candidate,
        check_nested_message_candidate, check_nested_without_outer_candidate,
        check_no_prior_relationship_candidate,
    };
    use crate::authoring::candidate::{
        DigestMismatchCandidate, DirectRequestCandidate, NestedMessageCandidate,
        NestedWithoutOuterCandidate, NoPriorRelationshipCandidate,
    };

    #[test]
    fn direct_request_check_rejects_empty_nonce() {
        let candidate = DirectRequestCandidate {
            case_id: "CC-001".into(),
            vector_id: "BV-001".into(),
            wire_base64: "d2lyZQ==".into(),
            request_digest: "abcd".into(),
            nonce: String::new(),
        };
        assert_eq!(
            check_direct_request_candidate(&candidate),
            Err("nonce must not be empty".into())
        );
    }

    #[test]
    fn digest_mismatch_check_rejects_equal_digests() {
        let candidate = DigestMismatchCandidate {
            case_id: "CC-001".into(),
            vector_id: "SV-005".into(),
            wire_base64: "d2lyZQ==".into(),
            expected_request_digest: "same".into(),
            mismatching_accept_digest: "same".into(),
        };
        assert_eq!(
            check_digest_mismatch_candidate(&candidate),
            Err("expected_request_digest must differ from mismatching_accept_digest".into())
        );
    }

    #[test]
    fn nested_message_check_rejects_same_outer_and_inner_context() {
        let candidate = NestedMessageCandidate {
            case_id: "CC-001".into(),
            vector_id: "SV-002".into(),
            wire_base64: "d2lyZQ==".into(),
            outer_context_ref: "ctx.same".into(),
            inner_context_ref: "ctx.same".into(),
            payload_semantics_ref: "payload.ref".into(),
            inner_sender_owned_vid_json: "{}".into(),
            inner_receiver_owned_vid_json: "{}".into(),
            sender: "did:example:alice".into(),
            receiver: "did:example:bob".into(),
            nonconfidential_data: "00".into(),
            payload: "6869".into(),
            crypto_type: "hpke-auth".into(),
            signature_type: "ed25519".into(),
        };
        assert_eq!(
            check_nested_message_candidate(&candidate),
            Err("outer_context_ref must differ from inner_context_ref".into())
        );
    }

    #[test]
    fn no_prior_relationship_check_requires_absent_relationship_context() {
        let candidate = NoPriorRelationshipCandidate {
            case_id: "CC-001".into(),
            vector_id: "SV-004".into(),
            source_vector_ref: "artifact.cc-001.vector.SV-001.wire".into(),
            source_binding_ref: "artifact.cc-001.binding.direct.message-01".into(),
            source_fixture_ref: "fixture.conversation.direct.message-01".into(),
            source_wire_base64: "d2lyZQ==".into(),
            authorization_state: "no-prior-relationship".into(),
            relationship_context_ref: "ctx.direct.01".into(),
            payload_semantics_ref: "payload.direct.01".into(),
        };
        assert_eq!(
            check_no_prior_relationship_candidate(&candidate),
            Err("relationship_context_ref must be absent".into())
        );
    }

    #[test]
    fn nested_without_outer_check_requires_inner_context() {
        let candidate = NestedWithoutOuterCandidate {
            case_id: "CC-001".into(),
            vector_id: "SV-006".into(),
            source_vector_ref: "artifact.cc-001.vector.SV-002.wire".into(),
            source_binding_ref: "artifact.cc-001.binding.negative.nested-without-outer-01".into(),
            source_fixture_ref: "fixture.conversation.negative.nested-without-outer-01".into(),
            source_wire_base64: "d2lyZQ==".into(),
            missing_outer_context: true,
            outer_context_ref: "absent".into(),
            inner_context_ref: String::new(),
            payload_semantics_ref: "payload.nested.01".into(),
        };
        assert_eq!(
            check_nested_without_outer_candidate(&candidate),
            Err("inner_context_ref must not be empty".into())
        );
    }
}
