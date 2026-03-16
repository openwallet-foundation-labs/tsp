pub trait CandidateIdentity {
    fn case_id(&self) -> &str;
    fn vector_id(&self) -> &str;
}

macro_rules! impl_candidate_identity {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CandidateIdentity for $ty {
                fn case_id(&self) -> &str {
                    &self.case_id
                }

                fn vector_id(&self) -> &str {
                    &self.vector_id
                }
            }
        )+
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectRequestCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectAcceptCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub reply_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectRfdCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub digest: String,
    pub reviewed_context: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestMismatchCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub expected_request_digest: String,
    pub mismatching_accept_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonConfidentialBindingCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub nonconfidential_data: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderFieldMechanismCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub confidentiality_mechanism: String,
    pub sender_field_rule: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CiphertextFamilyCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub confidentiality_mechanism: String,
    pub cesr_ciphertext_family: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectMessageCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub relationship_context_ref: String,
    pub payload_semantics_ref: String,
    pub sender: String,
    pub receiver: String,
    pub nonconfidential_data: String,
    pub payload: String,
    pub crypto_type: String,
    pub signature_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedRequestCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub nonce: String,
    pub inner_vid: String,
    pub inner_verification_key_jwk: String,
    pub inner_encryption_key_jwk: String,
    pub inner_private_vid_json: String,
    pub outer_context_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedAcceptCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub reply_digest: String,
    pub inner_vid: String,
    pub inner_verification_key_jwk: String,
    pub inner_encryption_key_jwk: String,
    pub inner_private_vid_json: String,
    pub outer_context_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedPathCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub current_hop_vid: String,
    pub next_hop_vid: String,
    pub remaining_route_json: String,
    pub opaque_payload_base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedRequestCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub nonce: String,
    pub path_context_ref: String,
    pub sender_vid: String,
    pub receiver_vid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedAcceptCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub request_digest: String,
    pub reply_digest: String,
    pub path_context_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedMessageCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub path_context_ref: String,
    pub payload_semantics_ref: String,
    pub sender: String,
    pub receiver: String,
    pub nonconfidential_data: String,
    pub payload: String,
    pub crypto_type: String,
    pub signature_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedMessageCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub wire_base64: String,
    pub outer_context_ref: String,
    pub inner_context_ref: String,
    pub payload_semantics_ref: String,
    pub inner_sender_owned_vid_json: String,
    pub inner_receiver_owned_vid_json: String,
    pub sender: String,
    pub receiver: String,
    pub nonconfidential_data: String,
    pub payload: String,
    pub crypto_type: String,
    pub signature_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoPriorRelationshipCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub source_vector_ref: String,
    pub source_binding_ref: String,
    pub source_fixture_ref: String,
    pub source_wire_base64: String,
    pub authorization_state: String,
    pub relationship_context_ref: String,
    pub payload_semantics_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedWithoutOuterCandidate {
    pub case_id: String,
    pub vector_id: String,
    pub source_vector_ref: String,
    pub source_binding_ref: String,
    pub source_fixture_ref: String,
    pub source_wire_base64: String,
    pub missing_outer_context: bool,
    pub outer_context_ref: String,
    pub inner_context_ref: String,
    pub payload_semantics_ref: String,
}

impl_candidate_identity!(
    DirectRequestCandidate,
    DirectAcceptCandidate,
    DirectRfdCandidate,
    DigestMismatchCandidate,
    NonConfidentialBindingCandidate,
    SenderFieldMechanismCandidate,
    CiphertextFamilyCandidate,
    DirectMessageCandidate,
    NestedRequestCandidate,
    NestedAcceptCandidate,
    RoutedPathCandidate,
    RoutedRequestCandidate,
    RoutedAcceptCandidate,
    RoutedMessageCandidate,
    NestedMessageCandidate,
    NoPriorRelationshipCandidate,
    NestedWithoutOuterCandidate,
);
