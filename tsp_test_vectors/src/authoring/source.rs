use crate::authoring::{
    CandidateIdentity, CiphertextFamilyCandidate, DigestMismatchCandidate, DirectAcceptCandidate,
    DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate, NestedAcceptCandidate,
    NestedMessageCandidate, NestedRequestCandidate, NestedWithoutOuterCandidate,
    NoPriorRelationshipCandidate, NonConfidentialBindingCandidate, RoutedAcceptCandidate,
    RoutedMessageCandidate, RoutedPathCandidate, RoutedRequestCandidate,
    SenderFieldMechanismCandidate,
};

/// The origin of a structured candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateSourceKind {
    /// Candidate values produced by exercising an implementation such as
    /// `tsp_sdk`.
    Sdk,
    /// Candidate values produced directly from spec-faithful logic in
    /// `tsp_test_vectors`.
    Spec,
}

/// Minimal provenance attached to a structured candidate value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateProvenance {
    pub kind: CandidateSourceKind,
    pub source_name: String,
    pub case_id: String,
    pub vector_id: String,
}

impl CandidateProvenance {
    pub fn new(
        kind: CandidateSourceKind,
        source_name: impl Into<String>,
        case_id: impl Into<String>,
        vector_id: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            source_name: source_name.into(),
            case_id: case_id.into(),
            vector_id: vector_id.into(),
        }
    }
}

/// Structured candidate paired with its provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcedCandidate<T> {
    pub provenance: CandidateProvenance,
    pub candidate: T,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseVectorRequest {
    pub case_id: String,
    pub vector_id: String,
}

impl CaseVectorRequest {
    pub fn new(case_id: impl Into<String>, vector_id: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            vector_id: vector_id.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoPriorRelationshipRequest {
    pub case_id: String,
    pub source_vector_ref: String,
    pub source_binding_ref: String,
    pub source_fixture_ref: String,
    pub source_wire_base64: String,
    pub payload_semantics_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedWithoutOuterRequest {
    pub case_id: String,
    pub source_vector_ref: String,
    pub source_binding_ref: String,
    pub source_fixture_ref: String,
    pub source_wire_base64: String,
    pub inner_context_ref: String,
    pub payload_semantics_ref: String,
}

impl<T> SourcedCandidate<T> {
    pub fn new(provenance: CandidateProvenance, candidate: T) -> Self {
        Self {
            provenance,
            candidate,
        }
    }
}

pub trait CandidateSourceMetadata {
    fn source_kind(&self) -> CandidateSourceKind;
    fn source_name(&self) -> &str;
}

/// Transitional direct-control source family.
///
/// The current legacy implementation still consumes SDK stdout. Future SDK-backed
/// and spec-backed sources may expose richer constructors while keeping the same
/// candidate family boundary.
pub trait DirectControlSource: CandidateSourceMetadata {
    fn direct_request_candidate(
        &self,
        candidate: DirectRequestCandidate,
    ) -> Result<SourcedCandidate<DirectRequestCandidate>, String>;

    fn direct_accept_candidate(
        &self,
        candidate: DirectAcceptCandidate,
    ) -> Result<SourcedCandidate<DirectAcceptCandidate>, String>;

    fn direct_rfd_candidate(
        &self,
        candidate: DirectRfdCandidate,
    ) -> Result<SourcedCandidate<DirectRfdCandidate>, String>;

    fn digest_mismatch_candidate(
        &self,
        candidate: DigestMismatchCandidate,
    ) -> Result<SourcedCandidate<DigestMismatchCandidate>, String>;

    fn nonconfidential_binding_candidate(
        &self,
        candidate: NonConfidentialBindingCandidate,
    ) -> Result<SourcedCandidate<NonConfidentialBindingCandidate>, String>;

    fn sender_field_mechanism_candidate(
        &self,
        candidate: SenderFieldMechanismCandidate,
    ) -> Result<SourcedCandidate<SenderFieldMechanismCandidate>, String>;

    fn ciphertext_family_candidate(
        &self,
        candidate: CiphertextFamilyCandidate,
    ) -> Result<SourcedCandidate<CiphertextFamilyCandidate>, String>;
}

pub trait NestedControlSource: CandidateSourceMetadata {
    fn nested_request_candidate(
        &self,
        candidate: NestedRequestCandidate,
    ) -> Result<SourcedCandidate<NestedRequestCandidate>, String>;

    fn nested_accept_candidate(
        &self,
        candidate: NestedAcceptCandidate,
    ) -> Result<SourcedCandidate<NestedAcceptCandidate>, String>;
}

pub trait RoutedControlSource: CandidateSourceMetadata {
    fn routed_path_candidate(
        &self,
        candidate: RoutedPathCandidate,
    ) -> Result<SourcedCandidate<RoutedPathCandidate>, String>;

    fn routed_request_candidate(
        &self,
        candidate: RoutedRequestCandidate,
    ) -> Result<SourcedCandidate<RoutedRequestCandidate>, String>;

    fn routed_accept_candidate(
        &self,
        candidate: RoutedAcceptCandidate,
    ) -> Result<SourcedCandidate<RoutedAcceptCandidate>, String>;
}

pub trait MessageSource: CandidateSourceMetadata {
    fn direct_message_candidate(
        &self,
        candidate: DirectMessageCandidate,
    ) -> Result<SourcedCandidate<DirectMessageCandidate>, String>;

    fn nested_message_candidate(
        &self,
        candidate: NestedMessageCandidate,
    ) -> Result<SourcedCandidate<NestedMessageCandidate>, String>;

    fn routed_message_candidate(
        &self,
        candidate: RoutedMessageCandidate,
    ) -> Result<SourcedCandidate<RoutedMessageCandidate>, String>;
}

pub trait NegativeDerivationSource: CandidateSourceMetadata {
    fn no_prior_relationship_candidate(
        &self,
        request: &NoPriorRelationshipRequest,
    ) -> Result<SourcedCandidate<NoPriorRelationshipCandidate>, String>;

    fn nested_without_outer_candidate(
        &self,
        request: &NestedWithoutOuterRequest,
    ) -> Result<SourcedCandidate<NestedWithoutOuterCandidate>, String>;
}

/// Reserved home for future SDK-backed structured candidate generation.
///
/// This type marks the intended long-term source boundary without requiring the
/// current PR to move SDK generation logic out of `tsp_sdk`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkCandidateSource {
    pub source_name: String,
}

impl SdkCandidateSource {
    pub fn new(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
        }
    }

    fn source_candidate<T>(&self, candidate: T) -> Result<SourcedCandidate<T>, String>
    where
        T: CandidateIdentity,
    {
        sourced_from_structured_candidate(self.source_kind(), &self.source_name, candidate)
    }
}

/// Reserved home for future spec-backed structured candidate generation.
///
/// This source is the place where `tsp_test_vectors` should implement
/// spec-faithful candidate generation when SDK behavior is known to diverge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecCandidateSource {
    pub source_name: String,
}

impl SpecCandidateSource {
    pub fn new(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
        }
    }

    fn spec_candidate<T>(
        &self,
        case_id: &str,
        vector_id: &str,
        candidate: T,
    ) -> SourcedCandidate<T> {
        let provenance = CandidateProvenance::new(
            CandidateSourceKind::Spec,
            &self.source_name,
            case_id,
            vector_id,
        );
        SourcedCandidate::new(provenance, candidate)
    }
}

impl CandidateSourceMetadata for SdkCandidateSource {
    fn source_kind(&self) -> CandidateSourceKind {
        CandidateSourceKind::Sdk
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

impl CandidateSourceMetadata for SpecCandidateSource {
    fn source_kind(&self) -> CandidateSourceKind {
        CandidateSourceKind::Spec
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }
}

impl DirectControlSource for SdkCandidateSource {
    fn direct_request_candidate(
        &self,
        candidate: DirectRequestCandidate,
    ) -> Result<SourcedCandidate<DirectRequestCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn direct_accept_candidate(
        &self,
        candidate: DirectAcceptCandidate,
    ) -> Result<SourcedCandidate<DirectAcceptCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn direct_rfd_candidate(
        &self,
        candidate: DirectRfdCandidate,
    ) -> Result<SourcedCandidate<DirectRfdCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn digest_mismatch_candidate(
        &self,
        candidate: DigestMismatchCandidate,
    ) -> Result<SourcedCandidate<DigestMismatchCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn nonconfidential_binding_candidate(
        &self,
        candidate: NonConfidentialBindingCandidate,
    ) -> Result<SourcedCandidate<NonConfidentialBindingCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn sender_field_mechanism_candidate(
        &self,
        candidate: SenderFieldMechanismCandidate,
    ) -> Result<SourcedCandidate<SenderFieldMechanismCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn ciphertext_family_candidate(
        &self,
        candidate: CiphertextFamilyCandidate,
    ) -> Result<SourcedCandidate<CiphertextFamilyCandidate>, String> {
        self.source_candidate(candidate)
    }
}

impl NestedControlSource for SdkCandidateSource {
    fn nested_request_candidate(
        &self,
        candidate: NestedRequestCandidate,
    ) -> Result<SourcedCandidate<NestedRequestCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn nested_accept_candidate(
        &self,
        candidate: NestedAcceptCandidate,
    ) -> Result<SourcedCandidate<NestedAcceptCandidate>, String> {
        self.source_candidate(candidate)
    }
}

impl RoutedControlSource for SdkCandidateSource {
    fn routed_path_candidate(
        &self,
        candidate: RoutedPathCandidate,
    ) -> Result<SourcedCandidate<RoutedPathCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn routed_request_candidate(
        &self,
        candidate: RoutedRequestCandidate,
    ) -> Result<SourcedCandidate<RoutedRequestCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn routed_accept_candidate(
        &self,
        candidate: RoutedAcceptCandidate,
    ) -> Result<SourcedCandidate<RoutedAcceptCandidate>, String> {
        self.source_candidate(candidate)
    }
}

impl MessageSource for SdkCandidateSource {
    fn direct_message_candidate(
        &self,
        candidate: DirectMessageCandidate,
    ) -> Result<SourcedCandidate<DirectMessageCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn nested_message_candidate(
        &self,
        candidate: NestedMessageCandidate,
    ) -> Result<SourcedCandidate<NestedMessageCandidate>, String> {
        self.source_candidate(candidate)
    }

    fn routed_message_candidate(
        &self,
        candidate: RoutedMessageCandidate,
    ) -> Result<SourcedCandidate<RoutedMessageCandidate>, String> {
        self.source_candidate(candidate)
    }
}

impl NegativeDerivationSource for SpecCandidateSource {
    fn no_prior_relationship_candidate(
        &self,
        request: &NoPriorRelationshipRequest,
    ) -> Result<SourcedCandidate<NoPriorRelationshipCandidate>, String> {
        let candidate = NoPriorRelationshipCandidate {
            case_id: request.case_id.clone(),
            vector_id: "SV-004".into(),
            source_vector_ref: request.source_vector_ref.clone(),
            source_binding_ref: request.source_binding_ref.clone(),
            source_fixture_ref: request.source_fixture_ref.clone(),
            source_wire_base64: request.source_wire_base64.clone(),
            authorization_state: "no-prior-relationship".into(),
            relationship_context_ref: "absent".into(),
            payload_semantics_ref: request.payload_semantics_ref.clone(),
        };
        Ok(self.spec_candidate(&request.case_id, "SV-004", candidate))
    }

    fn nested_without_outer_candidate(
        &self,
        request: &NestedWithoutOuterRequest,
    ) -> Result<SourcedCandidate<NestedWithoutOuterCandidate>, String> {
        let candidate = NestedWithoutOuterCandidate {
            case_id: request.case_id.clone(),
            vector_id: "SV-006".into(),
            source_vector_ref: request.source_vector_ref.clone(),
            source_binding_ref: request.source_binding_ref.clone(),
            source_fixture_ref: request.source_fixture_ref.clone(),
            source_wire_base64: request.source_wire_base64.clone(),
            missing_outer_context: true,
            outer_context_ref: "absent".into(),
            inner_context_ref: request.inner_context_ref.clone(),
            payload_semantics_ref: request.payload_semantics_ref.clone(),
        };
        Ok(self.spec_candidate(&request.case_id, "SV-006", candidate))
    }
}

fn sourced_from_structured_candidate<T>(
    source_kind: CandidateSourceKind,
    source_name: &str,
    candidate: T,
) -> Result<SourcedCandidate<T>, String>
where
    T: CandidateIdentity,
{
    let provenance = CandidateProvenance::new(
        source_kind,
        source_name,
        candidate.case_id(),
        candidate.vector_id(),
    );
    Ok(SourcedCandidate::new(provenance, candidate))
}

#[cfg(test)]
mod tests {
    use super::sourced_from_structured_candidate;
    use super::{
        CandidateProvenance, CandidateSourceKind, CandidateSourceMetadata, CaseVectorRequest,
        DirectControlSource, NegativeDerivationSource, NestedWithoutOuterRequest,
        NoPriorRelationshipRequest, SdkCandidateSource, SourcedCandidate, SpecCandidateSource,
    };
    use crate::authoring::DirectRequestCandidate;

    #[test]
    fn sourced_candidate_retains_provenance() {
        let sourced = SourcedCandidate::new(
            CandidateProvenance::new(
                CandidateSourceKind::Sdk,
                "legacy-sdk-stdout",
                "CC-001",
                "BV-001",
            ),
            "candidate-bytes".to_string(),
        );

        assert_eq!(sourced.provenance.kind, CandidateSourceKind::Sdk);
        assert_eq!(sourced.provenance.source_name, "legacy-sdk-stdout");
        assert_eq!(sourced.provenance.case_id, "CC-001");
        assert_eq!(sourced.provenance.vector_id, "BV-001");
        assert_eq!(sourced.candidate, "candidate-bytes");
    }

    #[test]
    fn sdk_source_can_wrap_structured_direct_candidate_without_legacy_stdout() {
        let source = SdkCandidateSource::new("sdk-structured");
        let sourced = DirectControlSource::direct_request_candidate(
            &source,
            DirectRequestCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-001".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                nonce: "def456".into(),
            },
        )
        .unwrap();

        assert_eq!(sourced.provenance.kind, CandidateSourceKind::Sdk);
        assert_eq!(sourced.provenance.source_name, "sdk-structured");
        assert_eq!(sourced.provenance.case_id, "CC-001");
        assert_eq!(sourced.provenance.vector_id, "BV-001");
    }

    #[test]
    fn spec_source_reserves_distinct_provenance_kind() {
        let source = SpecCandidateSource::new("spec-authoring");

        assert_eq!(source.source_kind(), CandidateSourceKind::Spec);
        assert_eq!(source.source_name(), "spec-authoring");
    }

    #[test]
    fn spec_source_can_derive_group_e_negative_candidates() {
        let source = SpecCandidateSource::new("spec-authoring");

        let sv004 = source
            .no_prior_relationship_candidate(&NoPriorRelationshipRequest {
                case_id: "CC-001".into(),
                source_vector_ref: "artifact.cc-001.vector.SV-001.wire".into(),
                source_binding_ref: "artifact.cc-001.binding.direct.message-01".into(),
                source_fixture_ref: "fixture.conversation.direct.message-01".into(),
                source_wire_base64: "Zm9v".into(),
                payload_semantics_ref: "cc001-direct-message-01".into(),
            })
            .unwrap();
        assert_eq!(sv004.provenance.kind, CandidateSourceKind::Spec);
        assert_eq!(sv004.provenance.vector_id, "SV-004");
        assert_eq!(sv004.candidate.relationship_context_ref, "absent");

        let sv006 = source
            .nested_without_outer_candidate(&NestedWithoutOuterRequest {
                case_id: "CC-001".into(),
                source_vector_ref: "artifact.cc-001.vector.SV-002.wire".into(),
                source_binding_ref: "artifact.cc-001.binding.nested.message-01".into(),
                source_fixture_ref: "fixture.conversation.nested.message-01".into(),
                source_wire_base64: "YmFy".into(),
                inner_context_ref: "ctx.inner.01".into(),
                payload_semantics_ref: "cc001-nested-message-01".into(),
            })
            .unwrap();
        assert_eq!(sv006.provenance.kind, CandidateSourceKind::Spec);
        assert_eq!(sv006.provenance.vector_id, "SV-006");
        assert!(sv006.candidate.missing_outer_context);
        assert_eq!(
            sv006.candidate.payload_semantics_ref,
            "cc001-nested-message-01"
        );
    }

    #[test]
    fn case_vector_request_is_typed_and_not_raw_stdout() {
        let request = CaseVectorRequest::new("CC-001", "BV-001");
        assert_eq!(request.case_id, "CC-001");
        assert_eq!(request.vector_id, "BV-001");
    }

    #[test]
    fn structured_candidate_sourcing_keeps_original_identity() {
        let sourced = sourced_from_structured_candidate(
            CandidateSourceKind::Sdk,
            "sdk-structured",
            DirectRequestCandidate {
                case_id: "CC-002".into(),
                vector_id: "BV-001".into(),
                wire_base64: "YmFy".into(),
                request_digest: "abcd".into(),
                nonce: "efgh".into(),
            },
        )
        .unwrap();

        assert_eq!(sourced.provenance.case_id, "CC-002");
        assert_eq!(sourced.provenance.vector_id, "BV-001");
        assert_eq!(sourced.candidate.request_digest, "abcd");
    }
}
