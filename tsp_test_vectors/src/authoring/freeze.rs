use crate::authoring::{
    CiphertextFamilyCandidate, DigestMismatchCandidate, DirectAcceptCandidate, DirectControlSource,
    DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate, MessageSource,
    NegativeDerivationSource, NestedAcceptCandidate, NestedControlSource, NestedMessageCandidate,
    NestedRequestCandidate, NestedWithoutOuterRequest, NoPriorRelationshipRequest,
    NonConfidentialBindingCandidate, PackageWriter, RoutedAcceptCandidate, RoutedControlSource,
    RoutedMessageCandidate, RoutedPathCandidate, RoutedRequestCandidate,
    SenderFieldMechanismCandidate, SourcedCandidate, write_ciphertext_family_candidate,
    write_digest_mismatch_candidate, write_direct_accept_candidate, write_direct_message_candidate,
    write_direct_request_candidate, write_direct_rfd_candidate, write_nested_accept_candidate,
    write_nested_message_candidate, write_nested_request_candidate,
    write_nested_without_outer_candidate, write_no_prior_relationship_candidate,
    write_nonconfidential_binding_candidate, write_routed_accept_candidate,
    write_routed_message_candidate, write_routed_path_candidate, write_routed_request_candidate,
    write_sender_field_mechanism_candidate,
};
use std::io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeResult {
    pub case_id: String,
    pub vector_id: String,
    pub source_name: String,
}

fn freeze_result_from_candidate<T>(sourced: &SourcedCandidate<T>) -> FreezeResult {
    FreezeResult {
        case_id: sourced.provenance.case_id.clone(),
        vector_id: sourced.provenance.vector_id.clone(),
        source_name: sourced.provenance.source_name.clone(),
    }
}

fn freeze_with_sourced_candidate<T, W>(
    sourced: Result<SourcedCandidate<T>, String>,
    write: W,
) -> io::Result<FreezeResult>
where
    W: FnOnce(&T) -> io::Result<()>,
{
    let sourced = sourced.map_err(io::Error::other)?;
    write(&sourced.candidate)?;
    Ok(freeze_result_from_candidate(&sourced))
}

pub fn freeze_direct_request_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: DirectRequestCandidate,
    sender_vid: &str,
    receiver_vid: &str,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(source.direct_request_candidate(candidate), |candidate| {
        write_direct_request_candidate(writer, candidate, sender_vid, receiver_vid)
    })
}

pub fn freeze_direct_message_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: DirectMessageCandidate,
) -> io::Result<FreezeResult>
where
    S: MessageSource,
{
    freeze_with_sourced_candidate(source.direct_message_candidate(candidate), |candidate| {
        write_direct_message_candidate(writer, candidate)
    })
}

pub fn freeze_direct_accept_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: DirectAcceptCandidate,
    sender_vid: &str,
    receiver_vid: &str,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(source.direct_accept_candidate(candidate), |candidate| {
        write_direct_accept_candidate(writer, candidate, sender_vid, receiver_vid)
    })
}

pub fn freeze_direct_rfd_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: DirectRfdCandidate,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(source.direct_rfd_candidate(candidate), |candidate| {
        write_direct_rfd_candidate(writer, candidate)
    })
}

pub fn freeze_digest_mismatch_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: DigestMismatchCandidate,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(source.digest_mismatch_candidate(candidate), |candidate| {
        write_digest_mismatch_candidate(writer, candidate)
    })
}

pub fn freeze_nonconfidential_binding_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: NonConfidentialBindingCandidate,
    confidentiality_mechanism: &str,
    binding_rule: &str,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(
        source.nonconfidential_binding_candidate(candidate),
        |candidate| {
            write_nonconfidential_binding_candidate(
                writer,
                candidate,
                confidentiality_mechanism,
                binding_rule,
            )
        },
    )
}

pub fn freeze_sender_field_mechanism_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: SenderFieldMechanismCandidate,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(
        source.sender_field_mechanism_candidate(candidate),
        |candidate| write_sender_field_mechanism_candidate(writer, candidate),
    )
}

pub fn freeze_ciphertext_family_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: CiphertextFamilyCandidate,
) -> io::Result<FreezeResult>
where
    S: DirectControlSource,
{
    freeze_with_sourced_candidate(source.ciphertext_family_candidate(candidate), |candidate| {
        write_ciphertext_family_candidate(writer, candidate)
    })
}

pub fn freeze_no_prior_relationship_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    request: &NoPriorRelationshipRequest,
) -> io::Result<FreezeResult>
where
    S: NegativeDerivationSource,
{
    freeze_with_sourced_candidate(
        source.no_prior_relationship_candidate(request),
        |candidate| write_no_prior_relationship_candidate(writer, candidate),
    )
}

pub fn freeze_nested_without_outer_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    request: &NestedWithoutOuterRequest,
) -> io::Result<FreezeResult>
where
    S: NegativeDerivationSource,
{
    freeze_with_sourced_candidate(
        source.nested_without_outer_candidate(request),
        |candidate| write_nested_without_outer_candidate(writer, candidate),
    )
}

pub fn freeze_nested_request_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: NestedRequestCandidate,
) -> io::Result<FreezeResult>
where
    S: NestedControlSource,
{
    freeze_with_sourced_candidate(source.nested_request_candidate(candidate), |candidate| {
        write_nested_request_candidate(writer, candidate)
    })
}

pub fn freeze_nested_accept_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: NestedAcceptCandidate,
    inner_receiver_vid: &str,
) -> io::Result<FreezeResult>
where
    S: NestedControlSource,
{
    freeze_with_sourced_candidate(source.nested_accept_candidate(candidate), |candidate| {
        write_nested_accept_candidate(writer, candidate, inner_receiver_vid)
    })
}

pub fn freeze_routed_path_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: RoutedPathCandidate,
) -> io::Result<FreezeResult>
where
    S: RoutedControlSource,
{
    freeze_with_sourced_candidate(source.routed_path_candidate(candidate), |candidate| {
        write_routed_path_candidate(writer, candidate)
    })
}

pub fn freeze_routed_request_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: RoutedRequestCandidate,
) -> io::Result<FreezeResult>
where
    S: RoutedControlSource,
{
    freeze_with_sourced_candidate(source.routed_request_candidate(candidate), |candidate| {
        write_routed_request_candidate(writer, candidate)
    })
}

pub fn freeze_routed_accept_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: RoutedAcceptCandidate,
) -> io::Result<FreezeResult>
where
    S: RoutedControlSource,
{
    freeze_with_sourced_candidate(source.routed_accept_candidate(candidate), |candidate| {
        write_routed_accept_candidate(writer, candidate)
    })
}

pub fn freeze_routed_message_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: RoutedMessageCandidate,
) -> io::Result<FreezeResult>
where
    S: MessageSource,
{
    freeze_with_sourced_candidate(source.routed_message_candidate(candidate), |candidate| {
        write_routed_message_candidate(writer, candidate)
    })
}

pub fn freeze_nested_message_from_source<S>(
    source: &S,
    writer: &PackageWriter,
    candidate: NestedMessageCandidate,
) -> io::Result<FreezeResult>
where
    S: MessageSource,
{
    freeze_with_sourced_candidate(source.nested_message_candidate(candidate), |candidate| {
        write_nested_message_candidate(writer, candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FreezeResult, freeze_digest_mismatch_from_source, freeze_direct_accept_from_source,
        freeze_direct_message_from_source, freeze_direct_request_from_source,
        freeze_direct_rfd_from_source, freeze_nested_accept_from_source,
        freeze_nested_message_from_source, freeze_nested_request_from_source,
        freeze_nested_without_outer_from_source, freeze_no_prior_relationship_from_source,
        freeze_nonconfidential_binding_from_source, freeze_routed_accept_from_source,
        freeze_routed_message_from_source, freeze_routed_path_from_source,
        freeze_routed_request_from_source,
    };
    use crate::authoring::{
        CasePackagePaths, CompleteCase, DigestMismatchCandidate, DirectAcceptCandidate,
        DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate, NestedAcceptCandidate,
        NestedMessageCandidate, NestedRequestCandidate, NestedWithoutOuterRequest,
        NoPriorRelationshipRequest, NonConfidentialBindingCandidate, PackageWriter,
        RoutedAcceptCandidate, RoutedMessageCandidate, RoutedPathCandidate, RoutedRequestCandidate,
        SdkCandidateSource, SpecCandidateSource,
    };
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tsp-test-vectors-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn freeze_direct_request_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-direct-request");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_direct_request_from_source(
            &source,
            &writer,
            DirectRequestCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-001".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                nonce: "def456".into(),
            },
            "did:web:alice.example",
            "did:web:bob.example",
        )
        .unwrap();

        assert_eq!(
            result,
            FreezeResult {
                case_id: "CC-001".into(),
                vector_id: "BV-001".into(),
                source_name: "sdk-structured".into(),
            }
        );
        assert!(writer.paths().vector_wire_path("BV-001").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Direct, "request-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_direct_message_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-direct-message");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_direct_message_from_source(
            &source,
            &writer,
            DirectMessageCandidate {
                case_id: "CC-001".into(),
                vector_id: "SV-001".into(),
                wire_base64: "Zm9v".into(),
                relationship_context_ref: "ctx.direct.01".into(),
                payload_semantics_ref: "payload.direct.01".into(),
                sender: "did:web:alice.example".into(),
                receiver: "did:web:bob.example".into(),
                nonconfidential_data: "00".into(),
                payload: "68656c6c6f".into(),
                crypto_type: "hpke-auth".into(),
                signature_type: "ed25519".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "SV-001");
        assert!(writer.paths().vector_wire_path("SV-001").exists());
    }

    #[test]
    fn freeze_group_e_negative_uses_spec_source_path() {
        let root = temp_root("freeze-sv004");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SpecCandidateSource::new("spec-structured");

        let result = freeze_no_prior_relationship_from_source(
            &source,
            &writer,
            &NoPriorRelationshipRequest {
                case_id: "CC-001".into(),
                source_vector_ref: "artifact.cc-001.vector.SV-001.wire".into(),
                source_binding_ref: "artifact.cc-001.binding.direct.message-01".into(),
                source_fixture_ref: "fixture.conversation.direct.message-01".into(),
                source_wire_base64: "Zm9v".into(),
                payload_semantics_ref: "cc001-direct-message-01".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "SV-004");
        assert!(writer.paths().vector_wire_path("SV-004").exists());
        assert!(
            writer
                .paths()
                .binding_path(
                    crate::authoring::BindingFamily::Negative,
                    "no-prior-relationship-01.yaml"
                )
                .exists()
        );
    }

    #[test]
    fn freeze_group_e_nested_without_outer_uses_spec_source_path() {
        let root = temp_root("freeze-sv006");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SpecCandidateSource::new("spec-structured");

        let result = freeze_nested_without_outer_from_source(
            &source,
            &writer,
            &NestedWithoutOuterRequest {
                case_id: "CC-001".into(),
                source_vector_ref: "artifact.cc-001.vector.SV-002.wire".into(),
                source_binding_ref: "artifact.cc-001.binding.nested.message-01".into(),
                source_fixture_ref: "fixture.conversation.nested.message-01".into(),
                source_wire_base64: "YmFy".into(),
                inner_context_ref: "cc001-inner-alice-1-bob-1-bidirectional".into(),
                payload_semantics_ref: "cc001-nested-message-01".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "SV-006");
        assert!(writer.paths().vector_wire_path("SV-006").exists());
        assert!(
            writer
                .paths()
                .binding_path(
                    crate::authoring::BindingFamily::Negative,
                    "nested-without-outer-01.yaml"
                )
                .exists()
        );
    }

    #[test]
    fn freeze_direct_accept_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-direct-accept");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_direct_accept_from_source(
            &source,
            &writer,
            DirectAcceptCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-002".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                reply_digest: "def456".into(),
            },
            "did:web:bob.example",
            "did:web:alice.example",
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-002");
        assert!(writer.paths().vector_wire_path("BV-002").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Direct, "accept-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_direct_rfd_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-direct-rfd");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_direct_rfd_from_source(
            &source,
            &writer,
            DirectRfdCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-003".into(),
                wire_base64: "Zm9v".into(),
                digest: "abc123".into(),
                reviewed_context: "decline-pending-request".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-003");
        assert!(writer.paths().vector_wire_path("BV-003").exists());
    }

    #[test]
    fn freeze_digest_mismatch_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-digest-mismatch");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_digest_mismatch_from_source(
            &source,
            &writer,
            DigestMismatchCandidate {
                case_id: "CC-001".into(),
                vector_id: "SV-005".into(),
                wire_base64: "Zm9v".into(),
                expected_request_digest: "abc123".into(),
                mismatching_accept_digest: "def456".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "SV-005");
        assert!(writer.paths().vector_wire_path("SV-005").exists());
    }

    #[test]
    fn freeze_nonconfidential_binding_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-av003");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_nonconfidential_binding_from_source(
            &source,
            &writer,
            NonConfidentialBindingCandidate {
                case_id: "CC-001".into(),
                vector_id: "AV-003".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                nonconfidential_data: "00".into(),
            },
            "hpke-auth",
            "non-confidential data is bound into ciphertext integrity scope",
        )
        .unwrap();

        assert_eq!(result.vector_id, "AV-003");
        assert!(writer.paths().vector_wire_path("AV-003").exists());
        assert!(
            writer
                .paths()
                .binding_path(
                    crate::authoring::BindingFamily::Mechanism,
                    "non-confidential-binding.yaml"
                )
                .exists()
        );
    }

    #[test]
    fn freeze_nested_request_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-nested-request");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_nested_request_from_source(
            &source,
            &writer,
            NestedRequestCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-004".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                nonce: "def456".into(),
                inner_vid: "did:peer:alice-1".into(),
                inner_verification_key_jwk: "{\"x\":\"sig\"}".into(),
                inner_encryption_key_jwk: "{\"x\":\"enc\"}".into(),
                inner_private_vid_json: "{\"id\":\"did:peer:alice-1\"}".into(),
                outer_context_ref: "outer.ctx.01".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-004");
        assert!(writer.paths().vector_wire_path("BV-004").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Nested, "request-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_nested_accept_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-nested-accept");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_nested_accept_from_source(
            &source,
            &writer,
            NestedAcceptCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-005".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                reply_digest: "def456".into(),
                inner_vid: "did:peer:bob-1".into(),
                inner_verification_key_jwk: "{\"x\":\"sig2\"}".into(),
                inner_encryption_key_jwk: "{\"x\":\"enc2\"}".into(),
                inner_private_vid_json: "{\"id\":\"did:peer:bob-1\"}".into(),
                outer_context_ref: "outer.ctx.01".into(),
            },
            "did:peer:alice-1",
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-005");
        assert!(writer.paths().vector_wire_path("BV-005").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Nested, "accept-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_routed_path_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-routed-path");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_routed_path_from_source(
            &source,
            &writer,
            RoutedPathCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-006".into(),
                wire_base64: "Zm9v".into(),
                current_hop_vid: "did:web:hop1.example".into(),
                next_hop_vid: "did:web:hop2.example".into(),
                remaining_route_json: "[\"did:web:hop2.example\",\"did:web:bob.example\"]".into(),
                opaque_payload_base64: "YmFy".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-006");
        assert!(writer.paths().vector_wire_path("BV-006").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Routed, "path-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_routed_request_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-routed-request");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_routed_request_from_source(
            &source,
            &writer,
            RoutedRequestCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-007".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                nonce: "def456".into(),
                path_context_ref: "path.ctx.01".into(),
                sender_vid: "did:web:alice.example".into(),
                receiver_vid: "did:web:bob.example".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-007");
        assert!(writer.paths().vector_wire_path("BV-007").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Routed, "request-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_routed_accept_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-routed-accept");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_routed_accept_from_source(
            &source,
            &writer,
            RoutedAcceptCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-008".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                reply_digest: "def456".into(),
                path_context_ref: "path.ctx.01".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "BV-008");
        assert!(writer.paths().vector_wire_path("BV-008").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Routed, "accept-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_routed_message_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-routed-message");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_routed_message_from_source(
            &source,
            &writer,
            RoutedMessageCandidate {
                case_id: "CC-001".into(),
                vector_id: "SV-003".into(),
                wire_base64: "Zm9v".into(),
                path_context_ref: "path.ctx.01".into(),
                payload_semantics_ref: "payload.route.01".into(),
                sender: "did:web:alice.example".into(),
                receiver: "did:web:bob.example".into(),
                nonconfidential_data: "00".into(),
                payload: "68656c6c6f".into(),
                crypto_type: "hpke-auth".into(),
                signature_type: "ed25519".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "SV-003");
        assert!(writer.paths().vector_wire_path("SV-003").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Routed, "message-01.yaml")
                .exists()
        );
    }

    #[test]
    fn freeze_nested_message_uses_structured_sdk_source_path() {
        let root = temp_root("freeze-nested-message");
        let paths = CasePackagePaths::new(root, CompleteCase::Cc001);
        paths.ensure_directory_layout().unwrap();
        let writer = PackageWriter::new(paths);
        let source = SdkCandidateSource::new("sdk-structured");

        let result = freeze_nested_message_from_source(
            &source,
            &writer,
            NestedMessageCandidate {
                case_id: "CC-001".into(),
                vector_id: "SV-002".into(),
                wire_base64: "Zm9v".into(),
                outer_context_ref: "outer.ctx.01".into(),
                inner_context_ref: "inner.ctx.01".into(),
                payload_semantics_ref: "payload.nested.01".into(),
                inner_sender_owned_vid_json:
                    "{\"id\":\"did:peer:alice-1\",\"publicSigkey\":\"sig\",\"publicEnckey\":\"enc\"}".into(),
                inner_receiver_owned_vid_json:
                    "{\"id\":\"did:peer:bob-1\",\"publicSigkey\":\"sig2\",\"publicEnckey\":\"enc2\"}".into(),
                sender: "did:peer:alice-1".into(),
                receiver: "did:peer:bob-1".into(),
                nonconfidential_data: "00".into(),
                payload: "68656c6c6f".into(),
                crypto_type: "hpke-auth".into(),
                signature_type: "ed25519".into(),
            },
        )
        .unwrap();

        assert_eq!(result.vector_id, "SV-002");
        assert!(writer.paths().vector_wire_path("SV-002").exists());
        assert!(
            writer
                .paths()
                .binding_path(crate::authoring::BindingFamily::Nested, "message-01.yaml")
                .exists()
        );
    }
}
