use crate::authoring::{
    BindingFamily, CasePackagePaths,
    candidate::{
        CiphertextFamilyCandidate, DigestMismatchCandidate, DirectAcceptCandidate,
        DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate, NestedAcceptCandidate,
        NestedMessageCandidate, NestedRequestCandidate, NestedWithoutOuterCandidate,
        NoPriorRelationshipCandidate, NonConfidentialBindingCandidate, RoutedAcceptCandidate,
        RoutedMessageCandidate, RoutedPathCandidate, RoutedRequestCandidate,
        SenderFieldMechanismCandidate,
    },
    check::{
        check_ciphertext_family_candidate, check_digest_mismatch_candidate,
        check_direct_accept_candidate, check_direct_message_candidate,
        check_direct_request_candidate, check_direct_rfd_candidate, check_nested_accept_candidate,
        check_nested_message_candidate, check_nested_request_candidate,
        check_nested_without_outer_candidate, check_nonconfidential_binding_candidate,
        check_routed_accept_candidate, check_routed_message_candidate, check_routed_path_candidate,
        check_routed_request_candidate, check_sender_field_mechanism_candidate,
    },
};
use serde_json::Value;
use std::{collections::BTreeMap, fs, io, path::Path};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VectorReviewRecord {
    pub vector_id: String,
    pub artifact_ref: String,
    pub review_status: String,
    pub reviewed_bindings: Vec<String>,
    pub review_notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BindingReviewRecord {
    pub binding_id: String,
    pub review_status: String,
    pub reviewed_for_vectors: Vec<String>,
    pub reviewed_for_fixtures: Vec<String>,
    pub value_checks: BTreeMap<String, String>,
    pub review_notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FixtureReviewRecord {
    pub fixture_id: String,
    pub artifact_ref: String,
    pub review_status: String,
    pub reviewed_for_bindings: Vec<String>,
    pub reviewed_for_vectors: Vec<String>,
    pub value_checks: BTreeMap<String, String>,
    pub review_notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConversationFixtureRecord {
    pub id: String,
    pub scope: String,
    pub scenario: String,
    pub sequence: String,
    pub related_identity_fixtures: Vec<String>,
    pub binding_material: BTreeMap<String, String>,
    pub used_by_vectors: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PackageWriter {
    paths: CasePackagePaths,
}

impl PackageWriter {
    pub fn new(paths: CasePackagePaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &CasePackagePaths {
        &self.paths
    }

    pub fn ensure_layout(&self) -> std::io::Result<()> {
        self.paths.ensure_directory_layout()
    }

    pub fn write_manifest_yaml(&self, yaml: &str) -> std::io::Result<()> {
        write_text_file(&self.paths.manifest_path(), yaml)
    }

    pub fn write_vector_wire(&self, vector_id: &str, wire_base64: &str) -> std::io::Result<()> {
        write_text_file(&self.paths.vector_wire_path(vector_id), wire_base64)
    }

    pub fn write_binding_yaml(
        &self,
        family: BindingFamily,
        file_name: &str,
        yaml: &str,
    ) -> std::io::Result<()> {
        write_text_file(&self.paths.binding_path(family, file_name), yaml)
    }

    pub fn write_fixture_yaml(&self, file_name: &str, yaml: &str) -> std::io::Result<()> {
        write_text_file(&self.paths.fixture_path(file_name), yaml)
    }

    pub fn write_fixture_json(&self, file_name: &str, json: &str) -> std::io::Result<()> {
        write_text_file(&self.paths.fixture_path(file_name), json)
    }

    pub fn write_private_fixture_json(&self, file_name: &str, json: &str) -> std::io::Result<()> {
        write_text_file(&self.paths.private_fixture_path(file_name), json)
    }

    pub fn write_vector_review(&self, record: &VectorReviewRecord) -> std::io::Result<()> {
        write_text_file(
            &self.paths.vector_review_path(&record.vector_id),
            &record.to_yaml(),
        )
    }

    pub fn write_binding_review(
        &self,
        file_name: &str,
        record: &BindingReviewRecord,
    ) -> std::io::Result<()> {
        write_text_file(
            &self.paths.binding_review_path(file_name),
            &record.to_yaml(),
        )
    }

    pub fn write_fixture_review(
        &self,
        file_name: &str,
        record: &FixtureReviewRecord,
    ) -> std::io::Result<()> {
        write_text_file(
            &self.paths.fixture_review_path(file_name),
            &record.to_yaml(),
        )
    }

    pub fn write_conversation_fixture(
        &self,
        file_name: &str,
        record: &ConversationFixtureRecord,
    ) -> std::io::Result<()> {
        write_text_file(&self.paths.fixture_path(file_name), &record.to_yaml())
    }
}

impl VectorReviewRecord {
    pub fn to_yaml(&self) -> String {
        let mut out = String::new();
        push_scalar(&mut out, "vector_id", &self.vector_id);
        push_scalar(&mut out, "artifact_ref", &self.artifact_ref);
        push_quoted_scalar(&mut out, "review_status", &self.review_status);
        push_list(&mut out, "reviewed_bindings", &self.reviewed_bindings);
        push_list(&mut out, "review_notes", &self.review_notes);
        out
    }
}

impl BindingReviewRecord {
    pub fn to_yaml(&self) -> String {
        let mut out = String::new();
        push_scalar(&mut out, "binding_id", &self.binding_id);
        push_quoted_scalar(&mut out, "review_status", &self.review_status);
        push_list(&mut out, "reviewed_for_vectors", &self.reviewed_for_vectors);
        if !self.reviewed_for_fixtures.is_empty() {
            push_list(
                &mut out,
                "reviewed_for_fixtures",
                &self.reviewed_for_fixtures,
            );
        }
        push_map(&mut out, "value_checks", &self.value_checks);
        push_list(&mut out, "review_notes", &self.review_notes);
        out
    }
}

impl FixtureReviewRecord {
    pub fn to_yaml(&self) -> String {
        let mut out = String::new();
        push_scalar(&mut out, "fixture_id", &self.fixture_id);
        push_scalar(&mut out, "artifact_ref", &self.artifact_ref);
        push_quoted_scalar(&mut out, "review_status", &self.review_status);
        push_list(
            &mut out,
            "reviewed_for_bindings",
            &self.reviewed_for_bindings,
        );
        push_list(&mut out, "reviewed_for_vectors", &self.reviewed_for_vectors);
        push_map(&mut out, "value_checks", &self.value_checks);
        push_list(&mut out, "review_notes", &self.review_notes);
        out
    }
}

impl ConversationFixtureRecord {
    pub fn to_yaml(&self) -> String {
        let mut out = String::new();
        push_scalar(&mut out, "id", &self.id);
        push_scalar(&mut out, "scope", &self.scope);
        push_scalar(&mut out, "scenario", &self.scenario);
        push_quoted_scalar(&mut out, "sequence", &self.sequence);
        push_list(
            &mut out,
            "related_identity_fixtures",
            &self.related_identity_fixtures,
        );
        push_map(&mut out, "binding_material", &self.binding_material);
        push_list(&mut out, "used_by_vectors", &self.used_by_vectors);
        out
    }
}

pub fn write_direct_request_candidate(
    writer: &PackageWriter,
    candidate: &DirectRequestCandidate,
    sender_vid: &str,
    receiver_vid: &str,
) -> std::io::Result<()> {
    check_direct_request_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.direct.request-01\nbinding_scope: direct\nscenario: request\nrelated_vectors:\n  - BV-001\n  - BV-002\n  - SV-005\nrelated_fixture_refs:\n  - fixture.conversation.direct.request-01\nreviewed_values:\n  request_digest: \"{request_digest}\"\n  nonce: \"{nonce}\"\n  sender_vid: \"{sender_vid}\"\n  receiver_vid: \"{receiver_vid}\"\ncomparison_boundary:\n  - digest is compared exactly where required by the vector\n  - nonce is compared exactly where required by the vector\n  - cross-case byte identity is not required\n",
        request_digest = candidate.request_digest,
        nonce = candidate.nonce,
    );
    writer.write_binding_yaml(BindingFamily::Direct, "request-01.yaml", &binding_yaml)?;

    let fixture = ConversationFixtureRecord {
        id: "fixture.conversation.direct.request-01".into(),
        scope: "direct".into(),
        scenario: "request".into(),
        sequence: "01".into(),
        related_identity_fixtures: vec![
            "fixture.identity.direct.alice".into(),
            "fixture.identity.direct.bob".into(),
        ],
        binding_material: BTreeMap::from([
            ("request_digest".into(), candidate.request_digest.clone()),
            ("nonce".into(), candidate.nonce.clone()),
            ("thread_binding".into(), candidate.request_digest.clone()),
        ]),
        used_by_vectors: vec!["BV-001".into(), "BV-002".into(), "SV-005".into()],
    };
    writer.write_conversation_fixture("fixture.conversation.direct.request-01.yaml", &fixture)
}

pub fn write_direct_accept_candidate(
    writer: &PackageWriter,
    candidate: &DirectAcceptCandidate,
    sender_vid: &str,
    receiver_vid: &str,
) -> std::io::Result<()> {
    check_direct_accept_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.direct.accept-01\nbinding_scope: direct\nscenario: accept\nrelated_vectors:\n  - BV-002\nrelated_fixture_refs:\n  - fixture.conversation.direct.accept-01\n  - fixture.conversation.direct.request-01\nreviewed_values:\n  request_digest: \"{request_digest}\"\n  reply_digest: \"{reply_digest}\"\n  sender_vid: \"{sender_vid}\"\n  receiver_vid: \"{receiver_vid}\"\ncomparison_boundary:\n  - request digest must bind exactly to the reviewed request context\n  - reply digest is compared exactly where required by the vector\n",
        request_digest = candidate.request_digest,
        reply_digest = candidate.reply_digest,
    );
    writer.write_binding_yaml(BindingFamily::Direct, "accept-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.direct.accept-01\nscope: direct\nscenario: accept\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.direct.alice\n  - fixture.identity.direct.bob\nrelated_conversation_fixtures:\n  - fixture.conversation.direct.request-01\nbinding_material:\n  request_digest: \"{request_digest}\"\n  reply_digest: \"{reply_digest}\"\nused_by_vectors:\n  - BV-002\n",
        request_digest = candidate.request_digest,
        reply_digest = candidate.reply_digest,
    );
    let _ = (sender_vid, receiver_vid);
    writer.write_fixture_yaml("fixture.conversation.direct.accept-01.yaml", &fixture_yaml)
}

pub fn write_direct_rfd_candidate(
    writer: &PackageWriter,
    candidate: &DirectRfdCandidate,
) -> std::io::Result<()> {
    check_direct_rfd_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.direct.rfd-01\nbinding_scope: direct\nscenario: rfd\nrelated_vectors:\n  - BV-003\nrelated_fixture_refs:\n  - fixture.conversation.direct.rfd-01\nreviewed_values:\n  digest: \"{digest}\"\n  reviewed_context: \"{reviewed_context}\"\ncomparison_boundary:\n  - digest is compared exactly where required by the vector\n  - local cleanup policy is not compared\n",
        digest = candidate.digest,
        reviewed_context = candidate.reviewed_context,
    );
    writer.write_binding_yaml(BindingFamily::Direct, "rfd-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.direct.rfd-01\nscope: direct\nscenario: rfd\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.direct.alice\n  - fixture.identity.direct.bob\nbinding_material:\n  digest: \"{digest}\"\n  reviewed_context: \"{reviewed_context}\"\nused_by_vectors:\n  - BV-003\n",
        digest = candidate.digest,
        reviewed_context = candidate.reviewed_context,
    );
    writer.write_fixture_yaml("fixture.conversation.direct.rfd-01.yaml", &fixture_yaml)
}

pub fn write_digest_mismatch_candidate(
    writer: &PackageWriter,
    candidate: &DigestMismatchCandidate,
) -> std::io::Result<()> {
    check_digest_mismatch_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.negative.digest-mismatch-01\nbinding_scope: negative\nscenario: digest-mismatch\nrelated_vectors:\n  - SV-005\nrelated_fixture_refs:\n  - fixture.conversation.direct.request-01\n  - fixture.conversation.negative.digest-mismatch-01\nreviewed_values:\n  expected_request_digest: \"{expected_request_digest}\"\n  mismatching_accept_digest: \"{mismatching_accept_digest}\"\ncomparison_boundary:\n  - mismatch relation is compared exactly\n  - local error categorization is not compared\n",
        expected_request_digest = candidate.expected_request_digest,
        mismatching_accept_digest = candidate.mismatching_accept_digest,
    );
    writer.write_binding_yaml(
        BindingFamily::Negative,
        "digest-mismatch-01.yaml",
        &binding_yaml,
    )?;

    let fixture_yaml = format!(
        "id: fixture.conversation.negative.digest-mismatch-01\nscope: negative\nscenario: digest-mismatch\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.direct.alice\n  - fixture.identity.direct.bob\nrelated_conversation_fixtures:\n  - fixture.conversation.direct.request-01\nbinding_material:\n  expected_request_digest: \"{expected_request_digest}\"\n  mismatching_request_digest: \"{mismatching_accept_digest}\"\nused_by_vectors:\n  - SV-005\n",
        expected_request_digest = candidate.expected_request_digest,
        mismatching_accept_digest = candidate.mismatching_accept_digest,
    );
    writer.write_fixture_yaml(
        "fixture.conversation.negative.digest-mismatch-01.yaml",
        &fixture_yaml,
    )
}

pub fn write_nonconfidential_binding_candidate(
    writer: &PackageWriter,
    candidate: &NonConfidentialBindingCandidate,
    confidentiality_mechanism: &str,
    binding_rule: &str,
) -> std::io::Result<()> {
    check_nonconfidential_binding_candidate(candidate).map_err(io::Error::other)?;
    let _ = (&candidate.request_digest, &candidate.nonconfidential_data);
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.mechanism.non-confidential-binding\nbinding_scope: mechanism\nscenario: non-confidential-binding\nrelated_vectors:\n  - AV-003\nreviewed_values:\n  confidentiality_mechanism: {confidentiality_mechanism}\n  binding_rule: \"{binding_rule}\"\ncomparison_boundary:\n  - binding rule is compared at the reviewed semantic constraint layer\n  - implementation-specific internal crypto API shape is not compared\n",
        confidentiality_mechanism = confidentiality_mechanism,
        binding_rule = binding_rule.replace('"', "\\\""),
    );
    writer.write_binding_yaml(
        BindingFamily::Mechanism,
        "non-confidential-binding.yaml",
        &binding_yaml,
    )
}

pub fn write_sender_field_mechanism_candidate(
    writer: &PackageWriter,
    candidate: &SenderFieldMechanismCandidate,
) -> std::io::Result<()> {
    check_sender_field_mechanism_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.mechanism.confidential-control-sender-field\nbinding_scope: mechanism\nscenario: confidential-control-sender-field\nrelated_vectors:\n  - AV-001\nreviewed_values:\n  confidentiality_mechanism: {confidentiality_mechanism}\n  sender_field_rule: \"{sender_field_rule}\"\ncomparison_boundary:\n  - the sender-field rule is compared at the semantic constraint layer\n  - cross-mechanism byte identity is not compared\n",
        confidentiality_mechanism = candidate.confidentiality_mechanism,
        sender_field_rule = candidate.sender_field_rule.replace('"', "\\\""),
    );
    writer.write_binding_yaml(
        BindingFamily::Mechanism,
        "confidential-control-sender-field.yaml",
        &binding_yaml,
    )
}

pub fn write_ciphertext_family_candidate(
    writer: &PackageWriter,
    candidate: &CiphertextFamilyCandidate,
) -> std::io::Result<()> {
    check_ciphertext_family_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.mechanism.ciphertext-family\nbinding_scope: mechanism\nscenario: ciphertext-family\nrelated_vectors:\n  - AV-002\nreviewed_values:\n  confidentiality_mechanism: {confidentiality_mechanism}\n  cesr_ciphertext_family: \"{cesr_ciphertext_family}\"\ncomparison_boundary:\n  - ciphertext family is compared exactly\n  - payload bytes are not compared across mechanisms\n",
        confidentiality_mechanism = candidate.confidentiality_mechanism,
        cesr_ciphertext_family = candidate.cesr_ciphertext_family.replace('"', "\\\""),
    );
    writer.write_binding_yaml(
        BindingFamily::Mechanism,
        "ciphertext-family.yaml",
        &binding_yaml,
    )
}

pub fn write_direct_message_candidate(
    writer: &PackageWriter,
    candidate: &DirectMessageCandidate,
) -> std::io::Result<()> {
    check_direct_message_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.direct.message-01\nbinding_scope: direct\nscenario: message\nrelated_vectors:\n  - SV-001\nrelated_fixture_refs:\n  - fixture.conversation.direct.message-01\nreviewed_values:\n  relationship_context_ref: \"{relationship_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\ncomparison_boundary:\n  - reviewed sender, receiver, and payload semantics are compared at the semantic layer\n  - regenerated confidential bytes are not compared\n",
        relationship_context_ref = candidate.relationship_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_binding_yaml(BindingFamily::Direct, "message-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.direct.message-01\nscope: direct\nscenario: message\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.direct.alice\n  - fixture.identity.direct.bob\nbinding_material:\n  relationship_context_ref: \"{relationship_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\nused_by_vectors:\n  - SV-001\n",
        relationship_context_ref = candidate.relationship_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.direct.message-01.yaml", &fixture_yaml)
}

pub fn write_no_prior_relationship_candidate(
    writer: &PackageWriter,
    candidate: &NoPriorRelationshipCandidate,
) -> std::io::Result<()> {
    crate::authoring::check_no_prior_relationship_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.source_wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.negative.no-prior-relationship-01\nbinding_scope: negative\nscenario: no-prior-relationship\nrelated_vectors:\n  - SV-004\nrelated_fixture_refs:\n  - fixture.conversation.negative.no-prior-relationship-01\nreviewed_values:\n  source_vector_ref: \"{source_vector_ref}\"\n  source_binding_ref: \"{source_binding_ref}\"\n  source_fixture_ref: \"{source_fixture_ref}\"\n  authorization_state: \"{authorization_state}\"\n  relationship_context_ref: \"{relationship_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\ncomparison_boundary:\n  - source wire is reused from the reviewed positive baseline\n  - missing relationship context is compared at the semantic layer\n",
        source_vector_ref = candidate.source_vector_ref,
        source_binding_ref = candidate.source_binding_ref,
        source_fixture_ref = candidate.source_fixture_ref,
        authorization_state = candidate.authorization_state,
        relationship_context_ref = candidate.relationship_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_binding_yaml(
        BindingFamily::Negative,
        "no-prior-relationship-01.yaml",
        &binding_yaml,
    )?;

    let fixture_yaml = format!(
        "id: fixture.conversation.negative.no-prior-relationship-01\nscope: negative\nscenario: no-prior-relationship\nsequence: \"01\"\nrelated_conversation_fixtures:\n  - {source_fixture_ref}\nbinding_material:\n  source_vector_ref: \"{source_vector_ref}\"\n  source_binding_ref: \"{source_binding_ref}\"\n  authorization_state: \"{authorization_state}\"\n  relationship_context_ref: \"{relationship_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\nused_by_vectors:\n  - SV-004\n",
        source_vector_ref = candidate.source_vector_ref,
        source_binding_ref = candidate.source_binding_ref,
        source_fixture_ref = candidate.source_fixture_ref,
        authorization_state = candidate.authorization_state,
        relationship_context_ref = candidate.relationship_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_fixture_yaml(
        "fixture.conversation.negative.no-prior-relationship-01.yaml",
        &fixture_yaml,
    )
}

pub fn write_nested_without_outer_candidate(
    writer: &PackageWriter,
    candidate: &NestedWithoutOuterCandidate,
) -> std::io::Result<()> {
    check_nested_without_outer_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.source_wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.negative.nested-without-outer-01\nbinding_scope: negative\nscenario: nested-without-outer\nrelated_vectors:\n  - SV-006\nrelated_fixture_refs:\n  - fixture.conversation.negative.nested-without-outer-01\nreviewed_values:\n  source_vector_ref: \"{source_vector_ref}\"\n  source_binding_ref: \"{source_binding_ref}\"\n  source_fixture_ref: \"{source_fixture_ref}\"\n  missing_outer_context: {missing_outer_context}\n  outer_context_ref: \"{outer_context_ref}\"\n  inner_context_ref: \"{inner_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\ncomparison_boundary:\n  - authoritative wire bytes are intentionally reused from the reviewed SV-002 baseline\n  - rejection under missing outer context is compared at the semantic layer\n  - exact rejection wording is not compared\n",
        source_vector_ref = candidate.source_vector_ref,
        source_binding_ref = candidate.source_binding_ref,
        source_fixture_ref = candidate.source_fixture_ref,
        missing_outer_context = candidate.missing_outer_context,
        outer_context_ref = candidate.outer_context_ref,
        inner_context_ref = candidate.inner_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_binding_yaml(
        BindingFamily::Negative,
        "nested-without-outer-01.yaml",
        &binding_yaml,
    )?;

    let fixture_yaml = format!(
        "id: fixture.conversation.negative.nested-without-outer-01\nscope: negative\nscenario: nested-without-outer\nsequence: \"01\"\nrelated_conversation_fixtures:\n  - {source_fixture_ref}\nbinding_material:\n  source_vector_ref: \"{source_vector_ref}\"\n  source_fixture_ref: \"{source_fixture_ref}\"\n  missing_outer_context: {missing_outer_context}\n  outer_context_ref: \"{outer_context_ref}\"\n  inner_context_ref: \"{inner_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\nused_by_vectors:\n  - SV-006\n",
        source_vector_ref = candidate.source_vector_ref,
        source_fixture_ref = candidate.source_fixture_ref,
        missing_outer_context = candidate.missing_outer_context,
        outer_context_ref = candidate.outer_context_ref,
        inner_context_ref = candidate.inner_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_fixture_yaml(
        "fixture.conversation.negative.nested-without-outer-01.yaml",
        &fixture_yaml,
    )
}

pub fn write_nested_request_candidate(
    writer: &PackageWriter,
    candidate: &NestedRequestCandidate,
) -> std::io::Result<()> {
    check_nested_request_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    writer.write_fixture_json(
        "fixture.identity.inner.alice-1.json",
        &build_inner_identity_fixture_json(
            "fixture.identity.inner.alice-1",
            "alice-1",
            &candidate.inner_vid,
            &candidate.inner_verification_key_jwk,
            &candidate.inner_encryption_key_jwk,
            &private_fixture_ref(writer, "fixture.identity.inner.alice-1.private.json"),
        )?,
    )?;
    writer.write_private_fixture_json(
        "fixture.identity.inner.alice-1.private.json",
        &candidate.inner_private_vid_json,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.nested.request-01\nbinding_scope: nested\nscenario: request\nrelated_vectors:\n  - BV-004\n  - BV-005\nrelated_fixture_refs:\n  - fixture.conversation.nested.request-01\nreviewed_values:\n  request_digest: \"{request_digest}\"\n  nonce: \"{nonce}\"\n  outer_context_ref: \"{outer_context_ref}\"\n  inner_sender_vid: \"{inner_vid}\"\ncomparison_boundary:\n  - digest is compared exactly where required by the vector\n  - nonce is compared exactly where required by the vector\n  - outer context is reviewed as a required prerequisite, not as optional metadata\n",
        request_digest = candidate.request_digest,
        nonce = candidate.nonce,
        outer_context_ref = candidate.outer_context_ref,
        inner_vid = candidate.inner_vid,
    );
    writer.write_binding_yaml(BindingFamily::Nested, "request-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.nested.request-01\nscope: nested\nscenario: request\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.outer.alice\n  - fixture.identity.outer.bob\n  - fixture.identity.inner.alice-1\nbinding_material:\n  request_digest: \"{request_digest}\"\n  nonce: \"{nonce}\"\n  outer_context_ref: \"{outer_context_ref}\"\nused_by_vectors:\n  - BV-004\n  - BV-005\n",
        request_digest = candidate.request_digest,
        nonce = candidate.nonce,
        outer_context_ref = candidate.outer_context_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.nested.request-01.yaml", &fixture_yaml)
}

pub fn write_nested_accept_candidate(
    writer: &PackageWriter,
    candidate: &NestedAcceptCandidate,
    inner_receiver_vid: &str,
) -> std::io::Result<()> {
    check_nested_accept_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;
    writer.write_fixture_json(
        "fixture.identity.inner.bob-1.json",
        &build_inner_identity_fixture_json(
            "fixture.identity.inner.bob-1",
            "bob-1",
            &candidate.inner_vid,
            &candidate.inner_verification_key_jwk,
            &candidate.inner_encryption_key_jwk,
            &private_fixture_ref(writer, "fixture.identity.inner.bob-1.private.json"),
        )?,
    )?;
    writer.write_private_fixture_json(
        "fixture.identity.inner.bob-1.private.json",
        &candidate.inner_private_vid_json,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.nested.accept-01\nbinding_scope: nested\nscenario: accept\nrelated_vectors:\n  - BV-005\nrelated_fixture_refs:\n  - fixture.conversation.nested.accept-01\n  - fixture.conversation.nested.request-01\nreviewed_values:\n  request_digest: \"{request_digest}\"\n  reply_digest: \"{reply_digest}\"\n  outer_context_ref: \"{outer_context_ref}\"\n  inner_sender_vid: \"{inner_sender_vid}\"\n  inner_receiver_vid: \"{inner_receiver_vid}\"\ncomparison_boundary:\n  - request digest must bind exactly to the reviewed nested request context\n  - reply digest is compared exactly where required by the vector\n  - outer context must remain the same reviewed prerequisite context\n",
        request_digest = candidate.request_digest,
        reply_digest = candidate.reply_digest,
        outer_context_ref = candidate.outer_context_ref,
        inner_sender_vid = candidate.inner_vid,
        inner_receiver_vid = inner_receiver_vid,
    );
    writer.write_binding_yaml(BindingFamily::Nested, "accept-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.nested.accept-01\nscope: nested\nscenario: accept\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.outer.alice\n  - fixture.identity.outer.bob\n  - fixture.identity.inner.alice-1\n  - fixture.identity.inner.bob-1\nrelated_conversation_fixtures:\n  - fixture.conversation.nested.request-01\nbinding_material:\n  request_digest: \"{request_digest}\"\n  reply_digest: \"{reply_digest}\"\n  outer_context_ref: \"{outer_context_ref}\"\nused_by_vectors:\n  - BV-005\n",
        request_digest = candidate.request_digest,
        reply_digest = candidate.reply_digest,
        outer_context_ref = candidate.outer_context_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.nested.accept-01.yaml", &fixture_yaml)
}

pub fn write_routed_path_candidate(
    writer: &PackageWriter,
    candidate: &RoutedPathCandidate,
) -> std::io::Result<()> {
    check_routed_path_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.routed.path-01\nbinding_scope: routed\nscenario: path\nrelated_vectors:\n  - BV-006\nrelated_fixture_refs:\n  - fixture.conversation.routed.path-01\nreviewed_values:\n  current_hop_vid: \"{current_hop_vid}\"\n  next_hop_vid: \"{next_hop_vid}\"\n  remaining_route_ref: \"{remaining_route_json}\"\n  opaque_payload_ref: \"{opaque_payload_base64}\"\ncomparison_boundary:\n  - next hop is compared exactly where required by the vector\n  - remaining route and opaque payload references are compared exactly where required by the vector\n  - onward forwarding bytes are not compared\n",
        current_hop_vid = candidate.current_hop_vid,
        next_hop_vid = candidate.next_hop_vid,
        remaining_route_json = candidate.remaining_route_json.replace('"', "\\\""),
        opaque_payload_base64 = candidate.opaque_payload_base64,
    );
    writer.write_binding_yaml(BindingFamily::Routed, "path-01.yaml", &binding_yaml)?;

    let fixture = ConversationFixtureRecord {
        id: "fixture.conversation.routed.path-01".into(),
        scope: "routed".into(),
        scenario: "path".into(),
        sequence: "01".into(),
        related_identity_fixtures: vec![
            "fixture.identity.route.alice".into(),
            "fixture.identity.route.hop-1".into(),
            "fixture.identity.route.hop-2".into(),
            "fixture.identity.route.bob".into(),
        ],
        binding_material: BTreeMap::from([
            ("next_hop_vid".into(), candidate.next_hop_vid.clone()),
            (
                "remaining_route_ref".into(),
                candidate.remaining_route_json.clone(),
            ),
            (
                "opaque_payload_ref".into(),
                candidate.opaque_payload_base64.clone(),
            ),
        ]),
        used_by_vectors: vec!["BV-006".into(), "SV-003".into()],
    };
    writer.write_conversation_fixture("fixture.conversation.routed.path-01.yaml", &fixture)
}

pub fn write_routed_request_candidate(
    writer: &PackageWriter,
    candidate: &RoutedRequestCandidate,
) -> std::io::Result<()> {
    check_routed_request_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.routed.request-01\nbinding_scope: routed\nscenario: request\nrelated_vectors:\n  - BV-007\nrelated_fixture_refs:\n  - fixture.conversation.routed.request-01\nreviewed_values:\n  request_digest: \"{request_digest}\"\n  nonce: \"{nonce}\"\n  path_context_ref: \"{path_context_ref}\"\n  sender_vid: \"{sender_vid}\"\n  receiver_vid: \"{receiver_vid}\"\ncomparison_boundary:\n  - request digest is compared exactly where required by the vector\n  - nonce is compared exactly where required by the vector\n  - path context is reviewed as a prerequisite for final decode\n",
        request_digest = candidate.request_digest,
        nonce = candidate.nonce,
        path_context_ref = candidate.path_context_ref,
        sender_vid = candidate.sender_vid,
        receiver_vid = candidate.receiver_vid,
    );
    writer.write_binding_yaml(BindingFamily::Routed, "request-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.routed.request-01\nscope: routed\nscenario: request\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.route.alice\n  - fixture.identity.route.hop-1\n  - fixture.identity.route.hop-2\n  - fixture.identity.route.dropoff-1\n  - fixture.identity.route.bob\nbinding_material:\n  request_digest: \"{request_digest}\"\n  nonce: \"{nonce}\"\n  path_context_ref: \"{path_context_ref}\"\nused_by_vectors:\n  - BV-007\n",
        request_digest = candidate.request_digest,
        nonce = candidate.nonce,
        path_context_ref = candidate.path_context_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.routed.request-01.yaml", &fixture_yaml)
}

pub fn write_routed_accept_candidate(
    writer: &PackageWriter,
    candidate: &RoutedAcceptCandidate,
) -> std::io::Result<()> {
    check_routed_accept_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.routed.accept-01\nbinding_scope: routed\nscenario: accept\nrelated_vectors:\n  - BV-008\nrelated_fixture_refs:\n  - fixture.conversation.routed.accept-01\n  - fixture.conversation.routed.request-01\nreviewed_values:\n  request_digest: \"{request_digest}\"\n  reply_digest: \"{reply_digest}\"\n  path_context_ref: \"{path_context_ref}\"\ncomparison_boundary:\n  - request digest must bind exactly to the reviewed routed request context\n  - reply digest is compared exactly where required by the vector\n  - path context must remain the same reviewed prerequisite context\n",
        request_digest = candidate.request_digest,
        reply_digest = candidate.reply_digest,
        path_context_ref = candidate.path_context_ref,
    );
    writer.write_binding_yaml(BindingFamily::Routed, "accept-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.routed.accept-01\nscope: routed\nscenario: accept\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.route.alice\n  - fixture.identity.route.hop-1\n  - fixture.identity.route.hop-2\n  - fixture.identity.route.dropoff-1\n  - fixture.identity.route.bob\nrelated_conversation_fixtures:\n  - fixture.conversation.routed.request-01\nbinding_material:\n  request_digest: \"{request_digest}\"\n  reply_digest: \"{reply_digest}\"\n  path_context_ref: \"{path_context_ref}\"\nused_by_vectors:\n  - BV-008\n",
        request_digest = candidate.request_digest,
        reply_digest = candidate.reply_digest,
        path_context_ref = candidate.path_context_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.routed.accept-01.yaml", &fixture_yaml)
}

pub fn write_routed_message_candidate(
    writer: &PackageWriter,
    candidate: &RoutedMessageCandidate,
) -> std::io::Result<()> {
    check_routed_message_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.routed.message-01\nbinding_scope: routed\nscenario: message\nrelated_vectors:\n  - SV-003\nrelated_fixture_refs:\n  - fixture.conversation.routed.message-01\nreviewed_values:\n  path_context_ref: \"{path_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\ncomparison_boundary:\n  - hop-local visibility and final payload semantics are compared at the semantic layer\n  - regenerated routed confidential bytes are not compared\n",
        path_context_ref = candidate.path_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_binding_yaml(BindingFamily::Routed, "message-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.routed.message-01\nscope: routed\nscenario: message\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.route.alice\n  - fixture.identity.route.hop-1\n  - fixture.identity.route.hop-2\n  - fixture.identity.route.bob\nrelated_conversation_fixtures:\n  - fixture.conversation.routed.path-01\nbinding_material:\n  path_context_ref: \"{path_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\nused_by_vectors:\n  - SV-003\n",
        path_context_ref = candidate.path_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.routed.message-01.yaml", &fixture_yaml)
}

pub fn write_nested_message_candidate(
    writer: &PackageWriter,
    candidate: &NestedMessageCandidate,
) -> std::io::Result<()> {
    check_nested_message_candidate(candidate).map_err(io::Error::other)?;
    write_case_vector_wire(
        writer,
        &candidate.case_id,
        &candidate.vector_id,
        &candidate.wire_base64,
    )?;

    writer.write_fixture_json(
        "fixture.identity.inner.alice-1.json",
        &build_inner_identity_fixture_json_from_owned_vid_json(
            "fixture.identity.inner.alice-1",
            "alice-1",
            &candidate.inner_sender_owned_vid_json,
            &private_fixture_ref(writer, "fixture.identity.inner.alice-1.private.json"),
        )?,
    )?;
    writer.write_fixture_json(
        "fixture.identity.inner.bob-1.json",
        &build_inner_identity_fixture_json_from_owned_vid_json(
            "fixture.identity.inner.bob-1",
            "bob-1",
            &candidate.inner_receiver_owned_vid_json,
            &private_fixture_ref(writer, "fixture.identity.inner.bob-1.private.json"),
        )?,
    )?;

    let namespace = writer.paths().artifact_namespace();
    let binding_yaml = format!(
        "binding_id: {namespace}.binding.nested.message-01\nbinding_scope: nested\nscenario: message\nrelated_vectors:\n  - SV-002\nrelated_fixture_refs:\n  - fixture.conversation.nested.message-01\nreviewed_values:\n  outer_context_ref: \"{outer_context_ref}\"\n  inner_context_ref: \"{inner_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\ncomparison_boundary:\n  - inner semantics are compared only within the reviewed outer context\n  - regenerated nested confidential bytes are not compared\n",
        outer_context_ref = candidate.outer_context_ref,
        inner_context_ref = candidate.inner_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_binding_yaml(BindingFamily::Nested, "message-01.yaml", &binding_yaml)?;

    let fixture_yaml = format!(
        "id: fixture.conversation.nested.message-01\nscope: nested\nscenario: message\nsequence: \"01\"\nrelated_identity_fixtures:\n  - fixture.identity.outer.alice\n  - fixture.identity.outer.bob\n  - fixture.identity.inner.alice-1\n  - fixture.identity.inner.bob-1\nrelated_conversation_fixtures:\n  - fixture.conversation.nested.request-01\n  - fixture.conversation.nested.accept-01\nbinding_material:\n  outer_context_ref: \"{outer_context_ref}\"\n  inner_context_ref: \"{inner_context_ref}\"\n  payload_semantics_ref: \"{payload_semantics_ref}\"\nused_by_vectors:\n  - SV-002\n",
        outer_context_ref = candidate.outer_context_ref,
        inner_context_ref = candidate.inner_context_ref,
        payload_semantics_ref = candidate.payload_semantics_ref,
    );
    writer.write_fixture_yaml("fixture.conversation.nested.message-01.yaml", &fixture_yaml)
}

fn write_text_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

fn write_case_vector_wire(
    writer: &PackageWriter,
    case_id: &str,
    vector_id: &str,
    wire_base64: &str,
) -> io::Result<()> {
    ensure_case_match(writer, case_id)?;
    writer.write_vector_wire(vector_id, wire_base64)
}

fn private_fixture_ref(writer: &PackageWriter, file_name: &str) -> String {
    format!(
        "{}/private-fixtures/{file_name}",
        writer.paths().case().artifact_dir_name()
    )
}

fn push_scalar(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn push_quoted_scalar(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": \"");
    out.push_str(&value.replace('"', "\\\""));
    out.push_str("\"\n");
}

fn push_list(out: &mut String, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    out.push_str(key);
    out.push_str(":\n");
    for value in values {
        out.push_str("  - ");
        out.push_str(&yaml_scalar(value));
        out.push('\n');
    }
}

fn push_map(out: &mut String, key: &str, values: &BTreeMap<String, String>) {
    if values.is_empty() {
        return;
    }
    out.push_str(key);
    out.push_str(":\n");
    for (map_key, map_value) in values {
        out.push_str("  ");
        out.push_str(map_key);
        out.push_str(": ");
        out.push_str(&yaml_scalar(map_value));
        out.push('\n');
    }
}

fn yaml_scalar(value: &str) -> String {
    if value.is_empty()
        || value.contains(':')
        || value.contains('`')
        || value.starts_with(' ')
        || value.ends_with(' ')
    {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

fn ensure_case_match(writer: &PackageWriter, candidate_case_id: &str) -> io::Result<()> {
    let expected = writer.paths().case().case_id();
    if candidate_case_id == expected {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "candidate case_id {} does not match package case_id {}",
            candidate_case_id, expected
        ),
    ))
}

fn build_inner_identity_fixture_json(
    fixture_id: &str,
    alias: &str,
    identifier: &str,
    verification_key_jwk_json: &str,
    encryption_key_jwk_json: &str,
    private_material_ref: &str,
) -> Result<String, io::Error> {
    let verification_key: Value = serde_json::from_str(verification_key_jwk_json)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let encryption_key: Value = serde_json::from_str(encryption_key_jwk_json)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let value = serde_json::json!({
        "id": fixture_id,
        "scope": "inner",
        "alias": alias,
        "identifier": identifier,
        "transport_or_route_role": "nested_inner_endpoint",
        "public_material": {
            "verification_key": verification_key,
            "encryption_key": encryption_key,
        },
        "private_material_ref": private_material_ref,
    });
    serde_json::to_string_pretty(&value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn build_inner_identity_fixture_json_from_owned_vid_json(
    fixture_id: &str,
    alias: &str,
    owned_vid_json: &str,
    private_material_ref: &str,
) -> Result<String, io::Error> {
    let value: Value = serde_json::from_str(owned_vid_json)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    let identifier = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing owned vid id"))?;
    let public_sigkey = value
        .get("publicSigkey")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing owned vid publicSigkey")
        })?;
    let public_enckey = value
        .get("publicEnckey")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing owned vid publicEnckey")
        })?;

    let fixture_value = serde_json::json!({
        "id": fixture_id,
        "scope": "inner",
        "alias": alias,
        "identifier": identifier,
        "transport_or_route_role": "nested_inner_endpoint",
        "public_material": {
            "verification_key": {
                "crv": "Ed25519",
                "kty": "OKP",
                "use": "sig",
                "x": public_sigkey,
            },
            "encryption_key": {
                "crv": "X25519",
                "kty": "OKP",
                "use": "enc",
                "x": public_enckey,
            }
        },
        "private_material_ref": private_material_ref,
    });

    serde_json::to_string_pretty(&fixture_value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::{
        BindingFamily, BindingReviewRecord, ConversationFixtureRecord, FixtureReviewRecord,
        PackageWriter, VectorReviewRecord, write_direct_request_candidate,
        write_nested_request_candidate, write_routed_path_candidate,
    };
    use crate::authoring::{CasePackagePaths, CompleteCase};
    use std::{
        collections::BTreeMap,
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tsp-test-vectors-writer-{}-{nanos}-{seq}",
            std::process::id()
        ))
    }

    #[test]
    fn writes_review_and_fixture_records() {
        let root = temp_root();
        let writer = PackageWriter::new(CasePackagePaths::new(&root, CompleteCase::Cc001));
        writer.ensure_layout().unwrap();

        writer
            .write_vector_review(&VectorReviewRecord {
                vector_id: "BV-001".into(),
                artifact_ref: "artifact.cc-001.vector.BV-001.wire".into(),
                review_status: "pass".into(),
                reviewed_bindings: vec!["artifact.cc-001.binding.direct.request-01".into()],
                review_notes: vec!["reviewed request baseline".into()],
            })
            .unwrap();

        let mut checks = BTreeMap::new();
        checks.insert("request_digest".into(), "abc123".into());
        writer
            .write_binding_review(
                "direct.request-01.yaml",
                &BindingReviewRecord {
                    binding_id: "artifact.cc-001.binding.direct.request-01".into(),
                    review_status: "pass".into(),
                    reviewed_for_vectors: vec!["BV-001".into()],
                    reviewed_for_fixtures: vec!["fixture.conversation.direct.request-01".into()],
                    value_checks: checks.clone(),
                    review_notes: vec!["digest checked".into()],
                },
            )
            .unwrap();

        writer
            .write_fixture_review(
                "direct.identity.alice.yaml",
                &FixtureReviewRecord {
                    fixture_id: "fixture.identity.direct.alice".into(),
                    artifact_ref: "artifact.cc-001.fixture.fixture.identity.direct.alice".into(),
                    review_status: "pass".into(),
                    reviewed_for_bindings: vec!["artifact.cc-001.binding.direct.request-01".into()],
                    reviewed_for_vectors: vec!["BV-001".into()],
                    value_checks: checks,
                    review_notes: vec!["identity checked".into()],
                },
            )
            .unwrap();

        writer
            .write_conversation_fixture(
                "fixture.conversation.direct.request-01.yaml",
                &ConversationFixtureRecord {
                    id: "fixture.conversation.direct.request-01".into(),
                    scope: "direct".into(),
                    scenario: "request".into(),
                    sequence: "01".into(),
                    related_identity_fixtures: vec![
                        "fixture.identity.direct.alice".into(),
                        "fixture.identity.direct.bob".into(),
                    ],
                    binding_material: BTreeMap::from([("request_digest".into(), "abc123".into())]),
                    used_by_vectors: vec!["BV-001".into()],
                },
            )
            .unwrap();

        assert!(writer.paths().vector_review_path("BV-001").is_file());
        assert!(
            writer
                .paths()
                .binding_review_path("direct.request-01.yaml")
                .is_file()
        );
        assert!(
            writer
                .paths()
                .fixture_review_path("direct.identity.alice.yaml")
                .is_file()
        );
        assert!(
            writer
                .paths()
                .fixture_path("fixture.conversation.direct.request-01.yaml")
                .is_file()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_wire_and_binding_files() {
        let root = temp_root();
        let writer = PackageWriter::new(CasePackagePaths::new(&root, CompleteCase::Cc002));
        writer.ensure_layout().unwrap();
        writer.write_vector_wire("BV-001", "Zm9v").unwrap();
        writer
            .write_binding_yaml(
                BindingFamily::Direct,
                "request-01.yaml",
                "binding_id: artifact.cc-002.binding.direct.request-01\n",
            )
            .unwrap();

        assert_eq!(
            fs::read_to_string(writer.paths().vector_wire_path("BV-001")).unwrap(),
            "Zm9v"
        );
        assert!(
            writer
                .paths()
                .binding_path(BindingFamily::Direct, "request-01.yaml")
                .is_file()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_candidate_slices_across_direct_nested_and_routed_families() {
        let root = temp_root();
        let writer = PackageWriter::new(CasePackagePaths::new(&root, CompleteCase::Cc001));
        writer.ensure_layout().unwrap();

        write_direct_request_candidate(
            &writer,
            &crate::authoring::DirectRequestCandidate {
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

        write_nested_request_candidate(
            &writer,
            &crate::authoring::NestedRequestCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-004".into(),
                wire_base64: "YmFy".into(),
                request_digest: "req123".into(),
                nonce: "nonce123".into(),
                inner_vid: "did:peer:alice-1".into(),
                inner_verification_key_jwk: "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"sig\"}"
                    .into(),
                inner_encryption_key_jwk: "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"enc\"}"
                    .into(),
                inner_private_vid_json: "{\"id\":\"did:peer:alice-1\"}".into(),
                outer_context_ref: "outer.ctx.01".into(),
            },
        )
        .unwrap();

        write_routed_path_candidate(
            &writer,
            &crate::authoring::RoutedPathCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-006".into(),
                wire_base64: "YmF6".into(),
                current_hop_vid: "did:web:hop1.example".into(),
                next_hop_vid: "did:web:hop2.example".into(),
                remaining_route_json: "[\"did:web:hop2.example\",\"did:web:bob.example\"]".into(),
                opaque_payload_base64: "cGF5bG9hZA==".into(),
            },
        )
        .unwrap();

        assert!(writer.paths().vector_wire_path("BV-001").is_file());
        assert!(writer.paths().vector_wire_path("BV-004").is_file());
        assert!(writer.paths().vector_wire_path("BV-006").is_file());
        assert!(
            writer
                .paths()
                .binding_path(BindingFamily::Direct, "request-01.yaml")
                .is_file()
        );
        assert!(
            writer
                .paths()
                .binding_path(BindingFamily::Nested, "request-01.yaml")
                .is_file()
        );
        assert!(
            writer
                .paths()
                .binding_path(BindingFamily::Routed, "path-01.yaml")
                .is_file()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writer_rejects_candidate_for_wrong_case_package() {
        let root = temp_root();
        let writer = PackageWriter::new(CasePackagePaths::new(&root, CompleteCase::Cc002));
        writer.ensure_layout().unwrap();

        let err = write_direct_request_candidate(
            &writer,
            &crate::authoring::DirectRequestCandidate {
                case_id: "CC-001".into(),
                vector_id: "BV-001".into(),
                wire_base64: "Zm9v".into(),
                request_digest: "abc123".into(),
                nonce: "def456".into(),
            },
            "did:web:alice.example",
            "did:web:bob.example",
        )
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        fs::remove_dir_all(root).unwrap();
    }
}
