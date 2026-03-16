use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use tsp_sdk::{AsyncSecureStore, OwnedVid, ReceivedTspMessage, RelationshipStatus, VerifiedVid};
use tsp_test_vectors::validator::{
    CaseOutputValidationRecord, ReplayProbeRecord, ReplayProbeStatus, collect_case_output_records,
    collect_replay_probe_records, validate_all_packages,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tsp_sdk crate should live under the workspace root")
        .to_path_buf()
}

fn test_vector_assets_root() -> PathBuf {
    workspace_root().join("tsp_test_vectors/assets")
}

fn test_vector_catalog_path() -> PathBuf {
    workspace_root().join("tsp_test_vectors/docs/spec/test-vector-instances.md")
}

fn canonical_vector_wire_base64(case_artifact_dir: &str, vector_id: &str) -> String {
    std::fs::read_to_string(
        test_vector_assets_root()
            .join(case_artifact_dir)
            .join(format!("vectors/{vector_id}/wire.base64")),
    )
    .expect("canonical vector wire should exist")
    .trim()
    .to_string()
}

async fn alice_owned() -> OwnedVid {
    OwnedVid::from_file(workspace_root().join("examples/test/alice/piv.json"))
        .await
        .expect("alice piv should load")
}

async fn bob_owned() -> OwnedVid {
    OwnedVid::from_file(workspace_root().join("examples/test/bob/piv.json"))
        .await
        .expect("bob piv should load")
}

async fn cc001_inner_alice_owned() -> OwnedVid {
    OwnedVid::from_file(
        workspace_root().join(
            "tsp_test_vectors/assets/artifact-set.cc-001/private-fixtures/fixture.identity.inner.alice-1.private.json",
        ),
    )
    .await
    .expect("cc001 inner alice private fixture should load")
}

async fn cc001_inner_bob_owned() -> OwnedVid {
    OwnedVid::from_file(
        workspace_root().join(
            "tsp_test_vectors/assets/artifact-set.cc-001/private-fixtures/fixture.identity.inner.bob-1.private.json",
        ),
    )
    .await
    .expect("cc001 inner bob private fixture should load")
}

fn decode_hex_digest_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "digest hex must have 64 chars");
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("digest hex should be utf8");
        digest[index] = u8::from_str_radix(pair, 16).expect("digest hex should decode");
    }
    digest
}

fn cc001_nested_request_thread_id() -> [u8; 32] {
    let binding = std::fs::read_to_string(
        test_vector_assets_root().join("artifact-set.cc-001/bindings/nested/request-01.yaml"),
    )
    .expect("cc001 nested request binding should exist");
    let digest = binding
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("request_digest: ")
                .map(|value| value.trim_matches('"').to_string())
        })
        .expect("cc001 nested request binding should declare request_digest");

    decode_hex_digest_32(&digest)
}

#[test]
fn sdk_can_consume_test_vector_packages_structurally() {
    let summaries = validate_all_packages(&test_vector_assets_root(), &test_vector_catalog_path())
        .expect("tsp_sdk should be able to consume the frozen test-vector package");

    assert_eq!(summaries.len(), 3);
    for summary in summaries {
        assert_eq!(
            summary.vectors, 17,
            "{} vector count drifted",
            summary.case_id
        );
        assert_eq!(
            summary.fixtures, 24,
            "{} fixture count drifted",
            summary.case_id
        );
        assert_eq!(
            summary.bindings, 17,
            "{} binding count drifted",
            summary.case_id
        );
        assert_eq!(
            summary.identity_fixture_reviews, 10,
            "{} identity review count drifted",
            summary.case_id
        );
    }
}

#[test]
fn sdk_consumer_surface_uses_new_package_home() {
    let assets_root = test_vector_assets_root();
    let vector_catalog = test_vector_catalog_path();

    assert!(
        assets_root
            .join("artifact-set.cc-001/case-manifest.yaml")
            .is_file()
    );
    assert!(
        assets_root
            .join("artifact-set.cc-002/case-manifest.yaml")
            .is_file()
    );
    assert!(
        assets_root
            .join("artifact-set.cc-003/case-manifest.yaml")
            .is_file()
    );
    assert!(vector_catalog.is_file());
}

#[test]
fn sdk_case_outputs_report_current_positive_and_negative_alignment_state() {
    let records =
        collect_case_output_records(&test_vector_assets_root(), &test_vector_catalog_path())
            .expect("case output records should be collectable from the canonical package");

    assert_eq!(records.len(), 3);
    for record in records {
        assert_case_output_record_reports_current_state(&record);
    }
}

#[test]
fn sdk_output_equivalence_replay_status_is_tracked_explicitly() {
    let records =
        collect_replay_probe_records(&test_vector_assets_root(), &test_vector_catalog_path())
            .expect("replay probe report should be collectable from the frozen package");

    for vector_id in [
        "BV-001", "BV-002", "BV-003", "BV-004", "BV-005", "BV-006", "BV-007", "BV-008", "SV-001",
        "SV-002", "SV-003", "SV-005",
    ] {
        assert_cc001_replay_status(&records, vector_id, ReplayProbeStatus::Verified);
    }

    for vector_id in ["SV-004", "SV-006"] {
        let record = cc001_replay_record(&records, vector_id);
        assert_eq!(record.status, ReplayProbeStatus::Failed);
        assert!(
            record
                .error
                .as_deref()
                .is_some_and(|err| err.contains("unexpectedly opened as GenericMessage")),
            "{vector_id} should expose the current negative-case acceptance gap: {:?}",
            record.error
        );
    }

    for vector_id in ["AV-001", "AV-002", "AV-003"] {
        assert_cc001_replay_status(&records, vector_id, ReplayProbeStatus::NotAttempted);
    }
}

#[tokio::test]
async fn sdk_canonical_sv004_opens_as_generic_message_without_prior_relationship() {
    let alice = alice_owned().await;
    let bob = bob_owned().await;
    let wire = Base64UrlUnpadded::decode_vec(&canonical_vector_wire_base64(
        "artifact-set.cc-001",
        "SV-004",
    ))
    .expect("canonical SV-004 wire should decode");

    let bob_store = AsyncSecureStore::new();
    bob_store
        .add_private_vid(bob.clone(), None)
        .expect("bob private vid should add");
    bob_store
        .add_verified_vid(alice.clone(), None)
        .expect("alice verified vid should add");

    let mut unopened = wire.clone();
    let opened = bob_store
        .open_message(&mut unopened)
        .expect("current SDK should still open canonical SV-004");

    match opened {
        ReceivedTspMessage::GenericMessage {
            sender, receiver, ..
        } => {
            assert_eq!(sender, alice.identifier());
            assert_eq!(receiver.as_deref(), Some(bob.identifier()));
        }
        other => panic!("canonical SV-004 should currently open as GenericMessage, got {other:?}"),
    }
}

#[tokio::test]
async fn sdk_canonical_sv006_opens_as_generic_message_without_outer_context() {
    let alice = alice_owned().await;
    let bob = bob_owned().await;
    let inner_alice = cc001_inner_alice_owned().await;
    let inner_bob = cc001_inner_bob_owned().await;
    let nested_thread_id = cc001_nested_request_thread_id();
    let wire = Base64UrlUnpadded::decode_vec(&canonical_vector_wire_base64(
        "artifact-set.cc-001",
        "SV-006",
    ))
    .expect("canonical SV-006 wire should decode");

    let bob_store = AsyncSecureStore::new();
    bob_store
        .add_private_vid(bob.clone(), None)
        .expect("outer bob private vid should add");
    bob_store
        .add_verified_vid(alice.clone(), None)
        .expect("outer alice verified vid should add");
    bob_store
        .add_private_vid(inner_bob.clone(), None)
        .expect("inner bob private vid should add");
    bob_store
        .add_verified_vid(inner_alice.clone(), None)
        .expect("inner alice verified vid should add");
    bob_store
        .set_parent_for_vid(inner_bob.identifier(), Some(bob.identifier()))
        .expect("inner bob parent should set");
    bob_store
        .set_parent_for_vid(inner_alice.identifier(), Some(alice.identifier()))
        .expect("inner alice parent should set");
    bob_store
        .set_relation_and_status_for_vid(
            inner_bob.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id,
                outstanding_nested_thread_ids: vec![],
            },
            inner_alice.identifier(),
        )
        .expect("receiver-side inner bob relationship should set");
    bob_store
        .set_relation_and_status_for_vid(
            inner_alice.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id,
                outstanding_nested_thread_ids: vec![],
            },
            inner_bob.identifier(),
        )
        .expect("receiver-side inner alice relationship should set");

    let mut unopened = wire.clone();
    let opened = bob_store
        .open_message(&mut unopened)
        .expect("current SDK should still open canonical SV-006");

    match opened {
        ReceivedTspMessage::GenericMessage {
            sender, receiver, ..
        } => {
            assert_eq!(sender, inner_alice.identifier());
            assert_eq!(receiver.as_deref(), Some(inner_bob.identifier()));
        }
        other => panic!("canonical SV-006 should currently open as GenericMessage, got {other:?}"),
    }
}

fn cc001_replay_record<'a>(
    records: &'a [ReplayProbeRecord],
    vector_id: &str,
) -> &'a ReplayProbeRecord {
    records
        .iter()
        .find(|record| record.case_id == "CC-001" && record.vector_id == vector_id)
        .unwrap_or_else(|| panic!("CC-001/{vector_id} replay record should exist"))
}

fn assert_cc001_replay_status(
    records: &[ReplayProbeRecord],
    vector_id: &str,
    expected: ReplayProbeStatus,
) {
    let record = cc001_replay_record(records, vector_id);
    assert_eq!(record.status, expected, "{vector_id} replay status drifted");
    if matches!(
        expected,
        ReplayProbeStatus::Verified | ReplayProbeStatus::NotAttempted
    ) {
        assert!(
            record.error.is_none(),
            "unexpected {vector_id} replay error: {:?}",
            record.error
        );
    }
}

fn assert_case_output_record_reports_current_state(record: &CaseOutputValidationRecord) {
    assert_eq!(
        record.status, "incomplete",
        "case output {} should currently expose the negative-output gap, missing checks: {:?}",
        record.case_output_id, record.missing_checks
    );
    assert_eq!(
        record.expected_positive_outcomes.len(),
        6,
        "{} should declare 6 positive outcomes",
        record.case_output_id
    );
    assert_eq!(
        record.actual_positive_outcomes.len(),
        6,
        "{} actual positive outcomes should all be replay-derived",
        record.case_output_id
    );
    assert_eq!(
        record.matched_positive_outcomes.len(),
        6,
        "{} positive outcomes should all match actual replay-derived outputs",
        record.case_output_id
    );
    assert_eq!(
        record.expected_negative_outcomes.len(),
        2,
        "{} should declare 2 negative outcomes",
        record.case_output_id
    );
    assert_eq!(
        record.represented_negative_outcomes.len(),
        2,
        "{} negative outcomes should both be represented",
        record.case_output_id
    );
    assert_eq!(
        record.actual_negative_outcomes.len(),
        0,
        "{} actual negative outcomes are not yet satisfied by current SDK replay",
        record.case_output_id
    );
    assert_eq!(
        record.matched_negative_outcomes.len(),
        0,
        "{} matched negative outcomes should still be empty",
        record.case_output_id
    );
    assert_eq!(
        record.missing_checks.len(),
        2,
        "{} should currently expose the two missing negative-output checks",
        record.case_output_id
    );
    assert_eq!(
        record.expected_relationship_state_summary.len(),
        2,
        "{} should declare 2 relationship summaries",
        record.case_output_id
    );
    assert_eq!(
        record.actual_relationship_state_summary.len(),
        2,
        "{} relationship summaries should be derived from replay",
        record.case_output_id
    );
    assert_eq!(
        record.matched_relationship_state_summary.len(),
        2,
        "{} relationship summaries should fully match actual replay-derived state",
        record.case_output_id
    );
    assert_eq!(
        record.expected_message_flow_summary.len(),
        3,
        "{} should declare 3 message-flow summaries",
        record.case_output_id
    );
    assert_eq!(
        record.actual_message_flow_summary.len(),
        3,
        "{} message-flow summaries should be derived from replay",
        record.case_output_id
    );
    assert_eq!(
        record.matched_message_flow_summary.len(),
        3,
        "{} message-flow summaries should fully match actual replay-derived outputs",
        record.case_output_id
    );
    assert_eq!(
        record.expected_family_summary.len(),
        1,
        "{} should declare 1 family summary",
        record.case_output_id
    );
    assert_eq!(
        record.actual_family_summary.len(),
        1,
        "{} family summary should be derived from manifest context",
        record.case_output_id
    );
    assert_eq!(
        record.matched_family_summary.len(),
        1,
        "{} family summary should match manifest-derived output",
        record.case_output_id
    );
    assert_eq!(
        record.expected_mechanism_summary.len(),
        1,
        "{} should declare 1 mechanism summary",
        record.case_output_id
    );
    assert_eq!(
        record.actual_mechanism_summary.len(),
        1,
        "{} mechanism summary should be derived from manifest context",
        record.case_output_id
    );
    assert_eq!(
        record.matched_mechanism_summary.len(),
        1,
        "{} mechanism summary should match manifest-derived output",
        record.case_output_id
    );
}
