use crate::authoring::{
    CasePackagePaths, CiphertextFamilyCandidate, CompleteCase, DigestMismatchCandidate,
    DirectAcceptCandidate, DirectMessageCandidate, DirectRequestCandidate, DirectRfdCandidate,
    FreezeResult, NestedAcceptCandidate, NestedMessageCandidate, NestedRequestCandidate,
    NestedWithoutOuterRequest, NoPriorRelationshipRequest, NonConfidentialBindingCandidate,
    PackageWriter, RoutedAcceptCandidate, RoutedMessageCandidate, RoutedPathCandidate,
    RoutedRequestCandidate, SdkCandidateSource, SenderFieldMechanismCandidate, SpecCandidateSource,
    freeze_ciphertext_family_from_source, freeze_digest_mismatch_from_source,
    freeze_direct_accept_from_source, freeze_direct_message_from_source,
    freeze_direct_request_from_source, freeze_direct_rfd_from_source,
    freeze_nested_accept_from_source, freeze_nested_message_from_source,
    freeze_nested_request_from_source, freeze_nested_without_outer_from_source,
    freeze_no_prior_relationship_from_source, freeze_nonconfidential_binding_from_source,
    freeze_routed_accept_from_source, freeze_routed_message_from_source,
    freeze_routed_path_from_source, freeze_routed_request_from_source,
    freeze_sender_field_mechanism_from_source,
};
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(all(feature = "nacl", not(feature = "pq")))]
use crypto_box::{ChaChaBox, PublicKey, SecretKey, aead::AeadInPlace};
#[cfg(not(all(feature = "nacl", not(feature = "pq"))))]
use hpke::{Deserializable, OpModeR, Serializable, aead, single_shot_open_in_place_detached};
use serde_json::to_string_pretty;
use std::{
    fs,
    future::Future,
    io,
    path::{Path, PathBuf},
};
use tsp_sdk::{
    AsyncSecureStore, OwnedVid, PrivateVid, RelationshipStatus, SecureStore, VerifiedVid,
};

const CC001_ALICE: &str =
    "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice";
const CC001_BOB: &str =
    "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob";
const NONCONFIDENTIAL_BINDING_RULE: &str = "non-confidential fields are part of the authenticated envelope header; a sample with explicit non-confidential data opens successfully, and tampering with that header field causes rejection";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tsp_test_vectors crate should live under the workspace root")
        .to_path_buf()
}

async fn create_vid_from_file(path: &str) -> OwnedVid {
    let original = PathBuf::from(path);
    let resolved = if original.exists() {
        original
    } else {
        let crate_relative = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        if crate_relative.exists() {
            crate_relative
        } else {
            workspace_root().join(path)
        }
    };
    let display = resolved.display().to_string();

    OwnedVid::from_file(resolved.to_string_lossy().as_ref())
        .await
        .unwrap_or_else(|e| panic!("Failed to load VID from {display}: {e}"))
}

fn create_test_store() -> SecureStore {
    SecureStore::new()
}

fn create_async_test_store() -> AsyncSecureStore {
    AsyncSecureStore::new()
}

fn export_owned_vid_json_for_tests(vid: &OwnedVid) -> String {
    to_string_pretty(vid).expect("owned VID should serialize into test fixture JSON")
}
async fn load_private_owned_vid_from_path(path: &Path) -> OwnedVid {
    OwnedVid::from_file(path.to_string_lossy().as_ref())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Failed to load private fixture from {}: {e}",
                path.display()
            )
        })
}

fn read_generated_vector_wire(paths: &CasePackagePaths, vector_id: &str) -> io::Result<Vec<u8>> {
    let encoded = fs::read_to_string(paths.vector_wire_path(vector_id))?;
    Base64UrlUnpadded::decode_vec(encoded.trim()).map_err(|err| {
        io::Error::other(format!(
            "failed to decode generated {vector_id} wire: {err}"
        ))
    })
}

fn read_generated_inner_alice_identifier(writer: &PackageWriter) -> io::Result<String> {
    let raw = fs::read_to_string(
        writer
            .paths()
            .fixture_path("fixture.identity.inner.alice-1.json"),
    )?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    value
        .get("identifier")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing identifier in generated fixture.identity.inner.alice-1.json",
            )
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateVectorRequest {
    pub case: CompleteCase,
    pub vector_id: String,
    pub assets_root: PathBuf,
}

impl GenerateVectorRequest {
    pub fn new(
        case: CompleteCase,
        vector_id: impl Into<String>,
        assets_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            case,
            vector_id: vector_id.into(),
            assets_root: assets_root.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateCaseRequest {
    pub case: CompleteCase,
    pub assets_root: PathBuf,
    pub vector_ids: Option<Vec<String>>,
}

impl GenerateCaseRequest {
    pub fn new(case: CompleteCase, assets_root: impl Into<PathBuf>) -> Self {
        Self {
            case,
            assets_root: assets_root.into(),
            vector_ids: None,
        }
    }
}

pub async fn generate_vector_asset_set(
    request: &GenerateVectorRequest,
) -> io::Result<FreezeResult> {
    let paths = CasePackagePaths::new(&request.assets_root, request.case);
    paths.ensure_directory_layout()?;
    let writer = PackageWriter::new(paths);
    let source = SdkCandidateSource::new("sdk-typed-generate");

    match request.case {
        CompleteCase::Cc001 => {
            generate_cc001_vector_asset_set(request.vector_id.as_str(), &source, &writer).await
        }
        CompleteCase::Cc002 => {
            generate_cc002_vector_asset_set(request.vector_id.as_str(), &source, &writer).await
        }
        CompleteCase::Cc003 => {
            generate_cc003_vector_asset_set(request.vector_id.as_str(), &source, &writer).await
        }
    }
}

pub async fn generate_case_package(request: &GenerateCaseRequest) -> io::Result<Vec<FreezeResult>> {
    seed_case_manifest_if_missing(request.case, &request.assets_root)?;
    seed_case_review_set_if_missing(request.case, &request.assets_root)?;
    seed_case_fixture_basis_if_missing(request.case, &request.assets_root)?;

    let vector_ids = request
        .vector_ids
        .clone()
        .unwrap_or_else(|| default_supported_vectors(request.case));

    let mut results = Vec::with_capacity(vector_ids.len());
    for vector_id in vector_ids {
        let result = generate_vector_asset_set(&GenerateVectorRequest {
            case: request.case,
            vector_id,
            assets_root: request.assets_root.clone(),
        })
        .await?;
        results.push(result);
    }
    Ok(results)
}

fn default_supported_vectors(case: CompleteCase) -> Vec<String> {
    match case {
        CompleteCase::Cc001 => default_supported_vectors_cc001(),
        CompleteCase::Cc002 => default_supported_vectors_cc002(),
        CompleteCase::Cc003 => default_supported_vectors_cc003(),
    }
}

fn read_wire_base64(path: PathBuf) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn owned_vector_list(vector_ids: &[&str]) -> Vec<String> {
    vector_ids.iter().map(|id| (*id).to_string()).collect()
}

fn read_yaml_scalar(path: &Path, key: &str) -> io::Result<String> {
    let raw = fs::read_to_string(path)?;
    let needle = format!("{key}: \"");
    raw.lines()
        .find_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix(&needle)
                .and_then(|rest| rest.strip_suffix('"'))
                .map(str::to_string)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing scalar {key} in {}", path.display()),
            )
        })
}

fn parse_hex_array_32(label: &str, hex: &str) -> io::Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} must be 64 hex chars, got {}", hex.len()),
        ));
    }

    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let chunk = std::str::from_utf8(chunk).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid utf-8 in {label}: {e}"),
            )
        })?;
        out[index] = u8::from_str_radix(chunk, 16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid hex in {label} at byte {index}: {e}"),
            )
        })?;
    }
    Ok(out)
}

fn generation_not_implemented(case_id: &str, vector_id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("generation not implemented for case {case_id} vector {vector_id}"),
    )
}

fn generation_requires_build(case_id: &str, vector_id: &str, requirement: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("generation for case {case_id} vector {vector_id} requires {requirement}"),
    )
}

fn seed_case_manifest_if_missing(case: CompleteCase, assets_root: &PathBuf) -> io::Result<()> {
    let paths = CasePackagePaths::new(assets_root, case);
    let manifest_path = paths.manifest_path();
    if manifest_path.is_file() {
        return Ok(());
    }

    let canonical_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join(case.artifact_dir_name())
        .join("case-manifest.yaml");
    let manifest_text = fs::read_to_string(&canonical_manifest)?;
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(manifest_path, manifest_text)?;
    Ok(())
}

fn seed_case_review_set_if_missing(case: CompleteCase, assets_root: &PathBuf) -> io::Result<()> {
    let paths = CasePackagePaths::new(assets_root, case);
    let review_root = paths.review_root();
    if review_root
        .join("vector-reviews")
        .join("BV-001.yaml")
        .is_file()
    {
        return Ok(());
    }

    let canonical_review_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join(case.review_dir_name());
    copy_tree(&canonical_review_root, &review_root)
}

fn seed_case_fixture_basis_if_missing(case: CompleteCase, assets_root: &PathBuf) -> io::Result<()> {
    let paths = CasePackagePaths::new(assets_root, case);
    let canonical_artifact_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join(case.artifact_dir_name());

    let canonical_fixture_root = canonical_artifact_root.join("fixtures");
    if !canonical_fixture_root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "canonical fixture root not found: {}",
                canonical_fixture_root.display()
            ),
        ));
    }

    for entry in fs::read_dir(&canonical_fixture_root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with("fixture.identity.") {
            continue;
        }

        let target = paths.fixture_path(&file_name);
        if target.is_file() {
            continue;
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), target)?;
    }

    let canonical_private_root = canonical_artifact_root.join("private-fixtures");
    if canonical_private_root.is_dir() {
        seed_missing_tree(&canonical_private_root, &paths.private_fixture_path(""))?;
    }

    Ok(())
}

fn seed_missing_tree(source: &Path, target: &Path) -> io::Result<()> {
    if !source.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("source directory not found: {}", source.display()),
        ));
    }

    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            seed_missing_tree(&source_path, &target_path)?;
        } else if file_type.is_file() && !target_path.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &target_path)?;
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, target: &Path) -> io::Result<()> {
    if !source.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("source directory not found: {}", source.display()),
        ));
    }

    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree(&source_path, &target_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &target_path)?;
        }
    }
    Ok(())
}

async fn ensure_vector_frozen_if_missing<F, Fut>(
    writer: &PackageWriter,
    vector_id: &str,
    generate: F,
) -> io::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<FreezeResult>>,
{
    if !writer.paths().vector_wire_path(vector_id).is_file() {
        let _ = generate().await?;
    }
    Ok(())
}

async fn ensure_generated_direct_request_root<F, Fut>(
    writer: &PackageWriter,
    generate_request: F,
) -> io::Result<[u8; 32]>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<FreezeResult>>,
{
    ensure_vector_frozen_if_missing(writer, "BV-001", generate_request).await?;
    let binding_path = writer
        .paths()
        .binding_path(crate::authoring::BindingFamily::Direct, "request-01.yaml");
    let request_digest = read_yaml_scalar(&binding_path, "request_digest")?;
    parse_hex_array_32("request_digest", &request_digest)
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn ensure_generated_nested_request_root<F, Fut>(
    writer: &PackageWriter,
    generate_request: F,
) -> io::Result<[u8; 32]>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<FreezeResult>>,
{
    ensure_vector_frozen_if_missing(writer, "BV-004", generate_request).await?;
    let binding_path = writer
        .paths()
        .binding_path(crate::authoring::BindingFamily::Nested, "request-01.yaml");
    let request_digest = read_yaml_scalar(&binding_path, "request_digest")?;
    parse_hex_array_32("request_digest", &request_digest)
}

async fn ensure_generated_routed_request_root<F, Fut>(
    writer: &PackageWriter,
    generate_request: F,
) -> io::Result<[u8; 32]>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<FreezeResult>>,
{
    ensure_vector_frozen_if_missing(writer, "BV-007", generate_request).await?;
    let binding_path = writer
        .paths()
        .binding_path(crate::authoring::BindingFamily::Routed, "request-01.yaml");
    let request_digest = read_yaml_scalar(&binding_path, "request_digest")?;
    parse_hex_array_32("request_digest", &request_digest)
}

async fn freeze_generated<C, F, Fut, W>(generate: F, freeze: W) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = C>,
    W: FnOnce(C) -> io::Result<FreezeResult>,
{
    let candidate = generate().await;
    freeze(candidate)
}

async fn freeze_direct_request_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    sender: &str,
    receiver: &str,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = GeneratedDirectRequestCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_direct_request_from_source(source, writer, candidate.into(), sender, receiver)
    })
    .await
}

async fn freeze_direct_accept_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    sender: &str,
    receiver: &str,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DirectAcceptCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_direct_accept_from_source(source, writer, candidate, sender, receiver)
    })
    .await
}

async fn freeze_direct_rfd_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DirectRfdCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_direct_rfd_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_direct_message_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = GeneratedDirectMessageCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_direct_message_from_source(source, writer, candidate.into())
    })
    .await
}

async fn freeze_digest_mismatch_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DigestMismatchCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_digest_mismatch_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_nested_request_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = NestedRequestCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_nested_request_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_routed_path_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = RoutedPathCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_routed_path_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_routed_request_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = RoutedRequestCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_routed_request_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_routed_accept_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = RoutedAcceptCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_routed_accept_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_nested_message_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = NestedMessageCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_nested_message_from_source(source, writer, candidate)
    })
    .await
}

async fn freeze_routed_message_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = RoutedMessageCandidate>,
{
    freeze_generated(generate, |candidate| {
        freeze_routed_message_from_source(source, writer, candidate)
    })
    .await
}

fn build_no_prior_relationship_request(
    case_id: &str,
    namespace: &str,
    writer: &PackageWriter,
    payload_semantics_ref: &str,
) -> io::Result<NoPriorRelationshipRequest> {
    Ok(NoPriorRelationshipRequest {
        case_id: case_id.into(),
        source_vector_ref: format!("{namespace}.vector.SV-001.wire"),
        source_binding_ref: format!("{namespace}.binding.direct.message-01"),
        source_fixture_ref: "fixture.conversation.direct.message-01".into(),
        source_wire_base64: read_wire_base64(writer.paths().vector_wire_path("SV-001"))?,
        payload_semantics_ref: payload_semantics_ref.into(),
    })
}

fn build_nested_without_outer_request(
    case_id: &str,
    namespace: &str,
    writer: &PackageWriter,
    inner_context_ref: &str,
    payload_semantics_ref: &str,
) -> io::Result<NestedWithoutOuterRequest> {
    Ok(NestedWithoutOuterRequest {
        case_id: case_id.into(),
        source_vector_ref: format!("{namespace}.vector.SV-002.wire"),
        source_binding_ref: format!("{namespace}.binding.nested.message-01"),
        source_fixture_ref: "fixture.conversation.nested.message-01".into(),
        source_wire_base64: read_wire_base64(writer.paths().vector_wire_path("SV-002"))?,
        inner_context_ref: inner_context_ref.into(),
        payload_semantics_ref: payload_semantics_ref.into(),
    })
}

fn freeze_nested_accept_generated(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    candidate: NestedAcceptCandidate,
) -> io::Result<FreezeResult> {
    let inner_receiver_vid = read_generated_inner_alice_identifier(writer)?;
    freeze_nested_accept_from_source(source, writer, candidate, &inner_receiver_vid)
}

async fn freeze_av003_from_generated<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    confidentiality_mechanism: &str,
    generate: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = NonConfidentialBindingCandidate>,
{
    let candidate = generate().await;
    freeze_nonconfidential_binding_from_source(
        source,
        writer,
        candidate,
        confidentiality_mechanism,
        NONCONFIDENTIAL_BINDING_RULE,
    )
}

async fn freeze_sv004_from_generated<F, Fut>(
    source: &SdkCandidateSource,
    spec_source: &SpecCandidateSource,
    writer: &PackageWriter,
    namespace: &str,
    case_id: &str,
    payload_semantics_ref: &str,
    generate_direct_message: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = GeneratedDirectMessageCandidate>,
{
    ensure_vector_frozen_if_missing(writer, "SV-001", || async {
        let candidate = generate_direct_message().await;
        freeze_direct_message_from_source(source, writer, candidate.into())
    })
    .await?;

    let request =
        build_no_prior_relationship_request(case_id, namespace, writer, payload_semantics_ref)?;
    freeze_no_prior_relationship_from_source(spec_source, writer, &request)
}

async fn freeze_sv006_from_generated<F, Fut>(
    source: &SdkCandidateSource,
    spec_source: &SpecCandidateSource,
    writer: &PackageWriter,
    namespace: &str,
    case_id: &str,
    inner_context_ref: &str,
    payload_semantics_ref: &str,
    generate_nested_message: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = NestedMessageCandidate>,
{
    ensure_vector_frozen_if_missing(writer, "SV-002", || async {
        let candidate = generate_nested_message().await;
        freeze_nested_message_from_source(source, writer, candidate)
    })
    .await?;

    let request = build_nested_without_outer_request(
        case_id,
        namespace,
        writer,
        inner_context_ref,
        payload_semantics_ref,
    )?;
    freeze_nested_without_outer_from_source(spec_source, writer, &request)
}

async fn freeze_av001_from_existing_request<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    case_id: &str,
    confidentiality_mechanism: &str,
    sender_field_rule: &str,
    generate_request: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<FreezeResult>>,
{
    ensure_vector_frozen_if_missing(writer, "BV-001", generate_request).await?;
    let wire_base64 = read_wire_base64(writer.paths().vector_wire_path("BV-001"))?;
    let candidate = build_sender_field_candidate(
        case_id,
        wire_base64,
        confidentiality_mechanism,
        sender_field_rule,
    );
    freeze_sender_field_mechanism_from_source(source, writer, candidate)
}

async fn freeze_av002_from_existing_request<F, Fut>(
    source: &SdkCandidateSource,
    writer: &PackageWriter,
    case_id: &str,
    confidentiality_mechanism: &str,
    cesr_ciphertext_family: &str,
    generate_request: F,
) -> io::Result<FreezeResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<FreezeResult>>,
{
    ensure_vector_frozen_if_missing(writer, "BV-001", generate_request).await?;
    let wire_base64 = read_wire_base64(writer.paths().vector_wire_path("BV-001"))?;
    let candidate = build_ciphertext_family_candidate(
        case_id,
        wire_base64,
        confidentiality_mechanism,
        cesr_ciphertext_family,
    );
    freeze_ciphertext_family_from_source(source, writer, candidate)
}

fn build_sender_field_candidate(
    case_id: &str,
    wire_base64: String,
    confidentiality_mechanism: &str,
    sender_field_rule: &str,
) -> SenderFieldMechanismCandidate {
    SenderFieldMechanismCandidate {
        case_id: case_id.into(),
        vector_id: "AV-001".into(),
        wire_base64,
        confidentiality_mechanism: confidentiality_mechanism.into(),
        sender_field_rule: sender_field_rule.into(),
    }
}

fn build_ciphertext_family_candidate(
    case_id: &str,
    wire_base64: String,
    confidentiality_mechanism: &str,
    cesr_ciphertext_family: &str,
) -> CiphertextFamilyCandidate {
    CiphertextFamilyCandidate {
        case_id: case_id.into(),
        vector_id: "AV-002".into(),
        wire_base64,
        confidentiality_mechanism: confidentiality_mechanism.into(),
        cesr_ciphertext_family: cesr_ciphertext_family.into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
const SUPPORTED_VECTORS_CC001: &[&str] = &[
    "BV-001", "BV-002", "BV-003", "SV-001", "SV-005", "AV-001", "AV-002", "AV-003", "BV-004",
    "BV-005", "BV-006", "BV-007", "BV-008", "SV-002", "SV-003", "SV-004", "SV-006",
];

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
fn default_supported_vectors_cc001() -> Vec<String> {
    owned_vector_list(SUPPORTED_VECTORS_CC001)
}

#[cfg(not(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr"))))]
fn default_supported_vectors_cc001() -> Vec<String> {
    Vec::new()
}

#[cfg(feature = "essr")]
const SUPPORTED_VECTORS_CC002: &[&str] = &[
    "BV-001", "BV-002", "BV-003", "BV-004", "BV-005", "BV-006", "BV-007", "BV-008", "SV-001",
    "SV-002", "SV-003", "SV-004", "SV-006", "SV-005", "AV-001", "AV-002", "AV-003",
];

#[cfg(feature = "essr")]
fn default_supported_vectors_cc002() -> Vec<String> {
    owned_vector_list(SUPPORTED_VECTORS_CC002)
}

#[cfg(not(feature = "essr"))]
fn default_supported_vectors_cc002() -> Vec<String> {
    Vec::new()
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
const SUPPORTED_VECTORS_CC003: &[&str] = &[
    "BV-001", "BV-002", "BV-003", "BV-004", "BV-005", "BV-006", "BV-007", "BV-008", "SV-001",
    "SV-002", "SV-003", "SV-004", "SV-006", "SV-005", "AV-001", "AV-002", "AV-003",
];

#[cfg(all(feature = "nacl", not(feature = "pq")))]
fn default_supported_vectors_cc003() -> Vec<String> {
    owned_vector_list(SUPPORTED_VECTORS_CC003)
}

#[cfg(not(all(feature = "nacl", not(feature = "pq"))))]
fn default_supported_vectors_cc003() -> Vec<String> {
    Vec::new()
}

impl From<GeneratedDirectRequestCandidate> for DirectRequestCandidate {
    fn from(value: GeneratedDirectRequestCandidate) -> Self {
        Self {
            case_id: value.case_id,
            vector_id: value.vector_id,
            wire_base64: value.wire_base64,
            request_digest: value.request_digest,
            nonce: value.nonce,
        }
    }
}

impl From<GeneratedDirectMessageCandidate> for DirectMessageCandidate {
    fn from(value: GeneratedDirectMessageCandidate) -> Self {
        Self {
            case_id: value.case_id,
            vector_id: value.vector_id,
            wire_base64: value.wire_base64,
            relationship_context_ref: value.relationship_context_ref,
            payload_semantics_ref: value.payload_semantics_ref,
            sender: value.sender,
            receiver: value.receiver,
            nonconfidential_data: value.nonconfidential_data,
            payload: value.payload,
            crypto_type: value.crypto_type,
            signature_type: value.signature_type,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GeneratedDirectRequestCandidate {
    case_id: String,
    vector_id: String,
    wire_base64: String,
    request_digest: String,
    nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GeneratedDirectMessageCandidate {
    case_id: String,
    vector_id: String,
    wire_base64: String,
    relationship_context_ref: String,
    payload_semantics_ref: String,
    sender: String,
    receiver: String,
    nonconfidential_data: String,
    payload: String,
    crypto_type: String,
    signature_type: String,
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(any(feature = "essr", all(feature = "nacl", not(feature = "pq"))))]
fn slice_range(haystack: &[u8], needle: &[u8]) -> std::ops::Range<usize> {
    let base = haystack.as_ptr() as usize;
    let start = needle.as_ptr() as usize;
    let offset = start
        .checked_sub(base)
        .expect("needle is not derived from haystack");
    offset..(offset + needle.len())
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_direct_request_candidate() -> GeneratedDirectRequestCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let (_endpoint, sealed) = alice_db
        .make_relationship_request(CC001_ALICE, CC001_BOB, None)
        .unwrap();

    let request_digest = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected request status: {status:?}"),
    };

    let mut unopened = sealed.clone();
    let opened = bob_db.open_message(&mut unopened).unwrap();
    match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship { nested_vid, .. } => {
            assert!(nested_vid.is_none());
        }
        _ => panic!("request candidate did not open as a relationship request"),
    }

    let mut probe = sealed.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("request candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeAuth);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        bob_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
        alice_vid.encryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Auth(sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let nonce = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationProposal { nonce, .. } => to_hex(nonce.as_bytes()),
        _ => panic!("decoded request candidate was not a direct relation proposal"),
    };

    GeneratedDirectRequestCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-001".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(request_digest),
        nonce,
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_direct_message_candidate() -> GeneratedDirectMessageCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid, None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid, None).unwrap();
    let bob_verified = create_vid_from_file("../examples/test/bob/piv.json").await;
    alice_db
        .add_verified_vid(bob_verified.vid().clone(), None)
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nonconfidential = b"cc001-direct-message-01-nonconf";
    let payload = b"hello direct world";

    let (_endpoint, sealed) = alice_db
        .seal_message(CC001_ALICE, CC001_BOB, Some(nonconfidential), payload)
        .unwrap();
    let mut unopened = sealed.clone();

    let opened = bob_db.open_message(&mut unopened).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("direct message candidate did not open as a generic message");
    };

    GeneratedDirectMessageCandidate {
        case_id: "CC-001".into(),
        vector_id: "SV-001".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        relationship_context_ref: "cc001-direct-alice-bob-bidirectional".into(),
        payload_semantics_ref: "cc001-direct-message-01".into(),
        sender,
        receiver: receiver.expect("expected direct receiver"),
        nonconfidential_data: String::from_utf8(nonconfidential_data.unwrap().to_vec()).unwrap(),
        payload: String::from_utf8(message.to_vec()).unwrap(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_direct_accept_candidate(request_digest: [u8; 32]) -> DirectAcceptCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();

    let (_endpoint, accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_digest, None)
        .unwrap();
    let mut unopened = accept.clone();

    let opened_accept = alice_db.open_message(&mut unopened).unwrap();
    match opened_accept {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender, receiver, ..
        } => {
            assert_eq!(sender, CC001_BOB);
            assert_eq!(receiver, CC001_ALICE);
        }
        _ => panic!("accept candidate did not open as a relationship accept"),
    }

    let mut probe = accept.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("accept candidate did not contain ciphertext");
    };

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        alice_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
        bob_vid.encryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Auth(sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let reply_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded accept candidate was not a direct relation affirm"),
    };

    DirectAcceptCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-002".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        request_digest: to_hex(request_digest),
        reply_digest,
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_direct_rfd_candidate(request_digest: [u8; 32]) -> DirectRfdCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::ReverseUnidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();

    let (_endpoint, cancel) = alice_db
        .make_relationship_cancel(CC001_ALICE, CC001_BOB)
        .unwrap();
    let mut unopened = cancel.clone();

    let opened_cancel = bob_db.open_message(&mut unopened).unwrap();
    match opened_cancel {
        tsp_sdk::ReceivedTspMessage::CancelRelationship { sender, receiver } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
        }
        _ => panic!("rfd candidate did not open as a relationship cancel"),
    }

    let mut probe = cancel.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("rfd candidate did not contain ciphertext");
    };

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        bob_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
        alice_vid.encryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Auth(sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let cancel_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::RelationshipCancel { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded rfd candidate was not a relationship cancel"),
    };

    DirectRfdCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&cancel),
        digest: cancel_digest,
        reviewed_context: "pending-request-cancel".into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_digest_mismatch_candidate(
    expected_request_digest: [u8; 32],
) -> DigestMismatchCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let mut mismatching_accept_digest = expected_request_digest;
    mismatching_accept_digest[31] ^= 0x01;

    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: expected_request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: expected_request_digest,
            },
            CC001_BOB,
        )
        .unwrap();

    let (_endpoint, accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, mismatching_accept_digest, None)
        .unwrap();
    let mut unopened = accept.clone();

    let err = alice_db.open_message(&mut unopened).unwrap_err();
    let tsp_sdk::Error::Relationship(message) = err else {
        panic!("digest-mismatch candidate did not fail as a relationship error");
    };
    assert!(message.contains("thread_id does not match digest"));

    let mut probe = accept.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("digest-mismatch candidate did not contain ciphertext");
    };

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        alice_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
        bob_vid.encryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Auth(sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let decoded_accept_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded digest-mismatch candidate was not a direct relation affirm"),
    };

    DigestMismatchCandidate {
        case_id: "CC-001".into(),
        vector_id: "SV-005".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        expected_request_digest: to_hex(expected_request_digest),
        mismatching_accept_digest: decoded_accept_digest,
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_nonconfidential_binding_candidate() -> NonConfidentialBindingCandidate {
    let alice = create_vid_from_file("../examples/test/alice/piv.json").await;
    let bob = create_vid_from_file("../examples/test/bob/piv.json").await;
    let sender = alice.identifier().to_string();
    let receiver = bob.identifier().to_string();
    let nonconfidential = b"cc001-av003-nonconfidential";

    let sender_store = create_test_store();
    sender_store.add_private_vid(alice.clone(), None).unwrap();
    sender_store.add_verified_vid(bob.clone(), None).unwrap();

    let receiver_store = create_test_store();
    receiver_store.add_private_vid(bob.clone(), None).unwrap();
    receiver_store
        .add_verified_vid(alice.clone(), None)
        .unwrap();

    let mut request_digest = [0_u8; 32];
    let sealed = tsp_sdk::crypto::seal_and_hash(
        &alice,
        &bob,
        Some(nonconfidential),
        tsp_sdk::Payload::RequestRelationship {
            route: None,
            thread_id: Default::default(),
        },
        Some(&mut request_digest),
    )
    .unwrap();

    let mut unopened = sealed.clone();
    let opened = receiver_store.open_message(&mut unopened).unwrap();
    let opened_request_digest = match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender: opened_sender,
            receiver: opened_receiver,
            thread_id,
            ..
        } => {
            assert_eq!(opened_sender, sender);
            assert_eq!(opened_receiver, receiver);
            thread_id
        }
        _ => panic!("non-confidential-binding candidate did not open as a relationship request"),
    };
    assert_eq!(opened_request_digest, request_digest);

    let parts = tsp_sdk::cesr::open_message_into_parts(&sealed).unwrap();
    let nonconf_part = parts
        .nonconfidential_data
        .expect("review sample should carry non-confidential data");
    assert_eq!(nonconf_part.data, nonconfidential);

    let mut tampered = sealed.clone();
    let range = find_slice_range(&sealed, nonconf_part.data)
        .expect("non-confidential data should be present in sealed sample");
    tampered[range.start] ^= 0x01;
    assert!(receiver_store.open_message(&mut tampered).is_err());

    NonConfidentialBindingCandidate {
        case_id: "CC-001".into(),
        vector_id: "AV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(request_digest),
        nonconfidential_data: std::str::from_utf8(nonconfidential).unwrap().into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
fn find_slice_range(haystack: &[u8], needle: &[u8]) -> Option<std::ops::Range<usize>> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|start| start..start + needle.len())
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_nested_request_candidate() -> NestedRequestCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let (sealed, nested_a_vid, nested_thread, nonce) = {
        let ((_endpoint, request), nested_a_vid) = alice_db
            .make_nested_relationship_request(CC001_ALICE, CC001_BOB)
            .unwrap();

        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Bidirectional {
                outstanding_nested_thread_ids,
                ..
            } => *outstanding_nested_thread_ids.last().unwrap(),
            status => panic!("missing outstanding nested thread id: {status:?}"),
        };

        let mut inspected_request = request.clone();
        let view = tsp_sdk::cesr::decode_envelope(&mut inspected_request).unwrap();
        let tsp_sdk::cesr::DecodedEnvelope {
            raw_header,
            envelope,
            ciphertext: Some(ciphertext),
        } = view.into_opened::<&[u8]>().unwrap()
        else {
            panic!("nested request candidate did not contain ciphertext");
        };
        assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeAuth);
        assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
        assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

        let (ciphertext, footer) = ciphertext.split_at_mut(
            ciphertext.len()
                - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
                - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
        );
        let (tag, encapped_key) = footer
            .split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

        let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
            bob_vid.decryption_key().as_ref(),
        )
        .unwrap();
        let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
            alice_vid.encryption_key().as_ref(),
        )
        .unwrap();
        let encapped_key =
            <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
        let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

        single_shot_open_in_place_detached::<
            tsp_sdk::crypto::Aead,
            tsp_sdk::crypto::Kdf,
            tsp_sdk::crypto::Kem,
        >(
            &OpModeR::Auth(sender_encryption_key),
            &receiver_decryption_key,
            &encapped_key,
            raw_header,
            ciphertext,
            &[],
            &tag,
        )
        .unwrap();

        let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
        assert!(decoded.sender_identity.is_none());
        let (nonce, mut inner) = match decoded.payload {
            tsp_sdk::cesr::Payload::NestedRelationProposal { nonce, message } => {
                (*nonce.as_bytes(), message.to_vec())
            }
            _ => panic!("decoded nested request candidate was not a nested relation proposal"),
        };

        let inner_sender = match tsp_sdk::cesr::probe(&mut inner).unwrap() {
            tsp_sdk::cesr::EnvelopeType::SignedMessage {
                sender, receiver, ..
            } => {
                assert!(receiver.is_none());
                sender
            }
            _ => panic!("inner nested relationship payload was not a signed message"),
        };
        assert_eq!(inner_sender, nested_a_vid.identifier().as_bytes());

        (request, nested_a_vid, thread_id, nonce)
    };

    let mut unopened = sealed.clone();
    let opened = bob_db.open_message(&mut unopened).unwrap();
    match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            thread_id,
            ..
        } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
            assert_eq!(nested_vid, nested_a_vid.identifier());
            assert_eq!(thread_id, nested_thread);
        }
        _ => panic!("nested request candidate did not open as a nested relationship request"),
    }

    NestedRequestCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-004".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(nested_thread),
        nonce: to_hex(nonce),
        inner_vid: nested_a_vid.identifier().into(),
        inner_verification_key_jwk: serde_json::to_string(&nested_a_vid.signature_key_jwk())
            .unwrap(),
        inner_encryption_key_jwk: serde_json::to_string(&nested_a_vid.encryption_key_jwk())
            .unwrap(),
        inner_private_vid_json: export_owned_vid_json_for_tests(&nested_a_vid),
        outer_context_ref: "cc001-outer-alice-bob-bidirectional".into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_nested_accept_candidate_from_generated_request(
    paths: &CasePackagePaths,
) -> NestedAcceptCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let alice =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice";
    let bob =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob";

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(alice, bob, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(alice, bob)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(bob, alice, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nested_thread = parse_hex_array_32(
        "generated nested request_digest",
        &read_yaml_scalar(
            &paths.binding_path(crate::authoring::BindingFamily::Nested, "request-01.yaml"),
            "request_digest",
        )
        .unwrap(),
    )
    .unwrap();
    let nested_request_wire = read_generated_vector_wire(paths, "BV-004").unwrap();
    let nested_a_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.alice-1.private.json"),
    )
    .await;

    let outer_thread = match alice_db
        .get_relation_status_for_vid_pair(alice, bob)
        .unwrap()
    {
        RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: _,
        } => thread_id,
        status => panic!("unexpected outer relationship status before nested accept: {status:?}"),
    };

    alice_db
        .add_private_vid(nested_a_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(alice))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob,
            RelationshipStatus::Bidirectional {
                thread_id: outer_thread,
                outstanding_nested_thread_ids: vec![nested_thread],
            },
            alice,
        )
        .unwrap();

    let mut nested_request = nested_request_wire;
    let opened_nested_a_vid = match bob_db.open_message(&mut nested_request).unwrap() {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            thread_id,
            ..
        } => {
            assert_eq!(sender, alice);
            assert_eq!(receiver, bob);
            assert_eq!(nested_vid, nested_a_vid.identifier());
            assert_eq!(thread_id, nested_thread);
            nested_vid
        }
        _ => panic!("generated nested request did not open as a nested relationship request"),
    };

    let (sealed, nested_b_vid, reply_digest) = {
        let ((_endpoint, nested_accept), nested_b_vid) = bob_db
            .make_nested_relationship_accept(bob, &opened_nested_a_vid, nested_thread)
            .unwrap();

        let mut inspected_accept = nested_accept.clone();
        let view = tsp_sdk::cesr::decode_envelope(&mut inspected_accept).unwrap();
        let tsp_sdk::cesr::DecodedEnvelope {
            raw_header,
            envelope,
            ciphertext: Some(ciphertext),
        } = view.into_opened::<&[u8]>().unwrap()
        else {
            panic!("nested accept candidate did not contain ciphertext");
        };
        assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeAuth);
        assert_eq!(envelope.sender, bob.as_bytes());
        assert_eq!(envelope.receiver, Some(alice.as_bytes()));

        let (ciphertext, footer) = ciphertext.split_at_mut(
            ciphertext.len()
                - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
                - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
        );
        let (tag, encapped_key) = footer
            .split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

        let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
            alice_vid.decryption_key().as_ref(),
        )
        .unwrap();
        let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
            bob_vid.encryption_key().as_ref(),
        )
        .unwrap();
        let encapped_key =
            <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
        let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

        single_shot_open_in_place_detached::<
            tsp_sdk::crypto::Aead,
            tsp_sdk::crypto::Kdf,
            tsp_sdk::crypto::Kem,
        >(
            &OpModeR::Auth(sender_encryption_key),
            &receiver_decryption_key,
            &encapped_key,
            raw_header,
            ciphertext,
            &[],
            &tag,
        )
        .unwrap();

        let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
        assert!(decoded.sender_identity.is_none());
        let (reply_digest, mut inner) = match decoded.payload {
            tsp_sdk::cesr::Payload::NestedRelationAffirm { reply, message } => {
                (*reply.as_bytes(), message.to_vec())
            }
            _ => panic!("decoded nested accept candidate was not a nested relation affirm"),
        };

        let inner_sender = match tsp_sdk::cesr::probe(&mut inner).unwrap() {
            tsp_sdk::cesr::EnvelopeType::SignedMessage {
                sender, receiver, ..
            } => {
                assert_eq!(receiver, Some(nested_a_vid.identifier().as_bytes()));
                sender
            }
            _ => panic!("inner nested relationship payload was not a signed message"),
        };
        assert_eq!(inner_sender, nested_b_vid.identifier().as_bytes());

        (nested_accept, nested_b_vid, reply_digest)
    };

    let mut unopened = sealed.clone();
    let opened_nested_b_vid = match alice_db.open_message(&mut unopened).unwrap() {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            ..
        } => {
            assert_eq!(sender, bob);
            assert_eq!(receiver, alice);
            nested_vid
        }
        _ => panic!("nested accept candidate did not open as a nested relationship accept"),
    };
    assert_eq!(opened_nested_b_vid, nested_b_vid.identifier());
    assert_eq!(reply_digest, nested_thread);

    NestedAcceptCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-005".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(nested_thread),
        reply_digest: to_hex(reply_digest),
        inner_vid: nested_b_vid.identifier().into(),
        inner_verification_key_jwk: serde_json::to_string(&nested_b_vid.signature_key_jwk())
            .unwrap(),
        inner_encryption_key_jwk: serde_json::to_string(&nested_b_vid.encryption_key_jwk())
            .unwrap(),
        inner_private_vid_json: export_owned_vid_json_for_tests(&nested_b_vid),
        outer_context_ref: "cc001-outer-alice-bob-bidirectional".into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_routed_path_candidate() -> RoutedPathCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let alice_did = CC001_ALICE;
    let bob_did = CC001_BOB;

    alice_db.add_verified_vid(hop1_vid.clone(), None).unwrap();
    alice_db.add_verified_vid(hop2_vid.clone(), None).unwrap();
    alice_db.add_verified_vid(bob_vid, None).unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, bob_did])
        .unwrap();

    hop1_db.add_verified_vid(alice_vid, None).unwrap();
    hop1_db.add_verified_vid(hop2_vid, None).unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop1_did,
        )
        .unwrap();

    let (_endpoint, sealed) = alice_db
        .seal_message(alice_did, bob_did, None, b"hello routed world")
        .unwrap();
    let mut unopened = sealed.clone();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        sender,
        receiver,
        next_hop,
        route,
        opaque_payload,
    } = hop1_db.open_message(&mut unopened).unwrap()
    else {
        panic!("path candidate did not open as a forward request");
    };

    assert_eq!(sender, alice_did);
    assert_eq!(receiver, hop1_did);
    assert_eq!(next_hop, hop2_did);

    let remaining_route = route
        .iter()
        .map(|segment| std::str::from_utf8(segment.iter().as_slice()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(remaining_route, vec![bob_did]);

    RoutedPathCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-006".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        current_hop_vid: hop1_did.into(),
        next_hop_vid: next_hop.into(),
        remaining_route_json: format!("[\"{bob_did}\"]"),
        opaque_payload_base64: Base64UrlUnpadded::encode_string(opaque_payload.iter().as_slice()),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_routed_request_candidate() -> RoutedRequestCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid, None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let alice_did = CC001_ALICE;
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";
    let bob_did = CC001_BOB;

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, dropoff_did])
        .unwrap();

    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop1_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            bob_did,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();

    let route = [hop1_did, hop2_did, dropoff_did];
    let (_endpoint, mut first_hop_message) = alice_db
        .make_relationship_request(alice_did, bob_did, Some(&route))
        .unwrap();

    let request_digest = match alice_db
        .get_relation_status_for_vid_pair(alice_did, bob_did)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected routed request status: {status:?}"),
    };

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed request candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop1_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed request candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let mut inner = opaque_payload.to_vec();
    let view = tsp_sdk::cesr::decode_envelope(&mut inner).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("routed request inner payload did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeAuth);
    assert_eq!(envelope.sender, alice_did.as_bytes());
    assert_eq!(envelope.receiver, Some(bob_did.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        bob_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
        alice_vid.encryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Auth(sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let nonce = match decoded.payload {
        tsp_sdk::cesr::Payload::DirectRelationProposal { nonce, .. } => *nonce.as_bytes(),
        _ => panic!("routed request inner payload was not a direct relation proposal"),
    };

    let (_endpoint, mut final_message) = hop2_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    let opened_thread_id = match bob_db.open_message(&mut final_message).unwrap() {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            route: Some(route),
            thread_id,
            nested_vid: None,
        } => {
            assert_eq!(sender, alice_did);
            assert_eq!(receiver, bob_did);
            let route = route
                .iter()
                .map(|vid| std::str::from_utf8(vid).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(route, vec![hop1_did, hop2_did, dropoff_did]);
            thread_id
        }
        _ => panic!("final routed request candidate did not open as a relationship request"),
    };

    assert_eq!(opened_thread_id, request_digest);

    RoutedRequestCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-007".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        request_digest: to_hex(request_digest),
        nonce: to_hex(nonce),
        path_context_ref: "cc001-routed-final-delivery-01".into(),
        sender_vid: alice_did.into(),
        receiver_vid: bob_did.into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_routed_accept_candidate(request_digest: [u8; 32]) -> RoutedAcceptCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid, None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid, None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let alice_did = CC001_ALICE;
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";
    let bob_did = CC001_BOB;

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            alice_did,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            alice_did,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            bob_did,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            bob_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop2_did,
        )
        .unwrap();

    hop1_db.add_private_vid(dropoff_vid.clone(), None).unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();

    let route = [hop2_did, hop1_did, dropoff_did];
    let (_endpoint, mut first_hop_message) = bob_db
        .make_relationship_accept(bob_did, alice_did, request_digest, Some(&route))
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed accept candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop2_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed accept candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let mut inner = opaque_payload.to_vec();
    let view = tsp_sdk::cesr::decode_envelope(&mut inner).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("routed accept inner payload did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeAuth);
    assert_eq!(envelope.sender, bob_did.as_bytes());
    assert_eq!(envelope.receiver, Some(alice_did.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        alice_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let sender_encryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PublicKey::from_bytes(
        bob_vid.encryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Auth(sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let reply_digest = match decoded.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => *reply.as_bytes(),
        _ => panic!("routed accept inner payload was not a direct relation affirm"),
    };

    let (_endpoint, mut final_message) = hop1_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    match alice_db.open_message(&mut final_message).unwrap() {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            nested_vid: None,
        } => {
            assert_eq!(sender, bob_did);
            assert_eq!(receiver, alice_did);
        }
        _ => panic!("final routed accept candidate did not open as a relationship accept"),
    }

    assert_eq!(reply_digest, request_digest);

    RoutedAcceptCandidate {
        case_id: "CC-001".into(),
        vector_id: "BV-008".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        request_digest: to_hex(request_digest),
        reply_digest: to_hex(reply_digest),
        path_context_ref: "cc001-routed-final-delivery-01".into(),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_routed_message_candidate() -> RoutedMessageCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid, None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid, None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid, None).unwrap();

    let alice_did = CC001_ALICE;
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";
    let bob_did = CC001_BOB;

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, dropoff_did])
        .unwrap();

    hop1_db.add_private_vid(dropoff_vid.clone(), None).unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            hop1_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            bob_did,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();

    let payload = b"hello routed world";
    let nonconfidential = b"cc001-routed-message-01-nonconf";

    let (_endpoint, mut first_hop_message) = alice_db
        .seal_message(alice_did, bob_did, Some(nonconfidential), payload)
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed generic-message candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop1_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed generic-message candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let (_endpoint, mut final_message) = hop2_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    let opened = bob_db.open_message(&mut final_message).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("final routed generic-message candidate did not open as a generic message");
    };

    assert_eq!(sender, alice_did);
    assert_eq!(receiver.as_deref(), Some(bob_did));
    assert_eq!(message.as_ref(), payload);
    assert_eq!(
        nonconfidential_data.as_ref().map(|d| d.as_ref()),
        Some(nonconfidential.as_slice())
    );

    RoutedMessageCandidate {
        case_id: "CC-001".into(),
        vector_id: "SV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        path_context_ref: "cc001-routed-final-delivery-01".into(),
        payload_semantics_ref: "cc001-routed-message-01".into(),
        sender,
        receiver: receiver.unwrap(),
        nonconfidential_data: std::str::from_utf8(nonconfidential).unwrap().into(),
        payload: std::str::from_utf8(payload).unwrap().into(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn cc001_nested_message_candidate(paths: &CasePackagePaths) -> NestedMessageCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();

    let alice = CC001_ALICE;
    let bob = CC001_BOB;

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(alice, bob, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(alice, bob)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(bob, alice, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nested_a_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.alice-1.private.json"),
    )
    .await;
    let nested_b_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.bob-1.private.json"),
    )
    .await;

    alice_db
        .add_private_vid(nested_a_vid.clone(), None)
        .unwrap();
    alice_db
        .add_verified_vid(nested_b_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(alice))
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_b_vid.identifier(), Some(bob))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_b_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_a_vid.identifier(),
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_a_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_b_vid.identifier(),
        )
        .unwrap();

    bob_db.add_private_vid(nested_b_vid.clone(), None).unwrap();
    bob_db.add_verified_vid(nested_a_vid.clone(), None).unwrap();
    bob_db
        .set_parent_for_vid(nested_b_vid.identifier(), Some(bob))
        .unwrap();
    bob_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(alice))
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            nested_a_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_b_vid.identifier(),
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            nested_b_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_a_vid.identifier(),
        )
        .unwrap();

    let payload = b"hello nested world";

    let (_endpoint, sealed) = alice_db
        .seal_message(
            nested_a_vid.identifier(),
            nested_b_vid.identifier(),
            None,
            payload,
        )
        .unwrap();
    let mut unopened = sealed.clone();

    let opened = bob_db.open_message(&mut unopened).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("nested message candidate did not open as a generic message");
    };

    assert_eq!(sender, nested_a_vid.identifier());
    assert_eq!(receiver.as_deref(), Some(nested_b_vid.identifier()));
    assert_eq!(message.as_ref(), payload);
    assert!(nonconfidential_data.is_none());

    NestedMessageCandidate {
        case_id: "CC-001".into(),
        vector_id: "SV-002".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        outer_context_ref: "cc001-outer-alice-bob-bidirectional".into(),
        inner_context_ref: "cc001-inner-alice-1-bob-1-bidirectional".into(),
        payload_semantics_ref: "cc001-nested-message-01".into(),
        inner_sender_owned_vid_json: serde_json::to_string(&nested_a_vid).unwrap(),
        inner_receiver_owned_vid_json: serde_json::to_string(&nested_b_vid).unwrap(),
        sender,
        receiver: receiver.unwrap(),
        nonconfidential_data: "<none>".into(),
        payload: std::str::from_utf8(payload).unwrap().into(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
async fn generate_cc001_vector_asset_set(
    vector_id: &str,
    source: &SdkCandidateSource,
    writer: &PackageWriter,
) -> io::Result<FreezeResult> {
    let spec_source = SpecCandidateSource::new("spec-generate");
    let namespace = writer.paths().artifact_namespace();
    match vector_id {
        "BV-001" => freeze_direct_request_generated(
            source,
            writer,
            CC001_ALICE,
            CC001_BOB,
            || async { cc001_direct_request_candidate().await },
        )
        .await,
        "BV-002" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc001_direct_request_candidate().await
                })
            })
            .await?;
            freeze_direct_accept_generated(source, writer, CC001_BOB, CC001_ALICE, || async move {
                cc001_direct_accept_candidate(request_digest).await
            })
            .await
        }
        "BV-003" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc001_direct_request_candidate().await
                })
            })
            .await?;
            freeze_direct_rfd_generated(source, writer, || async move {
                cc001_direct_rfd_candidate(request_digest).await
            })
            .await
        }
        "SV-001" => freeze_direct_message_generated(source, writer, || async {
            cc001_direct_message_candidate().await
        })
        .await,
        "SV-005" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc001_direct_request_candidate().await
                })
            })
            .await?;
            freeze_digest_mismatch_generated(source, writer, || async move {
                cc001_digest_mismatch_candidate(request_digest).await
            })
            .await
        }
        "AV-001" => freeze_av001_from_existing_request(
            source,
            writer,
            "CC-001",
            "HPKE-Auth",
            "outer envelope sender field is present and identifies the sender; the decrypted confidential payload carries no additional sender identity field",
            || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc001_direct_request_candidate().await
                })
            },
        )
        .await,
        "AV-002" => freeze_av002_from_existing_request(
            source,
            writer,
            "CC-001",
            "HPKE-Auth",
            "HpkeAuth",
            || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc001_direct_request_candidate().await
                })
            },
        )
        .await,
        "AV-003" => {
            freeze_av003_from_generated(source, writer, "HPKE-Auth", || async {
                cc001_nonconfidential_binding_candidate().await
            })
            .await
        }
        "BV-004" => freeze_nested_request_generated(source, writer, || async {
            cc001_nested_request_candidate().await
        })
        .await,
        "BV-005" => {
            ensure_generated_nested_request_root(writer, || {
                freeze_nested_request_generated(source, writer, || async {
                    cc001_nested_request_candidate().await
                })
            })
            .await?;
            freeze_generated(
                || async { cc001_nested_accept_candidate_from_generated_request(writer.paths()).await },
                |candidate| freeze_nested_accept_generated(source, writer, candidate),
            )
            .await
        }
        ,
        "BV-006" => freeze_routed_path_generated(source, writer, || async {
            cc001_routed_path_candidate().await
        })
        .await,
        "BV-007" => freeze_routed_request_generated(source, writer, || async {
            cc001_routed_request_candidate().await
        })
        .await,
        "BV-008" => {
            let request_digest = ensure_generated_routed_request_root(writer, || {
                freeze_routed_request_generated(source, writer, || async {
                    cc001_routed_request_candidate().await
                })
            })
            .await?;
            freeze_routed_accept_generated(source, writer, || async move {
                cc001_routed_accept_candidate(request_digest).await
            })
            .await
        }
        "SV-002" => freeze_nested_message_generated(source, writer, || async {
            cc001_nested_message_candidate(writer.paths()).await
        })
        .await,
        "SV-003" => freeze_routed_message_generated(source, writer, || async {
            cc001_routed_message_candidate().await
        })
        .await,
        "SV-004" => {
            freeze_sv004_from_generated(
                source,
                &spec_source,
                writer,
                &namespace,
                "CC-001",
                "cc001-direct-message-01",
                || async { cc001_direct_message_candidate().await },
            )
            .await
        }
        "SV-006" => {
            freeze_sv006_from_generated(
                source,
                &spec_source,
                writer,
                &namespace,
                "CC-001",
                "cc001-inner-alice-1-bob-1-bidirectional",
                "cc001-nested-message-01",
                || async { cc001_nested_message_candidate(writer.paths()).await },
            )
            .await
        }
        _ => Err(generation_not_implemented("CC-001", vector_id)),
    }
}

#[cfg(not(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr"))))]
async fn generate_cc001_vector_asset_set(
    vector_id: &str,
    _source: &SdkCandidateSource,
    _writer: &PackageWriter,
) -> io::Result<FreezeResult> {
    Err(generation_requires_build(
        "CC-001",
        vector_id,
        "tsp_test_vectors default HPKE-Auth build",
    ))
}

#[cfg(feature = "essr")]
async fn generate_cc002_vector_asset_set(
    vector_id: &str,
    source: &SdkCandidateSource,
    writer: &PackageWriter,
) -> io::Result<FreezeResult> {
    let spec_source = SpecCandidateSource::new("spec-generate");
    let namespace = writer.paths().artifact_namespace();
    match vector_id {
        "BV-001" => freeze_direct_request_generated(
            source,
            writer,
            CC001_ALICE,
            CC001_BOB,
            || async { cc002_direct_request_candidate().await },
        )
        .await,
        "BV-002" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc002_direct_request_candidate().await
                })
            })
            .await?;
            freeze_direct_accept_generated(source, writer, CC001_BOB, CC001_ALICE, || async move {
                cc002_direct_accept_candidate(request_digest).await
            })
            .await
        }
        "BV-003" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc002_direct_request_candidate().await
                })
            })
            .await?;
            freeze_direct_rfd_generated(source, writer, || async move {
                cc002_direct_rfd_candidate(request_digest).await
            })
            .await
        }
        "SV-001" => freeze_direct_message_generated(source, writer, || async {
            cc002_direct_message_candidate().await
        })
        .await,
        "SV-005" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc002_direct_request_candidate().await
                })
            })
            .await?;
            freeze_digest_mismatch_generated(source, writer, || async move {
                cc002_digest_mismatch_candidate(request_digest).await
            })
            .await
        }
        "AV-001" => freeze_av001_from_existing_request(
            source,
            writer,
            "CC-002",
            "HPKE-Base",
            "outer envelope sender field is present and identifies the sender; the decrypted confidential payload carries an explicit sender identity field equal to the sender identifier",
            || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc002_direct_request_candidate().await
                })
            },
        )
        .await,
        "AV-002" => freeze_av002_from_existing_request(
            source,
            writer,
            "CC-002",
            "HPKE-Base",
            "HpkeEssr",
            || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc002_direct_request_candidate().await
                })
            },
        )
        .await,
        "AV-003" => {
            freeze_av003_from_generated(source, writer, "HPKE-Base", || async {
                cc002_nonconfidential_binding_candidate().await
            })
            .await
        }
        "BV-004" => freeze_nested_request_generated(source, writer, || async {
            cc002_nested_request_candidate().await
        })
        .await,
        "BV-005" => freeze_generated(
            || async { cc002_nested_accept_candidate_from_generated_request(writer.paths()).await },
            |candidate| freeze_nested_accept_generated(source, writer, candidate),
        )
        .await,
        "BV-006" => freeze_routed_path_generated(source, writer, || async {
            cc002_routed_path_candidate().await
        })
        .await,
        "BV-007" => freeze_routed_request_generated(source, writer, || async {
            cc002_routed_request_candidate().await
        })
        .await,
        "BV-008" => {
            let request_digest = ensure_generated_routed_request_root(writer, || {
                freeze_routed_request_generated(source, writer, || async {
                    cc002_routed_request_candidate().await
                })
            })
            .await?;
            freeze_routed_accept_generated(source, writer, || async move {
                cc002_routed_accept_candidate(request_digest).await
            })
            .await
        }
        "SV-002" => freeze_nested_message_generated(source, writer, || async {
            cc002_nested_message_candidate(writer.paths()).await
        })
        .await,
        "SV-003" => freeze_routed_message_generated(source, writer, || async {
            cc002_routed_message_candidate().await
        })
        .await,
        "SV-004" => {
            freeze_sv004_from_generated(
                source,
                &spec_source,
                writer,
                &namespace,
                "CC-002",
                "cc002-direct-message-01",
                || async { cc002_direct_message_candidate().await },
            )
            .await
        }
        "SV-006" => {
            freeze_sv006_from_generated(
                source,
                &spec_source,
                writer,
                &namespace,
                "CC-002",
                "cc002-inner-alice-1-bob-1-bidirectional",
                "cc002-nested-message-01",
                || async { cc002_nested_message_candidate(writer.paths()).await },
            )
            .await
        }
        _ => Err(generation_not_implemented("CC-002", vector_id)),
    }
}

#[cfg(not(feature = "essr"))]
async fn generate_cc002_vector_asset_set(
    vector_id: &str,
    _source: &SdkCandidateSource,
    _writer: &PackageWriter,
) -> io::Result<FreezeResult> {
    Err(generation_requires_build(
        "CC-002",
        vector_id,
        "tsp_test_vectors feature `essr`",
    ))
}

#[cfg(feature = "essr")]
async fn cc002_direct_request_candidate() -> GeneratedDirectRequestCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let (_endpoint, sealed) = alice_db
        .make_relationship_request(CC001_ALICE, CC001_BOB, None)
        .unwrap();

    let request_digest = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected request status: {status:?}"),
    };

    let mut unopened = sealed.clone();
    let opened = bob_db.open_message(&mut unopened).unwrap();
    match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship { nested_vid, .. } => {
            assert!(nested_vid.is_none());
        }
        _ => panic!("request candidate did not open as a relationship request"),
    }

    let mut probe = sealed.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("request candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        bob_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(
        decoded_payload.sender_identity,
        Some(CC001_ALICE.as_bytes())
    );
    let nonce = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationProposal { nonce, .. } => to_hex(nonce.as_bytes()),
        _ => panic!("decoded request candidate was not a direct relation proposal"),
    };

    GeneratedDirectRequestCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-001".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(request_digest),
        nonce,
    }
}

#[cfg(feature = "essr")]
async fn cc002_direct_message_candidate() -> GeneratedDirectMessageCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nonconfidential = b"cc002-direct-message-01-nonconf";
    let payload = b"hello direct world";

    let (_endpoint, sealed) = alice_db
        .seal_message(CC001_ALICE, CC001_BOB, Some(nonconfidential), payload)
        .unwrap();
    let mut unopened = sealed.clone();

    let opened = bob_db.open_message(&mut unopened).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("direct message candidate did not open as a generic message");
    };

    GeneratedDirectMessageCandidate {
        case_id: "CC-002".into(),
        vector_id: "SV-001".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        relationship_context_ref: "cc002-direct-alice-bob-bidirectional".into(),
        payload_semantics_ref: "cc002-direct-message-01".into(),
        sender,
        receiver: receiver.expect("expected direct receiver"),
        nonconfidential_data: String::from_utf8(nonconfidential_data.unwrap().to_vec()).unwrap(),
        payload: String::from_utf8(message.to_vec()).unwrap(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(feature = "essr")]
async fn cc002_nested_request_candidate() -> NestedRequestCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let (sealed, nested_a_vid, nested_thread, nonce) = {
        let ((_endpoint, request), nested_a_vid) = alice_db
            .make_nested_relationship_request(CC001_ALICE, CC001_BOB)
            .unwrap();

        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Bidirectional {
                outstanding_nested_thread_ids,
                ..
            } => *outstanding_nested_thread_ids.last().unwrap(),
            status => panic!("missing outstanding nested thread id: {status:?}"),
        };

        let mut inspected_request = request.clone();
        let view = tsp_sdk::cesr::decode_envelope(&mut inspected_request).unwrap();
        let tsp_sdk::cesr::DecodedEnvelope {
            raw_header,
            envelope,
            ciphertext: Some(ciphertext),
        } = view.into_opened::<&[u8]>().unwrap()
        else {
            panic!("nested request candidate did not contain ciphertext");
        };
        assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
        assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
        assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

        let (ciphertext, footer) = ciphertext.split_at_mut(
            ciphertext.len()
                - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
                - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
        );
        let (tag, encapped_key) = footer
            .split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

        let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
            bob_vid.decryption_key().as_ref(),
        )
        .unwrap();
        let encapped_key =
            <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
        let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

        single_shot_open_in_place_detached::<
            tsp_sdk::crypto::Aead,
            tsp_sdk::crypto::Kdf,
            tsp_sdk::crypto::Kem,
        >(
            &OpModeR::Base,
            &receiver_decryption_key,
            &encapped_key,
            raw_header,
            ciphertext,
            &[],
            &tag,
        )
        .unwrap();

        let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
        assert_eq!(decoded.sender_identity, Some(CC001_ALICE.as_bytes()));
        let (nonce, mut inner) = match decoded.payload {
            tsp_sdk::cesr::Payload::NestedRelationProposal { nonce, message } => {
                (*nonce.as_bytes(), message.to_vec())
            }
            _ => panic!("decoded nested request candidate was not a nested relation proposal"),
        };

        let inner_sender = match tsp_sdk::cesr::probe(&mut inner).unwrap() {
            tsp_sdk::cesr::EnvelopeType::SignedMessage {
                receiver, sender, ..
            } => {
                assert!(receiver.is_none());
                sender
            }
            _ => panic!("inner nested relationship payload was not a signed message"),
        };
        assert_eq!(inner_sender, nested_a_vid.identifier().as_bytes());

        (request, nested_a_vid, thread_id, nonce)
    };

    let mut unopened = sealed.clone();
    let opened = bob_db.open_message(&mut unopened).unwrap();
    match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            thread_id,
            ..
        } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
            assert_eq!(nested_vid, nested_a_vid.identifier());
            assert_eq!(thread_id, nested_thread);
        }
        _ => panic!("nested request candidate did not open as a nested relationship request"),
    }

    NestedRequestCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-004".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(nested_thread),
        nonce: to_hex(nonce),
        inner_vid: nested_a_vid.identifier().into(),
        inner_verification_key_jwk: serde_json::to_string(&nested_a_vid.signature_key_jwk())
            .unwrap(),
        inner_encryption_key_jwk: serde_json::to_string(&nested_a_vid.encryption_key_jwk())
            .unwrap(),
        inner_private_vid_json: export_owned_vid_json_for_tests(&nested_a_vid),
        outer_context_ref: "cc002-outer-alice-bob-bidirectional".into(),
    }
}

#[cfg(feature = "essr")]
async fn cc002_nested_accept_candidate_from_generated_request(
    paths: &CasePackagePaths,
) -> NestedAcceptCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nested_thread = parse_hex_array_32(
        "generated nested request_digest",
        &read_yaml_scalar(
            &paths.binding_path(crate::authoring::BindingFamily::Nested, "request-01.yaml"),
            "request_digest",
        )
        .unwrap(),
    )
    .unwrap();
    let nested_request_wire = read_generated_vector_wire(paths, "BV-004").unwrap();
    let nested_a_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.alice-1.private.json"),
    )
    .await;

    let outer_thread = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: _,
        } => thread_id,
        status => panic!("unexpected outer relationship status before nested accept: {status:?}"),
    };

    alice_db
        .add_private_vid(nested_a_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(CC001_ALICE))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Bidirectional {
                thread_id: outer_thread,
                outstanding_nested_thread_ids: vec![nested_thread],
            },
            CC001_ALICE,
        )
        .unwrap();

    let mut nested_request = nested_request_wire;
    let opened_nested_a_vid = match bob_db.open_message(&mut nested_request).unwrap() {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            thread_id,
            ..
        } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
            assert_eq!(nested_vid, nested_a_vid.identifier());
            assert_eq!(thread_id, nested_thread);
            nested_vid
        }
        _ => panic!("nested request candidate did not open as a nested relationship request"),
    };

    let (sealed, nested_b_vid, reply_digest) = {
        let ((_endpoint, nested_accept), nested_b_vid) = bob_db
            .make_nested_relationship_accept(CC001_BOB, &opened_nested_a_vid, nested_thread)
            .unwrap();

        let mut inspected_accept = nested_accept.clone();
        let view = tsp_sdk::cesr::decode_envelope(&mut inspected_accept).unwrap();
        let tsp_sdk::cesr::DecodedEnvelope {
            raw_header,
            envelope,
            ciphertext: Some(ciphertext),
        } = view.into_opened::<&[u8]>().unwrap()
        else {
            panic!("nested accept candidate did not contain ciphertext");
        };
        assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
        assert_eq!(envelope.sender, CC001_BOB.as_bytes());
        assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

        let (ciphertext, footer) = ciphertext.split_at_mut(
            ciphertext.len()
                - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
                - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
        );
        let (tag, encapped_key) = footer
            .split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

        let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
            alice_vid.decryption_key().as_ref(),
        )
        .unwrap();
        let encapped_key =
            <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
        let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

        single_shot_open_in_place_detached::<
            tsp_sdk::crypto::Aead,
            tsp_sdk::crypto::Kdf,
            tsp_sdk::crypto::Kem,
        >(
            &OpModeR::Base,
            &receiver_decryption_key,
            &encapped_key,
            raw_header,
            ciphertext,
            &[],
            &tag,
        )
        .unwrap();

        let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
        assert_eq!(decoded.sender_identity, Some(CC001_BOB.as_bytes()));
        let (reply_digest, mut inner) = match decoded.payload {
            tsp_sdk::cesr::Payload::NestedRelationAffirm { reply, message } => {
                (*reply.as_bytes(), message.to_vec())
            }
            _ => panic!("decoded nested accept candidate was not a nested relation affirm"),
        };

        let inner_sender = match tsp_sdk::cesr::probe(&mut inner).unwrap() {
            tsp_sdk::cesr::EnvelopeType::SignedMessage {
                receiver, sender, ..
            } => {
                assert_eq!(receiver, Some(nested_a_vid.identifier().as_bytes()));
                sender
            }
            _ => panic!("inner nested relationship payload was not a signed message"),
        };
        assert_eq!(inner_sender, nested_b_vid.identifier().as_bytes());

        (nested_accept, nested_b_vid, reply_digest)
    };

    let mut unopened = sealed.clone();
    let opened_nested_b_vid = match alice_db.open_message(&mut unopened).unwrap() {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            ..
        } => {
            assert_eq!(sender, CC001_BOB);
            assert_eq!(receiver, CC001_ALICE);
            nested_vid
        }
        _ => panic!("nested accept candidate did not open as a nested relationship accept"),
    };
    assert_eq!(opened_nested_b_vid, nested_b_vid.identifier());
    assert_eq!(reply_digest, nested_thread);

    NestedAcceptCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-005".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(nested_thread),
        reply_digest: to_hex(reply_digest),
        inner_vid: nested_b_vid.identifier().into(),
        inner_verification_key_jwk: serde_json::to_string(&nested_b_vid.signature_key_jwk())
            .unwrap(),
        inner_encryption_key_jwk: serde_json::to_string(&nested_b_vid.encryption_key_jwk())
            .unwrap(),
        inner_private_vid_json: export_owned_vid_json_for_tests(&nested_b_vid),
        outer_context_ref: "cc002-outer-alice-bob-bidirectional".into(),
    }
}

#[cfg(feature = "essr")]
async fn cc002_routed_path_candidate() -> RoutedPathCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let alice_did = CC001_ALICE;
    let bob_did = CC001_BOB;

    alice_db.add_verified_vid(hop1_vid.clone(), None).unwrap();
    alice_db.add_verified_vid(hop2_vid.clone(), None).unwrap();
    alice_db.add_verified_vid(bob_vid, None).unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, bob_did])
        .unwrap();

    hop1_db.add_verified_vid(alice_vid, None).unwrap();
    hop1_db.add_verified_vid(hop2_vid, None).unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop1_did,
        )
        .unwrap();

    let (_endpoint, sealed) = alice_db
        .seal_message(alice_did, bob_did, None, b"hello routed world")
        .unwrap();
    let mut unopened = sealed.clone();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        sender,
        receiver,
        next_hop,
        route,
        opaque_payload,
    } = hop1_db.open_message(&mut unopened).unwrap()
    else {
        panic!("path candidate did not open as a forward request");
    };

    assert_eq!(sender, alice_did);
    assert_eq!(receiver, hop1_did);
    assert_eq!(next_hop, hop2_did);

    let remaining_route = route
        .iter()
        .map(|segment| std::str::from_utf8(segment.iter().as_slice()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(remaining_route, vec![bob_did]);

    RoutedPathCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-006".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        current_hop_vid: hop1_did.into(),
        next_hop_vid: next_hop.into(),
        remaining_route_json: format!("[\"{bob_did}\"]"),
        opaque_payload_base64: Base64UrlUnpadded::encode_string(opaque_payload.iter().as_slice()),
    }
}

#[cfg(feature = "essr")]
async fn cc002_routed_request_candidate() -> RoutedRequestCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid, None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let alice_did = CC001_ALICE;
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";
    let bob_did = CC001_BOB;

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, dropoff_did])
        .unwrap();

    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop1_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            bob_did,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();

    let route = [hop1_did, hop2_did, dropoff_did];
    let (_endpoint, mut first_hop_message) = alice_db
        .make_relationship_request(alice_did, bob_did, Some(&route))
        .unwrap();

    let request_digest = match alice_db
        .get_relation_status_for_vid_pair(alice_did, bob_did)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected routed request status: {status:?}"),
    };

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed request candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop1_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed request candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let mut inner = opaque_payload.to_vec();
    let view = tsp_sdk::cesr::decode_envelope(&mut inner).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("routed request inner payload did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
    assert_eq!(envelope.sender, alice_did.as_bytes());
    assert_eq!(envelope.receiver, Some(bob_did.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        bob_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let nonce = match decoded.payload {
        tsp_sdk::cesr::Payload::DirectRelationProposal { nonce, .. } => *nonce.as_bytes(),
        _ => panic!("routed request inner payload was not a direct relation proposal"),
    };

    let (_endpoint, mut final_message) = hop2_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    let opened_thread_id = match bob_db.open_message(&mut final_message).unwrap() {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            route: Some(route),
            thread_id,
            nested_vid: None,
        } => {
            assert_eq!(sender, alice_did);
            assert_eq!(receiver, bob_did);
            let route = route
                .iter()
                .map(|vid| std::str::from_utf8(vid).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(route, vec![hop1_did, hop2_did, dropoff_did]);
            thread_id
        }
        _ => panic!("final routed request candidate did not open as a relationship request"),
    };

    assert_eq!(opened_thread_id, request_digest);

    RoutedRequestCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-007".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        request_digest: to_hex(request_digest),
        nonce: to_hex(nonce),
        path_context_ref: "cc002-routed-final-delivery-01".into(),
        sender_vid: alice_did.into(),
        receiver_vid: bob_did.into(),
    }
}

#[cfg(feature = "essr")]
async fn cc002_routed_accept_candidate(request_digest: [u8; 32]) -> RoutedAcceptCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid, None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid, None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let alice_did = CC001_ALICE;
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";
    let bob_did = CC001_BOB;

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            alice_did,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            alice_did,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            bob_did,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            bob_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop2_did,
        )
        .unwrap();

    hop1_db.add_private_vid(dropoff_vid.clone(), None).unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            alice_did,
        )
        .unwrap();

    let route = [hop2_did, hop1_did, dropoff_did];
    let (_endpoint, mut first_hop_message) = bob_db
        .make_relationship_accept(bob_did, alice_did, request_digest, Some(&route))
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed accept candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop2_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed accept candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let mut inner = opaque_payload.to_vec();
    let view = tsp_sdk::cesr::decode_envelope(&mut inner).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("routed accept inner payload did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
    assert_eq!(envelope.sender, bob_did.as_bytes());
    assert_eq!(envelope.receiver, Some(alice_did.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        alice_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let reply_digest = match decoded.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => *reply.as_bytes(),
        _ => panic!("routed accept inner payload was not a direct relation affirm"),
    };

    let (_endpoint, mut final_message) = hop1_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    match alice_db.open_message(&mut final_message).unwrap() {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            nested_vid: None,
        } => {
            assert_eq!(sender, bob_did);
            assert_eq!(receiver, alice_did);
        }
        _ => panic!("final routed accept candidate did not open as a relationship accept"),
    }

    assert_eq!(reply_digest, request_digest);

    RoutedAcceptCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-008".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        request_digest: to_hex(request_digest),
        reply_digest: to_hex(reply_digest),
        path_context_ref: "cc002-routed-final-delivery-01".into(),
    }
}

#[cfg(feature = "essr")]
async fn cc002_routed_message_candidate() -> RoutedMessageCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid.clone(), None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let alice_did = CC001_ALICE;
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";
    let bob_did = CC001_BOB;

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            alice_did,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, dropoff_did])
        .unwrap();

    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            hop1_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            bob_did,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();

    let payload = b"hello routed world";
    let nonconfidential = b"cc002-routed-message-01-nonconf";

    let (_endpoint, mut first_hop_message) = alice_db
        .seal_message(alice_did, bob_did, Some(nonconfidential), payload)
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed generic-message candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop1_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed generic-message candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let (_endpoint, mut final_message) = hop2_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    let opened = bob_db.open_message(&mut final_message).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("final routed generic-message candidate did not open as a generic message");
    };

    assert_eq!(sender, alice_did);
    assert_eq!(receiver.as_deref(), Some(bob_did));
    assert_eq!(message.as_ref(), payload);
    assert_eq!(
        nonconfidential_data.as_ref().map(|d| d.as_ref()),
        Some(nonconfidential.as_slice())
    );

    RoutedMessageCandidate {
        case_id: "CC-002".into(),
        vector_id: "SV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        path_context_ref: "cc002-routed-final-delivery-01".into(),
        payload_semantics_ref: "cc002-routed-message-01".into(),
        sender,
        receiver: receiver.unwrap(),
        nonconfidential_data: std::str::from_utf8(nonconfidential).unwrap().into(),
        payload: std::str::from_utf8(payload).unwrap().into(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(feature = "essr")]
async fn cc002_nested_message_candidate(paths: &CasePackagePaths) -> NestedMessageCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();

    let alice = CC001_ALICE;
    let bob = CC001_BOB;

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(alice, bob, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(alice, bob)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(bob, alice, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nested_a_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.alice-1.private.json"),
    )
    .await;
    let nested_b_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.bob-1.private.json"),
    )
    .await;

    alice_db
        .add_private_vid(nested_a_vid.clone(), None)
        .unwrap();
    alice_db
        .add_verified_vid(nested_b_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(alice))
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_b_vid.identifier(), Some(bob))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_b_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_a_vid.identifier(),
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_a_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_b_vid.identifier(),
        )
        .unwrap();

    bob_db.add_private_vid(nested_b_vid.clone(), None).unwrap();
    bob_db.add_verified_vid(nested_a_vid.clone(), None).unwrap();
    bob_db
        .set_parent_for_vid(nested_b_vid.identifier(), Some(bob))
        .unwrap();
    bob_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(alice))
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            nested_a_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_b_vid.identifier(),
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            nested_b_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_a_vid.identifier(),
        )
        .unwrap();

    let payload = b"hello nested world";

    let (_endpoint, sealed) = alice_db
        .seal_message(
            nested_a_vid.identifier(),
            nested_b_vid.identifier(),
            None,
            payload,
        )
        .unwrap();
    let mut unopened = sealed.clone();

    let opened = bob_db.open_message(&mut unopened).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("nested message candidate did not open as a generic message");
    };

    assert_eq!(sender, nested_a_vid.identifier());
    assert_eq!(receiver.as_deref(), Some(nested_b_vid.identifier()));
    assert_eq!(message.as_ref(), payload);
    assert!(nonconfidential_data.is_none());

    NestedMessageCandidate {
        case_id: "CC-002".into(),
        vector_id: "SV-002".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        outer_context_ref: "cc002-outer-alice-bob-bidirectional".into(),
        inner_context_ref: "cc002-inner-alice-1-bob-1-bidirectional".into(),
        payload_semantics_ref: "cc002-nested-message-01".into(),
        inner_sender_owned_vid_json: serde_json::to_string(&nested_a_vid).unwrap(),
        inner_receiver_owned_vid_json: serde_json::to_string(&nested_b_vid).unwrap(),
        sender,
        receiver: receiver.unwrap(),
        nonconfidential_data: "<none>".into(),
        payload: std::str::from_utf8(payload).unwrap().into(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(feature = "essr")]
async fn cc002_direct_accept_candidate(request_digest: [u8; 32]) -> DirectAcceptCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();

    let (_endpoint, accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_digest, None)
        .unwrap();
    let mut unopened = accept.clone();

    let opened_accept = alice_db.open_message(&mut unopened).unwrap();
    match opened_accept {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender, receiver, ..
        } => {
            assert_eq!(sender, CC001_BOB);
            assert_eq!(receiver, CC001_ALICE);
        }
        _ => panic!("accept candidate did not open as a relationship accept"),
    }

    let mut probe = accept.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("accept candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
    assert_eq!(envelope.sender, CC001_BOB.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        alice_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(decoded_payload.sender_identity, Some(CC001_BOB.as_bytes()));
    let reply_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded accept candidate was not a direct relation affirm"),
    };

    DirectAcceptCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-002".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        request_digest: to_hex(request_digest),
        reply_digest,
    }
}

#[cfg(feature = "essr")]
async fn cc002_direct_rfd_candidate(request_digest: [u8; 32]) -> DirectRfdCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::ReverseUnidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();

    let (_endpoint, cancel) = alice_db
        .make_relationship_cancel(CC001_ALICE, CC001_BOB)
        .unwrap();
    let mut unopened = cancel.clone();

    let opened_cancel = bob_db.open_message(&mut unopened).unwrap();
    match opened_cancel {
        tsp_sdk::ReceivedTspMessage::CancelRelationship { sender, receiver } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
        }
        _ => panic!("rfd candidate did not open as a relationship cancel"),
    }

    let mut probe = cancel.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("rfd candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        bob_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(
        decoded_payload.sender_identity,
        Some(CC001_ALICE.as_bytes())
    );
    let cancel_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::RelationshipCancel { reply, .. } => to_hex(reply.as_bytes()),
        _ => panic!("decoded rfd candidate was not a relationship cancel"),
    };

    DirectRfdCandidate {
        case_id: "CC-002".into(),
        vector_id: "BV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&cancel),
        digest: cancel_digest,
        reviewed_context: "pending-request-cancel".into(),
    }
}

#[cfg(feature = "essr")]
async fn cc002_digest_mismatch_candidate(
    expected_request_digest: [u8; 32],
) -> DigestMismatchCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let mut mismatching_accept_digest = expected_request_digest;
    mismatching_accept_digest[31] ^= 0x01;

    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: expected_request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: expected_request_digest,
            },
            CC001_BOB,
        )
        .unwrap();

    let (_endpoint, accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, mismatching_accept_digest, None)
        .unwrap();
    let mut unopened = accept.clone();

    let err = alice_db.open_message(&mut unopened).unwrap_err();
    let tsp_sdk::Error::Relationship(message) = err else {
        panic!("digest-mismatch candidate did not fail as a relationship error");
    };
    assert!(message.contains("thread_id does not match digest"));

    let mut probe = accept.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        ciphertext: Some(ciphertext),
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("digest-mismatch candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::HpkeEssr);
    assert_eq!(envelope.sender, CC001_BOB.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - aead::AeadTag::<tsp_sdk::crypto::Aead>::size()
            - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key = <tsp_sdk::crypto::Kem as hpke::Kem>::PrivateKey::from_bytes(
        alice_vid.decryption_key().as_ref(),
    )
    .unwrap();
    let encapped_key =
        <tsp_sdk::crypto::Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let tag = aead::AeadTag::<tsp_sdk::crypto::Aead>::from_bytes(tag).unwrap();

    single_shot_open_in_place_detached::<
        tsp_sdk::crypto::Aead,
        tsp_sdk::crypto::Kdf,
        tsp_sdk::crypto::Kem,
    >(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )
    .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(decoded_payload.sender_identity, Some(CC001_BOB.as_bytes()));
    let decoded_accept_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded digest-mismatch candidate was not a direct relation affirm"),
    };

    DigestMismatchCandidate {
        case_id: "CC-002".into(),
        vector_id: "SV-005".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        expected_request_digest: to_hex(expected_request_digest),
        mismatching_accept_digest: decoded_accept_digest,
    }
}

#[cfg(feature = "essr")]
async fn cc002_nonconfidential_binding_candidate() -> NonConfidentialBindingCandidate {
    let alice = create_vid_from_file("../examples/test/alice/piv.json").await;
    let bob = create_vid_from_file("../examples/test/bob/piv.json").await;
    let sender = alice.identifier().to_string();
    let receiver = bob.identifier().to_string();
    let nonconfidential = b"cc002-av003-nonconfidential";

    let sender_store = create_test_store();
    sender_store.add_private_vid(alice.clone(), None).unwrap();
    sender_store.add_verified_vid(bob.clone(), None).unwrap();

    let receiver_store = create_test_store();
    receiver_store.add_private_vid(bob.clone(), None).unwrap();
    receiver_store
        .add_verified_vid(alice.clone(), None)
        .unwrap();

    let mut request_digest = [0_u8; 32];
    let sealed = tsp_sdk::crypto::seal_and_hash(
        &alice,
        &bob,
        Some(nonconfidential),
        tsp_sdk::Payload::RequestRelationship {
            route: None,
            thread_id: Default::default(),
        },
        Some(&mut request_digest),
    )
    .unwrap();

    let mut unopened = sealed.clone();
    let opened = receiver_store.open_message(&mut unopened).unwrap();
    let opened_request_digest = match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender: opened_sender,
            receiver: opened_receiver,
            thread_id,
            ..
        } => {
            assert_eq!(opened_sender, sender);
            assert_eq!(opened_receiver, receiver);
            thread_id
        }
        _ => panic!("non-confidential-binding candidate did not open as a relationship request"),
    };
    assert_eq!(opened_request_digest, request_digest);

    let parts = tsp_sdk::cesr::open_message_into_parts(&sealed).unwrap();
    let nonconf_part = parts
        .nonconfidential_data
        .expect("review sample should carry non-confidential data");
    assert_eq!(nonconf_part.data, nonconfidential);

    let mut tampered = sealed.clone();
    let range = slice_range(&sealed, nonconf_part.data);
    tampered[range.start] ^= 0x01;
    assert!(receiver_store.open_message(&mut tampered).is_err());

    NonConfidentialBindingCandidate {
        case_id: "CC-002".into(),
        vector_id: "AV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(request_digest),
        nonconfidential_data: std::str::from_utf8(nonconfidential).unwrap().into(),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn generate_cc003_vector_asset_set(
    vector_id: &str,
    source: &SdkCandidateSource,
    writer: &PackageWriter,
) -> io::Result<FreezeResult> {
    let spec_source = SpecCandidateSource::new("spec-generate");
    let namespace = writer.paths().artifact_namespace();
    match vector_id {
        "BV-001" => freeze_direct_request_generated(
            source,
            writer,
            CC001_ALICE,
            CC001_BOB,
            || async { cc003_direct_request_candidate().await },
        )
        .await,
        "BV-002" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc003_direct_request_candidate().await
                })
            })
            .await?;
            freeze_direct_accept_generated(source, writer, CC001_BOB, CC001_ALICE, || async move {
                cc003_direct_accept_candidate(request_digest).await
            })
            .await
        }
        "BV-003" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc003_direct_request_candidate().await
                })
            })
            .await?;
            freeze_direct_rfd_generated(source, writer, || async move {
                cc003_direct_rfd_candidate(request_digest).await
            })
            .await
        }
        "SV-001" => freeze_direct_message_generated(source, writer, || async {
            cc003_direct_message_candidate().await
        })
        .await,
        "BV-004" => freeze_nested_request_generated(source, writer, || async {
            cc003_nested_request_candidate().await
        })
        .await,
        "BV-005" => freeze_generated(
            || async { cc003_nested_accept_candidate_from_generated_request(writer.paths()).await },
            |candidate| freeze_nested_accept_generated(source, writer, candidate),
        )
        .await,
        "BV-006" => freeze_routed_path_generated(source, writer, || async {
            cc003_routed_path_candidate().await
        })
        .await,
        "BV-007" => freeze_routed_request_generated(source, writer, || async {
            cc003_routed_request_candidate().await
        })
        .await,
        "BV-008" => {
            let request_digest = ensure_generated_routed_request_root(writer, || {
                freeze_routed_request_generated(source, writer, || async {
                    cc003_routed_request_candidate().await
                })
            })
            .await?;
            freeze_routed_accept_generated(source, writer, || async move {
                cc003_routed_accept_candidate(request_digest).await
            })
            .await
        }
        "SV-002" => freeze_nested_message_generated(source, writer, || async {
            cc003_nested_message_candidate(writer.paths()).await
        })
        .await,
        "SV-003" => freeze_routed_message_generated(source, writer, || async {
            cc003_routed_message_candidate().await
        })
        .await,
        "SV-004" => {
            freeze_sv004_from_generated(
                source,
                &spec_source,
                writer,
                &namespace,
                "CC-003",
                "cc003-direct-message-01",
                || async { cc003_direct_message_candidate().await },
            )
            .await
        }
        "SV-006" => {
            freeze_sv006_from_generated(
                source,
                &spec_source,
                writer,
                &namespace,
                "CC-003",
                "cc003-inner-alice-1-bob-1-bidirectional",
                "cc003-nested-message-01",
                || async { cc003_nested_message_candidate(writer.paths()).await },
            )
            .await
        }
        "SV-005" => {
            let request_digest = ensure_generated_direct_request_root(writer, || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc003_direct_request_candidate().await
                })
            })
            .await?;
            freeze_digest_mismatch_generated(source, writer, || async move {
                cc003_digest_mismatch_candidate(request_digest).await
            })
            .await
        }
        "AV-001" => freeze_av001_from_existing_request(
            source,
            writer,
            "CC-003",
            "Sealed Box",
            "outer envelope sender field is present and identifies the sender; the decrypted confidential payload carries an explicit sender identity field equal to the sender identifier",
            || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc003_direct_request_candidate().await
                })
            },
        )
        .await,
        "AV-002" => freeze_av002_from_existing_request(
            source,
            writer,
            "CC-003",
            "Sealed Box",
            "NaclEssr",
            || {
                freeze_direct_request_generated(source, writer, CC001_ALICE, CC001_BOB, || async {
                    cc003_direct_request_candidate().await
                })
            },
        )
        .await,
        "AV-003" => {
            freeze_av003_from_generated(source, writer, "Sealed Box", || async {
                cc003_nonconfidential_binding_candidate().await
            })
            .await
        }
        _ => Err(generation_not_implemented("CC-003", vector_id)),
    }
}

#[cfg(not(all(feature = "nacl", not(feature = "pq"))))]
async fn generate_cc003_vector_asset_set(
    vector_id: &str,
    _source: &SdkCandidateSource,
    _writer: &PackageWriter,
) -> io::Result<FreezeResult> {
    Err(generation_requires_build(
        "CC-003",
        vector_id,
        "tsp_test_vectors feature `nacl`",
    ))
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_direct_request_candidate() -> GeneratedDirectRequestCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let (_endpoint, sealed) = alice_db
        .make_relationship_request(CC001_ALICE, CC001_BOB, None)
        .unwrap();

    let request_digest = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected request status: {status:?}"),
    };

    let mut unopened = sealed.clone();
    let opened = bob_db.open_message(&mut unopened).unwrap();
    match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship { nested_vid, .. } => {
            assert!(nested_vid.is_none())
        }
        _ => panic!("request candidate did not open as a relationship request"),
    }

    let mut probe = sealed.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("request candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(bob_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(alice_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(
        decoded_payload.sender_identity,
        Some(CC001_ALICE.as_bytes())
    );
    let nonce = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationProposal { nonce, .. } => to_hex(nonce.as_bytes()),
        _ => panic!("decoded request candidate was not a direct relation proposal"),
    };

    GeneratedDirectRequestCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-001".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(request_digest),
        nonce,
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_direct_message_candidate() -> GeneratedDirectMessageCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nonconfidential = b"cc003-direct-message-01-nonconf";
    let payload = b"hello direct world";

    let (_endpoint, sealed) = alice_db
        .seal_message(CC001_ALICE, CC001_BOB, Some(nonconfidential), payload)
        .unwrap();
    let mut unopened = sealed.clone();

    let opened = bob_db.open_message(&mut unopened).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("direct message candidate did not open as a generic message");
    };

    GeneratedDirectMessageCandidate {
        case_id: "CC-003".into(),
        vector_id: "SV-001".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        relationship_context_ref: "cc003-direct-alice-bob-bidirectional".into(),
        payload_semantics_ref: "cc003-direct-message-01".into(),
        sender,
        receiver: receiver.expect("expected direct receiver"),
        nonconfidential_data: String::from_utf8(nonconfidential_data.unwrap().to_vec()).unwrap(),
        payload: String::from_utf8(message.to_vec()).unwrap(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_nested_request_candidate() -> NestedRequestCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let ((_endpoint, request), nested_a_vid) = alice_db
        .make_nested_relationship_request(CC001_ALICE, CC001_BOB)
        .unwrap();

    let nested_thread = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Bidirectional {
            outstanding_nested_thread_ids,
            ..
        } => *outstanding_nested_thread_ids.last().unwrap(),
        status => panic!("missing outstanding nested thread id: {status:?}"),
    };

    let mut inspected_request = request.clone();
    let view = tsp_sdk::cesr::decode_envelope(&mut inspected_request).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("nested request candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(bob_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(alice_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(decoded.sender_identity, Some(CC001_ALICE.as_bytes()));
    let (nonce, mut inner) = match decoded.payload {
        tsp_sdk::cesr::Payload::NestedRelationProposal { nonce, message } => {
            (*nonce.as_bytes(), message.to_vec())
        }
        _ => panic!("decoded nested request candidate was not a nested relation proposal"),
    };

    let inner_sender = match tsp_sdk::cesr::probe(&mut inner).unwrap() {
        tsp_sdk::cesr::EnvelopeType::SignedMessage {
            sender, receiver, ..
        } => {
            assert!(receiver.is_none());
            sender
        }
        _ => panic!("inner nested relationship payload was not a signed message"),
    };
    assert_eq!(inner_sender, nested_a_vid.identifier().as_bytes());

    let mut unopened = request.clone();
    let opened = bob_db.open_message(&mut unopened).unwrap();
    match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            thread_id,
            ..
        } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
            assert_eq!(nested_vid, nested_a_vid.identifier());
            assert_eq!(thread_id, nested_thread);
        }
        _ => panic!("nested request candidate did not open as a nested relationship request"),
    }

    NestedRequestCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-004".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&request),
        request_digest: to_hex(nested_thread),
        nonce: to_hex(nonce),
        inner_vid: nested_a_vid.identifier().into(),
        inner_verification_key_jwk: serde_json::to_string(&nested_a_vid.signature_key_jwk())
            .unwrap(),
        inner_encryption_key_jwk: serde_json::to_string(&nested_a_vid.encryption_key_jwk())
            .unwrap(),
        inner_private_vid_json: export_owned_vid_json_for_tests(&nested_a_vid),
        outer_context_ref: "cc003-outer-alice-bob-bidirectional".into(),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_nested_accept_candidate_from_generated_request(
    paths: &CasePackagePaths,
) -> NestedAcceptCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nested_thread = parse_hex_array_32(
        "generated nested request_digest",
        &read_yaml_scalar(
            &paths.binding_path(crate::authoring::BindingFamily::Nested, "request-01.yaml"),
            "request_digest",
        )
        .unwrap(),
    )
    .unwrap();
    let nested_request_wire = read_generated_vector_wire(paths, "BV-004").unwrap();
    let nested_a_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.alice-1.private.json"),
    )
    .await;

    let outer_thread = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: _,
        } => thread_id,
        status => panic!("unexpected outer relationship status before nested accept: {status:?}"),
    };

    alice_db
        .add_private_vid(nested_a_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(CC001_ALICE))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Bidirectional {
                thread_id: outer_thread,
                outstanding_nested_thread_ids: vec![nested_thread],
            },
            CC001_ALICE,
        )
        .unwrap();

    let mut nested_request = nested_request_wire;
    let opened_nested_a_vid = match bob_db.open_message(&mut nested_request).unwrap() {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            thread_id,
            ..
        } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
            assert_eq!(nested_vid, nested_a_vid.identifier());
            assert_eq!(thread_id, nested_thread);
            nested_vid
        }
        _ => panic!("nested request candidate did not open as a nested relationship request"),
    };

    let ((_endpoint, accept), nested_b_vid) = bob_db
        .make_nested_relationship_accept(CC001_BOB, &opened_nested_a_vid, nested_thread)
        .unwrap();

    let mut inspected_accept = accept.clone();
    let view = tsp_sdk::cesr::decode_envelope(&mut inspected_accept).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("nested accept candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_BOB.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(alice_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(bob_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(decoded.sender_identity, Some(CC001_BOB.as_bytes()));
    let (reply_digest, mut inner) = match decoded.payload {
        tsp_sdk::cesr::Payload::NestedRelationAffirm { reply, message } => {
            (*reply.as_bytes(), message.to_vec())
        }
        _ => panic!("decoded nested accept candidate was not a nested relation affirm"),
    };

    let inner_sender = match tsp_sdk::cesr::probe(&mut inner).unwrap() {
        tsp_sdk::cesr::EnvelopeType::SignedMessage {
            sender, receiver, ..
        } => {
            assert_eq!(receiver, Some(nested_a_vid.identifier().as_bytes()));
            sender
        }
        _ => panic!("inner nested relationship payload was not a signed message"),
    };
    assert_eq!(inner_sender, nested_b_vid.identifier().as_bytes());

    let mut unopened = accept.clone();
    let opened_nested_b_vid = match alice_db.open_message(&mut unopened).unwrap() {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            nested_vid: Some(nested_vid),
            ..
        } => {
            assert_eq!(sender, CC001_BOB);
            assert_eq!(receiver, CC001_ALICE);
            nested_vid
        }
        _ => panic!("nested accept candidate did not open as a nested relationship accept"),
    };
    assert_eq!(opened_nested_b_vid, nested_b_vid.identifier());
    assert_eq!(reply_digest, nested_thread);

    NestedAcceptCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-005".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        request_digest: to_hex(nested_thread),
        reply_digest: to_hex(reply_digest),
        inner_vid: nested_b_vid.identifier().into(),
        inner_verification_key_jwk: serde_json::to_string(&nested_b_vid.signature_key_jwk())
            .unwrap(),
        inner_encryption_key_jwk: serde_json::to_string(&nested_b_vid.encryption_key_jwk())
            .unwrap(),
        inner_private_vid_json: export_owned_vid_json_for_tests(&nested_b_vid),
        outer_context_ref: "cc003-outer-alice-bob-bidirectional".into(),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_routed_path_candidate() -> RoutedPathCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let bob_did = CC001_BOB;

    alice_db.add_verified_vid(hop1_vid.clone(), None).unwrap();
    alice_db.add_verified_vid(hop2_vid.clone(), None).unwrap();
    alice_db.add_verified_vid(bob_vid, None).unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            CC001_ALICE,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            bob_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            CC001_ALICE,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(bob_did, &[hop1_did, hop2_did, bob_did])
        .unwrap();

    hop1_db.add_verified_vid(alice_vid, None).unwrap();
    hop1_db.add_verified_vid(hop2_vid, None).unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop1_did,
        )
        .unwrap();

    let (_endpoint, sealed) = alice_db
        .seal_message(CC001_ALICE, bob_did, None, b"hello routed world")
        .unwrap();
    let mut unopened = sealed.clone();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        sender,
        receiver,
        next_hop,
        route,
        opaque_payload,
    } = hop1_db.open_message(&mut unopened).unwrap()
    else {
        panic!("path candidate did not open as a forward request");
    };

    assert_eq!(sender, CC001_ALICE);
    assert_eq!(receiver, hop1_did);
    assert_eq!(next_hop, hop2_did);

    let remaining_route = route
        .iter()
        .map(|segment| std::str::from_utf8(segment.iter().as_slice()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(remaining_route, vec![bob_did]);

    RoutedPathCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-006".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        current_hop_vid: hop1_did.into(),
        next_hop_vid: next_hop.into(),
        remaining_route_json: format!("[\"{bob_did}\"]"),
        opaque_payload_base64: Base64UrlUnpadded::encode_string(opaque_payload.iter().as_slice()),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_routed_request_candidate() -> RoutedRequestCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid.clone(), None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            CC001_ALICE,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(CC001_BOB, &[hop1_did, hop2_did, dropoff_did])
        .unwrap();

    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop1_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            CC001_BOB,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();

    let route = [hop1_did, hop2_did, dropoff_did];
    let (_endpoint, mut first_hop_message) = alice_db
        .make_relationship_request(CC001_ALICE, CC001_BOB, Some(&route))
        .unwrap();

    let request_digest = match alice_db
        .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected routed request status: {status:?}"),
    };

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed request candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop1_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed request candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let mut inner = opaque_payload.to_vec();
    let view = tsp_sdk::cesr::decode_envelope(&mut inner).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("routed request inner payload did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(bob_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(alice_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let nonce = match decoded.payload {
        tsp_sdk::cesr::Payload::DirectRelationProposal { nonce, .. } => *nonce.as_bytes(),
        _ => panic!("routed request inner payload was not a direct relation proposal"),
    };

    let (_endpoint, mut final_message) = hop2_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    let opened_thread_id = match bob_db.open_message(&mut final_message).unwrap() {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            route: Some(route),
            thread_id,
            nested_vid: None,
        } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
            let route = route
                .iter()
                .map(|vid| std::str::from_utf8(vid).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(route, vec![hop1_did, hop2_did, dropoff_did]);
            thread_id
        }
        _ => panic!("final routed request candidate did not open as a relationship request"),
    };

    assert_eq!(opened_thread_id, request_digest);

    RoutedRequestCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-007".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        request_digest: to_hex(request_digest),
        nonce: to_hex(nonce),
        path_context_ref: "cc003-routed-final-delivery-01".into(),
        sender_vid: CC001_ALICE.into(),
        receiver_vid: CC001_BOB.into(),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_routed_accept_candidate(request_digest: [u8; 32]) -> RoutedAcceptCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();
    hop1_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    hop2_db.add_private_vid(hop2_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            CC001_BOB,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            hop2_did,
        )
        .unwrap();

    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            CC001_ALICE,
        )
        .unwrap();

    let route = [hop2_did, hop1_did, dropoff_did];
    let (_endpoint, mut first_hop_message) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_digest, Some(&route))
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed accept candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop2_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed accept candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let mut inner = opaque_payload.to_vec();
    let view = tsp_sdk::cesr::decode_envelope(&mut inner).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = view.into_opened::<&[u8]>().unwrap()
    else {
        panic!("routed accept inner payload did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_BOB.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(alice_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(bob_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    let reply_digest = match decoded.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => *reply.as_bytes(),
        _ => panic!("routed accept inner payload was not a direct relation affirm"),
    };

    let (_endpoint, mut final_message) = hop1_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    match alice_db.open_message(&mut final_message).unwrap() {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            nested_vid: None,
        } => {
            assert_eq!(sender, CC001_BOB);
            assert_eq!(receiver, CC001_ALICE);
        }
        _ => panic!("final routed accept candidate did not open as a relationship accept"),
    }

    assert_eq!(reply_digest, request_digest);

    RoutedAcceptCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-008".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        request_digest: to_hex(request_digest),
        reply_digest: to_hex(reply_digest),
        path_context_ref: "cc003-routed-final-delivery-01".into(),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_nested_message_candidate(paths: &CasePackagePaths) -> NestedMessageCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();

    let ((_endpoint, mut direct_request), request_thread_id) = {
        let (endpoint, request) = alice_db
            .make_relationship_request(CC001_ALICE, CC001_BOB, None)
            .unwrap();
        let thread_id = match alice_db
            .get_relation_status_for_vid_pair(CC001_ALICE, CC001_BOB)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected direct request status: {status:?}"),
        };
        ((endpoint, request), thread_id)
    };
    let (_endpoint, mut direct_accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_thread_id, None)
        .unwrap();
    let _ = bob_db.open_message(&mut direct_request).unwrap();
    let _ = alice_db.open_message(&mut direct_accept).unwrap();

    let nested_a_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.alice-1.private.json"),
    )
    .await;
    let nested_b_vid = load_private_owned_vid_from_path(
        &paths.private_fixture_path("fixture.identity.inner.bob-1.private.json"),
    )
    .await;

    alice_db
        .add_private_vid(nested_a_vid.clone(), None)
        .unwrap();
    alice_db
        .add_verified_vid(nested_b_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(CC001_ALICE))
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_b_vid.identifier(), Some(CC001_BOB))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_b_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_a_vid.identifier(),
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_a_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_b_vid.identifier(),
        )
        .unwrap();

    bob_db.add_private_vid(nested_b_vid.clone(), None).unwrap();
    bob_db.add_verified_vid(nested_a_vid.clone(), None).unwrap();
    bob_db
        .set_parent_for_vid(nested_b_vid.identifier(), Some(CC001_BOB))
        .unwrap();
    bob_db
        .set_parent_for_vid(nested_a_vid.identifier(), Some(CC001_ALICE))
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            nested_a_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_b_vid.identifier(),
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            nested_b_vid.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: parse_hex_array_32(
                    "generated nested request_digest",
                    &read_yaml_scalar(
                        &paths.binding_path(
                            crate::authoring::BindingFamily::Nested,
                            "request-01.yaml",
                        ),
                        "request_digest",
                    )
                    .unwrap(),
                )
                .unwrap(),
                outstanding_nested_thread_ids: vec![],
            },
            nested_a_vid.identifier(),
        )
        .unwrap();

    let payload = b"hello nested world";
    let (_endpoint, sealed) = alice_db
        .seal_message(
            nested_a_vid.identifier(),
            nested_b_vid.identifier(),
            None,
            payload,
        )
        .unwrap();
    let mut unopened = sealed.clone();

    let opened = bob_db.open_message(&mut unopened).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("nested message candidate did not open as a generic message");
    };

    assert_eq!(sender, nested_a_vid.identifier());
    assert_eq!(receiver.as_deref(), Some(nested_b_vid.identifier()));
    assert_eq!(message.as_ref(), payload);
    assert!(nonconfidential_data.is_none());

    NestedMessageCandidate {
        case_id: "CC-003".into(),
        vector_id: "SV-002".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        outer_context_ref: "cc003-outer-alice-bob-bidirectional".into(),
        inner_context_ref: "cc003-inner-alice-1-bob-1-bidirectional".into(),
        payload_semantics_ref: "cc003-nested-message-01".into(),
        inner_sender_owned_vid_json: serde_json::to_string(&nested_a_vid).unwrap(),
        inner_receiver_owned_vid_json: serde_json::to_string(&nested_b_vid).unwrap(),
        sender,
        receiver: receiver.unwrap(),
        nonconfidential_data: "<none>".into(),
        payload: std::str::from_utf8(payload).unwrap().into(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_routed_message_candidate() -> RoutedMessageCandidate {
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    let hop1_db = create_async_test_store();
    let hop1_vid = create_vid_from_file("../examples/test/a/piv.json").await;
    hop1_db.add_private_vid(hop1_vid.clone(), None).unwrap();

    let hop2_db = create_async_test_store();
    let hop2_vid = create_vid_from_file("../examples/test/b/piv.json").await;
    let dropoff_vid = create_vid_from_file("../examples/test/timestamp-server/piv.json").await;
    hop2_db.add_private_vid(hop2_vid.clone(), None).unwrap();
    hop2_db.add_private_vid(dropoff_vid.clone(), None).unwrap();

    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let hop1_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:a";
    let hop2_did =
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:b";
    let dropoff_did = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server";

    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            hop1_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            CC001_ALICE,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            CC001_ALICE,
        )
        .unwrap();
    alice_db
        .set_route_for_vid(CC001_BOB, &[hop1_did, hop2_did, dropoff_did])
        .unwrap();

    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/b/piv.json").await,
            None,
        )
        .unwrap();
    hop1_db
        .set_relation_and_status_for_vid(
            hop2_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            hop1_did,
        )
        .unwrap();

    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/a/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/bob/piv.json").await,
            None,
        )
        .unwrap();
    hop2_db
        .set_relation_and_status_for_vid(
            dropoff_did,
            RelationshipStatus::Bidirectional {
                thread_id: [0; 32],
                outstanding_nested_thread_ids: vec![],
            },
            CC001_BOB,
        )
        .unwrap();

    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/alice/piv.json").await,
            None,
        )
        .unwrap();
    bob_db
        .add_verified_vid(
            create_vid_from_file("../examples/test/timestamp-server/piv.json").await,
            None,
        )
        .unwrap();

    let payload = b"hello routed world";
    let nonconfidential = b"cc003-routed-message-01-nonconf";

    let (_endpoint, mut first_hop_message) = alice_db
        .seal_message(CC001_ALICE, CC001_BOB, Some(nonconfidential), payload)
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop1_db.open_message(&mut first_hop_message).unwrap()
    else {
        panic!("first routed generic-message candidate did not open as a forward request");
    };

    let (_endpoint, mut second_hop_message) = hop1_db
        .make_next_routed_message(
            &next_hop,
            route
                .iter()
                .map(|segment| segment.iter().as_slice())
                .collect(),
            &opaque_payload,
        )
        .unwrap();

    let tsp_sdk::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = hop2_db.open_message(&mut second_hop_message).unwrap()
    else {
        panic!("second routed generic-message candidate did not open as a forward request");
    };

    assert!(route.is_empty());
    assert_eq!(next_hop, dropoff_did);

    let (_endpoint, mut final_message) = hop2_db
        .make_next_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .unwrap();
    let final_wire = final_message.clone();

    let opened = bob_db.open_message(&mut final_message).unwrap();
    let tsp_sdk::ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        panic!("final routed generic-message candidate did not open as a generic message");
    };

    assert_eq!(sender, CC001_ALICE);
    assert_eq!(receiver.as_deref(), Some(CC001_BOB));
    assert_eq!(message.as_ref(), payload);
    assert_eq!(
        nonconfidential_data.as_ref().map(|d| d.as_ref()),
        Some(nonconfidential.as_slice())
    );

    RoutedMessageCandidate {
        case_id: "CC-003".into(),
        vector_id: "SV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&final_wire),
        path_context_ref: "cc003-routed-final-delivery-01".into(),
        payload_semantics_ref: "cc003-routed-message-01".into(),
        sender,
        receiver: receiver.unwrap(),
        nonconfidential_data: std::str::from_utf8(nonconfidential).unwrap().into(),
        payload: std::str::from_utf8(payload).unwrap().into(),
        crypto_type: format!("{:?}", message_type.crypto_type),
        signature_type: format!("{:?}", message_type.signature_type),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_direct_accept_candidate(request_digest: [u8; 32]) -> DirectAcceptCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();

    let (_endpoint, accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, request_digest, None)
        .unwrap();
    let mut unopened = accept.clone();

    let opened_accept = alice_db.open_message(&mut unopened).unwrap();
    match opened_accept {
        tsp_sdk::ReceivedTspMessage::AcceptRelationship {
            sender, receiver, ..
        } => {
            assert_eq!(sender, CC001_BOB);
            assert_eq!(receiver, CC001_ALICE);
        }
        _ => panic!("accept candidate did not open as a relationship accept"),
    }

    let mut probe = accept.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("accept candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_BOB.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(alice_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(bob_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(decoded_payload.sender_identity, Some(CC001_BOB.as_bytes()));
    let reply_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded accept candidate was not a direct relation affirm"),
    };

    DirectAcceptCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-002".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        request_digest: to_hex(request_digest),
        reply_digest,
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_direct_rfd_candidate(request_digest: [u8; 32]) -> DirectRfdCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::ReverseUnidirectional {
                thread_id: request_digest,
            },
            CC001_BOB,
        )
        .unwrap();

    let (_endpoint, cancel) = alice_db
        .make_relationship_cancel(CC001_ALICE, CC001_BOB)
        .unwrap();
    let mut unopened = cancel.clone();

    let opened_cancel = bob_db.open_message(&mut unopened).unwrap();
    match opened_cancel {
        tsp_sdk::ReceivedTspMessage::CancelRelationship { sender, receiver } => {
            assert_eq!(sender, CC001_ALICE);
            assert_eq!(receiver, CC001_BOB);
        }
        _ => panic!("rfd candidate did not open as a relationship cancel"),
    }

    let mut probe = cancel.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("rfd candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_ALICE.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_BOB.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(bob_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(alice_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(
        decoded_payload.sender_identity,
        Some(CC001_ALICE.as_bytes())
    );
    let cancel_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::RelationshipCancel { reply, .. } => to_hex(reply.as_bytes()),
        _ => panic!("decoded rfd candidate was not a relationship cancel"),
    };

    DirectRfdCandidate {
        case_id: "CC-003".into(),
        vector_id: "BV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&cancel),
        digest: cancel_digest,
        reviewed_context: "pending-request-cancel".into(),
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_digest_mismatch_candidate(
    expected_request_digest: [u8; 32],
) -> DigestMismatchCandidate {
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    let alice_verified = create_vid_from_file("../examples/test/alice/piv.json").await;
    bob_db
        .add_verified_vid(alice_verified.vid().clone(), None)
        .unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_vid.vid().clone(), None)
        .unwrap();

    let mut mismatching_accept_digest = expected_request_digest;
    mismatching_accept_digest[31] ^= 0x01;

    alice_db
        .set_relation_and_status_for_vid(
            CC001_BOB,
            RelationshipStatus::Unidirectional {
                thread_id: expected_request_digest,
            },
            CC001_ALICE,
        )
        .unwrap();
    bob_db
        .set_relation_and_status_for_vid(
            CC001_ALICE,
            RelationshipStatus::Unidirectional {
                thread_id: expected_request_digest,
            },
            CC001_BOB,
        )
        .unwrap();

    let (_endpoint, accept) = bob_db
        .make_relationship_accept(CC001_BOB, CC001_ALICE, mismatching_accept_digest, None)
        .unwrap();
    let mut unopened = accept.clone();

    let err = alice_db.open_message(&mut unopened).unwrap_err();
    let tsp_sdk::Error::Relationship(message) = err else {
        panic!("digest-mismatch candidate did not fail as a relationship error");
    };
    assert!(message.contains("thread_id does not match digest"));

    let mut probe = accept.clone();
    let decoded = tsp_sdk::cesr::decode_envelope(&mut probe).unwrap();
    let tsp_sdk::cesr::DecodedEnvelope {
        envelope,
        ciphertext: Some(ciphertext),
        ..
    } = decoded.into_opened::<&[u8]>().unwrap()
    else {
        panic!("digest-mismatch candidate did not contain ciphertext");
    };
    assert_eq!(envelope.crypto_type, tsp_sdk::cesr::CryptoType::NaclEssr);
    assert_eq!(envelope.sender, CC001_BOB.as_bytes());
    assert_eq!(envelope.receiver, Some(CC001_ALICE.as_bytes()));

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce_bytes) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(alice_vid.decryption_key()).unwrap();
    let sender_public_key = PublicKey::from_slice(bob_vid.encryption_key()).unwrap();
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);
    receiver_box
        .decrypt_in_place_detached(nonce_bytes.into(), &[], ciphertext, tag.into())
        .unwrap();

    let decoded_payload = tsp_sdk::cesr::decode_payload(ciphertext).unwrap();
    assert_eq!(decoded_payload.sender_identity, Some(CC001_BOB.as_bytes()));
    let decoded_accept_digest = match decoded_payload.payload {
        tsp_sdk::cesr::Payload::DirectRelationAffirm { reply } => to_hex(reply.as_bytes()),
        _ => panic!("decoded digest-mismatch candidate was not a direct relation affirm"),
    };

    DigestMismatchCandidate {
        case_id: "CC-003".into(),
        vector_id: "SV-005".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&accept),
        expected_request_digest: to_hex(expected_request_digest),
        mismatching_accept_digest: decoded_accept_digest,
    }
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
async fn cc003_nonconfidential_binding_candidate() -> NonConfidentialBindingCandidate {
    let alice = create_vid_from_file("../examples/test/alice/piv.json").await;
    let bob = create_vid_from_file("../examples/test/bob/piv.json").await;
    let sender = alice.identifier().to_string();
    let receiver = bob.identifier().to_string();
    let nonconfidential = b"cc003-av003-nonconfidential";

    let sender_store = create_test_store();
    sender_store.add_private_vid(alice.clone(), None).unwrap();
    sender_store.add_verified_vid(bob.clone(), None).unwrap();

    let receiver_store = create_test_store();
    receiver_store.add_private_vid(bob.clone(), None).unwrap();
    receiver_store
        .add_verified_vid(alice.clone(), None)
        .unwrap();

    let mut request_digest = [0_u8; 32];
    let sealed = tsp_sdk::crypto::seal_and_hash(
        &alice,
        &bob,
        Some(nonconfidential),
        tsp_sdk::Payload::RequestRelationship {
            route: None,
            thread_id: Default::default(),
        },
        Some(&mut request_digest),
    )
    .unwrap();

    let mut unopened = sealed.clone();
    let opened = receiver_store.open_message(&mut unopened).unwrap();
    let opened_request_digest = match opened {
        tsp_sdk::ReceivedTspMessage::RequestRelationship {
            sender: opened_sender,
            receiver: opened_receiver,
            thread_id,
            ..
        } => {
            assert_eq!(opened_sender, sender);
            assert_eq!(opened_receiver, receiver);
            thread_id
        }
        _ => panic!("non-confidential-binding candidate did not open as a relationship request"),
    };
    assert_eq!(opened_request_digest, request_digest);

    let parts = tsp_sdk::cesr::open_message_into_parts(&sealed).unwrap();
    let nonconf_part = parts
        .nonconfidential_data
        .expect("review sample should carry non-confidential data");
    assert_eq!(nonconf_part.data, nonconfidential);

    let mut tampered = sealed.clone();
    let range = slice_range(&sealed, nonconf_part.data);
    tampered[range.start] ^= 0x01;
    assert!(receiver_store.open_message(&mut tampered).is_err());

    NonConfidentialBindingCandidate {
        case_id: "CC-003".into(),
        vector_id: "AV-003".into(),
        wire_base64: Base64UrlUnpadded::encode_string(&sealed),
        request_digest: to_hex(request_digest),
        nonconfidential_data: std::str::from_utf8(nonconfidential).unwrap().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GenerateCaseRequest, GenerateVectorRequest, generate_case_package,
        generate_vector_asset_set,
    };
    use crate::authoring::CompleteCase;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tsp_sdk::{OwnedVid, VerifiedVid};

    static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tsp-test-vectors-generate-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn read_generated_vector_wire(root: &Path, case: CompleteCase, vector_id: &str) -> String {
        fs::read_to_string(
            root.join(case.artifact_dir_name())
                .join("vectors")
                .join(vector_id)
                .join("wire.base64"),
        )
        .unwrap()
        .trim()
        .to_string()
    }

    fn read_generated_binding_value(
        root: &Path,
        case: CompleteCase,
        binding_rel: &str,
        key: &str,
    ) -> Option<String> {
        let raw = fs::read_to_string(
            root.join(case.artifact_dir_name())
                .join("bindings")
                .join(binding_rel),
        )
        .unwrap();
        let needle = format!("{key}: \"");
        raw.lines().find_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix(&needle)
                .and_then(|rest| rest.strip_suffix('"'))
                .map(str::to_string)
        })
    }

    fn assert_generated_vector_wire_matches(
        root: &Path,
        case: CompleteCase,
        left_vector_id: &str,
        right_vector_id: &str,
    ) {
        let left = read_generated_vector_wire(root, case, left_vector_id);
        let right = read_generated_vector_wire(root, case, right_vector_id);
        assert_eq!(
            left,
            right,
            "generated wire mismatch between {left_vector_id} and {right_vector_id} for {}",
            case.case_id()
        );
    }

    async fn timestamp_server_owned() -> OwnedVid {
        OwnedVid::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../examples/test/timestamp-server/piv.json"),
        )
        .await
        .expect("timestamp-server piv should load")
    }

    fn verify_envelope_signature(wire: &[u8], signer: &OwnedVid) -> Result<(), String> {
        let mut probe = wire.to_vec();
        let view = tsp_sdk::cesr::decode_envelope(&mut probe).map_err(|err| err.to_string())?;
        let challenge = view.as_challenge();
        let signature =
            Signature::from_slice(challenge.signature).map_err(|err| err.to_string())?;
        let verifying_key = VerifyingKey::try_from(signer.verifying_key().as_slice())
            .map_err(|err| err.to_string())?;

        verifying_key
            .verify_strict(challenge.signed_data, &signature)
            .map_err(|err| err.to_string())
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generates_cc001_direct_request_slice() {
        let root = temp_root("cc001-bv001");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc001,
            "BV-001",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-001");
        assert_eq!(result.vector_id, "BV-001");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/bindings/direct/request-01.yaml")
                .is_file()
        );
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generates_supported_cc001_case_subset() {
        let root = temp_root("cc001-case");
        let results = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc001, &root))
            .await
            .unwrap();

        assert_eq!(results.len(), 17);
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/SV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/SV-005/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/AV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/AV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/AV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-005/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-006/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-007/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/BV-008/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/SV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/SV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/SV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-001/vectors/SV-006/wire.base64")
                .is_file()
        );
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generated_cc001_derivation_wires_remain_self_consistent() {
        let root = temp_root("cc001-golden");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc001, &root))
            .await
            .unwrap();
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc001, "AV-001", "BV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc001, "AV-002", "BV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc001, "SV-004", "SV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc001, "SV-006", "SV-002");
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generated_cc001_direct_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc001-direct-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc001, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc001,
            "direct/request-01.yaml",
            "request_digest",
        )
        .expect("generated direct request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "direct/accept-01.yaml",
                "request_digest"
            )
            .expect("generated direct accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "direct/rfd-01.yaml",
                "digest"
            )
            .expect("generated direct rfd digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "negative/digest-mismatch-01.yaml",
                "expected_request_digest",
            )
            .expect("generated digest mismatch request digest should exist")
        );
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generated_cc001_nested_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc001-nested-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc001, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc001,
            "nested/request-01.yaml",
            "request_digest",
        )
        .expect("generated nested request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "nested/accept-01.yaml",
                "request_digest",
            )
            .expect("generated nested accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "nested/accept-01.yaml",
                "reply_digest",
            )
            .expect("generated nested accept reply digest should exist")
        );
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generated_cc001_routed_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc001-routed-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc001, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc001,
            "routed/request-01.yaml",
            "request_digest",
        )
        .expect("generated routed request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "routed/accept-01.yaml",
                "request_digest",
            )
            .expect("generated routed accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc001,
                "routed/accept-01.yaml",
                "reply_digest",
            )
            .expect("generated routed accept reply digest should exist")
        );
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generated_cc001_bv007_signature_verifies_against_current_timestamp_server_key() {
        let root = temp_root("cc001-bv007-signature");
        generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc001,
            "BV-007",
            &root,
        ))
        .await
        .unwrap();

        let wire = Base64UrlUnpadded::decode_vec(&read_generated_vector_wire(
            &root,
            CompleteCase::Cc001,
            "BV-007",
        ))
        .expect("generated BV-007 wire should decode");
        let timestamp_server = timestamp_server_owned().await;

        verify_envelope_signature(&wire, &timestamp_server)
            .expect("generated BV-007 should verify against current timestamp-server key");
    }

    #[cfg(all(not(feature = "nacl"), not(feature = "pq"), not(feature = "essr")))]
    #[tokio::test]
    async fn generated_cc001_bv008_signature_verifies_against_current_timestamp_server_key() {
        let root = temp_root("cc001-bv008-signature");
        generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc001,
            "BV-008",
            &root,
        ))
        .await
        .unwrap();

        let wire = Base64UrlUnpadded::decode_vec(&read_generated_vector_wire(
            &root,
            CompleteCase::Cc001,
            "BV-008",
        ))
        .expect("generated BV-008 wire should decode");
        let timestamp_server = timestamp_server_owned().await;

        verify_envelope_signature(&wire, &timestamp_server)
            .expect("generated BV-008 should verify against current timestamp-server key");
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generates_cc002_direct_request_slice() {
        let root = temp_root("cc002-bv001");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc002,
            "BV-001",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-002");
        assert_eq!(result.vector_id, "BV-001");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/bindings/direct/request-01.yaml")
                .is_file()
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generates_cc002_nested_request_slice() {
        let root = temp_root("cc002-bv004");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc002,
            "BV-004",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-002");
        assert_eq!(result.vector_id, "BV-004");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/bindings/nested/request-01.yaml")
                .is_file()
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generates_cc002_routed_path_slice() {
        let root = temp_root("cc002-bv006");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc002,
            "BV-006",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-002");
        assert_eq!(result.vector_id, "BV-006");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-006/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/bindings/routed/path-01.yaml")
                .is_file()
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generates_cc002_routed_message_slice() {
        let root = temp_root("cc002-sv003");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc002,
            "SV-003",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-002");
        assert_eq!(result.vector_id, "SV-003");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/bindings/routed/message-01.yaml")
                .is_file()
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generates_supported_cc002_direct_subset() {
        let root = temp_root("cc002-case");
        let results = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc002, &root))
            .await
            .unwrap();

        assert_eq!(results.len(), 17);
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-005/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/AV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/AV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/AV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-005/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-006/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-007/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/BV-008/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-002/vectors/SV-006/wire.base64")
                .is_file()
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generated_cc002_derivation_wires_remain_self_consistent() {
        let root = temp_root("cc002-golden");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc002, &root))
            .await
            .unwrap();
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc002, "AV-001", "BV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc002, "AV-002", "BV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc002, "SV-004", "SV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc002, "SV-006", "SV-002");
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generated_cc002_direct_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc002-direct-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc002, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc002,
            "direct/request-01.yaml",
            "request_digest",
        )
        .expect("generated direct request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "direct/accept-01.yaml",
                "request_digest"
            )
            .expect("generated direct accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "direct/rfd-01.yaml",
                "digest"
            )
            .expect("generated direct rfd digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "negative/digest-mismatch-01.yaml",
                "expected_request_digest",
            )
            .expect("generated digest mismatch request digest should exist")
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generated_cc002_nested_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc002-nested-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc002, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc002,
            "nested/request-01.yaml",
            "request_digest",
        )
        .expect("generated nested request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "nested/accept-01.yaml",
                "request_digest",
            )
            .expect("generated nested accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "nested/accept-01.yaml",
                "reply_digest",
            )
            .expect("generated nested accept reply digest should exist")
        );
    }

    #[cfg(feature = "essr")]
    #[tokio::test]
    async fn generated_cc002_routed_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc002-routed-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc002, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc002,
            "routed/request-01.yaml",
            "request_digest",
        )
        .expect("generated routed request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "routed/accept-01.yaml",
                "request_digest",
            )
            .expect("generated routed accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc002,
                "routed/accept-01.yaml",
                "reply_digest",
            )
            .expect("generated routed accept reply digest should exist")
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generates_cc003_direct_request_slice() {
        let root = temp_root("cc003-bv001");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc003,
            "BV-001",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-003");
        assert_eq!(result.vector_id, "BV-001");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/bindings/direct/request-01.yaml")
                .is_file()
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generates_cc003_nested_request_slice() {
        let root = temp_root("cc003-bv004");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc003,
            "BV-004",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-003");
        assert_eq!(result.vector_id, "BV-004");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/bindings/nested/request-01.yaml")
                .is_file()
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generates_cc003_routed_path_slice() {
        let root = temp_root("cc003-bv006");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc003,
            "BV-006",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-003");
        assert_eq!(result.vector_id, "BV-006");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-006/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/bindings/routed/path-01.yaml")
                .is_file()
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generates_cc003_routed_message_slice() {
        let root = temp_root("cc003-sv003");
        let result = generate_vector_asset_set(&GenerateVectorRequest::new(
            CompleteCase::Cc003,
            "SV-003",
            &root,
        ))
        .await
        .unwrap();

        assert_eq!(result.case_id, "CC-003");
        assert_eq!(result.vector_id, "SV-003");
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/bindings/routed/message-01.yaml")
                .is_file()
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generates_supported_cc003_direct_subset() {
        let root = temp_root("cc003-case");
        let results = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc003, &root))
            .await
            .unwrap();

        assert_eq!(results.len(), 17);
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-005/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-006/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-007/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/BV-008/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-003/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-004/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-006/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/SV-005/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/AV-001/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/AV-002/wire.base64")
                .is_file()
        );
        assert!(
            Path::new(&root)
                .join("artifact-set.cc-003/vectors/AV-003/wire.base64")
                .is_file()
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generated_cc003_derivation_wires_remain_self_consistent() {
        let root = temp_root("cc003-golden");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc003, &root))
            .await
            .unwrap();
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc003, "AV-001", "BV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc003, "AV-002", "BV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc003, "SV-004", "SV-001");
        assert_generated_vector_wire_matches(&root, CompleteCase::Cc003, "SV-006", "SV-002");
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generated_cc003_nested_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc003-nested-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc003, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc003,
            "nested/request-01.yaml",
            "request_digest",
        )
        .expect("generated nested request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "nested/accept-01.yaml",
                "request_digest",
            )
            .expect("generated nested accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "nested/accept-01.yaml",
                "reply_digest",
            )
            .expect("generated nested accept reply digest should exist")
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generated_cc003_routed_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc003-routed-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc003, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc003,
            "routed/request-01.yaml",
            "request_digest",
        )
        .expect("generated routed request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "routed/accept-01.yaml",
                "request_digest",
            )
            .expect("generated routed accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "routed/accept-01.yaml",
                "reply_digest",
            )
            .expect("generated routed accept reply digest should exist")
        );
    }

    #[cfg(all(feature = "nacl", not(feature = "pq")))]
    #[tokio::test]
    async fn generated_cc003_direct_family_bindings_share_fresh_request_root() {
        let root = temp_root("cc003-direct-family");
        let _ = generate_case_package(&GenerateCaseRequest::new(CompleteCase::Cc003, &root))
            .await
            .unwrap();

        let request_digest = read_generated_binding_value(
            &root,
            CompleteCase::Cc003,
            "direct/request-01.yaml",
            "request_digest",
        )
        .expect("generated direct request digest should exist");
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "direct/accept-01.yaml",
                "request_digest"
            )
            .expect("generated direct accept request digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "direct/rfd-01.yaml",
                "digest"
            )
            .expect("generated direct rfd digest should exist")
        );
        assert_eq!(
            request_digest,
            read_generated_binding_value(
                &root,
                CompleteCase::Cc003,
                "negative/digest-mismatch-01.yaml",
                "expected_request_digest",
            )
            .expect("generated digest mismatch request digest should exist")
        );
    }
}
