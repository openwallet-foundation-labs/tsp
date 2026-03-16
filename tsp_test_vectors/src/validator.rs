use crate::layout::{DEFAULT_CASE_OUTPUTS, DEFAULT_PACKAGE_ROOT, DEFAULT_VECTOR_CATALOG};
use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fmt, fs,
    path::{Path, PathBuf},
};
use tsp_sdk::{
    OwnedVid, ReceivedTspMessage, RelationshipStatus, SecureStore, VerifiedVid,
    definitions::{
        PublicKeyData, PublicVerificationKeyData, VidEncryptionKeyType, VidSignatureKeyType,
    },
};

#[derive(Debug, Parser)]
#[command(name = "tsp-vector-validator", version)]
#[command(about = "Validate frozen TSP test-vector case packages")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Validate one case manifest and its case-local package")]
    Case {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_root: Option<PathBuf>,
        #[arg(long)]
        review_root: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_VECTOR_CATALOG)]
        vector_catalog: PathBuf,
        #[arg(long)]
        records: bool,
        #[arg(long)]
        sdk_replay_probe: bool,
    },
    #[command(about = "Validate all case packages under a package root")]
    All {
        #[arg(long = "package-root", default_value = DEFAULT_PACKAGE_ROOT)]
        package_root: PathBuf,
        #[arg(long, default_value = DEFAULT_VECTOR_CATALOG)]
        vector_catalog: PathBuf,
        #[arg(long)]
        records: bool,
        #[arg(long)]
        sdk_replay_probe: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationSummary {
    pub case_id: String,
    pub vectors: usize,
    pub fixtures: usize,
    pub bindings: usize,
    pub identity_fixture_reviews: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayProbeStatus {
    Verified,
    Failed,
    NotAttempted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayProbeRecord {
    pub case_id: String,
    pub vector_id: String,
    pub status: ReplayProbeStatus,
    pub notes: Vec<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseOutputValidationRecord {
    pub case_id: String,
    pub case_output_id: String,
    pub status: &'static str,
    pub expected_positive_outcomes: Vec<String>,
    pub actual_positive_outcomes: Vec<String>,
    pub matched_positive_outcomes: Vec<String>,
    pub expected_negative_outcomes: Vec<String>,
    pub actual_negative_outcomes: Vec<String>,
    pub matched_negative_outcomes: Vec<String>,
    pub represented_negative_outcomes: Vec<String>,
    pub expected_relationship_state_summary: Vec<String>,
    pub actual_relationship_state_summary: Vec<String>,
    pub matched_relationship_state_summary: Vec<String>,
    pub expected_message_flow_summary: Vec<String>,
    pub actual_message_flow_summary: Vec<String>,
    pub matched_message_flow_summary: Vec<String>,
    pub expected_family_summary: Vec<String>,
    pub actual_family_summary: Vec<String>,
    pub matched_family_summary: Vec<String>,
    pub expected_mechanism_summary: Vec<String>,
    pub actual_mechanism_summary: Vec<String>,
    pub matched_mechanism_summary: Vec<String>,
    pub missing_checks: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActualCaseOutcomeRecord {
    pub case_id: String,
    pub positive_outcomes: Vec<String>,
    pub negative_outcomes: Vec<String>,
    pub represented_negative_outcomes: Vec<String>,
    pub relationship_state_summary: Vec<String>,
    pub message_flow_summary: Vec<String>,
    pub family_summary: Vec<String>,
    pub mechanism_summary: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseValidationBundle {
    pub summary: ValidationSummary,
    pub case_output: CaseOutputValidationRecord,
    pub replay_records: Vec<ReplayProbeRecord>,
}

#[derive(Debug)]
struct ValidationRecord {
    vector_id: String,
    case_id: String,
    classification: String,
    artifact_ref: String,
    binding_refs: Vec<String>,
    fixture_refs: Vec<String>,
    result: &'static str,
    comparison_boundary_used: Vec<String>,
    notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayProbeMode {
    Off,
    FailFast,
    Collect,
}

#[derive(Debug, Default)]
struct ManifestData {
    case_id: String,
    case_profile: String,
    artifact_set_id: String,
    case_output_ref: String,
    applicable_vector_refs: Vec<String>,
    applicable_fixture_refs: Vec<String>,
    binding_artifact_refs: Vec<String>,
}

#[derive(Debug, Default)]
struct CaseOutputData {
    case_output_id: String,
    case_id: String,
    case_profile: String,
    supported_vector_ids: Vec<String>,
    positive_outcomes: Vec<String>,
    negative_outcomes: Vec<String>,
    relationship_state_summary: Vec<String>,
    message_flow_summary: Vec<String>,
    family_summary: Vec<String>,
    mechanism_summary: Vec<String>,
}

#[derive(Debug, Default)]
struct ReviewData {
    review_status: Option<String>,
    artifact_ref: Option<String>,
    binding_id: Option<String>,
    fixture_id: Option<String>,
    reviewed_bindings: Vec<String>,
    reviewed_for_vectors: Vec<String>,
    value_checks: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct BindingData {
    related_vectors: Vec<String>,
    related_fixture_refs: Vec<String>,
    reviewed_values: BTreeMap<String, String>,
    comparison_boundary: Vec<String>,
    review_value_checks: BTreeMap<String, String>,
    reviewed_for_vectors: Vec<String>,
}

#[derive(Debug, Default)]
struct FixtureData {
    id: String,
    used_by_vectors: Vec<String>,
    binding_material: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct ValidationError(pub(crate) String);

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ValidationError {}

pub fn main_entry() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Case {
            manifest,
            artifact_root,
            review_root,
            vector_catalog,
            records,
            sdk_replay_probe,
        } => validate_case_command(
            &manifest,
            artifact_root,
            review_root,
            &vector_catalog,
            records,
            sdk_replay_probe,
        ),
        Command::All {
            package_root,
            vector_catalog,
            records,
            sdk_replay_probe,
        } => validate_all_command(&package_root, &vector_catalog, records, sdk_replay_probe),
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

pub fn validate_all_packages(
    package_root: &Path,
    vector_catalog_path: &Path,
) -> Result<Vec<ValidationSummary>, ValidationError> {
    validate_all_packages_with_options(package_root, vector_catalog_path, false)
}

pub fn validate_all_packages_with_options(
    package_root: &Path,
    vector_catalog_path: &Path,
    sdk_replay_probe: bool,
) -> Result<Vec<ValidationSummary>, ValidationError> {
    let manifests = manifest_paths_under(package_root);

    let mut summaries = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        let replay_mode = if sdk_replay_probe {
            ReplayProbeMode::FailFast
        } else {
            ReplayProbeMode::Off
        };
        let (summary, _records, _replay_records) =
            validate_case(&manifest, None, None, vector_catalog_path, replay_mode)?;
        summaries.push(summary);
    }

    Ok(summaries)
}

pub fn validate_case_package(
    manifest_path: &Path,
    vector_catalog_path: &Path,
) -> Result<ValidationSummary, ValidationError> {
    let (summary, _records, _replay_records) = validate_case(
        manifest_path,
        None,
        None,
        vector_catalog_path,
        ReplayProbeMode::Off,
    )?;
    Ok(summary)
}

pub fn collect_replay_probe_records(
    package_root: &Path,
    vector_catalog_path: &Path,
) -> Result<Vec<ReplayProbeRecord>, ValidationError> {
    collect_replay_probe_records_by_mode(
        package_root,
        vector_catalog_path,
        ReplayProbeMode::Collect,
    )
}

pub fn collect_replay_probe_records_relaxed(
    package_root: &Path,
    _vector_catalog_path: &Path,
) -> Result<Vec<ReplayProbeRecord>, ValidationError> {
    let mut records = Vec::new();
    for manifest_path in manifest_paths_under(package_root) {
        let manifest = load_manifest_from_path(&manifest_path)?;
        let artifact_root = manifest_path.parent().ok_or_else(|| {
            ValidationError(format!(
                "manifest has no parent: {}",
                manifest_path.display()
            ))
        })?;
        records.extend(collect_replay_probe_records_for_manifest_relaxed(
            &manifest,
            artifact_root,
        )?);
    }

    Ok(records)
}

pub fn collect_case_output_records(
    package_root: &Path,
    vector_catalog_path: &Path,
) -> Result<Vec<CaseOutputValidationRecord>, ValidationError> {
    collect_case_output_records_inner(package_root, vector_catalog_path, false)
}

pub fn collect_case_output_records_relaxed(
    package_root: &Path,
    vector_catalog_path: &Path,
) -> Result<Vec<CaseOutputValidationRecord>, ValidationError> {
    collect_case_output_records_inner(package_root, vector_catalog_path, true)
}

pub fn collect_case_validation_bundles(
    package_root: &Path,
    vector_catalog_path: &Path,
) -> Result<Vec<CaseValidationBundle>, ValidationError> {
    collect_case_validation_bundles_inner(package_root, vector_catalog_path, false)
}

pub fn collect_case_validation_bundles_relaxed(
    package_root: &Path,
    vector_catalog_path: &Path,
) -> Result<Vec<CaseValidationBundle>, ValidationError> {
    collect_case_validation_bundles_inner(package_root, vector_catalog_path, true)
}

fn default_case_outputs_path(package_root: &Path) -> PathBuf {
    if let Some(parent) = package_root.parent() {
        let candidate = parent.join("docs/spec/test-vector-case-outputs.md");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(DEFAULT_CASE_OUTPUTS)
}

fn load_manifest_from_path(manifest_path: &Path) -> Result<ManifestData, ValidationError> {
    parse_manifest(&read_file(manifest_path)?)
}

fn load_case_output_catalog_for_package(
    package_root: &Path,
) -> Result<BTreeMap<String, CaseOutputData>, ValidationError> {
    let case_outputs_path = default_case_outputs_path(package_root);
    parse_case_output_catalog(&case_outputs_path, &read_file(&case_outputs_path)?)
}

fn manifest_paths_under(package_root: &Path) -> Vec<PathBuf> {
    [
        package_root.join("artifact-set.cc-001/case-manifest.yaml"),
        package_root.join("artifact-set.cc-002/case-manifest.yaml"),
        package_root.join("artifact-set.cc-003/case-manifest.yaml"),
    ]
    .into_iter()
    .filter(|path| path.is_file())
    .collect()
}

fn collect_replay_probe_records_by_mode(
    package_root: &Path,
    vector_catalog_path: &Path,
    replay_mode: ReplayProbeMode,
) -> Result<Vec<ReplayProbeRecord>, ValidationError> {
    let mut records = Vec::new();
    for manifest_path in manifest_paths_under(package_root) {
        let (_summary, _validation_records, replay_records) =
            validate_case(&manifest_path, None, None, vector_catalog_path, replay_mode)?;
        records.extend(replay_records);
    }
    Ok(records)
}

fn collect_case_output_records_inner(
    package_root: &Path,
    vector_catalog_path: &Path,
    relaxed: bool,
) -> Result<Vec<CaseOutputValidationRecord>, ValidationError> {
    let case_outputs = load_case_output_catalog_for_package(package_root)?;
    let manifests = manifest_paths_under(package_root);
    let mut records = Vec::with_capacity(manifests.len());

    for manifest_path in manifests {
        let manifest = load_manifest_from_path(&manifest_path)?;
        let replay_records = if relaxed {
            let artifact_root = manifest_path.parent().ok_or_else(|| {
                ValidationError(format!(
                    "manifest has no parent: {}",
                    manifest_path.display()
                ))
            })?;
            collect_replay_probe_records_for_manifest_relaxed(&manifest, artifact_root)?
        } else {
            let (_summary, _validation_records, replay_records) = validate_case(
                &manifest_path,
                None,
                None,
                vector_catalog_path,
                ReplayProbeMode::Collect,
            )?;
            replay_records
        };
        let case_output = case_outputs.get(&manifest.case_output_ref).ok_or_else(|| {
            ValidationError(format!(
                "case output {} not found for manifest {}",
                manifest.case_output_ref,
                manifest_path.display()
            ))
        })?;
        records.push(validate_case_output_record(
            &manifest,
            case_output,
            &replay_records,
        )?);
    }

    Ok(records)
}

fn collect_case_validation_bundles_inner(
    package_root: &Path,
    vector_catalog_path: &Path,
    relaxed: bool,
) -> Result<Vec<CaseValidationBundle>, ValidationError> {
    let manifests = manifest_paths_under(package_root);

    let case_outputs = if relaxed {
        collect_case_output_records_relaxed(package_root, vector_catalog_path)?
    } else {
        collect_case_output_records(package_root, vector_catalog_path)?
    };
    let replay_records = if relaxed {
        collect_replay_probe_records_relaxed(package_root, vector_catalog_path)?
    } else {
        collect_replay_probe_records(package_root, vector_catalog_path)?
    };

    let mut output_by_case = case_outputs
        .into_iter()
        .map(|record| (record.case_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut replay_by_case = BTreeMap::<String, Vec<ReplayProbeRecord>>::new();
    for record in replay_records {
        replay_by_case
            .entry(record.case_id.clone())
            .or_default()
            .push(record);
    }

    let mut bundles = Vec::with_capacity(manifests.len());
    for manifest_path in manifests {
        let manifest = load_manifest_from_path(&manifest_path)?;
        let artifact_root = manifest_path.parent().ok_or_else(|| {
            ValidationError(format!(
                "manifest has no parent: {}",
                manifest_path.display()
            ))
        })?;
        let review_root = infer_review_root(artifact_root);
        let summary = if relaxed {
            relaxed_summary(&manifest, &review_root)?
        } else {
            validate_case_package(&manifest_path, vector_catalog_path)?
        };
        let case_output = output_by_case.remove(&manifest.case_id).ok_or_else(|| {
            ValidationError(format!(
                "missing case output record for {}",
                manifest.case_id
            ))
        })?;
        let replay = replay_by_case.remove(&manifest.case_id).unwrap_or_default();
        bundles.push(CaseValidationBundle {
            summary,
            case_output,
            replay_records: replay,
        });
    }

    Ok(bundles)
}

fn relaxed_summary(
    manifest: &ManifestData,
    review_root: &Path,
) -> Result<ValidationSummary, ValidationError> {
    let fixture_review_root = review_root.join("fixture-reviews");
    let identity_fixture_reviews = if fixture_review_root.is_dir() {
        fs::read_dir(&fixture_review_root)
            .map_err(|err| {
                ValidationError(format!(
                    "failed to read fixture review directory {}: {err}",
                    fixture_review_root.display()
                ))
            })?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("yaml"))
            .count()
    } else {
        0
    };

    Ok(ValidationSummary {
        case_id: manifest.case_id.clone(),
        vectors: manifest.applicable_vector_refs.len(),
        fixtures: manifest.applicable_fixture_refs.len(),
        bindings: manifest.binding_artifact_refs.len(),
        identity_fixture_reviews,
    })
}

fn validate_all_command(
    package_root: &Path,
    vector_catalog_path: &Path,
    emit_records: bool,
    sdk_replay_probe: bool,
) -> Result<(), ValidationError> {
    let manifests = [
        package_root.join("artifact-set.cc-001/case-manifest.yaml"),
        package_root.join("artifact-set.cc-002/case-manifest.yaml"),
        package_root.join("artifact-set.cc-003/case-manifest.yaml"),
    ];

    let mut summaries = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        let (summary, records, _replay_records) = validate_case(
            &manifest,
            None,
            None,
            vector_catalog_path,
            if sdk_replay_probe {
                ReplayProbeMode::FailFast
            } else {
                ReplayProbeMode::Off
            },
        )?;
        if emit_records {
            emit_records_jsonl(&records);
        }
        summaries.push(summary);
    }

    for summary in summaries {
        println!(
            "{}: {} vectors, {} fixtures, {} bindings, {} identity fixture reviews",
            summary.case_id,
            summary.vectors,
            summary.fixtures,
            summary.bindings,
            summary.identity_fixture_reviews
        );
    }

    Ok(())
}

fn validate_case_command(
    manifest: &Path,
    artifact_root: Option<PathBuf>,
    review_root: Option<PathBuf>,
    vector_catalog_path: &Path,
    emit_records: bool,
    sdk_replay_probe: bool,
) -> Result<(), ValidationError> {
    let (summary, records, _replay_records) = validate_case(
        manifest,
        artifact_root,
        review_root,
        vector_catalog_path,
        if sdk_replay_probe {
            ReplayProbeMode::FailFast
        } else {
            ReplayProbeMode::Off
        },
    )?;
    if emit_records {
        emit_records_jsonl(&records);
    }
    println!(
        "{}: {} vectors, {} fixtures, {} bindings, {} identity fixture reviews",
        summary.case_id,
        summary.vectors,
        summary.fixtures,
        summary.bindings,
        summary.identity_fixture_reviews
    );
    Ok(())
}

fn validate_case(
    manifest_path: &Path,
    artifact_root_override: Option<PathBuf>,
    review_root_override: Option<PathBuf>,
    vector_catalog_path: &Path,
    replay_mode: ReplayProbeMode,
) -> Result<
    (
        ValidationSummary,
        Vec<ValidationRecord>,
        Vec<ReplayProbeRecord>,
    ),
    ValidationError,
> {
    let manifest_text = read_file(manifest_path)?;
    let manifest = parse_manifest(&manifest_text)?;
    let vector_catalog =
        parse_vector_catalog(vector_catalog_path, &read_file(vector_catalog_path)?)?;

    let inferred_artifact_root = manifest_path.parent().ok_or_else(|| {
        ValidationError(format!(
            "manifest has no parent: {}",
            manifest_path.display()
        ))
    })?;
    let artifact_root =
        artifact_root_override.unwrap_or_else(|| inferred_artifact_root.to_path_buf());
    let review_root = review_root_override.unwrap_or_else(|| infer_review_root(&artifact_root));

    if !artifact_root.is_dir() {
        return Err(ValidationError(format!(
            "artifact root not found: {}",
            artifact_root.display()
        )));
    }
    if !review_root.is_dir() {
        return Err(ValidationError(format!(
            "review root not found: {}",
            review_root.display()
        )));
    }

    if manifest.applicable_vector_refs.is_empty()
        || manifest.applicable_fixture_refs.is_empty()
        || manifest.binding_artifact_refs.is_empty()
    {
        return Err(ValidationError(format!(
            "manifest missing required refs: {}",
            manifest_path.display()
        )));
    }

    let mut records = Vec::with_capacity(manifest.applicable_vector_refs.len());
    let mut replay_records = Vec::with_capacity(manifest.applicable_vector_refs.len());

    for vector_id in &manifest.applicable_vector_refs {
        let wire_path = artifact_root
            .join("vectors")
            .join(vector_id)
            .join("wire.base64");
        ensure_file(&wire_path)?;
        let artifact_bytes = load_wire_artifact(&wire_path)?;

        let review_path = review_root
            .join("vector-reviews")
            .join(format!("{vector_id}.yaml"));
        let review = parse_review(&read_file(&review_path)?)?;
        ensure_review_pass(&review_path, &review)?;

        let classification = vector_catalog.get(vector_id).cloned().ok_or_else(|| {
            ValidationError(format!("vector classification not found for {}", vector_id))
        })?;

        if let Some(artifact_ref) = review.artifact_ref.as_deref() {
            let expected_ref = format!(
                "{}.vector.{vector_id}.wire",
                manifest.artifact_set_id.replace("artifact-set", "artifact")
            );
            if artifact_ref != expected_ref {
                return Err(ValidationError(format!(
                    "vector review artifact_ref mismatch in {}: expected {}, got {}",
                    review_path.display(),
                    expected_ref,
                    artifact_ref
                )));
            }
        }

        let binding_refs = if review.reviewed_bindings.is_empty() {
            find_binding_refs_for_vector(&manifest, &artifact_root, vector_id)?
        } else {
            review.reviewed_bindings.clone()
        };

        if binding_refs.is_empty() {
            return Err(ValidationError(format!(
                "no reviewed bindings found for vector {}",
                vector_id
            )));
        }

        let mut fixture_refs = Vec::new();
        let mut comparison_boundary_used = Vec::new();
        let mut notes = vec![format!(
            "wire artifact decoded successfully from {}",
            wire_path.display()
        )];
        let mut has_direct_binding_match = false;
        let mut has_direct_fixture_match = false;
        let mut aggregated_reviewed_values = BTreeMap::new();

        for binding_ref in &binding_refs {
            if !manifest
                .binding_artifact_refs
                .iter()
                .any(|candidate| candidate == binding_ref)
            {
                return Err(ValidationError(format!(
                    "vector {} references binding outside manifest scope: {}",
                    vector_id, binding_ref
                )));
            }

            let binding = load_binding(&manifest, &artifact_root, &review_root, binding_ref)?;
            if binding
                .related_vectors
                .iter()
                .any(|candidate| candidate == vector_id)
            {
                has_direct_binding_match = true;
                if !binding
                    .reviewed_for_vectors
                    .iter()
                    .any(|candidate| candidate == vector_id)
                {
                    return Err(ValidationError(format!(
                        "binding review {} does not explicitly list {} in reviewed_for_vectors",
                        binding_ref, vector_id
                    )));
                }
            }

            for fixture_ref in &binding.related_fixture_refs {
                if !manifest
                    .applicable_fixture_refs
                    .iter()
                    .any(|candidate| candidate == fixture_ref)
                {
                    return Err(ValidationError(format!(
                        "binding {} references fixture outside manifest scope: {}",
                        binding_ref, fixture_ref
                    )));
                }
                let fixture_path =
                    resolve_fixture_path(&artifact_root.join("fixtures"), fixture_ref)?;
                let fixture = load_fixture(&fixture_path)?;
                if fixture.id != *fixture_ref {
                    return Err(ValidationError(format!(
                        "fixture id mismatch in {}: expected {}, got {}",
                        fixture_path.display(),
                        fixture_ref,
                        fixture.id
                    )));
                }
                if fixture
                    .used_by_vectors
                    .iter()
                    .any(|candidate| candidate == vector_id)
                {
                    has_direct_fixture_match = true;
                }
                verify_binding_fixture_alignment(binding_ref, &binding, fixture_ref, &fixture)?;
                if !fixture_refs
                    .iter()
                    .any(|candidate| candidate == fixture_ref)
                {
                    fixture_refs.push(fixture_ref.clone());
                }
            }

            verify_binding_review_value_alignment(binding_ref, &binding)?;

            comparison_boundary_used.extend(binding.comparison_boundary.iter().cloned());
            aggregated_reviewed_values.extend(binding.reviewed_values.clone());

            match classification.as_str() {
                "byte-exact" => {
                    if binding.reviewed_values.is_empty() {
                        return Err(ValidationError(format!(
                            "byte-exact binding {} has no reviewed values",
                            binding_ref
                        )));
                    }
                    if binding
                        .related_vectors
                        .iter()
                        .any(|candidate| candidate == vector_id)
                        && binding.review_value_checks.is_empty()
                    {
                        return Err(ValidationError(format!(
                            "byte-exact binding {} has no review value_checks for directly related vector {}",
                            binding_ref, vector_id
                        )));
                    }
                }
                "semantic-only" => {
                    if binding.reviewed_values.is_empty() {
                        return Err(ValidationError(format!(
                            "semantic-only binding {} has no reviewed values",
                            binding_ref
                        )));
                    }

                    if matches!(vector_id.as_str(), "SV-001" | "SV-002" | "SV-003")
                        && !binding
                            .reviewed_values
                            .contains_key("payload_semantics_ref")
                    {
                        return Err(ValidationError(format!(
                            "binding {} is missing payload_semantics_ref for {}",
                            binding_ref, vector_id
                        )));
                    }

                    if matches!(vector_id.as_str(), "SV-004" | "SV-006") {
                        let source_vector_ref = binding
                            .reviewed_values
                            .get("source_vector_ref")
                            .ok_or_else(|| {
                                ValidationError(format!(
                                    "negative binding {} is missing source_vector_ref",
                                    binding_ref
                                ))
                            })?;
                        binding
                            .reviewed_values
                            .get("source_binding_ref")
                            .ok_or_else(|| {
                                ValidationError(format!(
                                    "negative binding {} is missing source_binding_ref",
                                    binding_ref
                                ))
                            })?;
                        binding
                            .reviewed_values
                            .get("source_fixture_ref")
                            .ok_or_else(|| {
                                ValidationError(format!(
                                    "negative binding {} is missing source_fixture_ref",
                                    binding_ref
                                ))
                            })?;

                        let source_wire_path =
                            vector_artifact_path(&artifact_root, &manifest, source_vector_ref)?;
                        let source_bytes = load_wire_artifact(&source_wire_path)?;
                        if source_bytes != artifact_bytes {
                            return Err(ValidationError(format!(
                                "negative vector {} does not reuse the reviewed source wire {}",
                                vector_id, source_vector_ref
                            )));
                        }
                        notes.push(format!(
                            "negative derivation reuses reviewed source wire {}",
                            source_vector_ref
                        ));
                    }
                }
                other => {
                    return Err(ValidationError(format!(
                        "unsupported classification {} for {}",
                        other, vector_id
                    )));
                }
            }
        }

        if !has_direct_binding_match {
            return Err(ValidationError(format!(
                "no reviewed binding declares {} as a directly related vector",
                vector_id
            )));
        }
        if !fixture_refs.is_empty() && !has_direct_fixture_match {
            return Err(ValidationError(format!(
                "no reviewed fixture declares {} as a directly used vector",
                vector_id
            )));
        }

        for required_key in required_reviewed_value_keys(vector_id) {
            if !aggregated_reviewed_values.contains_key(*required_key) {
                return Err(ValidationError(format!(
                    "vector {} is missing required reviewed value {}",
                    vector_id, required_key
                )));
            }
        }

        verify_reviewed_value_references(
            &manifest,
            &artifact_root,
            vector_id,
            &aggregated_reviewed_values,
        )?;
        verify_reviewed_identity_values(
            &manifest,
            &artifact_root,
            vector_id,
            &aggregated_reviewed_values,
        )?;
        verify_semantic_constraints(vector_id, &aggregated_reviewed_values)?;

        if replay_mode != ReplayProbeMode::Off {
            let replay_record = collect_replay_probe_for_vector(
                &manifest,
                &artifact_root,
                vector_id,
                &aggregated_reviewed_values,
                &artifact_bytes,
            );
            match replay_mode {
                ReplayProbeMode::Off => {}
                ReplayProbeMode::FailFast => match replay_record.status {
                    ReplayProbeStatus::Verified => notes.extend(replay_record.notes.clone()),
                    ReplayProbeStatus::Failed => {
                        return Err(ValidationError(replay_record.error.unwrap_or_else(|| {
                            format!("replay probe failed for {}", replay_record.vector_id)
                        })));
                    }
                    ReplayProbeStatus::NotAttempted => {}
                },
                ReplayProbeMode::Collect => {
                    if replay_record.status == ReplayProbeStatus::Verified {
                        notes.extend(replay_record.notes.clone());
                    }
                }
            }
            replay_records.push(replay_record);
        }

        comparison_boundary_used.sort();
        comparison_boundary_used.dedup();
        fixture_refs.sort();
        fixture_refs.dedup();

        let artifact_ref = format!(
            "{}.vector.{vector_id}.wire",
            manifest.artifact_set_id.replace("artifact-set", "artifact")
        );

        records.push(ValidationRecord {
            vector_id: vector_id.clone(),
            case_id: manifest.case_id.clone(),
            classification,
            artifact_ref,
            binding_refs,
            fixture_refs,
            result: "pass",
            comparison_boundary_used,
            notes,
        });
    }

    let mut identity_fixture_reviews = 0usize;
    for fixture_id in &manifest.applicable_fixture_refs {
        let fixture_path = resolve_fixture_path(&artifact_root.join("fixtures"), fixture_id)?;
        ensure_file(&fixture_path)?;

        if fixture_id.starts_with("fixture.identity.") {
            let review_path = review_root
                .join("fixture-reviews")
                .join(identity_review_filename(fixture_id)?);
            let review = parse_review(&read_file(&review_path)?)?;
            ensure_review_pass(&review_path, &review)?;

            if let Some(reviewed_fixture_id) = review.fixture_id.as_deref() {
                if reviewed_fixture_id != fixture_id {
                    return Err(ValidationError(format!(
                        "fixture review id mismatch in {}: expected {}, got {}",
                        review_path.display(),
                        fixture_id,
                        reviewed_fixture_id
                    )));
                }
            }

            identity_fixture_reviews += 1;
        }
    }

    Ok((
        ValidationSummary {
            case_id: manifest.case_id,
            vectors: manifest.applicable_vector_refs.len(),
            fixtures: manifest.applicable_fixture_refs.len(),
            bindings: manifest.binding_artifact_refs.len(),
            identity_fixture_reviews,
        },
        records,
        replay_records,
    ))
}

fn validate_case_output_record(
    manifest: &ManifestData,
    case_output: &CaseOutputData,
    replay_records: &[ReplayProbeRecord],
) -> Result<CaseOutputValidationRecord, ValidationError> {
    if case_output.case_id != manifest.case_id {
        return Err(ValidationError(format!(
            "case output {} case_id mismatch: expected {}, got {}",
            case_output.case_output_id, manifest.case_id, case_output.case_id
        )));
    }
    if case_output.case_profile != manifest.case_profile {
        return Err(ValidationError(format!(
            "case output {} case_profile mismatch: expected {}, got {}",
            case_output.case_output_id, manifest.case_profile, case_output.case_profile
        )));
    }

    let mut manifest_vectors = manifest.applicable_vector_refs.clone();
    let mut output_vectors = case_output.supported_vector_ids.clone();
    manifest_vectors.sort();
    output_vectors.sort();
    if manifest_vectors != output_vectors {
        return Err(ValidationError(format!(
            "case output {} supported_vector_ids do not match manifest {} applicable vectors",
            case_output.case_output_id, manifest.case_id
        )));
    }

    let replay_statuses = replay_records
        .iter()
        .map(|record| (record.vector_id.as_str(), &record.status))
        .collect::<BTreeMap<_, _>>();
    let actual = derive_actual_case_outcome_record(manifest, case_output, &replay_statuses)?;

    let mut matched_positive_outcomes = Vec::new();
    let mut matched_negative_outcomes = Vec::new();
    let mut matched_relationship_state_summary = Vec::new();
    let mut matched_message_flow_summary = Vec::new();
    let mut matched_family_summary = Vec::new();
    let mut matched_mechanism_summary = Vec::new();
    let mut missing_checks = Vec::new();

    for outcome in &case_output.positive_outcomes {
        if actual
            .positive_outcomes
            .iter()
            .any(|candidate| candidate == outcome)
        {
            matched_positive_outcomes.push(outcome.clone());
        } else {
            missing_checks.push(outcome.clone());
        }
    }

    for outcome in &case_output.negative_outcomes {
        if actual
            .negative_outcomes
            .iter()
            .any(|candidate| candidate == outcome)
        {
            matched_negative_outcomes.push(outcome.clone());
        } else {
            missing_checks.push(format!(
                "negative outcome not satisfied by replay-derived actual output: {}",
                outcome
            ));
        }
        if !actual
            .represented_negative_outcomes
            .iter()
            .any(|candidate| candidate == outcome)
        {
            missing_checks.push(outcome.clone());
        }
    }

    for summary in &case_output.relationship_state_summary {
        if actual
            .relationship_state_summary
            .iter()
            .any(|candidate| candidate == summary)
        {
            matched_relationship_state_summary.push(summary.clone());
        } else {
            missing_checks.push(format!(
                "relationship summary not satisfied by replay-derived actual output: {}",
                summary
            ));
        }
    }

    for summary in &case_output.message_flow_summary {
        if actual
            .message_flow_summary
            .iter()
            .any(|candidate| candidate == summary)
        {
            matched_message_flow_summary.push(summary.clone());
        } else {
            missing_checks.push(format!(
                "message-flow summary not satisfied by replay-derived actual output: {}",
                summary
            ));
        }
    }

    for summary in &case_output.family_summary {
        if actual
            .family_summary
            .iter()
            .any(|candidate| candidate == summary)
        {
            matched_family_summary.push(summary.clone());
        } else {
            missing_checks.push(format!(
                "family summary not satisfied by manifest-derived actual output: {}",
                summary
            ));
        }
    }

    for summary in &case_output.mechanism_summary {
        if actual
            .mechanism_summary
            .iter()
            .any(|candidate| candidate == summary)
        {
            matched_mechanism_summary.push(summary.clone());
        } else {
            missing_checks.push(format!(
                "mechanism summary not satisfied by manifest-derived actual output: {}",
                summary
            ));
        }
    }

    Ok(CaseOutputValidationRecord {
        case_id: manifest.case_id.clone(),
        case_output_id: case_output.case_output_id.clone(),
        status: if missing_checks.is_empty() {
            "pass"
        } else {
            "incomplete"
        },
        expected_positive_outcomes: case_output.positive_outcomes.clone(),
        actual_positive_outcomes: actual.positive_outcomes,
        matched_positive_outcomes,
        expected_negative_outcomes: case_output.negative_outcomes.clone(),
        actual_negative_outcomes: actual.negative_outcomes,
        matched_negative_outcomes,
        represented_negative_outcomes: actual.represented_negative_outcomes,
        expected_relationship_state_summary: case_output.relationship_state_summary.clone(),
        actual_relationship_state_summary: actual.relationship_state_summary,
        matched_relationship_state_summary,
        expected_message_flow_summary: case_output.message_flow_summary.clone(),
        actual_message_flow_summary: actual.message_flow_summary,
        matched_message_flow_summary,
        expected_family_summary: case_output.family_summary.clone(),
        actual_family_summary: actual.family_summary,
        matched_family_summary,
        expected_mechanism_summary: case_output.mechanism_summary.clone(),
        actual_mechanism_summary: actual.mechanism_summary,
        matched_mechanism_summary,
        missing_checks,
    })
}

fn derive_actual_case_outcome_record(
    manifest: &ManifestData,
    case_output: &CaseOutputData,
    replay_statuses: &BTreeMap<&str, &ReplayProbeStatus>,
) -> Result<ActualCaseOutcomeRecord, ValidationError> {
    let mut positive_outcomes = Vec::new();
    let mut negative_outcomes = Vec::new();
    let mut represented_negative_outcomes = Vec::new();
    let mut relationship_state_summary = Vec::new();
    let mut message_flow_summary = Vec::new();
    let mut family_summary = Vec::new();
    let mut mechanism_summary = Vec::new();

    for outcome in &case_output.positive_outcomes {
        match positive_outcome_satisfied(outcome, replay_statuses) {
            Ok(true) => positive_outcomes.push(outcome.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported positive outcome {} in {}: {}",
                    outcome, case_output.case_output_id, err
                )));
            }
        }
    }

    for outcome in &case_output.negative_outcomes {
        match negative_outcome_satisfied_by_replay(outcome, replay_statuses) {
            Ok(true) => negative_outcomes.push(outcome.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported replay-derived negative outcome {} in {}: {}",
                    outcome, case_output.case_output_id, err
                )));
            }
        }
        match negative_outcome_represented(outcome, manifest) {
            Ok(true) => represented_negative_outcomes.push(outcome.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported negative outcome {} in {}: {}",
                    outcome, case_output.case_output_id, err
                )));
            }
        }
    }

    for summary in &case_output.relationship_state_summary {
        match relationship_state_summary_satisfied(summary, replay_statuses) {
            Ok(true) => relationship_state_summary.push(summary.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported relationship summary {} in {}: {}",
                    summary, case_output.case_output_id, err
                )));
            }
        }
    }

    for summary in &case_output.message_flow_summary {
        match message_flow_summary_satisfied(summary, replay_statuses) {
            Ok(true) => message_flow_summary.push(summary.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported message-flow summary {} in {}: {}",
                    summary, case_output.case_output_id, err
                )));
            }
        }
    }

    for summary in &case_output.family_summary {
        match family_summary_satisfied(summary, manifest) {
            Ok(true) => family_summary.push(summary.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported family summary {} in {}: {}",
                    summary, case_output.case_output_id, err
                )));
            }
        }
    }

    for summary in &case_output.mechanism_summary {
        match mechanism_summary_satisfied(summary, manifest) {
            Ok(true) => mechanism_summary.push(summary.clone()),
            Ok(false) => {}
            Err(err) => {
                return Err(ValidationError(format!(
                    "unsupported mechanism summary {} in {}: {}",
                    summary, case_output.case_output_id, err
                )));
            }
        }
    }

    Ok(ActualCaseOutcomeRecord {
        case_id: manifest.case_id.clone(),
        positive_outcomes,
        negative_outcomes,
        represented_negative_outcomes,
        relationship_state_summary,
        message_flow_summary,
        family_summary,
        mechanism_summary,
    })
}

fn positive_outcome_satisfied(
    outcome: &str,
    replay_statuses: &BTreeMap<&str, &ReplayProbeStatus>,
) -> Result<bool, &'static str> {
    match outcome {
        "direct relationship forming succeeds"
        | "HPKE-family direct relationship establishment is demonstrated"
        | "direct relationship establishment is demonstrated under Sealed Box" => {
            Ok(is_verified(replay_statuses, "BV-001"))
        }
        "nested relationship forming succeeds"
        | "HPKE-family nested relationship establishment is demonstrated"
        | "nested relationship establishment is demonstrated under Sealed Box" => {
            Ok(is_verified(replay_statuses, "BV-004") && is_verified(replay_statuses, "BV-005"))
        }
        "routed control path succeeds"
        | "HPKE-family routed control delivery is demonstrated"
        | "routed control delivery is demonstrated under Sealed Box" => {
            Ok(is_verified(replay_statuses, "BV-006")
                && is_verified(replay_statuses, "BV-007")
                && is_verified(replay_statuses, "BV-008"))
        }
        "direct message replay succeeds"
        | "HPKE-family direct message replay succeeds"
        | "direct message replay succeeds under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-001"))
        }
        "nested message replay succeeds"
        | "HPKE-family nested message replay succeeds"
        | "nested message replay succeeds under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-002"))
        }
        "routed message replay succeeds"
        | "HPKE-family routed message replay succeeds"
        | "routed message replay succeeds under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-003"))
        }
        _ => Err("outcome is not mapped to a validator check"),
    }
}

fn negative_outcome_represented(
    outcome: &str,
    manifest: &ManifestData,
) -> Result<bool, &'static str> {
    match outcome {
        "no-prior-relationship traffic is represented as invalid"
        | "HPKE-family no-prior-relationship traffic is represented as invalid"
        | "no-prior-relationship traffic is represented as invalid under Sealed Box" => {
            Ok(manifest
                .applicable_vector_refs
                .iter()
                .any(|id| id == "SV-004"))
        }
        "nested-without-outer traffic is represented as invalid"
        | "HPKE-family nested-without-outer traffic is represented as invalid"
        | "nested-without-outer traffic is represented as invalid under Sealed Box" => Ok(manifest
            .applicable_vector_refs
            .iter()
            .any(|id| id == "SV-006")),
        _ => Err("outcome is not mapped to a validator check"),
    }
}

fn negative_outcome_satisfied_by_replay(
    outcome: &str,
    replay_statuses: &BTreeMap<&str, &ReplayProbeStatus>,
) -> Result<bool, &'static str> {
    match outcome {
        "no-prior-relationship traffic is represented as invalid"
        | "HPKE-family no-prior-relationship traffic is represented as invalid"
        | "no-prior-relationship traffic is represented as invalid under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-004"))
        }
        "nested-without-outer traffic is represented as invalid"
        | "HPKE-family nested-without-outer traffic is represented as invalid"
        | "nested-without-outer traffic is represented as invalid under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-006"))
        }
        _ => Err("outcome is not mapped to a replay-derived negative check"),
    }
}

fn relationship_state_summary_satisfied(
    summary: &str,
    replay_statuses: &BTreeMap<&str, &ReplayProbeStatus>,
) -> Result<bool, &'static str> {
    match summary {
        "HPKE-family direct relationship reaches bidirectional state"
        | "direct relationship reaches bidirectional state under Sealed Box" => {
            Ok(is_verified(replay_statuses, "BV-001") && is_verified(replay_statuses, "BV-002"))
        }
        "HPKE-family nested relationship is coupled to an outer relationship"
        | "nested relationship is coupled to an outer relationship under Sealed Box" => {
            Ok(is_verified(replay_statuses, "BV-004") && is_verified(replay_statuses, "BV-005"))
        }
        _ => Err("summary is not mapped to a relationship-state validator check"),
    }
}

fn message_flow_summary_satisfied(
    summary: &str,
    replay_statuses: &BTreeMap<&str, &ReplayProbeStatus>,
) -> Result<bool, &'static str> {
    match summary {
        "HPKE-family direct message semantics are available after direct relationship forming"
        | "direct message semantics are available after direct relationship forming under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-001"))
        }
        "HPKE-family nested message semantics are available after nested relationship forming"
        | "nested message semantics are available after nested relationship forming under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-002"))
        }
        "HPKE-family routed message semantics are available after routed path and final delivery"
        | "routed message semantics are available after routed path and final delivery under Sealed Box" => {
            Ok(is_verified(replay_statuses, "SV-003"))
        }
        _ => Err("summary is not mapped to a message-flow validator check"),
    }
}

fn family_summary_satisfied(summary: &str, manifest: &ManifestData) -> Result<bool, &'static str> {
    match summary {
        "HPKE-family case-level output" => Ok(matches!(
            manifest.case_profile.as_str(),
            "tsp-hpke-auth-complete-case-01" | "tsp-hpke-base-complete-case-01"
        )),
        "case output belongs to the Sealed Box case-level vocabulary" => {
            Ok(manifest.case_profile == "tsp-sealed-box-complete-case-01")
        }
        _ => Err("summary is not mapped to a family validator check"),
    }
}

fn mechanism_summary_satisfied(
    summary: &str,
    manifest: &ManifestData,
) -> Result<bool, &'static str> {
    match summary {
        "confidentiality mechanism: HPKE-Auth" => {
            Ok(manifest.case_profile == "tsp-hpke-auth-complete-case-01")
        }
        "confidentiality mechanism: HPKE-Base" => {
            Ok(manifest.case_profile == "tsp-hpke-base-complete-case-01")
        }
        "confidentiality mechanism: Sealed Box" => {
            Ok(manifest.case_profile == "tsp-sealed-box-complete-case-01")
        }
        _ => Err("summary is not mapped to a mechanism validator check"),
    }
}

fn is_verified(replay_statuses: &BTreeMap<&str, &ReplayProbeStatus>, vector_id: &str) -> bool {
    replay_statuses
        .get(vector_id)
        .is_some_and(|status| **status == ReplayProbeStatus::Verified)
}

fn infer_review_root(artifact_root: &Path) -> PathBuf {
    let artifact_name = artifact_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let review_name = artifact_name.replacen("artifact-set", "review-set", 1);
    artifact_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(review_name)
}

fn binding_path_for(artifact_root: &Path, binding_suffix: &str) -> PathBuf {
    let mut parts = binding_suffix.split('.');
    let scope = parts.next().unwrap_or_default();
    let scenario = parts.collect::<Vec<_>>().join(".");
    artifact_root
        .join("bindings")
        .join(scope)
        .join(format!("{scenario}.yaml"))
}

fn resolve_fixture_path(
    fixtures_root: &Path,
    fixture_id: &str,
) -> Result<PathBuf, ValidationError> {
    for extension in ["json", "yaml", "yml", "base64", "txt"] {
        let candidate = fixtures_root.join(format!("{fixture_id}.{extension}"));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(ValidationError(format!(
        "fixture artifact not found for {} under {}",
        fixture_id,
        fixtures_root.display()
    )))
}

fn identity_review_filename(fixture_id: &str) -> Result<String, ValidationError> {
    let suffix = fixture_id
        .strip_prefix("fixture.identity.")
        .ok_or_else(|| ValidationError(format!("not an identity fixture id: {fixture_id}")))?;
    let mut parts = suffix.split('.');
    let scope = parts
        .next()
        .ok_or_else(|| ValidationError(format!("malformed identity fixture id: {fixture_id}")))?;
    let alias = parts.collect::<Vec<_>>().join(".");
    if alias.is_empty() {
        return Err(ValidationError(format!(
            "malformed identity fixture id: {fixture_id}"
        )));
    }
    Ok(format!("{scope}.identity.{alias}.yaml"))
}

fn ensure_file(path: &Path) -> Result<(), ValidationError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(ValidationError(format!(
            "required file not found: {}",
            path.display()
        )))
    }
}

fn ensure_review_pass(path: &Path, review: &ReviewData) -> Result<(), ValidationError> {
    match review.review_status.as_deref() {
        Some("pass") => Ok(()),
        Some(other) => Err(ValidationError(format!(
            "review status is not pass in {}: {}",
            path.display(),
            other
        ))),
        None => Err(ValidationError(format!(
            "review status missing in {}",
            path.display()
        ))),
    }
}

fn read_file(path: &Path) -> Result<String, ValidationError> {
    fs::read_to_string(path)
        .map_err(|err| ValidationError(format!("failed to read {}: {}", path.display(), err)))
}

fn normalize_jsonish_scalar(value: &str) -> String {
    value.replace("\\\"", "\"")
}

fn load_wire_artifact(path: &Path) -> Result<Vec<u8>, ValidationError> {
    let text = read_file(path)?;
    let normalized = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<String>();

    if normalized.is_empty() {
        return Err(ValidationError(format!(
            "wire artifact is empty: {}",
            path.display()
        )));
    }

    Ok(normalized.into_bytes())
}

fn parse_manifest(input: &str) -> Result<ManifestData, ValidationError> {
    let data = parse_yaml_top_level(input);
    Ok(ManifestData {
        case_id: required_scalar(&data, "case_id")?,
        case_profile: required_scalar(&data, "case_profile")?,
        artifact_set_id: required_scalar(&data, "artifact_set_id")?,
        case_output_ref: required_scalar(&data, "case_output_ref")?,
        applicable_vector_refs: list_values(&data, "applicable_vector_refs"),
        applicable_fixture_refs: list_values(&data, "applicable_fixture_refs"),
        binding_artifact_refs: list_values(&data, "binding_artifact_refs"),
    })
}

fn parse_case_output_catalog(
    source_path: &Path,
    input: &str,
) -> Result<BTreeMap<String, CaseOutputData>, ValidationError> {
    let mut map = BTreeMap::new();
    let mut in_yaml = false;
    let mut current = Vec::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed == "```yaml" {
            in_yaml = true;
            current.clear();
            continue;
        }
        if trimmed == "```" && in_yaml {
            let data = parse_yaml_top_level(&current.join("\n"));
            let record = CaseOutputData {
                case_output_id: required_scalar(&data, "case_output_id")?,
                case_id: required_scalar(&data, "case_id")?,
                case_profile: required_scalar(&data, "case_profile")?,
                supported_vector_ids: list_values(&data, "supported_vector_ids"),
                positive_outcomes: list_values(&data, "positive_outcomes"),
                negative_outcomes: list_values(&data, "negative_outcomes"),
                relationship_state_summary: list_values(&data, "relationship_state_summary"),
                message_flow_summary: list_values(&data, "message_flow_summary"),
                family_summary: list_values(&data, "family_summary"),
                mechanism_summary: list_values(&data, "mechanism_summary"),
            };
            map.insert(record.case_output_id.clone(), record);
            in_yaml = false;
            current.clear();
            continue;
        }
        if in_yaml {
            current.push(line);
        }
    }

    if map.is_empty() {
        return Err(ValidationError(format!(
            "failed to parse case outputs from {}",
            source_path.display()
        )));
    }

    Ok(map)
}

fn parse_review(input: &str) -> Result<ReviewData, ValidationError> {
    let data = parse_yaml_top_level(input);
    Ok(ReviewData {
        review_status: scalar_value(&data, "review_status"),
        artifact_ref: scalar_value(&data, "artifact_ref"),
        binding_id: scalar_value(&data, "binding_id"),
        fixture_id: scalar_value(&data, "fixture_id"),
        reviewed_bindings: list_values(&data, "reviewed_bindings"),
        reviewed_for_vectors: list_values(&data, "reviewed_for_vectors"),
        value_checks: map_values(&data, "value_checks"),
    })
}

#[derive(Debug, Clone)]
enum TopLevelValue {
    Scalar(String),
    List(Vec<String>),
    Map(BTreeMap<String, String>),
}

fn parse_yaml_top_level(input: &str) -> BTreeMap<String, TopLevelValue> {
    let mut values = BTreeMap::new();
    let lines: Vec<&str> = input.lines().collect();
    let mut index = 0usize;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            index += 1;
            continue;
        }

        let Some((key, rest)) = trimmed.split_once(':') else {
            index += 1;
            continue;
        };

        let remainder = rest.trim();
        if !remainder.is_empty() {
            values.insert(
                key.to_string(),
                TopLevelValue::Scalar(unquote(remainder).to_string()),
            );
            index += 1;
            continue;
        }

        let mut list = Vec::new();
        let mut map = BTreeMap::new();
        let mut lookahead = index + 1;
        while lookahead < lines.len() {
            let next_line = lines[lookahead];
            if next_line.trim().is_empty() {
                lookahead += 1;
                continue;
            }
            if !next_line.starts_with(' ') && !next_line.starts_with('\t') {
                break;
            }

            let next_trimmed = next_line.trim();
            if let Some(item) = next_trimmed.strip_prefix("- ") {
                list.push(unquote(item.trim()).to_string());
            } else if let Some((nested_key, nested_rest)) = next_trimmed.split_once(':') {
                let nested_value = nested_rest.trim();
                if !nested_value.is_empty() {
                    map.insert(nested_key.to_string(), unquote(nested_value).to_string());
                }
            }
            lookahead += 1;
        }

        if !list.is_empty() {
            values.insert(key.to_string(), TopLevelValue::List(list));
        } else if !map.is_empty() {
            values.insert(key.to_string(), TopLevelValue::Map(map));
        }

        index = lookahead;
    }

    values
}

fn scalar_value(values: &BTreeMap<String, TopLevelValue>, key: &str) -> Option<String> {
    match values.get(key) {
        Some(TopLevelValue::Scalar(value)) => Some(value.clone()),
        _ => None,
    }
}

fn required_scalar(
    values: &BTreeMap<String, TopLevelValue>,
    key: &str,
) -> Result<String, ValidationError> {
    scalar_value(values, key).ok_or_else(|| ValidationError(format!("missing scalar field: {key}")))
}

fn list_values(values: &BTreeMap<String, TopLevelValue>, key: &str) -> Vec<String> {
    match values.get(key) {
        Some(TopLevelValue::List(items)) => items.clone(),
        _ => Vec::new(),
    }
}

fn map_values(values: &BTreeMap<String, TopLevelValue>, key: &str) -> BTreeMap<String, String> {
    match values.get(key) {
        Some(TopLevelValue::Map(items)) => items.clone(),
        _ => BTreeMap::new(),
    }
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn parse_vector_catalog(
    source_path: &Path,
    input: &str,
) -> Result<BTreeMap<String, String>, ValidationError> {
    let mut map = BTreeMap::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| `") || trimmed.contains("Vector |") {
            continue;
        }

        let parts = trimmed
            .split('|')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();

        if parts.len() < 3 {
            continue;
        }

        let vector_id = parts[0].trim_matches('`');
        let classification = parts[1].trim_matches('`');
        if !vector_id.is_empty() && !classification.is_empty() {
            map.insert(vector_id.to_string(), classification.to_string());
        }
    }

    if map.is_empty() {
        return Err(ValidationError(format!(
            "failed to parse vector catalog from {}",
            source_path.display()
        )));
    }

    Ok(map)
}

fn load_binding(
    manifest: &ManifestData,
    artifact_root: &Path,
    review_root: &Path,
    binding_ref: &str,
) -> Result<BindingData, ValidationError> {
    let namespace = format!(
        "{}.binding.",
        manifest.artifact_set_id.replace("artifact-set", "artifact")
    );
    let binding_suffix = binding_ref.strip_prefix(&namespace).ok_or_else(|| {
        ValidationError(format!(
            "binding ref does not match manifest namespace: {}",
            binding_ref
        ))
    })?;

    let binding_path = binding_path_for(artifact_root, binding_suffix);
    ensure_file(&binding_path)?;
    let binding_values = parse_yaml_top_level(&read_file(&binding_path)?);

    let review_path = review_root
        .join("binding-reviews")
        .join(format!("{binding_suffix}.yaml"));
    let review = parse_review(&read_file(&review_path)?)?;
    ensure_review_pass(&review_path, &review)?;
    if let Some(binding_id) = review.binding_id.as_deref() {
        if binding_id != binding_ref {
            return Err(ValidationError(format!(
                "binding review id mismatch in {}: expected {}, got {}",
                review_path.display(),
                binding_ref,
                binding_id
            )));
        }
    }

    Ok(BindingData {
        related_vectors: list_values(&binding_values, "related_vectors"),
        related_fixture_refs: list_values(&binding_values, "related_fixture_refs"),
        reviewed_values: map_values(&binding_values, "reviewed_values"),
        comparison_boundary: list_values(&binding_values, "comparison_boundary"),
        review_value_checks: review.value_checks,
        reviewed_for_vectors: review.reviewed_for_vectors,
    })
}

fn load_binding_relaxed(
    manifest: &ManifestData,
    artifact_root: &Path,
    binding_ref: &str,
) -> Result<BindingData, ValidationError> {
    let namespace = format!(
        "{}.binding.",
        manifest.artifact_set_id.replace("artifact-set", "artifact")
    );
    let binding_suffix = binding_ref.strip_prefix(&namespace).ok_or_else(|| {
        ValidationError(format!(
            "binding ref does not match manifest namespace: {}",
            binding_ref
        ))
    })?;

    let binding_path = binding_path_for(artifact_root, binding_suffix);
    ensure_file(&binding_path)?;
    let binding_values = parse_yaml_top_level(&read_file(&binding_path)?);

    Ok(BindingData {
        related_vectors: list_values(&binding_values, "related_vectors"),
        related_fixture_refs: list_values(&binding_values, "related_fixture_refs"),
        reviewed_values: map_values(&binding_values, "reviewed_values"),
        comparison_boundary: list_values(&binding_values, "comparison_boundary"),
        review_value_checks: BTreeMap::new(),
        reviewed_for_vectors: Vec::new(),
    })
}

fn load_fixture(path: &Path) -> Result<FixtureData, ValidationError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml" | "yml") => {
            let values = parse_yaml_top_level(&read_file(path)?);
            Ok(FixtureData {
                id: required_scalar(&values, "id")?,
                used_by_vectors: list_values(&values, "used_by_vectors"),
                binding_material: map_values(&values, "binding_material"),
            })
        }
        Some("json") => {
            let raw = read_file(path)?;
            let value: Value = serde_json::from_str(&raw).map_err(|err| {
                ValidationError(format!(
                    "failed to parse fixture json {}: {}",
                    path.display(),
                    err
                ))
            })?;
            let id = value
                .get("id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    ValidationError(format!("fixture json missing id: {}", path.display()))
                })?;
            if id.starts_with("fixture.identity.") {
                validate_public_identity_fixture_json(path, &value)?;
            }
            Ok(FixtureData {
                id: id.to_string(),
                used_by_vectors: Vec::new(),
                binding_material: BTreeMap::new(),
            })
        }
        _ => Err(ValidationError(format!(
            "unsupported fixture format: {}",
            path.display()
        ))),
    }
}

fn validate_public_identity_fixture_json(
    path: &Path,
    value: &Value,
) -> Result<(), ValidationError> {
    require_json_string(value, path, &["identifier"])?;
    require_json_string(value, path, &["public_material", "verification_key", "x"])?;
    require_json_string(value, path, &["public_material", "encryption_key", "x"])?;

    if let Some(private_ref) = value.get("private_material_ref").and_then(Value::as_str) {
        let private_path = resolve_fixture_reference_path(path, private_ref).ok_or_else(|| {
            ValidationError(format!(
                "fixture private_material_ref target not found from {}: {}",
                path.display(),
                private_ref
            ))
        })?;
        validate_private_identity_fixture_json(&private_path)?;
    }

    Ok(())
}

fn validate_private_identity_fixture_json(path: &Path) -> Result<(), ValidationError> {
    let raw = read_file(path)?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| {
        ValidationError(format!(
            "failed to parse private fixture json {}: {}",
            path.display(),
            err
        ))
    })?;

    for field_path in [
        ["id"].as_slice(),
        ["transport"].as_slice(),
        ["sigKeyType"].as_slice(),
        ["publicSigkey"].as_slice(),
        ["encKeyType"].as_slice(),
        ["publicEnckey"].as_slice(),
        ["sigkey"].as_slice(),
        ["enckey"].as_slice(),
    ] {
        require_json_string(&value, path, field_path)?;
    }

    Ok(())
}

fn require_json_string(
    value: &Value,
    path: &Path,
    field_path: &[&str],
) -> Result<String, ValidationError> {
    let mut current = value;
    for segment in field_path {
        current = current.get(*segment).ok_or_else(|| {
            ValidationError(format!(
                "fixture json missing {} in {}",
                field_path.join("."),
                path.display()
            ))
        })?;
    }

    current.as_str().map(str::to_string).ok_or_else(|| {
        ValidationError(format!(
            "fixture json field {} is not a string in {}",
            field_path.join("."),
            path.display()
        ))
    })
}

fn resolve_fixture_reference_path(base_fixture_path: &Path, reference: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join(reference));
        for ancestor in cwd.ancestors().skip(1) {
            candidates.push(ancestor.join(reference));
        }
    }

    if let Some(fixtures_dir) = base_fixture_path.parent() {
        candidates.push(fixtures_dir.join(reference));
        if let Some(artifact_root) = fixtures_dir.parent() {
            candidates.push(artifact_root.join(reference));
            if let Some(package_root) = artifact_root.parent() {
                candidates.push(package_root.join(reference));
            }
        }
    }

    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[derive(Debug)]
struct PublicIdentityFixtureInfo {
    fixture_id: String,
    private_material_ref: Option<String>,
    path: PathBuf,
}

#[derive(Clone)]
struct LocalVerifiedVid {
    identifier: String,
    endpoint: url::Url,
    verifying_key: PublicVerificationKeyData,
    encryption_key: PublicKeyData,
}

impl VerifiedVid for LocalVerifiedVid {
    fn identifier(&self) -> &str {
        &self.identifier
    }

    fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }

    fn verifying_key(&self) -> &PublicVerificationKeyData {
        &self.verifying_key
    }

    fn encryption_key(&self) -> &PublicKeyData {
        &self.encryption_key
    }

    fn encryption_key_type(&self) -> VidEncryptionKeyType {
        VidEncryptionKeyType::X25519
    }

    fn signature_key_type(&self) -> VidSignatureKeyType {
        VidSignatureKeyType::Ed25519
    }
}

fn attempt_sdk_replay_for_vector(
    manifest: &ManifestData,
    artifact_root: &Path,
    vector_id: &str,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    match vector_id {
        "BV-001" => replay_direct_request(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-002" => replay_direct_accept(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-003" => replay_direct_rfd(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-006" => replay_routed_path(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-007" => replay_routed_request(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-008" => replay_routed_accept(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-004" => replay_nested_request(manifest, artifact_root, reviewed_values, artifact_bytes),
        "BV-005" => replay_nested_accept(manifest, artifact_root, reviewed_values, artifact_bytes),
        "SV-001" => replay_direct_message(manifest, artifact_root, reviewed_values, artifact_bytes),
        "SV-002" => replay_nested_message(manifest, artifact_root, reviewed_values, artifact_bytes),
        "SV-003" => replay_routed_message(manifest, artifact_root, reviewed_values, artifact_bytes),
        "SV-005" => {
            replay_digest_mismatch(manifest, artifact_root, reviewed_values, artifact_bytes)
        }
        "SV-004" => {
            replay_no_prior_relationship(manifest, artifact_root, reviewed_values, artifact_bytes)
        }
        "SV-006" => {
            replay_nested_without_outer(manifest, artifact_root, reviewed_values, artifact_bytes)
        }
        _ => Ok(Vec::new()),
    }
}

fn collect_replay_probe_for_vector(
    manifest: &ManifestData,
    artifact_root: &Path,
    vector_id: &str,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> ReplayProbeRecord {
    match vector_id {
        "BV-001" | "BV-002" | "BV-003" | "BV-004" | "BV-005" | "BV-006" | "BV-007" | "BV-008"
        | "SV-001" | "SV-002" | "SV-003" | "SV-004" | "SV-005" | "SV-006" => {
            match attempt_sdk_replay_for_vector(
                manifest,
                artifact_root,
                vector_id,
                reviewed_values,
                artifact_bytes,
            ) {
                Ok(notes) => ReplayProbeRecord {
                    case_id: manifest.case_id.clone(),
                    vector_id: vector_id.to_string(),
                    status: ReplayProbeStatus::Verified,
                    notes,
                    error: None,
                },
                Err(err) => ReplayProbeRecord {
                    case_id: manifest.case_id.clone(),
                    vector_id: vector_id.to_string(),
                    status: ReplayProbeStatus::Failed,
                    notes: Vec::new(),
                    error: Some(err.to_string()),
                },
            }
        }
        _ => ReplayProbeRecord {
            case_id: manifest.case_id.clone(),
            vector_id: vector_id.to_string(),
            status: ReplayProbeStatus::NotAttempted,
            notes: Vec::new(),
            error: None,
        },
    }
}

fn collect_replay_probe_records_for_manifest_relaxed(
    manifest: &ManifestData,
    artifact_root: &Path,
) -> Result<Vec<ReplayProbeRecord>, ValidationError> {
    let mut replay_records = Vec::with_capacity(manifest.applicable_vector_refs.len());

    for vector_id in &manifest.applicable_vector_refs {
        let wire_path = artifact_root
            .join("vectors")
            .join(vector_id)
            .join("wire.base64");
        ensure_file(&wire_path)?;
        let artifact_bytes = load_wire_artifact(&wire_path)?;

        let binding_refs = find_binding_refs_for_vector(manifest, artifact_root, vector_id)?;
        if binding_refs.is_empty() {
            replay_records.push(ReplayProbeRecord {
                case_id: manifest.case_id.clone(),
                vector_id: vector_id.clone(),
                status: ReplayProbeStatus::NotAttempted,
                notes: Vec::new(),
                error: Some(format!("no binding refs found for {}", vector_id)),
            });
            continue;
        }

        let mut aggregated_reviewed_values = BTreeMap::new();
        for binding_ref in &binding_refs {
            let binding = load_binding_relaxed(manifest, artifact_root, binding_ref)?;
            aggregated_reviewed_values.extend(binding.reviewed_values);
        }

        replay_records.push(collect_replay_probe_for_vector(
            manifest,
            artifact_root,
            vector_id,
            &aggregated_reviewed_values,
            &artifact_bytes,
        ));
    }

    Ok(replay_records)
}

fn replay_direct_request(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = reviewed_values.get("sender_vid").ok_or_else(|| {
        ValidationError("BV-001 replay is missing sender_vid in reviewed values".into())
    })?;
    let receiver_identifier = reviewed_values.get("receiver_vid").ok_or_else(|| {
        ValidationError("BV-001 replay is missing receiver_vid in reviewed values".into())
    })?;
    let request_digest = reviewed_values.get("request_digest").ok_or_else(|| {
        ValidationError("BV-001 replay is missing request_digest in reviewed values".into())
    })?;

    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, receiver_identifier)?;

    let sender_private_ref = sender_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "sender fixture {} is missing private_material_ref",
                sender_fixture.fixture_id
            ))
        })?;
    let receiver_private_ref = receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "receiver fixture {} is missing private_material_ref",
                receiver_fixture.fixture_id
            ))
        })?;

    let sender_owned = load_owned_vid_from_ref(&sender_fixture.path, sender_private_ref)?;
    let receiver_owned = load_owned_vid_from_ref(&receiver_fixture.path, receiver_private_ref)?;

    let store = SecureStore::new();
    store
        .add_private_vid(receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("BV-001 replay failed to add receiver vid: {err}"))
        })?;
    store
        .add_verified_vid(sender_owned, None::<Value>)
        .map_err(|err| ValidationError(format!("BV-001 replay failed to add sender vid: {err}")))?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("BV-001 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::RequestRelationship {
        sender,
        receiver,
        thread_id,
        ..
    } = opened
    else {
        return Err(ValidationError(
            "BV-001 replay did not decode as RequestRelationship".into(),
        ));
    };

    let replay_digest = hex_lower(&thread_id);
    if sender != *sender_identifier {
        return Err(ValidationError(format!(
            "BV-001 replay sender mismatch: expected {}, got {}",
            sender_identifier, sender
        )));
    }
    if receiver != *receiver_identifier {
        return Err(ValidationError(format!(
            "BV-001 replay receiver mismatch: expected {}, got {}",
            receiver_identifier, receiver
        )));
    }
    if replay_digest != *request_digest {
        return Err(ValidationError(format!(
            "BV-001 replay thread_id mismatch: expected {}, got {}",
            request_digest, replay_digest
        )));
    }

    Ok(vec![format!(
        "sdk replay verified direct request sender/receiver/thread_id against reviewed binding using {} -> {}",
        sender_fixture.fixture_id, receiver_fixture.fixture_id
    )])
}

fn replay_direct_accept(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let alice_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.alice",
    )?;
    let bob_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.bob",
    )?;
    let alice_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &alice_identifier)?;
    let bob_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &bob_identifier)?;
    let (alice_store, bob_store) =
        prepare_direct_context_without_relationship(&alice_fixture, &bob_fixture)?;

    let request_bytes = load_wire_artifact(&vector_artifact_path(
        artifact_root,
        manifest,
        &format!(
            "{}.vector.BV-001.wire",
            manifest.artifact_set_id.replace("artifact-set", "artifact")
        ),
    )?)?;
    let mut request_message = decode_wire_artifact_payload(&request_bytes)?;
    let request_thread_id = match bob_store
        .open_message(&mut request_message)
        .map_err(|err| {
            ValidationError(format!(
                "BV-002 replay failed while replaying prerequisite BV-001: {err}"
            ))
        })? {
        ReceivedTspMessage::RequestRelationship { thread_id, .. } => thread_id,
        other => {
            return Err(ValidationError(format!(
                "BV-002 replay prerequisite BV-001 decoded as {other:?} instead of RequestRelationship"
            )));
        }
    };

    alice_store
        .set_relation_and_status_for_vid(
            &bob_identifier,
            RelationshipStatus::Unidirectional {
                thread_id: request_thread_id,
            },
            &alice_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "BV-002 replay failed to reconstruct sender-side prerequisite relationship: {err}"
            ))
        })?;

    let expected_sender = reviewed_values.get("sender_vid").ok_or_else(|| {
        ValidationError("BV-002 replay is missing sender_vid in reviewed values".into())
    })?;
    let expected_receiver = reviewed_values.get("receiver_vid").ok_or_else(|| {
        ValidationError("BV-002 replay is missing receiver_vid in reviewed values".into())
    })?;
    let expected_request_digest = reviewed_values.get("request_digest").ok_or_else(|| {
        ValidationError("BV-002 replay is missing request_digest in reviewed values".into())
    })?;
    let expected_reply_digest = reviewed_values.get("reply_digest").ok_or_else(|| {
        ValidationError("BV-002 replay is missing reply_digest in reviewed values".into())
    })?;

    let mut accept_message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = alice_store
        .open_message(&mut accept_message)
        .map_err(|err| ValidationError(format!("BV-002 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::AcceptRelationship {
        sender,
        receiver,
        nested_vid,
    } = opened
    else {
        return Err(ValidationError(
            "BV-002 replay did not decode as AcceptRelationship".into(),
        ));
    };

    if sender != *expected_sender {
        return Err(ValidationError(format!(
            "BV-002 replay sender mismatch: expected {}, got {}",
            expected_sender, sender
        )));
    }
    if receiver != *expected_receiver {
        return Err(ValidationError(format!(
            "BV-002 replay receiver mismatch: expected {}, got {}",
            expected_receiver, receiver
        )));
    }
    if nested_vid.is_some() {
        return Err(ValidationError(format!(
            "BV-002 replay unexpectedly carried nested_vid {:?}",
            nested_vid
        )));
    }
    let status = alice_store
        .relation_status_for_vid_pair(&alice_identifier, &bob_identifier)
        .map_err(|err| {
            ValidationError(format!(
                "BV-002 replay failed to read updated relation status: {err}"
            ))
        })?;
    match status {
        RelationshipStatus::Bidirectional { thread_id, .. } => {
            let actual = hex_lower(&thread_id);
            if actual != *expected_request_digest || actual != *expected_reply_digest {
                return Err(ValidationError(format!(
                    "BV-002 replay bidirectional thread mismatch: expected request/reply digest {} / {}, got {}",
                    expected_request_digest, expected_reply_digest, actual
                )));
            }
        }
        other => {
            return Err(ValidationError(format!(
                "BV-002 replay expected bidirectional relationship after accept, found {other:?}"
            )));
        }
    }

    Ok(vec![format!(
        "sdk replay verified direct accept sender/receiver and upgraded relationship against reviewed binding using {} -> {}",
        bob_fixture.fixture_id, alice_fixture.fixture_id
    )])
}

fn replay_direct_rfd(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let alice_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.alice",
    )?;
    let bob_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.bob",
    )?;
    let alice_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &alice_identifier)?;
    let bob_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &bob_identifier)?;
    let (_alice_store, bob_store) =
        prepare_direct_context_without_relationship(&alice_fixture, &bob_fixture)?;

    let expected_digest = reviewed_values.get("digest").ok_or_else(|| {
        ValidationError("BV-003 replay is missing digest in reviewed values".into())
    })?;
    let expected_context = reviewed_values.get("reviewed_context").ok_or_else(|| {
        ValidationError("BV-003 replay is missing reviewed_context in reviewed values".into())
    })?;

    let mut request_message =
        decode_wire_artifact_payload(&load_wire_artifact(&vector_artifact_path(
            artifact_root,
            manifest,
            &format!(
                "{}.vector.BV-001.wire",
                manifest.artifact_set_id.replace("artifact-set", "artifact")
            ),
        )?)?)?;
    let request_thread_id = match bob_store
        .open_message(&mut request_message)
        .map_err(|err| {
            ValidationError(format!(
                "BV-003 replay failed while replaying prerequisite BV-001: {err}"
            ))
        })? {
        ReceivedTspMessage::RequestRelationship { thread_id, .. } => thread_id,
        other => {
            return Err(ValidationError(format!(
                "BV-003 replay prerequisite BV-001 decoded as {other:?} instead of RequestRelationship"
            )));
        }
    };

    let mut cancel_message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = bob_store
        .open_message(&mut cancel_message)
        .map_err(|err| ValidationError(format!("BV-003 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::CancelRelationship { sender, receiver } = opened else {
        return Err(ValidationError(
            "BV-003 replay did not decode as CancelRelationship".into(),
        ));
    };

    if sender != alice_identifier {
        return Err(ValidationError(format!(
            "BV-003 replay sender mismatch: expected {}, got {}",
            alice_identifier, sender
        )));
    }
    if receiver != bob_identifier {
        return Err(ValidationError(format!(
            "BV-003 replay receiver mismatch: expected {}, got {}",
            bob_identifier, receiver
        )));
    }
    if hex_lower(&request_thread_id) != *expected_digest {
        return Err(ValidationError(format!(
            "BV-003 replay digest mismatch: expected {}, got {}",
            expected_digest,
            hex_lower(&request_thread_id)
        )));
    }
    let status = bob_store
        .relation_status_for_vid_pair(&bob_identifier, &alice_identifier)
        .map_err(|err| {
            ValidationError(format!(
                "BV-003 replay failed to read receiver-side relation status: {err}"
            ))
        })?;
    if !matches!(status, RelationshipStatus::Unrelated) {
        return Err(ValidationError(format!(
            "BV-003 replay expected unrelated status after cancel, found {status:?}"
        )));
    }
    if expected_context != "pending-request-cancel" {
        return Err(ValidationError(format!(
            "BV-003 replay reviewed_context mismatch: expected pending-request-cancel, got {}",
            expected_context
        )));
    }

    Ok(vec![format!(
        "sdk replay verified direct cancel sender/receiver/digest and receiver-side unrelated cleanup using {} -> {}",
        alice_fixture.fixture_id, bob_fixture.fixture_id
    )])
}

fn replay_digest_mismatch(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let alice_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.alice",
    )?;
    let bob_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.bob",
    )?;
    let alice_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &alice_identifier)?;
    let bob_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &bob_identifier)?;
    let (alice_store, bob_store) =
        prepare_direct_context_without_relationship(&alice_fixture, &bob_fixture)?;

    let expected_request_digest =
        reviewed_values
            .get("expected_request_digest")
            .ok_or_else(|| {
                ValidationError(
                    "SV-005 replay is missing expected_request_digest in reviewed values".into(),
                )
            })?;
    let mismatching_accept_digest = reviewed_values
        .get("mismatching_accept_digest")
        .ok_or_else(|| {
            ValidationError(
                "SV-005 replay is missing mismatching_accept_digest in reviewed values".into(),
            )
        })?;

    let mut request_message =
        decode_wire_artifact_payload(&load_wire_artifact(&vector_artifact_path(
            artifact_root,
            manifest,
            &format!(
                "{}.vector.BV-001.wire",
                manifest.artifact_set_id.replace("artifact-set", "artifact")
            ),
        )?)?)?;
    let request_thread_id = match bob_store
        .open_message(&mut request_message)
        .map_err(|err| {
            ValidationError(format!(
                "SV-005 replay failed while replaying prerequisite BV-001: {err}"
            ))
        })? {
        ReceivedTspMessage::RequestRelationship { thread_id, .. } => thread_id,
        other => {
            return Err(ValidationError(format!(
                "SV-005 replay prerequisite BV-001 decoded as {other:?} instead of RequestRelationship"
            )));
        }
    };

    alice_store
        .set_relation_and_status_for_vid(
            &bob_identifier,
            RelationshipStatus::Unidirectional {
                thread_id: request_thread_id,
            },
            &alice_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "SV-005 replay failed to reconstruct sender-side prerequisite relationship: {err}"
            ))
        })?;

    let actual_request_digest = hex_lower(&request_thread_id);
    if actual_request_digest != *expected_request_digest {
        return Err(ValidationError(format!(
            "SV-005 replay request digest mismatch before replay: expected {}, got {}",
            expected_request_digest, actual_request_digest
        )));
    }
    if actual_request_digest == *mismatching_accept_digest {
        return Err(ValidationError(
            "SV-005 replay mismatch precondition failed: mismatching_accept_digest equals request digest".into(),
        ));
    }

    let mut accept_message = decode_wire_artifact_payload(artifact_bytes)?;
    match alice_store.open_message(&mut accept_message) {
        Err(err) => Ok(vec![format!(
            "sdk replay verified digest-mismatch rejection for direct accept using {} -> {}: {}",
            bob_fixture.fixture_id, alice_fixture.fixture_id, err
        )]),
        Ok(ReceivedTspMessage::AcceptRelationship { .. }) => Err(ValidationError(
            "SV-005 replay unexpectedly accepted mismatching direct accept".into(),
        )),
        Ok(other) => Err(ValidationError(format!(
            "SV-005 replay unexpectedly decoded as {other:?} instead of rejecting mismatching accept"
        ))),
    }
}

fn replay_routed_path(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.alice",
    )?;
    let current_hop_identifier = reviewed_values.get("current_hop_vid").ok_or_else(|| {
        ValidationError("BV-006 replay is missing current_hop_vid in reviewed values".into())
    })?;
    let next_hop_identifier = reviewed_values.get("next_hop_vid").ok_or_else(|| {
        ValidationError("BV-006 replay is missing next_hop_vid in reviewed values".into())
    })?;
    let expected_remaining_route = reviewed_values.get("remaining_route_ref").ok_or_else(|| {
        ValidationError("BV-006 replay is missing remaining_route_ref in reviewed values".into())
    })?;
    let expected_opaque_payload = reviewed_values.get("opaque_payload_ref").ok_or_else(|| {
        ValidationError("BV-006 replay is missing opaque_payload_ref in reviewed values".into())
    })?;
    let expected_remaining_route = normalize_jsonish_scalar(expected_remaining_route);

    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let current_hop_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        current_hop_identifier,
    )?;
    let next_hop_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, next_hop_identifier)?;

    let current_hop_private_ref = current_hop_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "current hop fixture {} is missing private_material_ref",
                current_hop_fixture.fixture_id
            ))
        })?;
    let current_hop_owned =
        load_owned_vid_from_ref(&current_hop_fixture.path, current_hop_private_ref)?;
    let sender_verified = load_local_verified_vid_from_fixture(&sender_fixture.path)?;
    let next_hop_verified = load_local_verified_vid_from_fixture(&next_hop_fixture.path)?;

    let hop_store = SecureStore::new();
    hop_store
        .add_private_vid(current_hop_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "BV-006 replay failed to add current hop vid: {err}"
            ))
        })?;
    hop_store
        .add_verified_vid(sender_verified, None::<Value>)
        .map_err(|err| ValidationError(format!("BV-006 replay failed to add sender vid: {err}")))?;
    hop_store
        .add_verified_vid(next_hop_verified, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("BV-006 replay failed to add next hop vid: {err}"))
        })?;

    hop_store
        .set_relation_and_status_for_vid(
            next_hop_identifier,
            RelationshipStatus::Unidirectional {
                thread_id: Default::default(),
            },
            current_hop_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "BV-006 replay failed to set routed hop relationship: {err}"
            ))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = hop_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("BV-006 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::ForwardRequest {
        sender,
        receiver,
        next_hop,
        route,
        opaque_payload,
    } = opened
    else {
        return Err(ValidationError(
            "BV-006 replay did not decode as ForwardRequest".into(),
        ));
    };

    let actual_remaining_route = format!(
        "[{}]",
        route
            .iter()
            .map(|segment| {
                let value = std::str::from_utf8(segment.iter().as_slice()).map_err(|err| {
                    ValidationError(format!(
                        "BV-006 replay remaining route segment is not valid UTF-8: {err}"
                    ))
                })?;
                Ok(format!("\"{value}\""))
            })
            .collect::<Result<Vec<_>, ValidationError>>()?
            .join(",")
    );
    let actual_opaque_payload = Base64UrlUnpadded::encode_string(opaque_payload.iter().as_slice());

    if sender != sender_identifier {
        return Err(ValidationError(format!(
            "BV-006 replay sender mismatch: expected {}, got {}",
            sender_identifier, sender
        )));
    }
    if receiver != *current_hop_identifier {
        return Err(ValidationError(format!(
            "BV-006 replay receiver mismatch: expected {}, got {}",
            current_hop_identifier, receiver
        )));
    }
    if next_hop != *next_hop_identifier {
        return Err(ValidationError(format!(
            "BV-006 replay next_hop mismatch: expected {}, got {}",
            next_hop_identifier, next_hop
        )));
    }
    if actual_remaining_route != expected_remaining_route {
        return Err(ValidationError(format!(
            "BV-006 replay remaining_route mismatch: expected {}, got {}",
            expected_remaining_route, actual_remaining_route
        )));
    }
    if actual_opaque_payload != *expected_opaque_payload {
        return Err(ValidationError(format!(
            "BV-006 replay opaque_payload mismatch: expected {}, got {}",
            expected_opaque_payload, actual_opaque_payload
        )));
    }

    Ok(vec![format!(
        "sdk replay verified routed hop unwrap sender/current_hop/next_hop/remaining_route/opaque_payload against reviewed binding using {} -> {}",
        current_hop_fixture.fixture_id, next_hop_fixture.fixture_id
    )])
}

fn replay_routed_request(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = reviewed_values.get("sender_vid").cloned().ok_or_else(|| {
        ValidationError("BV-007 replay is missing sender_vid in reviewed values".into())
    })?;
    let receiver_identifier = reviewed_values
        .get("receiver_vid")
        .cloned()
        .ok_or_else(|| {
            ValidationError("BV-007 replay is missing receiver_vid in reviewed values".into())
        })?;
    let request_digest = reviewed_values.get("request_digest").ok_or_else(|| {
        ValidationError("BV-007 replay is missing request_digest in reviewed values".into())
    })?;

    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;
    let dropoff_fixture = load_authoring_only_route_dropoff_fixture(artifact_root)?;

    let receiver_private_ref = receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "receiver fixture {} is missing private_material_ref",
                receiver_fixture.fixture_id
            ))
        })?;
    let receiver_owned = load_owned_vid_from_ref(&receiver_fixture.path, receiver_private_ref)?;
    let sender_verified = load_local_verified_vid_from_fixture(&sender_fixture.path)?;
    let dropoff_verified = load_local_verified_vid_from_fixture(&dropoff_fixture.path)?;

    let receiver_store = SecureStore::new();
    receiver_store
        .add_private_vid(receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("BV-007 replay failed to add receiver vid: {err}"))
        })?;
    receiver_store
        .add_verified_vid(sender_verified, None::<Value>)
        .map_err(|err| ValidationError(format!("BV-007 replay failed to add sender vid: {err}")))?;
    receiver_store
        .add_verified_vid(dropoff_verified, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("BV-007 replay failed to add dropoff vid: {err}"))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = receiver_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("BV-007 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::RequestRelationship {
        sender,
        receiver,
        route: Some(route),
        nested_vid: None,
        thread_id,
    } = opened
    else {
        return Err(ValidationError(
            "BV-007 replay did not decode as final routed RequestRelationship".into(),
        ));
    };

    let replay_digest = hex_lower(&thread_id);
    if sender != sender_identifier {
        return Err(ValidationError(format!(
            "BV-007 replay sender mismatch: expected {}, got {}",
            sender_identifier, sender
        )));
    }
    if receiver != receiver_identifier {
        return Err(ValidationError(format!(
            "BV-007 replay receiver mismatch: expected {}, got {}",
            receiver_identifier, receiver
        )));
    }
    if replay_digest != *request_digest {
        return Err(ValidationError(format!(
            "BV-007 replay request_digest mismatch: expected {}, got {}",
            request_digest, replay_digest
        )));
    }

    let expected_route = expected_routed_final_delivery_route(manifest, artifact_root)?;
    let actual_route = route
        .iter()
        .map(|segment| {
            std::str::from_utf8(segment)
                .map(str::to_string)
                .map_err(|err| {
                    ValidationError(format!(
                        "BV-007 replay route segment is not valid UTF-8: {err}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, ValidationError>>()?;
    if actual_route != expected_route {
        return Err(ValidationError(format!(
            "BV-007 replay route mismatch: expected {:?}, got {:?}",
            expected_route, actual_route
        )));
    }

    Ok(vec![format!(
        "sdk replay verified final routed request sender/receiver/request_digest/route against reviewed binding using {} -> {}",
        sender_fixture.fixture_id, receiver_fixture.fixture_id
    )])
}

fn replay_routed_accept(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.bob",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.alice",
    )?;
    let request_digest = reviewed_values.get("request_digest").ok_or_else(|| {
        ValidationError("BV-008 replay is missing request_digest in reviewed values".into())
    })?;

    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;
    let dropoff_fixture = load_authoring_only_route_dropoff_fixture(artifact_root)?;

    let receiver_private_ref = receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "receiver fixture {} is missing private_material_ref",
                receiver_fixture.fixture_id
            ))
        })?;
    let receiver_owned = load_owned_vid_from_ref(&receiver_fixture.path, receiver_private_ref)?;
    let sender_verified = load_local_verified_vid_from_fixture(&sender_fixture.path)?;
    let dropoff_verified = load_local_verified_vid_from_fixture(&dropoff_fixture.path)?;

    let receiver_store = SecureStore::new();
    receiver_store
        .add_private_vid(receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("BV-008 replay failed to add receiver vid: {err}"))
        })?;
    receiver_store
        .add_verified_vid(sender_verified, None::<Value>)
        .map_err(|err| ValidationError(format!("BV-008 replay failed to add sender vid: {err}")))?;
    receiver_store
        .add_verified_vid(dropoff_verified, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("BV-008 replay failed to add dropoff vid: {err}"))
        })?;
    receiver_store
        .set_relation_and_status_for_vid(
            &sender_identifier,
            RelationshipStatus::Unidirectional {
                thread_id: hex_to_digest(request_digest, "BV-008 request_digest")?,
            },
            &receiver_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "BV-008 replay failed to seed prerequisite relationship: {err}"
            ))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = receiver_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("BV-008 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::AcceptRelationship {
        sender,
        receiver,
        nested_vid: None,
    } = opened
    else {
        return Err(ValidationError(
            "BV-008 replay did not decode as final routed AcceptRelationship".into(),
        ));
    };

    if sender != sender_identifier {
        return Err(ValidationError(format!(
            "BV-008 replay sender mismatch: expected {}, got {}",
            sender_identifier, sender
        )));
    }
    if receiver != receiver_identifier {
        return Err(ValidationError(format!(
            "BV-008 replay receiver mismatch: expected {}, got {}",
            receiver_identifier, receiver
        )));
    }

    match receiver_store
        .relation_status_for_vid_pair(&receiver_identifier, &sender_identifier)
        .map_err(|err| {
            ValidationError(format!(
                "BV-008 replay failed to inspect post-accept relationship state: {err}"
            ))
        })? {
        RelationshipStatus::Bidirectional { thread_id, .. } => {
            if hex_lower(&thread_id) != *request_digest {
                return Err(ValidationError(format!(
                    "BV-008 replay bidirectional thread mismatch: expected {}, got {}",
                    request_digest,
                    hex_lower(&thread_id)
                )));
            }
        }
        other => {
            return Err(ValidationError(format!(
                "BV-008 replay expected bidirectional relationship after accept, found {other:?}"
            )));
        }
    }

    Ok(vec![format!(
        "sdk replay verified final routed accept sender/receiver and bidirectional upgrade against reviewed binding using {} -> {}",
        sender_fixture.fixture_id, receiver_fixture.fixture_id
    )])
}

fn replay_routed_message(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.alice",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.bob",
    )?;
    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;
    let dropoff_fixture = load_authoring_only_route_dropoff_fixture(artifact_root)?;

    let receiver_private_ref = receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "receiver fixture {} is missing private_material_ref",
                receiver_fixture.fixture_id
            ))
        })?;
    let receiver_owned = load_owned_vid_from_ref(&receiver_fixture.path, receiver_private_ref)?;
    let sender_verified = load_local_verified_vid_from_fixture(&sender_fixture.path)?;
    let dropoff_verified = load_local_verified_vid_from_fixture(&dropoff_fixture.path)?;

    let receiver_store = SecureStore::new();
    receiver_store
        .add_private_vid(receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("SV-003 replay failed to add receiver vid: {err}"))
        })?;
    receiver_store
        .add_verified_vid(sender_verified, None::<Value>)
        .map_err(|err| ValidationError(format!("SV-003 replay failed to add sender vid: {err}")))?;
    receiver_store
        .add_verified_vid(dropoff_verified, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("SV-003 replay failed to add dropoff vid: {err}"))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = receiver_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("SV-003 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        return Err(ValidationError(
            "SV-003 replay did not decode as GenericMessage".into(),
        ));
    };

    let expected = expected_routed_message_baseline(&manifest.case_id, reviewed_values)?;
    let actual_message = std::str::from_utf8(message.as_ref()).map_err(|err| {
        ValidationError(format!("SV-003 replay message is not valid UTF-8: {err}"))
    })?;
    let actual_nonconf = nonconfidential_data
        .as_ref()
        .map(|data| {
            std::str::from_utf8(data.as_ref()).map_err(|err| {
                ValidationError(format!(
                    "SV-003 replay nonconfidential_data is not valid UTF-8: {err}"
                ))
            })
        })
        .transpose()?;

    if sender != expected.sender_vid {
        return Err(ValidationError(format!(
            "SV-003 replay sender mismatch: expected {}, got {}",
            expected.sender_vid, sender
        )));
    }
    if receiver.as_deref() != Some(expected.receiver_vid.as_str()) {
        return Err(ValidationError(format!(
            "SV-003 replay receiver mismatch: expected {}, got {:?}",
            expected.receiver_vid, receiver
        )));
    }
    if actual_message != expected.payload {
        return Err(ValidationError(format!(
            "SV-003 replay payload mismatch: expected {:?}, got {:?}",
            expected.payload, actual_message
        )));
    }
    if actual_nonconf != Some(expected.nonconfidential.as_str()) {
        return Err(ValidationError(format!(
            "SV-003 replay nonconfidential data mismatch: expected {:?}, got {:?}",
            expected.nonconfidential, actual_nonconf
        )));
    }
    if message_type.crypto_type != expected.crypto_type {
        return Err(ValidationError(format!(
            "SV-003 replay crypto_type mismatch: expected {:?}, got {:?}",
            expected.crypto_type, message_type.crypto_type
        )));
    }
    if message_type.signature_type != expected.signature_type {
        return Err(ValidationError(format!(
            "SV-003 replay signature_type mismatch: expected {:?}, got {:?}",
            expected.signature_type, message_type.signature_type
        )));
    }

    Ok(vec![format!(
        "sdk replay verified routed message sender/receiver/payload/nonconfidential/message_type against reviewed baseline {}",
        expected.payload_semantics_ref
    )])
}

fn replay_no_prior_relationship(
    manifest: &ManifestData,
    artifact_root: &Path,
    _reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.alice",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.bob",
    )?;
    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;

    let sender_verified = load_local_verified_vid_from_fixture(&sender_fixture.path)?;
    let receiver_private_ref = receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "receiver fixture {} is missing private_material_ref",
                receiver_fixture.fixture_id
            ))
        })?;
    let receiver_owned = load_owned_vid_from_ref(&receiver_fixture.path, receiver_private_ref)?;

    let store = SecureStore::new();
    store
        .add_private_vid(receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("SV-004 replay failed to add receiver vid: {err}"))
        })?;
    store
        .add_verified_vid(sender_verified, None::<Value>)
        .map_err(|err| ValidationError(format!("SV-004 replay failed to add sender vid: {err}")))?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    match store.open_message(&mut message) {
        Err(_) => Ok(vec!["sdk replay rejected no-prior-relationship traffic as invalid".into()]),
        Ok(ReceivedTspMessage::GenericMessage { .. }) => Err(ValidationError(
            "SV-004 replay unexpectedly opened as GenericMessage instead of rejecting unauthorized traffic".into(),
        )),
        Ok(other) => Err(ValidationError(format!(
            "SV-004 replay unexpectedly decoded as {other:?} instead of rejecting unauthorized traffic"
        ))),
    }
}

fn replay_nested_without_outer(
    manifest: &ManifestData,
    artifact_root: &Path,
    _reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let outer_sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.alice",
    )?;
    let outer_receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.bob",
    )?;
    let outer_sender_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        &outer_sender_identifier,
    )?;
    let outer_receiver_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        &outer_receiver_identifier,
    )?;

    let (alice_store, bob_store) = prepare_direct_context_without_relationship(
        &outer_sender_fixture,
        &outer_receiver_fixture,
    )?;

    let inner_sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.inner.alice-1",
    )?;
    let inner_receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.inner.bob-1",
    )?;
    let inner_sender_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        &inner_sender_identifier,
    )?;
    let inner_receiver_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        &inner_receiver_identifier,
    )?;
    let inner_sender_private_ref = inner_sender_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "nested sender fixture {} is missing private_material_ref",
                inner_sender_fixture.fixture_id
            ))
        })?;
    let inner_receiver_private_ref = inner_receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "nested receiver fixture {} is missing private_material_ref",
                inner_receiver_fixture.fixture_id
            ))
        })?;

    let inner_sender_owned =
        load_owned_vid_from_ref(&inner_sender_fixture.path, inner_sender_private_ref)?;
    let inner_receiver_owned =
        load_owned_vid_from_ref(&inner_receiver_fixture.path, inner_receiver_private_ref)?;
    let nested_thread_id = load_nested_request_thread_id(manifest, artifact_root)?;

    alice_store
        .add_private_vid(inner_sender_owned.clone(), None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to add inner sender private vid: {err}"
            ))
        })?;
    alice_store
        .add_verified_vid(inner_receiver_owned.clone(), None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to add inner receiver verified vid: {err}"
            ))
        })?;
    alice_store
        .set_parent_for_vid(&inner_sender_identifier, Some(&outer_sender_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to set parent for inner sender vid: {err}"
            ))
        })?;
    alice_store
        .set_parent_for_vid(&inner_receiver_identifier, Some(&outer_receiver_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to set parent for inner receiver vid: {err}"
            ))
        })?;
    alice_store
        .set_relation_and_status_for_vid(
            &inner_receiver_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id.clone(),
                outstanding_nested_thread_ids: vec![],
            },
            &inner_sender_identifier,
        )
        .map_err(|err| ValidationError(format!(
            "SV-006 replay failed to set inner receiver relationship status on sender store: {err}"
        )))?;
    alice_store
        .set_relation_and_status_for_vid(
            &inner_sender_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id.clone(),
                outstanding_nested_thread_ids: vec![],
            },
            &inner_receiver_identifier,
        )
        .map_err(|err| ValidationError(format!(
            "SV-006 replay failed to set inner sender relationship status on sender store: {err}"
        )))?;

    bob_store
        .add_private_vid(inner_receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to add inner receiver private vid: {err}"
            ))
        })?;
    bob_store
        .add_verified_vid(inner_sender_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to add inner sender verified vid: {err}"
            ))
        })?;
    bob_store
        .set_parent_for_vid(&inner_receiver_identifier, Some(&outer_receiver_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to set parent for inner receiver vid on receiver store: {err}"
            ))
        })?;
    bob_store
        .set_parent_for_vid(&inner_sender_identifier, Some(&outer_sender_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-006 replay failed to set parent for inner sender vid on receiver store: {err}"
            ))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    match bob_store.open_message(&mut message) {
        Err(_) => Ok(vec![
            "sdk replay rejected nested traffic without outer context as invalid".into(),
        ]),
        Ok(ReceivedTspMessage::GenericMessage { .. }) => Err(ValidationError(
            "SV-006 replay unexpectedly opened as GenericMessage instead of rejecting nested traffic without outer context".into(),
        )),
        Ok(other) => Err(ValidationError(format!(
            "SV-006 replay unexpectedly decoded as {other:?} instead of rejecting nested traffic without outer context"
        ))),
    }
}

fn replay_direct_message(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.alice",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.direct.bob",
    )?;
    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;

    let (alice_store, bob_store) = prepare_direct_message_replay_context(
        manifest,
        artifact_root,
        &sender_fixture,
        &receiver_fixture,
    )?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = bob_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("SV-001 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        return Err(ValidationError(
            "SV-001 replay did not decode as GenericMessage".into(),
        ));
    };

    let expected = expected_direct_message_baseline(&manifest.case_id, reviewed_values)?;
    let actual_message = std::str::from_utf8(message.as_ref()).map_err(|err| {
        ValidationError(format!("SV-001 replay message is not valid UTF-8: {err}"))
    })?;
    let actual_nonconf = nonconfidential_data
        .as_ref()
        .map(|data| {
            std::str::from_utf8(data.as_ref()).map_err(|err| {
                ValidationError(format!(
                    "SV-001 replay nonconfidential_data is not valid UTF-8: {err}"
                ))
            })
        })
        .transpose()?;

    if sender != expected.sender_vid {
        return Err(ValidationError(format!(
            "SV-001 replay sender mismatch: expected {}, got {}",
            expected.sender_vid, sender
        )));
    }
    if receiver.as_deref() != Some(expected.receiver_vid.as_str()) {
        return Err(ValidationError(format!(
            "SV-001 replay receiver mismatch: expected {}, got {:?}",
            expected.receiver_vid, receiver
        )));
    }
    if actual_message != expected.payload {
        return Err(ValidationError(format!(
            "SV-001 replay payload mismatch: expected {:?}, got {:?}",
            expected.payload, actual_message
        )));
    }
    if actual_nonconf != Some(expected.nonconfidential.as_str()) {
        return Err(ValidationError(format!(
            "SV-001 replay nonconfidential data mismatch: expected {:?}, got {:?}",
            expected.nonconfidential, actual_nonconf
        )));
    }
    if message_type.crypto_type != expected.crypto_type {
        return Err(ValidationError(format!(
            "SV-001 replay crypto_type mismatch: expected {:?}, got {:?}",
            expected.crypto_type, message_type.crypto_type
        )));
    }
    if message_type.signature_type != expected.signature_type {
        return Err(ValidationError(format!(
            "SV-001 replay signature_type mismatch: expected {:?}, got {:?}",
            expected.signature_type, message_type.signature_type
        )));
    }

    let _ = alice_store;
    Ok(vec![format!(
        "sdk replay verified direct message sender/receiver/payload/nonconfidential/message_type against reviewed baseline {}",
        expected.payload_semantics_ref
    )])
}

fn replay_nested_request(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.alice",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.bob",
    )?;
    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;

    let (_alice_store, bob_store) = prepare_direct_message_replay_context(
        manifest,
        artifact_root,
        &sender_fixture,
        &receiver_fixture,
    )?;

    let expected_digest = reviewed_values.get("request_digest").ok_or_else(|| {
        ValidationError("BV-004 replay is missing request_digest in reviewed values".into())
    })?;
    let expected_inner_sender = reviewed_values.get("inner_sender_vid").ok_or_else(|| {
        ValidationError("BV-004 replay is missing inner_sender_vid in reviewed values".into())
    })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = bob_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("BV-004 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::RequestRelationship {
        sender,
        receiver,
        thread_id,
        nested_vid,
        ..
    } = opened
    else {
        return Err(ValidationError(
            "BV-004 replay did not decode as RequestRelationship".into(),
        ));
    };

    if sender != sender_identifier {
        return Err(ValidationError(format!(
            "BV-004 replay sender mismatch: expected {}, got {}",
            sender_identifier, sender
        )));
    }
    if receiver != receiver_identifier {
        return Err(ValidationError(format!(
            "BV-004 replay receiver mismatch: expected {}, got {}",
            receiver_identifier, receiver
        )));
    }
    if hex_lower(&thread_id) != *expected_digest {
        return Err(ValidationError(format!(
            "BV-004 replay request_digest mismatch: expected {}, got {}",
            expected_digest,
            hex_lower(&thread_id)
        )));
    }
    if nested_vid.as_deref() != Some(expected_inner_sender.as_str()) {
        return Err(ValidationError(format!(
            "BV-004 replay nested_vid mismatch: expected {}, got {:?}",
            expected_inner_sender, nested_vid
        )));
    }

    Ok(vec![format!(
        "sdk replay verified nested request sender/receiver/request_digest/nested_vid against reviewed binding using {} -> {}",
        sender_fixture.fixture_id, receiver_fixture.fixture_id
    )])
}

fn replay_nested_accept(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.alice",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.bob",
    )?;
    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;

    let (alice_store, bob_store) = prepare_direct_message_replay_context(
        manifest,
        artifact_root,
        &sender_fixture,
        &receiver_fixture,
    )?;

    let inner_receiver_identifier = reviewed_values.get("inner_receiver_vid").ok_or_else(|| {
        ValidationError("BV-005 replay is missing inner_receiver_vid in reviewed values".into())
    })?;
    let inner_sender_identifier = reviewed_values.get("inner_sender_vid").ok_or_else(|| {
        ValidationError("BV-005 replay is missing inner_sender_vid in reviewed values".into())
    })?;
    let expected_reply_digest = reviewed_values.get("reply_digest").ok_or_else(|| {
        ValidationError("BV-005 replay is missing reply_digest in reviewed values".into())
    })?;

    let mut nested_request_message =
        decode_wire_artifact_payload(&load_wire_artifact(&vector_artifact_path(
            artifact_root,
            manifest,
            &format!(
                "{}.vector.BV-004.wire",
                manifest.artifact_set_id.replace("artifact-set", "artifact")
            ),
        )?)?)?;
    let nested_thread_id = match bob_store
        .open_message(&mut nested_request_message)
        .map_err(|err| {
            ValidationError(format!(
                "BV-005 replay failed while replaying prerequisite BV-004: {err}"
            ))
        })? {
        ReceivedTspMessage::RequestRelationship { thread_id, .. } => thread_id,
        _ => {
            return Err(ValidationError(
                "BV-005 replay prerequisite BV-004 did not decode as RequestRelationship".into(),
            ));
        }
    };

    let inner_receiver_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        inner_receiver_identifier,
    )?;
    let inner_receiver_private_ref = inner_receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "inner receiver fixture {} is missing private_material_ref",
                inner_receiver_fixture.fixture_id
            ))
        })?;
    let inner_receiver_owned =
        load_owned_vid_from_ref(&inner_receiver_fixture.path, inner_receiver_private_ref)?;
    alice_store
        .add_private_vid(inner_receiver_owned.clone(), None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "BV-005 replay failed to add inner receiver private vid: {err}"
            ))
        })?;
    alice_store
        .set_parent_for_vid(inner_receiver_identifier, Some(&sender_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "BV-005 replay failed to set parent for inner receiver vid: {err}"
            ))
        })?;

    let outer_thread_id = match alice_store
        .relation_status_for_vid_pair(&sender_identifier, &receiver_identifier)
        .map_err(|err| {
            ValidationError(format!(
                "BV-005 replay failed to read outer relationship status: {err}"
            ))
        })? {
        RelationshipStatus::Bidirectional { thread_id, .. } => thread_id,
        other => {
            return Err(ValidationError(format!(
                "BV-005 replay expected bidirectional outer relationship, found {other:?}"
            )));
        }
    };
    alice_store
        .set_relation_status_for_vid(
            &receiver_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: outer_thread_id,
                outstanding_nested_thread_ids: vec![nested_thread_id],
            },
        )
        .map_err(|err| {
            ValidationError(format!(
                "BV-005 replay failed to reconstruct outstanding nested thread id on outer relationship: {err}"
            ))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = alice_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("BV-005 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::AcceptRelationship {
        sender,
        receiver,
        nested_vid,
    } = opened
    else {
        return Err(ValidationError(
            "BV-005 replay did not decode as AcceptRelationship".into(),
        ));
    };

    if sender != receiver_identifier {
        return Err(ValidationError(format!(
            "BV-005 replay sender mismatch: expected {}, got {}",
            receiver_identifier, sender
        )));
    }
    if receiver != sender_identifier {
        return Err(ValidationError(format!(
            "BV-005 replay receiver mismatch: expected {}, got {}",
            sender_identifier, receiver
        )));
    }
    if nested_vid.as_deref() != Some(inner_sender_identifier.as_str()) {
        return Err(ValidationError(format!(
            "BV-005 replay nested_vid mismatch: expected {}, got {:?}",
            inner_sender_identifier, nested_vid
        )));
    }
    if hex_lower(&nested_thread_id) != *expected_reply_digest {
        return Err(ValidationError(format!(
            "BV-005 replay reply_digest mismatch: expected {}, got {}",
            expected_reply_digest,
            hex_lower(&nested_thread_id)
        )));
    }

    Ok(vec![format!(
        "sdk replay verified nested accept sender/receiver/reply_digest/nested_vid against reviewed binding using {} -> {}",
        sender_fixture.fixture_id, receiver_fixture.fixture_id
    )])
}

fn replay_nested_message(
    manifest: &ManifestData,
    artifact_root: &Path,
    reviewed_values: &BTreeMap<String, String>,
    artifact_bytes: &[u8],
) -> Result<Vec<String>, ValidationError> {
    let sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.alice",
    )?;
    let receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.outer.bob",
    )?;
    let sender_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &sender_identifier)?;
    let receiver_fixture =
        find_public_identity_fixture_by_identifier(manifest, artifact_root, &receiver_identifier)?;

    let (alice_store, bob_store) = prepare_direct_message_replay_context(
        manifest,
        artifact_root,
        &sender_fixture,
        &receiver_fixture,
    )?;

    let inner_sender_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.inner.alice-1",
    )?;
    let inner_receiver_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.inner.bob-1",
    )?;
    let inner_sender_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        &inner_sender_identifier,
    )?;
    let inner_receiver_fixture = find_public_identity_fixture_by_identifier(
        manifest,
        artifact_root,
        &inner_receiver_identifier,
    )?;

    let inner_sender_private_ref = inner_sender_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "nested sender fixture {} is missing private_material_ref",
                inner_sender_fixture.fixture_id
            ))
        })?;
    let inner_receiver_private_ref = inner_receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "nested receiver fixture {} is missing private_material_ref",
                inner_receiver_fixture.fixture_id
            ))
        })?;

    let inner_sender_owned =
        load_owned_vid_from_ref(&inner_sender_fixture.path, inner_sender_private_ref)?;
    let inner_receiver_owned =
        load_owned_vid_from_ref(&inner_receiver_fixture.path, inner_receiver_private_ref)?;

    let mut nested_request_message =
        decode_wire_artifact_payload(&load_wire_artifact(&vector_artifact_path(
            artifact_root,
            manifest,
            &format!(
                "{}.vector.BV-004.wire",
                manifest.artifact_set_id.replace("artifact-set", "artifact")
            ),
        )?)?)?;
    let nested_thread_id = match bob_store
        .open_message(&mut nested_request_message)
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed while replaying prerequisite BV-004: {err}"
            ))
        })? {
        ReceivedTspMessage::RequestRelationship { thread_id, .. } => thread_id,
        _ => {
            return Err(ValidationError(
                "SV-002 replay prerequisite BV-004 did not decode as RequestRelationship".into(),
            ));
        }
    };

    alice_store
        .add_private_vid(inner_sender_owned.clone(), None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to add inner sender private vid: {err}"
            ))
        })?;
    alice_store
        .add_verified_vid(inner_receiver_owned.clone(), None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to add inner receiver verified vid: {err}"
            ))
        })?;
    alice_store
        .set_parent_for_vid(&inner_sender_identifier, Some(&sender_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set parent for inner sender vid: {err}"
            ))
        })?;
    alice_store
        .set_parent_for_vid(&inner_receiver_identifier, Some(&receiver_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set parent for inner receiver vid: {err}"
            ))
        })?;
    alice_store
        .set_relation_and_status_for_vid(
            &inner_receiver_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id,
                outstanding_nested_thread_ids: vec![],
            },
            &inner_sender_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set inner receiver relationship status on sender store: {err}"
            ))
        })?;
    alice_store
        .set_relation_and_status_for_vid(
            &inner_sender_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id,
                outstanding_nested_thread_ids: vec![],
            },
            &inner_receiver_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set inner sender relationship status on sender store: {err}"
            ))
        })?;

    bob_store
        .add_private_vid(inner_receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to add inner receiver private vid: {err}"
            ))
        })?;
    bob_store
        .add_verified_vid(inner_sender_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to add inner sender verified vid: {err}"
            ))
        })?;
    bob_store
        .set_parent_for_vid(&inner_receiver_identifier, Some(&receiver_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set parent for inner receiver vid on receiver store: {err}"
            ))
        })?;
    bob_store
        .set_parent_for_vid(&inner_sender_identifier, Some(&sender_identifier))
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set parent for inner sender vid on receiver store: {err}"
            ))
        })?;
    bob_store
        .set_relation_and_status_for_vid(
            &inner_sender_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id,
                outstanding_nested_thread_ids: vec![],
            },
            &inner_receiver_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set inner sender relationship status on receiver store: {err}"
            ))
        })?;
    bob_store
        .set_relation_and_status_for_vid(
            &inner_receiver_identifier,
            RelationshipStatus::Bidirectional {
                thread_id: nested_thread_id,
                outstanding_nested_thread_ids: vec![],
            },
            &inner_sender_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "SV-002 replay failed to set inner receiver relationship status on receiver store: {err}"
            ))
        })?;

    let mut message = decode_wire_artifact_payload(artifact_bytes)?;
    let opened = bob_store
        .open_message(&mut message)
        .map_err(|err| ValidationError(format!("SV-002 replay open_message failed: {err}")))?;

    let ReceivedTspMessage::GenericMessage {
        sender,
        receiver,
        nonconfidential_data,
        message,
        message_type,
    } = opened
    else {
        return Err(ValidationError(
            "SV-002 replay did not decode as GenericMessage".into(),
        ));
    };

    let expected = expected_nested_message_baseline(
        &manifest.case_id,
        reviewed_values,
        &inner_sender_identifier,
        &inner_receiver_identifier,
    )?;
    let actual_message = std::str::from_utf8(message.as_ref()).map_err(|err| {
        ValidationError(format!("SV-002 replay message is not valid UTF-8: {err}"))
    })?;
    let actual_nonconf = nonconfidential_data
        .as_ref()
        .map(|data| {
            std::str::from_utf8(data.as_ref()).map_err(|err| {
                ValidationError(format!(
                    "SV-002 replay nonconfidential_data is not valid UTF-8: {err}"
                ))
            })
        })
        .transpose()?;

    if sender != expected.sender_vid {
        return Err(ValidationError(format!(
            "SV-002 replay sender mismatch: expected {}, got {}",
            expected.sender_vid, sender
        )));
    }
    if receiver.as_deref() != Some(expected.receiver_vid.as_str()) {
        return Err(ValidationError(format!(
            "SV-002 replay receiver mismatch: expected {}, got {:?}",
            expected.receiver_vid, receiver
        )));
    }
    if actual_message != expected.payload {
        return Err(ValidationError(format!(
            "SV-002 replay payload mismatch: expected {:?}, got {:?}",
            expected.payload, actual_message
        )));
    }
    if actual_nonconf.is_some() {
        return Err(ValidationError(format!(
            "SV-002 replay nonconfidential data mismatch: expected none, got {:?}",
            actual_nonconf
        )));
    }
    if message_type.crypto_type != expected.crypto_type {
        return Err(ValidationError(format!(
            "SV-002 replay crypto_type mismatch: expected {:?}, got {:?}",
            expected.crypto_type, message_type.crypto_type
        )));
    }
    if message_type.signature_type != expected.signature_type {
        return Err(ValidationError(format!(
            "SV-002 replay signature_type mismatch: expected {:?}, got {:?}",
            expected.signature_type, message_type.signature_type
        )));
    }

    Ok(vec![format!(
        "sdk replay verified nested message sender/receiver/payload/message_type against reviewed baseline {}",
        expected.payload_semantics_ref
    )])
}

fn prepare_direct_message_replay_context(
    manifest: &ManifestData,
    artifact_root: &Path,
    sender_fixture: &PublicIdentityFixtureInfo,
    receiver_fixture: &PublicIdentityFixtureInfo,
) -> Result<(SecureStore, SecureStore), ValidationError> {
    let sender_identifier = load_identity_identifier(&sender_fixture.path)?;
    let receiver_identifier = load_identity_identifier(&receiver_fixture.path)?;
    let (alice_store, bob_store) =
        prepare_direct_context_without_relationship(sender_fixture, receiver_fixture)?;

    let request_bytes = load_wire_artifact(&vector_artifact_path(
        artifact_root,
        manifest,
        &format!(
            "{}.vector.BV-001.wire",
            manifest.artifact_set_id.replace("artifact-set", "artifact")
        ),
    )?)?;
    let mut request_message = decode_wire_artifact_payload(&request_bytes)?;
    let request_thread_id = match bob_store
        .open_message(&mut request_message)
        .map_err(|err| {
            ValidationError(format!(
                "SV-001 replay failed while replaying prerequisite BV-001: {err}"
            ))
        })? {
        ReceivedTspMessage::RequestRelationship { thread_id, .. } => thread_id,
        _ => {
            return Err(ValidationError(
                "SV-001 replay prerequisite BV-001 did not decode as RequestRelationship".into(),
            ));
        }
    };

    alice_store
        .set_relation_and_status_for_vid(
            &receiver_identifier,
            RelationshipStatus::Unidirectional {
                thread_id: request_thread_id,
            },
            &sender_identifier,
        )
        .map_err(|err| {
            ValidationError(format!(
                "SV-001 replay failed to reconstruct sender-side prerequisite relationship after BV-001: {err}"
            ))
        })?;

    let accept_bytes = load_wire_artifact(&vector_artifact_path(
        artifact_root,
        manifest,
        &format!(
            "{}.vector.BV-002.wire",
            manifest.artifact_set_id.replace("artifact-set", "artifact")
        ),
    )?)?;
    let mut accept_message = decode_wire_artifact_payload(&accept_bytes)?;
    let _ = alice_store
        .open_message(&mut accept_message)
        .map_err(|err| {
            ValidationError(format!(
                "SV-001 replay failed while replaying prerequisite BV-002: {err}"
            ))
        })?;

    Ok((alice_store, bob_store))
}

fn prepare_direct_context_without_relationship(
    sender_fixture: &PublicIdentityFixtureInfo,
    receiver_fixture: &PublicIdentityFixtureInfo,
) -> Result<(SecureStore, SecureStore), ValidationError> {
    let sender_private_ref = sender_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "sender fixture {} is missing private_material_ref",
                sender_fixture.fixture_id
            ))
        })?;
    let receiver_private_ref = receiver_fixture
        .private_material_ref
        .as_deref()
        .ok_or_else(|| {
            ValidationError(format!(
                "receiver fixture {} is missing private_material_ref",
                receiver_fixture.fixture_id
            ))
        })?;

    let sender_owned = load_owned_vid_from_ref(&sender_fixture.path, sender_private_ref)?;
    let receiver_owned = load_owned_vid_from_ref(&receiver_fixture.path, receiver_private_ref)?;

    let alice_store = SecureStore::new();
    alice_store
        .add_private_vid(sender_owned.clone(), None::<Value>)
        .map_err(|err| ValidationError(format!("SV-001 replay failed to add sender vid: {err}")))?;
    alice_store
        .add_verified_vid(receiver_owned.clone(), None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-001 replay failed to add verified receiver vid: {err}"
            ))
        })?;

    let bob_store = SecureStore::new();
    bob_store
        .add_private_vid(receiver_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!("SV-001 replay failed to add receiver vid: {err}"))
        })?;
    bob_store
        .add_verified_vid(sender_owned, None::<Value>)
        .map_err(|err| {
            ValidationError(format!(
                "SV-001 replay failed to add verified sender vid: {err}"
            ))
        })?;

    Ok((alice_store, bob_store))
}

fn load_identity_identifier(path: &Path) -> Result<String, ValidationError> {
    let raw = read_file(path)?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| {
        ValidationError(format!(
            "failed to parse identity fixture json {}: {}",
            path.display(),
            err
        ))
    })?;
    value
        .get("identifier")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            ValidationError(format!(
                "fixture json missing identifier in {}",
                path.display()
            ))
        })
}

fn find_public_identifier_by_fixture_id(
    manifest: &ManifestData,
    artifact_root: &Path,
    fixture_id: &str,
) -> Result<String, ValidationError> {
    if !manifest
        .applicable_fixture_refs
        .iter()
        .any(|candidate| candidate == fixture_id)
    {
        return Err(ValidationError(format!(
            "fixture {} is outside manifest scope for {}",
            fixture_id, manifest.case_id
        )));
    }

    let path = resolve_fixture_path(&artifact_root.join("fixtures"), fixture_id)?;
    let raw = read_file(&path)?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| {
        ValidationError(format!(
            "failed to parse identity fixture json {}: {}",
            path.display(),
            err
        ))
    })?;
    value
        .get("identifier")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            ValidationError(format!(
                "fixture json missing identifier in {}",
                path.display()
            ))
        })
}

struct DirectMessageBaseline {
    payload_semantics_ref: String,
    sender_vid: String,
    receiver_vid: String,
    payload: String,
    nonconfidential: String,
    crypto_type: tsp_sdk::cesr::CryptoType,
    signature_type: tsp_sdk::cesr::SignatureType,
}

struct NestedMessageBaseline {
    payload_semantics_ref: String,
    sender_vid: String,
    receiver_vid: String,
    payload: String,
    crypto_type: tsp_sdk::cesr::CryptoType,
    signature_type: tsp_sdk::cesr::SignatureType,
}

fn expected_direct_message_baseline(
    case_id: &str,
    reviewed_values: &BTreeMap<String, String>,
) -> Result<DirectMessageBaseline, ValidationError> {
    let payload_semantics_ref = reviewed_values
        .get("payload_semantics_ref")
        .cloned()
        .ok_or_else(|| ValidationError("SV-001 replay is missing payload_semantics_ref".into()))?;

    let (crypto_type, nonconfidential) = match case_id {
        "CC-001" => (
            tsp_sdk::cesr::CryptoType::HpkeAuth,
            "cc001-direct-message-01-nonconf",
        ),
        "CC-002" => (
            tsp_sdk::cesr::CryptoType::HpkeEssr,
            "cc002-direct-message-01-nonconf",
        ),
        "CC-003" => (
            tsp_sdk::cesr::CryptoType::NaclEssr,
            "cc003-direct-message-01-nonconf",
        ),
        other => {
            return Err(ValidationError(format!(
                "SV-001 replay has no direct message baseline for {other}"
            )));
        }
    };

    Ok(DirectMessageBaseline {
        payload_semantics_ref,
        sender_vid:
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
                .into(),
        receiver_vid:
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
                .into(),
        payload: "hello direct world".into(),
        nonconfidential: nonconfidential.into(),
        crypto_type,
        signature_type: tsp_sdk::cesr::SignatureType::Ed25519,
    })
}

fn expected_nested_message_baseline(
    case_id: &str,
    reviewed_values: &BTreeMap<String, String>,
    sender_vid: &str,
    receiver_vid: &str,
) -> Result<NestedMessageBaseline, ValidationError> {
    let payload_semantics_ref = reviewed_values
        .get("payload_semantics_ref")
        .cloned()
        .ok_or_else(|| ValidationError("SV-002 replay is missing payload_semantics_ref".into()))?;

    let crypto_type = match case_id {
        "CC-001" => tsp_sdk::cesr::CryptoType::HpkeAuth,
        "CC-002" => tsp_sdk::cesr::CryptoType::HpkeEssr,
        "CC-003" => tsp_sdk::cesr::CryptoType::NaclEssr,
        other => {
            return Err(ValidationError(format!(
                "SV-002 replay has no nested message baseline for {other}"
            )));
        }
    };

    Ok(NestedMessageBaseline {
        payload_semantics_ref,
        sender_vid: sender_vid.into(),
        receiver_vid: receiver_vid.into(),
        payload: "hello nested world".into(),
        crypto_type,
        signature_type: tsp_sdk::cesr::SignatureType::Ed25519,
    })
}

fn expected_routed_message_baseline(
    case_id: &str,
    reviewed_values: &BTreeMap<String, String>,
) -> Result<DirectMessageBaseline, ValidationError> {
    let payload_semantics_ref = reviewed_values
        .get("payload_semantics_ref")
        .cloned()
        .ok_or_else(|| ValidationError("SV-003 replay is missing payload_semantics_ref".into()))?;

    let (crypto_type, nonconfidential) = match case_id {
        "CC-001" => (
            tsp_sdk::cesr::CryptoType::HpkeAuth,
            "cc001-routed-message-01-nonconf",
        ),
        "CC-002" => (
            tsp_sdk::cesr::CryptoType::HpkeEssr,
            "cc002-routed-message-01-nonconf",
        ),
        "CC-003" => (
            tsp_sdk::cesr::CryptoType::NaclEssr,
            "cc003-routed-message-01-nonconf",
        ),
        other => {
            return Err(ValidationError(format!(
                "SV-003 replay has no routed message baseline for {other}"
            )));
        }
    };

    Ok(DirectMessageBaseline {
        payload_semantics_ref,
        sender_vid:
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
                .into(),
        receiver_vid:
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
                .into(),
        payload: "hello routed world".into(),
        nonconfidential: nonconfidential.into(),
        crypto_type,
        signature_type: tsp_sdk::cesr::SignatureType::Ed25519,
    })
}

fn find_public_identity_fixture_by_identifier(
    manifest: &ManifestData,
    artifact_root: &Path,
    identifier: &str,
) -> Result<PublicIdentityFixtureInfo, ValidationError> {
    let fixtures_root = artifact_root.join("fixtures");
    for fixture_id in &manifest.applicable_fixture_refs {
        if !fixture_id.starts_with("fixture.identity.") {
            continue;
        }

        let path = resolve_fixture_path(&fixtures_root, fixture_id)?;
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let raw = read_file(&path)?;
        let value: Value = serde_json::from_str(&raw).map_err(|err| {
            ValidationError(format!(
                "failed to parse identity fixture json {}: {}",
                path.display(),
                err
            ))
        })?;

        let fixture_identifier = value
            .get("identifier")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if fixture_identifier != identifier {
            continue;
        }

        return Ok(PublicIdentityFixtureInfo {
            fixture_id: fixture_id.clone(),
            private_material_ref: value
                .get("private_material_ref")
                .and_then(Value::as_str)
                .map(str::to_string),
            path,
        });
    }

    Err(ValidationError(format!(
        "no public identity fixture found for identifier {} in {}",
        identifier, manifest.case_id
    )))
}

fn load_authoring_only_route_dropoff_fixture(
    artifact_root: &Path,
) -> Result<PublicIdentityFixtureInfo, ValidationError> {
    let path = resolve_fixture_path(
        &artifact_root.join("fixtures"),
        "fixture.identity.route.dropoff-1",
    )?;
    let raw = read_file(&path)?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| {
        ValidationError(format!(
            "failed to parse route dropoff fixture json {}: {}",
            path.display(),
            err
        ))
    })?;

    Ok(PublicIdentityFixtureInfo {
        fixture_id: "fixture.identity.route.dropoff-1".into(),
        private_material_ref: value
            .get("private_material_ref")
            .and_then(Value::as_str)
            .map(str::to_string),
        path,
    })
}

fn load_nested_request_thread_id(
    manifest: &ManifestData,
    artifact_root: &Path,
) -> Result<[u8; 32], ValidationError> {
    let binding_ref = format!(
        "{}.binding.nested.request-01",
        manifest.artifact_set_id.replace("artifact-set", "artifact")
    );
    let review_root = infer_review_root(artifact_root);
    let binding = load_binding(manifest, artifact_root, &review_root, &binding_ref)?;
    let request_digest = binding
        .reviewed_values
        .get("request_digest")
        .ok_or_else(|| {
            ValidationError(format!(
                "nested request binding {} is missing request_digest",
                binding_ref
            ))
        })?;
    let decoded = decode_hex_bytes(request_digest)?;
    decoded.try_into().map_err(|_| {
        ValidationError(format!(
            "nested request digest for {} did not decode to 32 bytes",
            binding_ref
        ))
    })
}

fn expected_routed_final_delivery_route(
    manifest: &ManifestData,
    artifact_root: &Path,
) -> Result<Vec<String>, ValidationError> {
    let hop1_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.hop-1",
    )?;
    let hop2_identifier = find_public_identifier_by_fixture_id(
        manifest,
        artifact_root,
        "fixture.identity.route.hop-2",
    )?;
    let dropoff_fixture = load_authoring_only_route_dropoff_fixture(artifact_root)?;
    let dropoff_raw = read_file(&dropoff_fixture.path)?;
    let dropoff_value: Value = serde_json::from_str(&dropoff_raw).map_err(|err| {
        ValidationError(format!(
            "failed to parse route dropoff fixture json {}: {}",
            dropoff_fixture.path.display(),
            err
        ))
    })?;
    let dropoff_identifier =
        require_json_string(&dropoff_value, &dropoff_fixture.path, &["identifier"])?;

    Ok(vec![hop1_identifier, hop2_identifier, dropoff_identifier])
}

fn hex_to_digest(labelled_hex: &str, field_name: &str) -> Result<[u8; 32], ValidationError> {
    if labelled_hex.len() != 64 {
        return Err(ValidationError(format!(
            "digest {} must be 64 hex characters, got {}",
            field_name,
            labelled_hex.len()
        )));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in labelled_hex.as_bytes().chunks_exact(2).enumerate() {
        let piece = std::str::from_utf8(chunk).map_err(|err| {
            ValidationError(format!(
                "digest {} contains non-utf8 hex at byte pair {}: {}",
                field_name, index, err
            ))
        })?;
        bytes[index] = u8::from_str_radix(piece, 16).map_err(|err| {
            ValidationError(format!(
                "failed to decode digest {} pair {} ('{}') as hex: {}",
                field_name, index, piece, err
            ))
        })?;
    }
    Ok(bytes)
}

fn load_owned_vid_from_ref(
    base_fixture_path: &Path,
    private_ref: &str,
) -> Result<OwnedVid, ValidationError> {
    let private_path =
        resolve_fixture_reference_path(base_fixture_path, private_ref).ok_or_else(|| {
            ValidationError(format!(
                "private_material_ref target not found from {}: {}",
                base_fixture_path.display(),
                private_ref
            ))
        })?;

    let raw = read_file(&private_path)?;
    serde_json::from_str(&raw).map_err(|err| {
        ValidationError(format!(
            "failed to deserialize OwnedVid from {}: {}",
            private_path.display(),
            err
        ))
    })
}

fn load_local_verified_vid_from_fixture(path: &Path) -> Result<LocalVerifiedVid, ValidationError> {
    let raw = read_file(path)?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| {
        ValidationError(format!(
            "failed to parse verified fixture json {}: {}",
            path.display(),
            err
        ))
    })?;

    let identifier = require_json_string(&value, path, &["identifier"])?;
    let verifying_key =
        decode_fixture_okp_x(path, &value, &["public_material", "verification_key", "x"])?;
    let encryption_key =
        decode_fixture_okp_x(path, &value, &["public_material", "encryption_key", "x"])?;

    Ok(LocalVerifiedVid {
        identifier,
        endpoint: url::Url::parse("https://example.invalid")
            .expect("static placeholder endpoint should parse"),
        verifying_key: verifying_key.into(),
        encryption_key: encryption_key.into(),
    })
}

fn decode_fixture_okp_x(
    path: &Path,
    value: &Value,
    field_path: &[&str],
) -> Result<Vec<u8>, ValidationError> {
    let encoded = require_json_string(value, path, field_path)?;
    Base64UrlUnpadded::decode_vec(&encoded).map_err(|err| {
        ValidationError(format!(
            "failed to decode base64url field {} in {}: {}",
            field_path.join("."),
            path.display(),
            err
        ))
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, ValidationError> {
    if value.len() % 2 != 0 {
        return Err(ValidationError(format!(
            "hex value has odd length: {}",
            value
        )));
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    let mut index = 0usize;
    while index < value.len() {
        let byte = u8::from_str_radix(&value[index..index + 2], 16).map_err(|err| {
            ValidationError(format!("failed to decode hex value {}: {}", value, err))
        })?;
        bytes.push(byte);
        index += 2;
    }
    Ok(bytes)
}

fn decode_wire_artifact_payload(artifact_bytes: &[u8]) -> Result<Vec<u8>, ValidationError> {
    let encoded = std::str::from_utf8(artifact_bytes).map_err(|err| {
        ValidationError(format!(
            "wire artifact is not valid UTF-8 base64url text: {err}"
        ))
    })?;
    Base64UrlUnpadded::decode_vec(encoded).map_err(|err| {
        ValidationError(format!(
            "failed to decode wire artifact base64url payload: {err}"
        ))
    })
}

fn verify_reviewed_value_references(
    manifest: &ManifestData,
    artifact_root: &Path,
    vector_id: &str,
    reviewed_values: &BTreeMap<String, String>,
) -> Result<(), ValidationError> {
    for (key, value) in reviewed_values {
        if key.ends_with("_vector_ref") {
            if vector_artifact_path(artifact_root, manifest, value).is_err() {
                return Err(ValidationError(format!(
                    "vector {} has reviewed value {} pointing outside manifest vector artifact scope: {}",
                    vector_id, key, value
                )));
            }
        } else if key.ends_with("_binding_ref") {
            if !manifest
                .binding_artifact_refs
                .iter()
                .any(|candidate| candidate == value)
            {
                return Err(ValidationError(format!(
                    "vector {} has reviewed value {} pointing outside manifest binding scope: {}",
                    vector_id, key, value
                )));
            }
        } else if key.ends_with("_fixture_ref") {
            if !manifest
                .applicable_fixture_refs
                .iter()
                .any(|candidate| candidate == value)
            {
                return Err(ValidationError(format!(
                    "vector {} has reviewed value {} pointing outside manifest fixture scope: {}",
                    vector_id, key, value
                )));
            }
        }
    }

    Ok(())
}

fn verify_reviewed_identity_values(
    manifest: &ManifestData,
    artifact_root: &Path,
    vector_id: &str,
    reviewed_values: &BTreeMap<String, String>,
) -> Result<(), ValidationError> {
    let fixtures_root = artifact_root.join("fixtures");
    let mut available_identifiers = Vec::new();

    for fixture_id in &manifest.applicable_fixture_refs {
        if !fixture_id.starts_with("fixture.identity.") {
            continue;
        }
        let path = resolve_fixture_path(&fixtures_root, fixture_id)?;
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let raw = read_file(&path)?;
        let value: Value = serde_json::from_str(&raw).map_err(|err| {
            ValidationError(format!(
                "failed to parse identity fixture json {}: {}",
                path.display(),
                err
            ))
        })?;

        if let Some(identifier) = value.get("identifier").and_then(Value::as_str) {
            available_identifiers.push(identifier.to_string());
        }
    }

    for key in [
        "sender_vid",
        "receiver_vid",
        "inner_sender_vid",
        "inner_receiver_vid",
        "next_hop_vid",
    ] {
        if let Some(identifier) = reviewed_values.get(key) {
            if !available_identifiers
                .iter()
                .any(|candidate| candidate == identifier)
            {
                return Err(ValidationError(format!(
                    "vector {} reviewed value {} does not match any identity fixture in scope: {}",
                    vector_id, key, identifier
                )));
            }
        }
    }

    Ok(())
}

fn verify_semantic_constraints(
    vector_id: &str,
    reviewed_values: &BTreeMap<String, String>,
) -> Result<(), ValidationError> {
    match vector_id {
        "SV-001" => {
            require_non_absent(reviewed_values, vector_id, "relationship_context_ref")?;
            require_non_empty(reviewed_values, vector_id, "payload_semantics_ref")?;
        }
        "SV-002" => {
            require_non_absent(reviewed_values, vector_id, "outer_context_ref")?;
            require_non_absent(reviewed_values, vector_id, "inner_context_ref")?;
            require_distinct_values(
                reviewed_values,
                vector_id,
                "outer_context_ref",
                "inner_context_ref",
            )?;
            require_non_empty(reviewed_values, vector_id, "payload_semantics_ref")?;
        }
        "SV-003" => {
            require_non_absent(reviewed_values, vector_id, "path_context_ref")?;
            require_non_empty(reviewed_values, vector_id, "payload_semantics_ref")?;
        }
        "SV-004" => {
            require_exact_value(
                reviewed_values,
                vector_id,
                "source_vector_ref",
                ".vector.SV-001.wire",
            )?;
            require_exact_value(
                reviewed_values,
                vector_id,
                "source_binding_ref",
                ".binding.direct.message-01",
            )?;
            require_full_match(
                reviewed_values,
                vector_id,
                "source_fixture_ref",
                "fixture.conversation.direct.message-01",
            )?;
            require_full_match(
                reviewed_values,
                vector_id,
                "authorization_state",
                "no-prior-relationship",
            )?;
            require_full_match(
                reviewed_values,
                vector_id,
                "relationship_context_ref",
                "absent",
            )?;
        }
        "SV-005" => {
            require_distinct_values(
                reviewed_values,
                vector_id,
                "expected_request_digest",
                "mismatching_accept_digest",
            )?;
        }
        "SV-006" => {
            require_exact_value(
                reviewed_values,
                vector_id,
                "source_vector_ref",
                ".vector.SV-002.wire",
            )?;
            require_exact_value(
                reviewed_values,
                vector_id,
                "source_binding_ref",
                ".binding.nested.message-01",
            )?;
            require_full_match(
                reviewed_values,
                vector_id,
                "source_fixture_ref",
                "fixture.conversation.nested.message-01",
            )?;
            require_full_match(reviewed_values, vector_id, "missing_outer_context", "true")?;
            require_full_match(reviewed_values, vector_id, "outer_context_ref", "absent")?;
            require_non_absent(reviewed_values, vector_id, "inner_context_ref")?;
        }
        _ => {}
    }

    Ok(())
}

fn require_non_empty(
    reviewed_values: &BTreeMap<String, String>,
    vector_id: &str,
    key: &str,
) -> Result<(), ValidationError> {
    let value = reviewed_values.get(key).ok_or_else(|| {
        ValidationError(format!(
            "vector {} is missing reviewed value {}",
            vector_id, key
        ))
    })?;
    if value.trim().is_empty() {
        return Err(ValidationError(format!(
            "vector {} has empty reviewed value {}",
            vector_id, key
        )));
    }
    Ok(())
}

fn require_non_absent(
    reviewed_values: &BTreeMap<String, String>,
    vector_id: &str,
    key: &str,
) -> Result<(), ValidationError> {
    let value = reviewed_values.get(key).ok_or_else(|| {
        ValidationError(format!(
            "vector {} is missing reviewed value {}",
            vector_id, key
        ))
    })?;
    if value == "absent" {
        return Err(ValidationError(format!(
            "vector {} unexpectedly uses absent for {}",
            vector_id, key
        )));
    }
    Ok(())
}

fn require_distinct_values(
    reviewed_values: &BTreeMap<String, String>,
    vector_id: &str,
    left: &str,
    right: &str,
) -> Result<(), ValidationError> {
    let left_value = reviewed_values.get(left).ok_or_else(|| {
        ValidationError(format!(
            "vector {} is missing reviewed value {}",
            vector_id, left
        ))
    })?;
    let right_value = reviewed_values.get(right).ok_or_else(|| {
        ValidationError(format!(
            "vector {} is missing reviewed value {}",
            vector_id, right
        ))
    })?;
    if left_value == right_value {
        return Err(ValidationError(format!(
            "vector {} expects distinct reviewed values for {} and {}",
            vector_id, left, right
        )));
    }
    Ok(())
}

fn require_exact_value(
    reviewed_values: &BTreeMap<String, String>,
    vector_id: &str,
    key: &str,
    expected_suffix: &str,
) -> Result<(), ValidationError> {
    let value = reviewed_values.get(key).ok_or_else(|| {
        ValidationError(format!(
            "vector {} is missing reviewed value {}",
            vector_id, key
        ))
    })?;
    if !value.ends_with(expected_suffix) {
        return Err(ValidationError(format!(
            "vector {} has unexpected {}: {}",
            vector_id, key, value
        )));
    }
    Ok(())
}

fn require_full_match(
    reviewed_values: &BTreeMap<String, String>,
    vector_id: &str,
    key: &str,
    expected: &str,
) -> Result<(), ValidationError> {
    let value = reviewed_values.get(key).ok_or_else(|| {
        ValidationError(format!(
            "vector {} is missing reviewed value {}",
            vector_id, key
        ))
    })?;
    if value != expected {
        return Err(ValidationError(format!(
            "vector {} has unexpected {}: expected {}, got {}",
            vector_id, key, expected, value
        )));
    }
    Ok(())
}

fn verify_binding_fixture_alignment(
    binding_ref: &str,
    binding: &BindingData,
    fixture_ref: &str,
    fixture: &FixtureData,
) -> Result<(), ValidationError> {
    for (key, fixture_value) in &fixture.binding_material {
        if let Some(binding_value) = binding.reviewed_values.get(key) {
            if binding_value != fixture_value {
                return Err(ValidationError(format!(
                    "binding/fixture mismatch for {} and {} on {}: expected {}, got {}",
                    binding_ref, fixture_ref, key, fixture_value, binding_value
                )));
            }
        }
    }

    Ok(())
}

fn verify_binding_review_value_alignment(
    binding_ref: &str,
    binding: &BindingData,
) -> Result<(), ValidationError> {
    for (key, review_value) in &binding.review_value_checks {
        if let Some(binding_value) = binding.reviewed_values.get(key) {
            if review_value == "reviewed" {
                if binding_value.trim().is_empty() {
                    return Err(ValidationError(format!(
                        "binding/review mismatch for {} on {}: review expects a non-empty reviewed value",
                        binding_ref, key
                    )));
                }
                continue;
            }
            if key.ends_with("_rule") || key.ends_with("_relation") {
                if binding_value.trim().is_empty() {
                    return Err(ValidationError(format!(
                        "binding/review mismatch for {} on {}: binding value is empty",
                        binding_ref, key
                    )));
                }
                continue;
            }
            if binding_value != review_value {
                return Err(ValidationError(format!(
                    "binding/review mismatch for {} on {}: expected {}, got {}",
                    binding_ref, key, binding_value, review_value
                )));
            }
        }
    }

    Ok(())
}

fn find_binding_refs_for_vector(
    manifest: &ManifestData,
    artifact_root: &Path,
    vector_id: &str,
) -> Result<Vec<String>, ValidationError> {
    let mut refs = Vec::new();
    for binding_ref in &manifest.binding_artifact_refs {
        let namespace = format!(
            "{}.binding.",
            manifest.artifact_set_id.replace("artifact-set", "artifact")
        );
        let binding_suffix = binding_ref
            .strip_prefix(&namespace)
            .ok_or_else(|| ValidationError(format!("binding ref malformed: {}", binding_ref)))?;
        let binding_path = binding_path_for(artifact_root, binding_suffix);
        let binding_values = parse_yaml_top_level(&read_file(&binding_path)?);
        let related_vectors = list_values(&binding_values, "related_vectors");
        if related_vectors
            .iter()
            .any(|candidate| candidate == vector_id)
        {
            refs.push(binding_ref.clone());
        }
    }
    Ok(refs)
}

fn vector_artifact_path(
    artifact_root: &Path,
    manifest: &ManifestData,
    artifact_ref: &str,
) -> Result<PathBuf, ValidationError> {
    let namespace = format!(
        "{}.vector.",
        manifest.artifact_set_id.replace("artifact-set", "artifact")
    );
    let suffix = artifact_ref.strip_prefix(&namespace).ok_or_else(|| {
        ValidationError(format!("vector artifact ref malformed: {}", artifact_ref))
    })?;
    let vector_id = suffix.strip_suffix(".wire").ok_or_else(|| {
        ValidationError(format!("vector artifact ref malformed: {}", artifact_ref))
    })?;
    Ok(artifact_root
        .join("vectors")
        .join(vector_id)
        .join("wire.base64"))
}

fn emit_records_jsonl(records: &[ValidationRecord]) {
    for record in records {
        let value = serde_json::json!({
            "vector_id": record.vector_id,
            "case_id": record.case_id,
            "classification": record.classification,
            "artifact_ref": record.artifact_ref,
            "binding_refs": record.binding_refs,
            "fixture_refs": record.fixture_refs,
            "result": record.result,
            "comparison_boundary_used": record.comparison_boundary_used,
            "notes": record.notes,
        });
        println!("{}", value);
    }
}

fn required_reviewed_value_keys(vector_id: &str) -> &'static [&'static str] {
    match vector_id {
        "BV-001" => &["request_digest", "nonce", "sender_vid", "receiver_vid"],
        "BV-002" => &[
            "request_digest",
            "reply_digest",
            "sender_vid",
            "receiver_vid",
        ],
        "BV-003" => &["digest", "reviewed_context"],
        "BV-004" => &[
            "request_digest",
            "nonce",
            "outer_context_ref",
            "inner_sender_vid",
        ],
        "BV-005" => &[
            "request_digest",
            "reply_digest",
            "outer_context_ref",
            "inner_sender_vid",
            "inner_receiver_vid",
        ],
        "BV-006" => &["next_hop_vid", "remaining_route_ref", "opaque_payload_ref"],
        "BV-007" => &[
            "request_digest",
            "nonce",
            "path_context_ref",
            "sender_vid",
            "receiver_vid",
        ],
        "BV-008" => &["request_digest", "reply_digest", "path_context_ref"],
        "SV-001" => &["relationship_context_ref", "payload_semantics_ref"],
        "SV-002" => &[
            "outer_context_ref",
            "inner_context_ref",
            "payload_semantics_ref",
        ],
        "SV-003" => &["path_context_ref", "payload_semantics_ref"],
        "SV-004" => &[
            "source_vector_ref",
            "source_binding_ref",
            "source_fixture_ref",
            "authorization_state",
            "relationship_context_ref",
            "payload_semantics_ref",
        ],
        "SV-005" => &["expected_request_digest", "mismatching_accept_digest"],
        "SV-006" => &[
            "source_vector_ref",
            "source_binding_ref",
            "source_fixture_ref",
            "missing_outer_context",
            "outer_context_ref",
            "inner_context_ref",
            "payload_semantics_ref",
        ],
        "AV-001" => &["confidentiality_mechanism", "sender_field_rule"],
        "AV-002" => &["confidentiality_mechanism", "cesr_ciphertext_family"],
        "AV-003" => &["confidentiality_mechanism", "binding_rule"],
        _ => &[],
    }
}
