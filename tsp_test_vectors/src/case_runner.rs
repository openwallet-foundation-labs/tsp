use std::path::Path;

use crate::validator::{
    CaseOutputValidationRecord, CaseValidationBundle, ReplayProbeRecord, ReplayProbeStatus,
    ValidationError, ValidationSummary, collect_case_validation_bundles,
    collect_case_validation_bundles_relaxed,
};

#[derive(Debug)]
pub struct CaseRunnerReport {
    pub summary: ValidationSummary,
    pub case_output: CaseOutputValidationRecord,
    pub replay_records: Vec<ReplayProbeRecord>,
}

pub fn collect_case_runner_reports(
    package_root: &Path,
    vector_catalog: &Path,
) -> Result<Vec<CaseRunnerReport>, ValidationError> {
    Ok(convert_bundles(collect_case_validation_bundles(
        package_root,
        vector_catalog,
    )?))
}

pub fn collect_case_runner_reports_relaxed(
    package_root: &Path,
    vector_catalog: &Path,
) -> Result<Vec<CaseRunnerReport>, ValidationError> {
    Ok(convert_bundles(collect_case_validation_bundles_relaxed(
        package_root,
        vector_catalog,
    )?))
}

pub fn render_case_runner_report(report: &CaseRunnerReport) -> String {
    let verified = report
        .replay_records
        .iter()
        .filter(|record| record.status == ReplayProbeStatus::Verified)
        .count();
    let failed = report
        .replay_records
        .iter()
        .filter(|record| record.status == ReplayProbeStatus::Failed)
        .count();
    let not_attempted = report
        .replay_records
        .iter()
        .filter(|record| record.status == ReplayProbeStatus::NotAttempted)
        .count();

    let mut lines = vec![
        format!(
            "{} | vectors={} fixtures={} bindings={} identity_reviews={}",
            report.summary.case_id,
            report.summary.vectors,
            report.summary.fixtures,
            report.summary.bindings,
            report.summary.identity_fixture_reviews
        ),
        format!(
            "  replay status: verified={} failed={} not-attempted={}",
            verified, failed, not_attempted
        ),
        format!(
            "  case outputs: status={} positive={}/{} negative(represented)={}/{} negative(actual)={}/{}",
            report.case_output.status,
            report.case_output.matched_positive_outcomes.len(),
            report.case_output.expected_positive_outcomes.len(),
            report.case_output.represented_negative_outcomes.len(),
            report.case_output.expected_negative_outcomes.len(),
            report.case_output.matched_negative_outcomes.len(),
            report.case_output.expected_negative_outcomes.len(),
        ),
        format!(
            "  relationship summaries: {}/{} | message summaries: {}/{} | family/mechanism: {}/{} + {}/{}",
            report.case_output.matched_relationship_state_summary.len(),
            report.case_output.expected_relationship_state_summary.len(),
            report.case_output.matched_message_flow_summary.len(),
            report.case_output.expected_message_flow_summary.len(),
            report.case_output.matched_family_summary.len(),
            report.case_output.expected_family_summary.len(),
            report.case_output.matched_mechanism_summary.len(),
            report.case_output.expected_mechanism_summary.len(),
        ),
    ];

    if !report.case_output.missing_checks.is_empty() {
        lines.push("  missing checks:".to_string());
        for missing in &report.case_output.missing_checks {
            lines.push(format!("    - {missing}"));
        }
    }

    let failed_vectors = report
        .replay_records
        .iter()
        .filter(|record| record.status == ReplayProbeStatus::Failed)
        .collect::<Vec<_>>();
    if !failed_vectors.is_empty() {
        lines.push("  replay failures:".to_string());
        for record in failed_vectors {
            lines.push(format!(
                "    - {}: {}",
                record.vector_id,
                record
                    .error
                    .as_deref()
                    .unwrap_or("failed without an explicit error message")
            ));
        }
    }

    lines.push(String::new());
    lines.join("\n")
}

fn convert_bundles(bundles: Vec<CaseValidationBundle>) -> Vec<CaseRunnerReport> {
    bundles
        .into_iter()
        .map(|bundle| CaseRunnerReport {
            summary: bundle.summary,
            case_output: bundle.case_output,
            replay_records: bundle.replay_records,
        })
        .collect()
}
