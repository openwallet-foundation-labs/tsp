use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_assets_root(case: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("tsp-vector-generate-report-{case}-{nanos}-{seq}"))
}

fn run_generate_case_report(case: &str) -> String {
    let assets_root = temp_assets_root(case);
    let output = Command::new(env!("CARGO_BIN_EXE_tsp-vector-generate"))
        .args([
            "case",
            "--case",
            case,
            "--assets-root",
            assets_root.to_str().unwrap(),
            "--report",
        ])
        .output()
        .unwrap_or_else(|err| panic!("failed to run tsp-vector-generate for {case}: {err}"));

    assert!(
        output.status.success(),
        "tsp-vector-generate failed for {case}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("stdout for {case} was not valid UTF-8: {err}"));

    assert!(
        stdout.contains("generated 17 vectors"),
        "expected generation summary for {case}, got:\n{stdout}"
    );
    assert!(
        stdout.contains("replay status: verified=12 failed=2 not-attempted=3"),
        "expected replay report summary for {case}, got:\n{stdout}"
    );
    assert!(
        stdout.contains("case outputs: status=incomplete positive=6/6"),
        "expected case output summary for {case}, got:\n{stdout}"
    );

    stdout
}

#[cfg(all(not(feature = "essr"), not(feature = "nacl"), not(feature = "pq")))]
#[test]
fn generate_case_report_cc001_works_end_to_end() {
    let stdout = run_generate_case_report("cc001");
    assert!(
        stdout.contains("CC-001 | vectors=17 fixtures=24 bindings=17 identity_reviews=11"),
        "expected CC-001 report header, got:\n{stdout}"
    );
}

#[cfg(feature = "essr")]
#[test]
fn generate_case_report_cc002_works_end_to_end() {
    let stdout = run_generate_case_report("cc002");
    assert!(
        stdout.contains("CC-002 | vectors=17 fixtures=24 bindings=17 identity_reviews=11"),
        "expected CC-002 report header, got:\n{stdout}"
    );
}

#[cfg(feature = "nacl")]
#[test]
fn generate_case_report_cc003_works_end_to_end() {
    let stdout = run_generate_case_report("cc003");
    assert!(
        stdout.contains("CC-003 | vectors=17 fixtures=24 bindings=17 identity_reviews=11"),
        "expected CC-003 report header, got:\n{stdout}"
    );
}
