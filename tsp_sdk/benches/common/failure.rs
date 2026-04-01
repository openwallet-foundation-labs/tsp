use std::{
    env,
    fs::File,
    io,
    path::{Path, PathBuf},
};

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct FailureStats {
    pub failures: u64,
    pub total: u64,
}

#[allow(dead_code)]
pub fn clear_failure_summaries(project_root: &Path) -> io::Result<()> {
    let dir = failure_dir(project_root);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

#[allow(dead_code)]
pub fn write_failure_summary(benchmark_id: &str, failures: u64, total: u64) -> io::Result<()> {
    let root = workspace_root()?;
    let path = failure_summary_path(&root, benchmark_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let payload = serde_json::json!({
        "benchmark_id": benchmark_id,
        "failures": failures,
        "total": total,
    });
    let file = File::create(path)?;
    serde_json::to_writer(file, &payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

#[allow(dead_code)]
pub fn read_failure_summary(
    project_root: &Path,
    benchmark_id: &str,
) -> io::Result<Option<FailureStats>> {
    let path = failure_summary_path(project_root, benchmark_id);
    if !path.exists() {
        return Ok(None);
    }

    let value: serde_json::Value = serde_json::from_reader(File::open(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let failures = value
        .get("failures")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing failures"))?;
    let total = value
        .get("total")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing total"))?;
    Ok(Some(FailureStats { failures, total }))
}

#[allow(dead_code)]
fn workspace_root() -> io::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("CARGO_MANIFEST_DIR: {error}"),
        )
    })?);
    manifest_dir
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "failed to find workspace root"))
}

fn failure_dir(project_root: &Path) -> PathBuf {
    project_root.join("target/bench-results/failures")
}

fn failure_summary_path(project_root: &Path, benchmark_id: &str) -> PathBuf {
    let file_name = benchmark_id.replace('/', "__");
    failure_dir(project_root).join(format!("{file_name}.json"))
}
