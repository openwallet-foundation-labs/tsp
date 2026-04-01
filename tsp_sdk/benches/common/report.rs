use serde_json::Value;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

pub fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn project_root() -> anyhow::Result<PathBuf> {
    // Bench targets run in the workspace; `CARGO_MANIFEST_DIR` points at `tsp_sdk/`.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow("failed to find workspace root"))?;
    Ok(root.to_path_buf())
}

pub fn git_sha(project_root: &Path) -> anyhow::Result<String> {
    if let Ok(sha) = env::var("GITHUB_SHA") {
        if !sha.trim().is_empty() {
            return Ok(sha);
        }
    }
    let out = Command::new("git")
        .current_dir(project_root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow("git rev-parse HEAD failed"));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

pub fn rfc3339_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn rustc_version() -> anyhow::Result<String> {
    let out = Command::new("rustc").arg("-V").output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow("rustc -V failed"));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

pub fn environment(tool_versions: &Value) -> anyhow::Result<Value> {
    let runner = match env::var("GITHUB_ACTIONS") {
        Ok(v) if v == "true" => "github-actions",
        _ => "local",
    };

    Ok(serde_json::json!({
        "os": env::consts::OS,
        "arch": env::consts::ARCH,
        "runner": runner,
        "rustc": rustc_version()?,
        "tools": tool_versions,
    }))
}

pub fn read_lock_version(project_root: &Path, package_name: &str) -> Option<String> {
    let lock_path = project_root.join("Cargo.lock");
    let contents = std::fs::read_to_string(lock_path).ok()?;

    let mut in_pkg = false;
    let mut name: Option<&str> = None;

    for line in contents.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_pkg = true;
            name = None;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            name = rest.trim().trim_matches('"').into();
            continue;
        }
        if name == Some(package_name) {
            if let Some(rest) = line.strip_prefix("version = ") {
                return Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

pub fn make_relative_path(project_root: &Path, path: &str) -> String {
    let project_root = project_root.to_string_lossy();
    if let Some(rel) = path.strip_prefix(project_root.as_ref()) {
        return rel.trim_start_matches('/').to_string();
    }
    path.to_string()
}

pub struct Args {
    pub output: PathBuf,
}

impl Args {
    pub fn parse(
        bench_target: &str,
        default_output: &str,
        description: &str,
    ) -> anyhow::Result<Self> {
        let mut output: Option<PathBuf> = None;

        let mut it = env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--output" => {
                    let p = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow("--output requires a value"))?;
                    output = Some(PathBuf::from(p));
                }
                "-h" | "--help" => {
                    print_help(bench_target, default_output, description);
                    std::process::exit(0);
                }
                // Ignore any other arguments (cargo/libtest flags or future passthroughs).
                _other => {}
            }
        }

        Ok(Self {
            output: output.unwrap_or_else(|| PathBuf::from(default_output)),
        })
    }
}

fn print_help(bench_target: &str, default_output: &str, description: &str) {
    eprintln!(
        "Usage:\n  cargo bench -p tsp_sdk --bench {bench}\n  cargo bench -p tsp_sdk --bench {bench} -- --output <path>\n\n{description}\n\n\
Args:\n  --output  Output path (default: {default_output})\n",
        bench = bench_target,
        description = description,
        default_output = default_output,
    );
}

pub mod anyhow {
    pub type Result<T> = std::result::Result<T, Error>;

    pub struct Error(String);

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for Error {}

    pub fn anyhow(msg: impl Into<String>) -> Error {
        Error(msg.into())
    }

    impl From<std::io::Error> for Error {
        fn from(value: std::io::Error) -> Self {
            Error(value.to_string())
        }
    }

    impl From<std::env::VarError> for Error {
        fn from(value: std::env::VarError) -> Self {
            Error(value.to_string())
        }
    }

    impl From<serde_json::Error> for Error {
        fn from(value: serde_json::Error) -> Self {
            Error(value.to_string())
        }
    }

    impl From<std::string::FromUtf8Error> for Error {
        fn from(value: std::string::FromUtf8Error) -> Self {
            Error(value.to_string())
        }
    }
}
