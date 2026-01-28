use serde_json::Value;
use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() -> anyhow::Result<()> {
    let args = Args::parse()?;

    let project_root = project_root()?;
    ensure_callgrind_prereqs(&project_root)?;
    let output_path = project_root.join(&args.output);
    ensure_parent_dir(&output_path)?;

    let git_sha = git_sha(&project_root)?;
    let timestamp = env::var("BENCH_TIMESTAMP").unwrap_or_else(|_| rfc3339_now());
    let tool_versions = tool_versions(&project_root)?;
    let environment = environment(&tool_versions)?;

    let mut writer = BufWriter::new(File::create(&output_path)?);

    let mut parsed_count = 0usize;
    for run in guardrail_runs() {
        let raw_stdout = run_callgrind(&project_root, &run)?;
        let summaries = iter_json_values(&raw_stdout)?;

        let artifacts_summary_path =
            write_iai_summaries_artifact(&output_path, run.variant, &summaries)?;
        let artifacts_summary_path = make_relative_path(
            &project_root,
            artifacts_summary_path.to_string_lossy().as_ref(),
        );

        for summary in summaries {
            let Some(details) = summary.get("details").and_then(|v| v.as_str()) else {
                // Not a per-benchmark summary (or unexpected format).
                continue;
            };
            let benchmark_id = extract_benchmark_id(details)?;
            let ir = extract_ir(&summary)?;
            let artifacts = extract_callgrind_artifacts(&summary, &project_root);

            let record = serde_json::json!({
                "schema_version": "v1",
                "suite": "guardrail",
                "tool": "callgrind",
                "benchmark_id": benchmark_id,
                "metric": "Ir",
                "value": ir,
                "unit": "instructions",
                "git_sha": git_sha,
                "timestamp": timestamp,
                "environment": environment,
                "run": {
                    "variant": run.variant,
                    "bench_target": run.bench_target,
                    "cargo": {
                        "no_default_features": run.cargo.no_default_features,
                        "features": run.cargo.features,
                    },
                },
                "artifacts": {
                    "iai_summaries_json": artifacts_summary_path,
                    "callgrind": artifacts,
                }
            });
            writeln!(writer, "{}", serde_json::to_string(&record)?)?;
            parsed_count += 1;
        }
    }

    writer.flush()?;

    if parsed_count == 0 {
        return Err(anyhow::anyhow(
            "parsed 0 benchmark summaries from `cargo bench` output; did callgrind run?",
        ));
    }

    eprintln!("wrote {}", output_path.display());
    Ok(())
}

fn iter_json_values(stdout: &str) -> anyhow::Result<Vec<Value>> {
    // `iai-callgrind` may output either:
    // - multiple JSON objects (one per benchmark), separated by whitespace/newlines
    // - a JSON array of BenchmarkSummary objects
    //
    // Use serde's streaming deserializer to handle both, and be tolerant of pretty-printed JSON.
    let start = stdout
        .find(|c| c == '{' || c == '[')
        .unwrap_or(stdout.len());
    let json = &stdout[start..];

    let mut values = Vec::new();
    let mut stream = serde_json::Deserializer::from_str(json).into_iter::<Value>();
    while let Some(next) = stream.next() {
        let value = next?;
        match value {
            Value::Array(items) => values.extend(items),
            other => values.push(other),
        }
    }
    Ok(values)
}

fn ensure_callgrind_prereqs(project_root: &Path) -> anyhow::Result<()> {
    // `iai-callgrind` is a proc-macro + runner architecture; the benchmark binary delegates
    // execution to an external `iai-callgrind-runner` binary (which then runs Callgrind/Valgrind).
    let runner_cmd = match env::var("IAI_CALLGRIND_RUNNER") {
        Ok(p) if !p.trim().is_empty() => {
            if !Path::new(&p).is_file() {
                return Err(anyhow::anyhow(format!(
                    "IAI_CALLGRIND_RUNNER is set but not a file: {p}"
                )));
            }
            p
        }
        _ => "iai-callgrind-runner".to_string(),
    };

    if !command_exists(&runner_cmd) {
        return Err(anyhow::anyhow(concat!(
            "missing `iai-callgrind-runner` in $PATH.\n",
            "\n",
            "Install it with:\n",
            "  cargo install iai-callgrind-runner\n",
            "\n",
            "Or set an absolute path:\n",
            "  IAI_CALLGRIND_RUNNER=/abs/path/to/iai-callgrind-runner\n",
        )));
    }

    if let (Some(required), Some(installed)) = (
        read_lock_version(project_root, "iai-callgrind"),
        detect_iai_callgrind_runner_version(&runner_cmd),
    ) && installed != required
    {
        return Err(anyhow::anyhow(format!(
            "iai-callgrind version mismatch.\n\n\
Workspace uses `iai-callgrind` v{required}, but `iai-callgrind-runner` is v{installed}.\n\n\
Fix by installing the matching runner:\n\
  cargo install iai-callgrind-runner --version {required}\n"
        )));
    }

    if !command_exists("valgrind") {
        return Err(anyhow::anyhow(concat!(
            "missing `valgrind` in $PATH (required for Callgrind).\n",
            "\n",
            "Install it via your system package manager and try again.\n",
        )));
    }

    if !callgrind_smoke_test() {
        return Err(anyhow::anyhow(concat!(
            "valgrind Callgrind is not working on this machine (smoke test failed).\n",
            "\n",
            "This is common on some macOS versions/builds where Valgrind is unsupported or unstable.\n",
            "\n",
            "Recommended: run the Guardrail Suite on Linux (CI), where Callgrind is best supported.\n",
            "\n",
            "On macOS, you can run the Guardrail Suite via Docker:\n",
            "  bash tsp_sdk/benches/guardrail/run_docker.sh\n",
        )));
    }

    Ok(())
}

fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn callgrind_smoke_test() -> bool {
    // Ensure the full chain works (`valgrind --tool=callgrind`) rather than merely existing.
    // Keep this extremely small to avoid adding noticeable overhead.
    // Always write to a temp file to avoid polluting the workspace with `callgrind.out.<pid>`.
    let out_path = env::temp_dir().join(format!("tsp-callgrind-smoke.{}.out", std::process::id()));
    let out_arg = format!("--callgrind-out-file={}", out_path.display());

    let status = Command::new("valgrind")
        .args([
            "--tool=callgrind",
            "--quiet",
            out_arg.as_str(),
            "/usr/bin/true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let ok = status.is_ok_and(|s| s.success());
    let _ = std::fs::remove_file(out_path);
    ok
}

fn read_lock_version(project_root: &Path, package_name: &str) -> Option<String> {
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

fn detect_iai_callgrind_runner_version(runner_cmd: &str) -> Option<String> {
    // Newer runners may not support `--version`. They do, however, print their version on error.
    let out = Command::new(runner_cmd).output().ok()?;
    let mut text = Vec::new();
    text.extend_from_slice(&out.stdout);
    text.extend_from_slice(&out.stderr);
    let text = String::from_utf8_lossy(&text);

    let marker = "Detected version of iai-callgrind-runner is ";
    if let Some(idx) = text.find(marker) {
        let rest = &text[idx + marker.len()..];
        let version: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let version = version.trim_end_matches('.').to_string();
        if !version.is_empty() {
            return Some(version);
        }
    }

    None
}

struct Args {
    output: PathBuf,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
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
                    print_help();
                    std::process::exit(0);
                }
                // Ignore any other arguments (cargo/libtest flags or future passthroughs).
                _other => {}
            }
        }

        Ok(Self {
            output: output.unwrap_or_else(|| PathBuf::from("target/bench-results/guardrail.jsonl")),
        })
    }
}

fn print_help() {
    eprintln!(
        "Usage:\n  cargo bench -p tsp_sdk --bench guardrail_report\n  cargo bench -p tsp_sdk --bench guardrail_report -- --output <path>\n\n\
Runs the Guardrail Suite under iai-callgrind (Callgrind `Ir`) and writes canonical JSONL.\n\n\
Args:\n  --output  Output path (default: target/bench-results/guardrail.jsonl)\n"
    );
}

#[derive(Clone, Copy)]
struct GuardrailRun {
    variant: &'static str,
    bench_target: &'static str,
    cargo: CargoRun,
}

#[derive(Clone, Copy)]
struct CargoRun {
    no_default_features: bool,
    features: &'static [&'static str],
}

fn guardrail_runs() -> Vec<GuardrailRun> {
    vec![
        GuardrailRun {
            variant: "default",
            bench_target: "guardrail",
            cargo: CargoRun {
                no_default_features: false,
                features: &["resolve"],
            },
        },
        GuardrailRun {
            variant: "hpke",
            bench_target: "guardrail_hpke",
            cargo: CargoRun {
                no_default_features: true,
                features: &["resolve"],
            },
        },
        GuardrailRun {
            variant: "pq",
            bench_target: "guardrail_pq",
            cargo: CargoRun {
                no_default_features: true,
                features: &["pq", "resolve"],
            },
        },
    ]
}

fn run_callgrind(project_root: &Path, run: &GuardrailRun) -> anyhow::Result<String> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);

    cmd.current_dir(project_root)
        .arg("bench")
        .arg("-p")
        .arg("tsp_sdk")
        .arg("--bench")
        .arg(run.bench_target);

    if run.cargo.no_default_features {
        cmd.arg("--no-default-features");
    }

    if !run.cargo.features.is_empty() {
        cmd.arg("--features").arg(run.cargo.features.join(","));
    }

    cmd.arg("--")
        .arg("--output-format=json")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow("failed to capture child stdout"))?;

    let mut out = String::new();
    let mut reader = BufReader::new(stdout);
    reader.read_to_string(&mut out)?;

    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow(format!(
            "{bench} callgrind failed: {status}",
            bench = run.bench_target
        )));
    }

    Ok(out)
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn project_root() -> anyhow::Result<PathBuf> {
    // This bench target runs in the workspace; `CARGO_MANIFEST_DIR` points at `tsp_sdk/`.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow("failed to find workspace root"))?;
    Ok(root.to_path_buf())
}

fn git_sha(project_root: &Path) -> anyhow::Result<String> {
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

fn rfc3339_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn rustc_version() -> anyhow::Result<String> {
    let out = Command::new("rustc").arg("-V").output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow("rustc -V failed"));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn environment(tool_versions: &Value) -> anyhow::Result<Value> {
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

fn tool_versions(project_root: &Path) -> anyhow::Result<Value> {
    let iai_callgrind = read_lock_version(project_root, "iai-callgrind")
        .ok_or_else(|| anyhow::anyhow("failed to detect iai-callgrind version from Cargo.lock"))?;

    let runner_cmd = match env::var("IAI_CALLGRIND_RUNNER") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => "iai-callgrind-runner".to_string(),
    };
    let iai_callgrind_runner =
        detect_iai_callgrind_runner_version(&runner_cmd).unwrap_or_else(|| "unknown".to_string());

    let valgrind = valgrind_version().unwrap_or_else(|| "unknown".to_string());

    Ok(serde_json::json!({
        "iai_callgrind": iai_callgrind,
        "iai_callgrind_runner": iai_callgrind_runner,
        "valgrind": valgrind,
    }))
}

fn valgrind_version() -> Option<String> {
    let out = Command::new("valgrind").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();
    // Typical: "valgrind-3.19.0"
    let v = line.strip_prefix("valgrind-").unwrap_or(&line).to_string();
    Some(v)
}

fn write_iai_summaries_artifact(
    output_path: &Path,
    variant: &str,
    summaries: &[Value],
) -> anyhow::Result<PathBuf> {
    // Store a stable, machine-readable artifact for debugging and AI/CI analysis.
    // This avoids depending on whatever stdout format `iai-callgrind` chose.
    let stem = output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("guardrail");
    let filename = format!("{stem}.{variant}.iai.json");
    let path = output_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(filename);
    ensure_parent_dir(&path)?;
    let f = File::create(&path)?;
    serde_json::to_writer_pretty(f, summaries)?;
    Ok(path)
}

fn make_relative_path(project_root: &Path, path: &str) -> String {
    let project_root = project_root.to_string_lossy();
    if let Some(rel) = path.strip_prefix(project_root.as_ref()) {
        return rel.trim_start_matches('/').to_string();
    }
    path.to_string()
}

fn extract_callgrind_artifacts(summary: &Value, project_root: &Path) -> Value {
    let Some(profiles) = summary.get("profiles").and_then(|v| v.as_array()) else {
        return serde_json::json!({});
    };

    for profile in profiles {
        if profile.get("tool").and_then(|v| v.as_str()) != Some("Callgrind") {
            continue;
        }

        let out_paths: Vec<String> = profile
            .get("out_paths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|p| make_relative_path(project_root, p))
                    .collect()
            })
            .unwrap_or_default();

        let log_paths: Vec<String> = profile
            .get("log_paths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|p| make_relative_path(project_root, p))
                    .collect()
            })
            .unwrap_or_default();

        let flamegraphs: Vec<String> = profile
            .get("flamegraphs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|fg| {
                        fg.get("regular_path")
                            .or_else(|| fg.get("diff_path"))
                            .or_else(|| fg.get("old_path"))
                            .and_then(|v| v.as_str())
                    })
                    .map(|p| make_relative_path(project_root, p))
                    .collect()
            })
            .unwrap_or_default();

        return serde_json::json!({
            "out_paths": out_paths,
            "log_paths": log_paths,
            "flamegraphs": flamegraphs,
        });
    }

    serde_json::json!({})
}

fn extract_benchmark_id(details: &str) -> anyhow::Result<String> {
    let needle = "\"guardrail.";
    let Some(start) = details.find(needle) else {
        return Err(anyhow::anyhow(format!(
            "missing canonical benchmark id in details: {details}"
        )));
    };
    let start = start + 1; // skip the opening '"'
    let Some(end_rel) = details[start..].find('"') else {
        return Err(anyhow::anyhow(format!(
            "unterminated string literal in details: {details}"
        )));
    };
    let benchmark_id = &details[start..start + end_rel];
    if !benchmark_id.starts_with("guardrail.") {
        return Err(anyhow::anyhow(format!(
            "unexpected benchmark_id extracted: {benchmark_id}"
        )));
    }
    Ok(benchmark_id.to_string())
}

fn extract_ir(summary: &Value) -> anyhow::Result<u64> {
    // iai-callgrind-runner >= 0.16 emits metrics under `profiles`.
    // (Older versions used `callgrind_summary.callgrind_run.events.*`.)
    let metrics = if let Some(profiles) = summary.get("profiles").and_then(|v| v.as_array()) {
        let mut found: Option<&Value> = None;
        for profile in profiles {
            if profile.get("tool").and_then(|v| v.as_str()) != Some("Callgrind") {
                continue;
            }
            let candidate = &profile["summaries"]["total"]["summary"]["Callgrind"]["Ir"]["metrics"];
            if !candidate.is_null() {
                found = Some(candidate);
                break;
            }
        }
        found.ok_or_else(|| anyhow::anyhow("missing Callgrind Ir metrics in profiles"))?
    } else if let Some(callgrind_summary) = summary.get("callgrind_summary") {
        let metrics = &callgrind_summary["callgrind_run"]["events"]["Ir"]["metrics"];
        if metrics.is_null() {
            return Err(anyhow::anyhow("missing Ir metrics"));
        }
        metrics
    } else {
        return Err(anyhow::anyhow(
            "missing callgrind metrics (expected `profiles` with Callgrind summary)",
        ));
    };

    // `metrics` is EitherOrBoth_for_uint64: {Left}, {Right}, or {Both:[new, old]}
    if let Some(left) = metrics.get("Left") {
        return parse_metric_u64(left)
            .ok_or_else(|| anyhow::anyhow(format!("unexpected Ir Left metric shape: {left}")));
    }
    if let Some(both) = metrics.get("Both").and_then(|v| v.as_array())
        && both.len() == 2
        && let Some(new) = parse_metric_u64(&both[0])
    {
        return Ok(new);
    }
    if let Some(right) = metrics.get("Right") {
        return parse_metric_u64(right)
            .ok_or_else(|| anyhow::anyhow(format!("unexpected Ir Right metric shape: {right}")));
    }

    Err(anyhow::anyhow(format!(
        "unexpected Ir metrics shape: {metrics}"
    )))
}

fn parse_metric_u64(metric: &Value) -> Option<u64> {
    if let Some(n) = metric.as_u64() {
        return Some(n);
    }
    if let Some(n) = metric.get("Int").and_then(|v| v.as_u64()) {
        return Some(n);
    }
    None
}

mod anyhow {
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
