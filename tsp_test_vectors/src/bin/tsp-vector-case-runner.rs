use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tsp_test_vectors::case_runner::{collect_case_runner_reports, render_case_runner_report};
use tsp_test_vectors::layout::{DEFAULT_PACKAGE_ROOT, DEFAULT_VECTOR_CATALOG};

#[derive(Debug, Parser)]
#[command(name = "tsp-vector-case-runner", version)]
#[command(about = "Run case-level validation and report current replay/output status")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Report all complete cases under one package root")]
    All {
        #[arg(long = "package-root", default_value = DEFAULT_PACKAGE_ROOT)]
        package_root: PathBuf,
        #[arg(long = "vector-catalog", default_value = DEFAULT_VECTOR_CATALOG)]
        vector_catalog: PathBuf,
    },
    #[command(about = "Report one complete case under one package root")]
    Case {
        #[arg(long, value_enum)]
        case: CaseArg,
        #[arg(long = "package-root", default_value = DEFAULT_PACKAGE_ROOT)]
        package_root: PathBuf,
        #[arg(long = "vector-catalog", default_value = DEFAULT_VECTOR_CATALOG)]
        vector_catalog: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CaseArg {
    Cc001,
    Cc002,
    Cc003,
}

impl CaseArg {
    fn case_id(self) -> &'static str {
        match self {
            Self::Cc001 => "CC-001",
            Self::Cc002 => "CC-002",
            Self::Cc003 => "CC-003",
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::All {
            package_root,
            vector_catalog,
        } => {
            let reports = collect_case_runner_reports(&package_root, &vector_catalog)?;
            for report in &reports {
                print!("{}", render_case_runner_report(report));
            }
        }
        Command::Case {
            case,
            package_root,
            vector_catalog,
        } => {
            let reports = collect_case_runner_reports(&package_root, &vector_catalog)?;
            let report = reports
                .into_iter()
                .find(|report| report.summary.case_id == case.case_id())
                .ok_or_else(|| {
                    format!(
                        "case {} not found under {}",
                        case.case_id(),
                        package_root.display()
                    )
                })?;
            print!("{}", render_case_runner_report(&report));
        }
    }

    Ok(())
}
