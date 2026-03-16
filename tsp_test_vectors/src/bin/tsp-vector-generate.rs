use clap::{Parser, Subcommand, ValueEnum};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tsp_test_vectors::authoring::{
    CompleteCase, GenerateCaseRequest, GenerateVectorRequest, generate_case_package,
    generate_vector_asset_set,
};
use tsp_test_vectors::case_runner::{
    collect_case_runner_reports_relaxed, render_case_runner_report,
};
use tsp_test_vectors::validator::validate_case_package;

#[derive(Debug, Parser)]
#[command(name = "tsp-vector-generate", version)]
#[command(about = "Generate TSP test-vector case packages or individual vector assets")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Generate all currently supported vectors for one case")]
    Case {
        #[arg(long, value_enum)]
        case: CaseArg,
        #[arg(long = "assets-root")]
        assets_root: PathBuf,
        #[arg(long)]
        validate: bool,
        #[arg(long)]
        report: bool,
    },
    #[command(about = "Generate one vector for one case")]
    Vector {
        #[arg(long, value_enum)]
        case: CaseArg,
        #[arg(long)]
        vector: String,
        #[arg(long = "assets-root")]
        assets_root: PathBuf,
        #[arg(long)]
        validate: bool,
    },
    #[command(
        about = "Generate one case into a fresh temporary root and validate it against canonical reviewed records"
    )]
    ProbeCase {
        #[arg(long, value_enum)]
        case: CaseArg,
        #[arg(long)]
        report: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CaseArg {
    Cc001,
    Cc002,
    Cc003,
}

impl From<CaseArg> for CompleteCase {
    fn from(value: CaseArg) -> Self {
        match value {
            CaseArg::Cc001 => CompleteCase::Cc001,
            CaseArg::Cc002 => CompleteCase::Cc002,
            CaseArg::Cc003 => CompleteCase::Cc003,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Case {
            case,
            assets_root,
            validate,
            report,
        } => {
            let case: CompleteCase = case.into();
            let results =
                generate_case_package(&GenerateCaseRequest::new(case, &assets_root)).await?;
            println!(
                "generated {} vectors for {} under {}",
                results.len(),
                case.case_id(),
                assets_root.display()
            );
            for result in results {
                println!("  - {}", result.vector_id);
            }

            if validate {
                validate_generated_case(&assets_root, case)?;
            }
            if report {
                print_case_report(&assets_root, case)?;
            }
        }
        Command::Vector {
            case,
            vector,
            assets_root,
            validate,
        } => {
            let case: CompleteCase = case.into();
            let result =
                generate_vector_asset_set(&GenerateVectorRequest::new(case, &vector, &assets_root))
                    .await?;
            println!(
                "generated {} for {} under {}",
                result.vector_id,
                case.case_id(),
                assets_root.display()
            );

            if validate {
                validate_generated_case(&assets_root, case)?;
            }
        }
        Command::ProbeCase { case, report } => {
            let case: CompleteCase = case.into();
            let assets_root = temp_probe_root(case);
            let results =
                generate_case_package(&GenerateCaseRequest::new(case, &assets_root)).await?;
            println!(
                "generated {} vectors for {} under {}",
                results.len(),
                case.case_id(),
                assets_root.display()
            );
            match validate_generated_case(&assets_root, case) {
                Ok(()) => {
                    if report {
                        print_case_report(&assets_root, case)?;
                    }
                    println!("probe passed for {}", case.case_id());
                }
                Err(err) => {
                    println!("probe root retained at {}", assets_root.display());
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

fn temp_probe_root(case: CompleteCase) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tsp-vector-generate-{}-{nanos}-{seq}",
        case.short_id()
    ))
}

fn validate_generated_case(
    assets_root: &PathBuf,
    case: CompleteCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = assets_root
        .join(case.artifact_dir_name())
        .join("case-manifest.yaml");
    let summary = validate_case_package(
        &manifest,
        &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join("spec")
            .join("test-vector-instances.md"),
    )?;
    println!(
        "validated {}: {} vectors, {} fixtures, {} bindings, {} identity fixture reviews",
        summary.case_id,
        summary.vectors,
        summary.fixtures,
        summary.bindings,
        summary.identity_fixture_reviews
    );
    Ok(())
}

fn print_case_report(
    assets_root: &PathBuf,
    case: CompleteCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let vector_catalog = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("spec")
        .join("test-vector-instances.md");
    let report = collect_case_runner_reports_relaxed(assets_root, &vector_catalog)?
        .into_iter()
        .find(|report| report.summary.case_id == case.case_id())
        .ok_or_else(|| format!("case report not found for {}", case.case_id()))?;
    print!("{}", render_case_runner_report(&report));
    Ok(())
}
