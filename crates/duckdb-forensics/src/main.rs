#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use duckdb_forensics::inspect::{InspectError, inspect_path};
use duckdb_forensics::output::{OutputError, write_report};
use duckdb_forensics::recover::RecoveryLimits;
use duckdb_forensics::recover::{RecoverError, recover_plan_with_options};
use duckdb_forensics::verify::{VerifyError, verify_path_with_oracle};
use duckdb_forensics::wal::{WalInspectError, inspect_wal_path};
use duckdb_report::recovery::render_recovery_plan_text;
use duckdb_report::render_text;
use duckdb_report::verify::render_verify_text;
use duckdb_report::wal::render_wal_text;

#[derive(Debug, Parser)]
#[command(
    name = "duckdb-forensics",
    version,
    about = "Offline DuckDB crash-site inspector"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Inspect DuckDB v2.0.0 main-file headers and basic block geometry")]
    Inspect {
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        #[arg(long, help = "Hide the normalized input path in the report")]
        hide_path: bool,
    },
    #[command(about = "Verify DuckDB v2.0.0 headers, blocks, and metadata chains read-only")]
    Verify {
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,
        #[arg(long, help = "Stream and checksum every complete physical block")]
        blocks: bool,
        #[arg(
            long,
            value_name = "PATH",
            help = "Explicit official DuckDB v2.0.0 executable for copy-only Oracle checks"
        )]
        duckdb: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    #[command(about = "Generate an advisory recovery plan without modifying evidence")]
    RecoverPlan {
        #[arg(value_name = "EVIDENCE_DIR")]
        evidence_dir: PathBuf,
        #[arg(
            long,
            value_name = "PATH",
            help = "Explicit official DuckDB v2.0.0 executable for copy-only Oracle checks"
        )]
        duckdb: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    #[command(about = "Inspect unencrypted DuckDB WAL v2 frames without replay")]
    Wal {
        #[arg(value_name = "WAL_PATH")]
        wal_path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug)]
enum AppError {
    Inspect(InspectError),
    WalInspect(WalInspectError),
    Verify(VerifyError),
    Recover(RecoverError),
    Serialize(serde_json::Error),
    Output(OutputError),
    Stdout(io::Error),
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inspect(error) => Display::fmt(error, formatter),
            Self::WalInspect(error) => Display::fmt(error, formatter),
            Self::Verify(error) => Display::fmt(error, formatter),
            Self::Recover(error) => Display::fmt(error, formatter),
            Self::Serialize(error) => write!(formatter, "cannot serialize JSON report: {error}"),
            Self::Output(error) => Display::fmt(error, formatter),
            Self::Stdout(error) => write!(formatter, "cannot write report to stdout: {error}"),
        }
    }
}

impl Error for AppError {}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("duckdb-forensics: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Command::Inspect {
            db_path,
            format,
            output,
            hide_path,
        } => {
            let report = inspect_path(&db_path, hide_path).map_err(AppError::Inspect)?;
            let rendered = match format {
                OutputFormat::Text => render_text(&report),
                OutputFormat::Json => {
                    let mut json =
                        serde_json::to_string_pretty(&report).map_err(AppError::Serialize)?;
                    json.push('\n');
                    json
                }
            };
            if let Some(output) = output {
                write_report(&output, &db_path, &rendered).map_err(AppError::Output)
            } else {
                io::stdout()
                    .write_all(rendered.as_bytes())
                    .map_err(AppError::Stdout)
            }
        }
        Command::Verify {
            db_path,
            blocks,
            duckdb,
            format,
        } => {
            let report = verify_path_with_oracle(&db_path, blocks, duckdb.as_deref())
                .map_err(AppError::Verify)?;
            let rendered = match format {
                OutputFormat::Text => render_verify_text(&report),
                OutputFormat::Json => {
                    let mut json =
                        serde_json::to_string_pretty(&report).map_err(AppError::Serialize)?;
                    json.push('\n');
                    json
                }
            };
            io::stdout()
                .write_all(rendered.as_bytes())
                .map_err(AppError::Stdout)
        }
        Command::RecoverPlan {
            evidence_dir,
            duckdb,
            format,
        } => {
            let report = recover_plan_with_options(
                &evidence_dir,
                duckdb.as_deref(),
                RecoveryLimits::default(),
            )
            .map_err(AppError::Recover)?;
            let rendered = match format {
                OutputFormat::Text => render_recovery_plan_text(&report),
                OutputFormat::Json => {
                    let mut json =
                        serde_json::to_string_pretty(&report).map_err(AppError::Serialize)?;
                    json.push('\n');
                    json
                }
            };
            io::stdout()
                .write_all(rendered.as_bytes())
                .map_err(AppError::Stdout)
        }
        Command::Wal {
            wal_path,
            format,
            output,
        } => {
            let report = inspect_wal_path(&wal_path).map_err(AppError::WalInspect)?;
            let rendered = match format {
                OutputFormat::Text => render_wal_text(&report),
                OutputFormat::Json => {
                    let mut json =
                        serde_json::to_string_pretty(&report).map_err(AppError::Serialize)?;
                    json.push('\n');
                    json
                }
            };
            if let Some(output) = output {
                write_report(&output, &wal_path, &rendered).map_err(AppError::Output)
            } else {
                io::stdout()
                    .write_all(rendered.as_bytes())
                    .map_err(AppError::Stdout)
            }
        }
    }
}
