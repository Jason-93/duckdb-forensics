#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use duckdb_forensics::inspect::{InspectError, inspect_path};
use duckdb_forensics::output::{OutputError, write_report};
use duckdb_report::render_text;

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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug)]
enum AppError {
    Inspect(InspectError),
    Serialize(serde_json::Error),
    Output(OutputError),
    Stdout(io::Error),
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inspect(error) => Display::fmt(error, formatter),
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
    }
}
