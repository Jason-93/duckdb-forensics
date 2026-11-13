use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use duckdb_report::oracle::{OracleComparison, OracleReport, OracleRunReport};
use duckdb_report::verify::{VerifyReport, VerifyStatus};

use crate::util::{decode_text, path_text};
use sha2::{Digest, Sha256};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_OUTPUT_LIMIT: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const INIT_SQL: &str =
    "SET autoinstall_known_extensions=false;\nSET autoload_known_extensions=false;\n";

#[derive(Debug, Clone, Copy)]
pub struct OracleLimits {
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}

impl Default for OracleLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            output_limit_bytes: DEFAULT_OUTPUT_LIMIT,
        }
    }
}

#[derive(Debug)]
pub enum OracleError {
    Canonicalize { path: PathBuf, source: io::Error },
    Temporary(io::Error),
    Copy { path: PathBuf, source: io::Error },
    Hash { path: PathBuf, source: io::Error },
}

impl Display for OracleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonicalize { path, source } => {
                write!(
                    formatter,
                    "cannot canonicalize {}: {source}",
                    path.display()
                )
            }
            Self::Temporary(error) => write!(formatter, "cannot prepare Oracle workspace: {error}"),
            Self::Copy { path, source } => write!(
                formatter,
                "cannot copy evidence {} to the Oracle workspace: {source}",
                path.display()
            ),
            Self::Hash { path, source } => write!(
                formatter,
                "cannot hash Oracle evidence copy {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for OracleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonicalize { source, .. }
            | Self::Copy { source, .. }
            | Self::Hash { source, .. }
            | Self::Temporary(source) => Some(source),
        }
    }
}

pub fn run_oracle(
    executable: &Path,
    database: &Path,
    wal: Option<&Path>,
    verification: &VerifyReport,
) -> Result<OracleReport, OracleError> {
    run_oracle_with_limits(
        executable,
        database,
        wal,
        verification,
        OracleLimits::default(),
    )
}

pub fn run_oracle_with_limits(
    executable: &Path,
    database: &Path,
    wal: Option<&Path>,
    verification: &VerifyReport,
    limits: OracleLimits,
) -> Result<OracleReport, OracleError> {
    let executable = executable
        .canonicalize()
        .map_err(|source| OracleError::Canonicalize {
            path: executable.to_path_buf(),
            source,
        })?;
    let database = database
        .canonicalize()
        .map_err(|source| OracleError::Canonicalize {
            path: database.to_path_buf(),
            source,
        })?;
    let workspace = tempfile::tempdir().map_err(OracleError::Temporary)?;
    let home = workspace.path().join("home");
    let copies = workspace.path().join("copies");
    fs::create_dir_all(&home).map_err(OracleError::Temporary)?;
    fs::create_dir_all(&copies).map_err(OracleError::Temporary)?;
    let init = workspace.path().join("oracle-init.sql");
    fs::write(&init, INIT_SQL).map_err(OracleError::Temporary)?;

    let (executable_text, executable_encoding) = path_text(&executable);
    let mut report = OracleReport {
        executable: executable_text,
        executable_encoding: executable_encoding.to_owned(),
        version: None,
        runs: Vec::new(),
        comparison: OracleComparison::NotComparable,
        rationale: "The Oracle version preflight has not completed.".to_owned(),
        copy_hashes_match: None,
    };
    let version_run = execute(
        "version_preflight",
        &executable,
        &[
            "-csv".to_owned(),
            "-noheader".to_owned(),
            "-batch".to_owned(),
            "-init".to_owned(),
            init.display().to_string(),
            ":memory:".to_owned(),
            "SELECT version();".to_owned(),
        ],
        workspace.path(),
        &home,
        limits,
    );
    report.version = nonempty_trimmed(&version_run.stdout);
    let version_ok = version_run.exit_code == Some(0)
        && !version_run.timed_out
        && report.version.as_deref() == Some("v2.0.0");
    report.runs.push(version_run);
    if !version_ok {
        report.rationale = "The executable did not complete a successful exact DuckDB v2.0.0 version preflight; no evidence was copied or opened.".to_owned();
        return Ok(report);
    }

    let copied_database = copies.join("evidence.duckdb");
    fs::copy(&database, &copied_database).map_err(|source| OracleError::Copy {
        path: database.clone(),
        source,
    })?;
    let mut hashes_match = stream_sha256(&database)? == stream_sha256(&copied_database)?;
    if let Some(wal) = wal {
        let wal = wal
            .canonicalize()
            .map_err(|source| OracleError::Canonicalize {
                path: wal.to_path_buf(),
                source,
            })?;
        let destination = copies.join("evidence.duckdb.wal");
        fs::copy(&wal, &destination).map_err(|source| OracleError::Copy {
            path: wal.clone(),
            source,
        })?;
        hashes_match = hashes_match && stream_sha256(&wal)? == stream_sha256(&destination)?;
    }
    report.copy_hashes_match = Some(hashes_match);
    if !hashes_match {
        report.rationale =
            "A copied evidence hash differs from its source; the database copy was not opened."
                .to_owned();
        return Ok(report);
    }

    let sql = format!(
        "ATTACH '{}' AS evidence (READ_ONLY); SELECT 1;",
        sql_string(&copied_database)
    );
    let open_run = execute(
        "open_copy_read_only",
        &executable,
        &[
            "-csv".to_owned(),
            "-noheader".to_owned(),
            "-batch".to_owned(),
            "-init".to_owned(),
            init.display().to_string(),
            ":memory:".to_owned(),
            sql,
        ],
        workspace.path(),
        &home,
        limits,
    );
    let opened = open_run.exit_code == Some(0) && !open_run.timed_out;
    let inconclusive = open_run.timed_out || open_run.error.is_some();
    report.runs.push(open_run);
    let selected = verification.selected_header.is_some();
    let rust_complete = verification.status == VerifyStatus::Complete;
    if inconclusive {
        report.comparison = OracleComparison::NotComparable;
        report.rationale =
            "The Oracle did not produce a conclusive process result within the configured limits."
                .to_owned();
    } else if opened && rust_complete {
        report.comparison = OracleComparison::Agreement;
        report.rationale =
            "The official engine opened the copy read-only and the Rust checks completed; neither result validates unvisited business contents.".to_owned();
    } else if opened && !selected {
        report.comparison = OracleComparison::Disagreement;
        report.rationale =
            "The official engine opened the copy, but the Rust parser could not select a supported Database Header."
                .to_owned();
    } else if opened {
        report.comparison = OracleComparison::NotComparable;
        report.rationale =
            "The official engine opened the copy despite Rust structural findings. Its minimal query need not visit every damaged Block, so this coverage difference is not treated as agreement."
                .to_owned();
    } else if rust_complete {
        report.comparison = OracleComparison::Disagreement;
        report.rationale =
            "The Rust checks completed, but the official engine failed to open the copy or execute the minimal read-only query."
                .to_owned();
    } else {
        report.comparison = OracleComparison::Agreement;
        report.rationale =
            "The official engine failed to open the copy while Rust also reported unsupported or incomplete structural evidence; this is not a shared root-cause diagnosis."
                .to_owned();
    }

    Ok(report)
}

fn nonempty_trimmed(output: &str) -> Option<String> {
    let trimmed = output.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn sql_string(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

#[allow(clippy::too_many_arguments)]
fn execute(
    purpose: &str,
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    home: &Path,
    limits: OracleLimits,
) -> OracleRunReport {
    let mut argv = vec![path_text(executable).0];
    argv.extend(args.iter().cloned());
    let (working_directory_text, working_directory_encoding) = path_text(working_directory);
    let mut report = OracleRunReport {
        purpose: purpose.to_owned(),
        argv,
        working_directory: working_directory_text,
        working_directory_encoding: working_directory_encoding.to_owned(),
        timeout_ms: limits.timeout.as_millis().min(u64::MAX as u128) as u64,
        output_limit_bytes: limits.output_limit_bytes,
        exit_code: None,
        timed_out: false,
        killed: false,
        stdout: String::new(),
        stderr: String::new(),
        stdout_utf8_valid: true,
        stderr_utf8_valid: true,
        stdout_hex: None,
        stderr_hex: None,
        stdout_truncated: false,
        stderr_truncated: false,
        error: None,
    };
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(working_directory)
        .env("HOME", home)
        .env("DUCKDB_HOME", home.join(".duckdb"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report.error = Some(format!("cannot spawn Oracle process: {error}"));
            return report;
        }
    };
    let stdout_capture = Arc::new(Mutex::new(CapturedOutput::default()));
    let stderr_capture = Arc::new(Mutex::new(CapturedOutput::default()));
    let stdout_reader = child.stdout.take().map(|stream| {
        let capture = Arc::clone(&stdout_capture);
        thread::spawn(move || read_bounded(stream, limits.output_limit_bytes, capture))
    });
    let stderr_reader = child.stderr.take().map(|stream| {
        let capture = Arc::clone(&stderr_capture);
        thread::spawn(move || read_bounded(stream, limits.output_limit_bytes, capture))
    });

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                report.exit_code = status.code();
                break;
            }
            Ok(None) if started.elapsed() >= limits.timeout => {
                report.timed_out = true;
                if let Err(error) = child.kill() {
                    report.error = Some(format!("cannot kill timed-out Oracle process: {error}"));
                } else {
                    report.killed = true;
                }
                match child.wait() {
                    Ok(status) => report.exit_code = status.code(),
                    Err(error) => {
                        report.error = Some(format!("cannot reap Oracle process: {error}"));
                    }
                }
                break;
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                report.error = Some(format!("cannot wait for Oracle process: {error}"));
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    if !report.timed_out {
        join_reader(stdout_reader, "stdout", &mut report);
        join_reader(stderr_reader, "stderr", &mut report);
    }
    snapshot_capture(&stdout_capture, "stdout", &mut report);
    snapshot_capture(&stderr_capture, "stderr", &mut report);
    report
}

#[derive(Default)]
struct CapturedOutput {
    retained: Vec<u8>,
    truncated: bool,
}

fn read_bounded(
    mut stream: impl Read,
    limit: usize,
    capture: Arc<Mutex<CapturedOutput>>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if let Ok(mut capture) = capture.lock() {
                    let remaining = limit.saturating_sub(capture.retained.len());
                    let copied = remaining.min(count);
                    capture.retained.extend_from_slice(&buffer[..copied]);
                    capture.truncated |= copied < count;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn join_reader(
    reader: Option<thread::JoinHandle<io::Result<()>>>,
    stream: &str,
    report: &mut OracleRunReport,
) {
    let Some(reader) = reader else {
        return;
    };
    match reader.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            report.error = Some(format!("cannot read Oracle {stream}: {error}"));
        }
        Err(_) => {
            report.error = Some(format!("Oracle {stream} reader thread failed"));
        }
    }
}

fn snapshot_capture(
    capture: &Arc<Mutex<CapturedOutput>>,
    stream: &str,
    report: &mut OracleRunReport,
) {
    if let Ok(capture) = capture.lock() {
        let (contents, utf8_valid, raw_hex) = decode_text(&capture.retained);
        if stream == "stdout" {
            report.stdout = contents;
            report.stdout_utf8_valid = utf8_valid;
            report.stdout_hex = raw_hex;
            report.stdout_truncated = capture.truncated;
        } else {
            report.stderr = contents;
            report.stderr_utf8_valid = utf8_valid;
            report.stderr_hex = raw_hex;
            report.stderr_truncated = capture.truncated;
        }
    } else {
        report.error = Some(format!("Oracle {stream} capture lock failed"));
    }
}

fn stream_sha256(path: &Path) -> Result<String, OracleError> {
    let mut file = File::open(path).map_err(|source| OracleError::Hash {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(OracleError::Hash {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}
