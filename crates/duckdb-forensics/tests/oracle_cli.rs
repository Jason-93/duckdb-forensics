#![cfg(unix)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use duckdb_forensics::oracle::{OracleLimits, run_oracle_with_limits};
use duckdb_forensics::verify_path;
use duckdb_report::oracle::OracleComparison;
use duckdb_report::recovery::RecoveryPlanReport;
use duckdb_report::verify::VerifyReport;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NORMAL_DB: &[u8] = include_bytes!("fixtures/normal.duckdb");
const NORMAL_WAL: &[u8] = include_bytes!("fixtures/normal.wal");

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_duckdb-forensics")
}

fn sha256(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("read hash input"))
    )
}

fn mock_oracle(directory: &TempDir, version: &str, actual: &str) -> (PathBuf, PathBuf) {
    let path = directory.path().join("mock-duckdb");
    let log = directory.path().join("oracle-args.log");
    let script = format!(
        r#"#!/bin/sh
printf 'CALL' >> '{log}'
for arg in "$@"; do printf ' <%s>' "$arg" >> '{log}'; done
printf '\n' >> '{log}'
last=
for arg in "$@"; do last="$arg"; done
if [ "$last" = 'SELECT version();' ]; then
  printf '%s\n' '{version}'
  exit 0
fi
{actual}
"#,
        log = log.display(),
        version = version,
        actual = actual
    );
    fs::write(&path, script).expect("write mock Oracle");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).expect("executable permission");
    (path, log)
}

fn run_verify(path: &Path, oracle: &Path) -> VerifyReport {
    let before = sha256(path);
    let output = Command::new(binary())
        .arg("verify")
        .arg(path)
        .arg("--format")
        .arg("json")
        .arg("--duckdb")
        .arg(oracle)
        .output()
        .expect("run verify Oracle");
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(before, sha256(path));
    serde_json::from_slice(&output.stdout).expect("verify JSON")
}

#[test]
fn successful_oracle_uses_only_a_copy_and_can_modify_that_copy() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    fs::write(&database, NORMAL_DB).expect("database");
    let (oracle, log) = mock_oracle(
        &directory,
        "v2.0.0",
        "printf 'copy-only-change' >> \"$PWD/copies/evidence.duckdb\"\nprintf '1\\n'\nprintf 'oracle diagnostic\\n' >&2\nexit 0",
    );
    let report = run_verify(&database, &oracle);
    let oracle_report = report.oracle.expect("Oracle report");
    assert_eq!(oracle_report.comparison, OracleComparison::Agreement);
    assert_eq!(oracle_report.copy_hashes_match, Some(true));
    assert_eq!(oracle_report.runs.len(), 2);
    assert_eq!(oracle_report.runs[1].exit_code, Some(0));
    assert!(oracle_report.runs[1].stderr.contains("oracle diagnostic"));
    let args = fs::read_to_string(log).expect("args log");
    assert!(args.contains(":memory:"));
    assert!(args.contains("READ_ONLY"));
    assert!(args.contains("/copies/evidence.duckdb"));
    assert!(args.contains("-init"));
    assert!(!args.contains(&format!("ATTACH '{}'", database.display())));
    assert_eq!(
        sha256(&database),
        format!("{:x}", Sha256::digest(NORMAL_DB))
    );
}

#[test]
fn oracle_open_failure_preserves_exit_stderr_and_disagreement() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    fs::write(&database, NORMAL_DB).expect("database");
    let (oracle, _) = mock_oracle(
        &directory,
        "v2.0.0",
        "printf 'simulated open failure\\n' >&2\nexit 7",
    );
    let report = run_verify(&database, &oracle);
    let oracle_report = report.oracle.expect("Oracle report");
    assert_eq!(oracle_report.comparison, OracleComparison::Disagreement);
    let run = &oracle_report.runs[1];
    assert_eq!(run.exit_code, Some(7));
    assert!(run.stderr.contains("simulated open failure"));
}

#[test]
fn wrong_version_never_copies_or_opens_evidence() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    fs::write(&database, NORMAL_DB).expect("database");
    let (oracle, _) = mock_oracle(&directory, "v1.9.9", "exit 99");
    let report = run_verify(&database, &oracle);
    let oracle_report = report.oracle.expect("Oracle report");
    assert_eq!(oracle_report.version.as_deref(), Some("v1.9.9"));
    assert_eq!(oracle_report.runs.len(), 1);
    assert_eq!(oracle_report.copy_hashes_match, None);
    assert_eq!(oracle_report.comparison, OracleComparison::NotComparable);
}

#[test]
fn oracle_output_is_bounded_and_marked_truncated() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    fs::write(&database, NORMAL_DB).expect("database");
    let actual = "i=0\nwhile [ \"$i\" -lt 700 ]; do printf '%0100d' 0; i=$((i+1)); done\nexit 0";
    let (oracle, _) = mock_oracle(&directory, "v2.0.0", actual);
    let report = run_verify(&database, &oracle);
    let run = &report.oracle.expect("Oracle report").runs[1];
    assert!(run.stdout_truncated);
    assert_eq!(run.stdout.len(), 64 * 1024);
}

#[test]
fn oracle_timeout_kills_and_reaps_the_process() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    fs::write(&database, NORMAL_DB).expect("database");
    let (oracle, _) = mock_oracle(
        &directory,
        "v2.0.0",
        "printf 'before timeout\\n' >&2\nsleep 5\nexit 0",
    );
    let verification = verify_path(&database, false).expect("verification");
    let report = run_oracle_with_limits(
        &oracle,
        &database,
        None,
        &verification,
        OracleLimits {
            timeout: Duration::from_millis(500),
            output_limit_bytes: 1024,
        },
    )
    .expect("Oracle timeout report");
    let run = &report.runs[1];
    assert!(run.timed_out);
    assert!(run.killed);
    assert!(run.stderr.contains("before timeout"));
    assert_eq!(report.comparison, OracleComparison::NotComparable);
}

#[test]
fn recover_plan_oracle_preserves_every_original_evidence_hash() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("evidence");
    fs::create_dir(&root).expect("evidence");
    fs::write(root.join("evidence.duckdb"), NORMAL_DB).expect("database");
    fs::write(root.join("evidence.duckdb.wal"), NORMAL_WAL).expect("WAL");
    fs::write(root.join("notes.txt"), b"preserve me").expect("notes");
    let (oracle, _) = mock_oracle(
        &directory,
        "v2.0.0",
        "printf 'copy-only-change' >> \"$PWD/copies/evidence.duckdb\"\nprintf '1\\n'\nexit 0",
    );
    let paths = [
        root.join("evidence.duckdb"),
        root.join("evidence.duckdb.wal"),
        root.join("notes.txt"),
    ];
    let before: BTreeMap<_, _> = paths.iter().map(|path| (path, sha256(path))).collect();
    let output = Command::new(binary())
        .arg("recover-plan")
        .arg(&root)
        .arg("--format")
        .arg("json")
        .arg("--duckdb")
        .arg(&oracle)
        .output()
        .expect("run recover-plan Oracle");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: RecoveryPlanReport = serde_json::from_slice(&output.stdout).expect("plan JSON");
    assert!(report.observed_facts.oracle.is_some());
    assert!(report.observed_facts.evidence_unchanged);
    for (path, hash) in before {
        assert_eq!(hash, sha256(path));
    }
    assert_eq!(fs::read_dir(&root).expect("evidence entries").count(), 3);
}

#[test]
fn explicitly_provided_real_duckdb_v2_is_supported() {
    let Some(executable) = std::env::var_os("DUCKDB_V2_0_0") else {
        return;
    };
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    fs::write(&database, NORMAL_DB).expect("database");
    let report = run_verify(&database, Path::new(&executable));
    let oracle = report.oracle.expect("real Oracle");
    assert_eq!(oracle.version.as_deref(), Some("v2.0.0"));
    assert_eq!(oracle.runs.len(), 2);
    assert_eq!(oracle.comparison, OracleComparison::Agreement);
}
