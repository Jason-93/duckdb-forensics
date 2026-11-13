#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use duckdb_report::recovery::RecoveryPlanReport;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NORMAL_DB: &[u8] = include_bytes!("fixtures/normal.duckdb");
const NORMAL_WAL: &[u8] = include_bytes!("fixtures/normal.wal");
const SCHEMA: &str = include_str!("../../../schemas/recovery-plan.schema.json");

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_duckdb-forensics")
}

fn evidence(directory: &TempDir) -> PathBuf {
    let root = directory.path().join("evidence");
    fs::create_dir(&root).expect("evidence dir");
    fs::write(root.join("evidence.duckdb"), NORMAL_DB).expect("database");
    fs::write(root.join("evidence.duckdb.wal"), NORMAL_WAL).expect("WAL");
    root
}

fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(directory: &Path, root: &Path, output: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(directory).expect("read evidence dir") {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if entry.file_type().expect("file type").is_dir() {
                walk(&path, root, output);
            } else {
                let bytes = fs::read(&path).expect("read evidence");
                output.insert(
                    path.strip_prefix(root)
                        .expect("relative")
                        .to_string_lossy()
                        .into_owned(),
                    format!("{:x}", Sha256::digest(bytes)),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    output
}

fn run_json(root: &Path) -> (RecoveryPlanReport, String) {
    let before = snapshot(root);
    let output = Command::new(binary())
        .arg("recover-plan")
        .arg(root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run recover-plan");
    assert!(
        output.status.success(),
        "recover-plan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    assert_eq!(before, snapshot(root), "original evidence changed");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    let report = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("invalid recovery JSON: {error}\n{stdout}"));
    (report, stdout)
}

#[test]
fn normal_evidence_has_six_sections_and_no_noop_truncation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = evidence(&directory);
    let (report, _) = run_json(&root);
    assert!(report.observed_facts.evidence_unchanged);
    assert_eq!(report.observed_facts.files.len(), 2);
    assert!(report.observed_facts.database.is_some());
    assert!(report.observed_facts.wal.is_some());
    assert!(report.candidate_actions.is_empty());
    assert!(!report.risks.is_empty());
    let schema: Value = serde_json::from_str(SCHEMA).expect("schema");
    for section in [
        "observed_facts",
        "findings",
        "inferences",
        "unknowns",
        "candidate_actions",
        "risks",
    ] {
        assert!(
            schema["required"]
                .as_array()
                .expect("required")
                .contains(&Value::from(section))
        );
        assert!(
            serde_json::to_value(&report)
                .expect("report value")
                .get(section)
                .is_some()
        );
    }
}

#[test]
fn complete_unflushed_entry_is_included_in_possible_loss() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = evidence(&directory);
    fs::create_dir(root.join("nested")).expect("nested");
    fs::write(root.join("nested/note.bin"), [9, 8, 7]).expect("extra evidence");
    let mut wal = NORMAL_WAL.to_vec();
    wal.extend(&NORMAL_WAL[51..82]);
    fs::write(root.join("evidence.duckdb.wal"), &wal).expect("tail WAL");
    let (report, _) = run_json(&root);
    assert_eq!(report.observed_facts.files.len(), 3);
    assert_eq!(report.candidate_actions.len(), 1);
    let action = &report.candidate_actions[0];
    assert_eq!(action.action, "candidate_wal_truncation");
    assert_eq!(action.target_offset, NORMAL_WAL.len() as u64);
    assert_eq!(
        action.possible_data_loss.start_offset,
        NORMAL_WAL.len() as u64
    );
    assert_eq!(action.possible_data_loss.end_offset, wal.len() as u64);
    assert_eq!(action.possible_data_loss.byte_length, 31);
    assert!(
        report
            .observed_facts
            .wal
            .as_ref()
            .is_some_and(|wal| wal.summary.successfully_parsed_entries == 4)
    );
    assert!(action.must_execute_on_copy);
    assert!(action.must_reverify_result);
    assert!(
        action
            .evidence
            .iter()
            .any(|evidence| evidence.name == "wal_sha256")
    );
    assert!(
        report
            .risks
            .iter()
            .any(|risk| risk.code == "possible_post_flush_data_loss")
    );
}

#[test]
fn missing_or_ambiguous_database_does_not_produce_unique_action() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("evidence");
    fs::create_dir(&root).expect("evidence");
    fs::write(root.join("a.duckdb"), NORMAL_DB).expect("first DB");
    fs::write(root.join("b.duckdb"), NORMAL_DB).expect("second DB");
    let (report, _) = run_json(&root);
    assert!(report.observed_facts.database.is_none());
    assert!(report.candidate_actions.is_empty());
    assert!(
        report
            .unknowns
            .iter()
            .any(|unknown| unknown.code == "database_selection")
    );

    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("evidence");
    fs::create_dir(&root).expect("evidence");
    fs::write(root.join("single.duckdb"), NORMAL_DB).expect("DB");
    let (report, _) = run_json(&root);
    assert!(report.candidate_actions.is_empty());
    assert!(
        report
            .unknowns
            .iter()
            .any(|unknown| unknown.code == "wal_missing")
    );
}

#[test]
fn wal_without_verified_flush_has_no_candidate_action() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = evidence(&directory);
    fs::write(
        root.join("evidence.duckdb.wal"),
        [100, 0, 98, 101, 0, 2, 255, 255],
    )
    .expect("version-only WAL");
    let (report, _) = run_json(&root);
    assert!(report.candidate_actions.is_empty());
    assert!(
        report
            .observed_facts
            .wal
            .as_ref()
            .is_some_and(|wal| wal.last_good_flush.is_none())
    );
}

#[test]
fn text_report_is_explicitly_advisory() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = evidence(&directory);
    let before = snapshot(&root);
    let output = Command::new(binary())
        .arg("recover-plan")
        .arg(&root)
        .arg("--format")
        .arg("text")
        .output()
        .expect("run text");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(text.contains("advisory only; nothing executed"));
    for section in [
        "Observed Facts",
        "Findings",
        "Inferences",
        "Unknowns",
        "Candidate Actions",
        "Risks",
    ] {
        assert!(text.contains(section));
    }
    assert_eq!(before, snapshot(&root));
}
