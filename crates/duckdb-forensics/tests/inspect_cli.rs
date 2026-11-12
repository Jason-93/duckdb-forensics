#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use duckdb_format::duckdb_checksum;
use duckdb_report::{InspectionReport, Observation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NORMAL: &[u8] = include_bytes!("fixtures/normal.duckdb");
const MANIFEST: &str = include_str!("fixtures/normal.manifest.json");

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_duckdb-forensics")
}

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).unwrap_or_else(|error| panic!("invalid manifest: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fixture(directory: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.path().join(name);
    fs::write(&path, bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    path
}

fn run(path: &Path, extra_args: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command.arg("inspect").arg(path);
    command.args(extra_args);
    command
        .output()
        .unwrap_or_else(|error| panic!("cannot execute inspector: {error}"))
}

fn run_json(path: &Path) -> InspectionReport {
    run_json_with_args(path, &[]).0
}

fn run_json_with_args(path: &Path, extra_args: &[&str]) -> (InspectionReport, String) {
    let before =
        sha256(&fs::read(path).unwrap_or_else(|error| panic!("cannot read input: {error}")));
    let mut args = vec!["--format", "json"];
    args.extend_from_slice(extra_args);
    let output = run(path, &args);
    assert!(
        output.status.success(),
        "inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "process panicked"
    );
    let stdout =
        String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("non-UTF-8 JSON: {error}"));
    let report: InspectionReport = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("cannot deserialize report: {error}\n{stdout}"));
    let after =
        sha256(&fs::read(path).unwrap_or_else(|error| panic!("cannot read input: {error}")));
    assert_eq!(before, after, "input evidence changed");
    let wal = PathBuf::from(format!("{}.wal", path.display()));
    assert!(!wal.exists(), "inspector created a WAL file");
    (report, stdout)
}

fn observation<'a>(report: &'a InspectionReport, path: &str, name: &str) -> &'a Observation {
    report
        .observation(path, name)
        .unwrap_or_else(|| panic!("missing observation {path}.{name}"))
}

fn observation_u64(report: &InspectionReport, path: &str, name: &str) -> u64 {
    observation(report, path, name)
        .value
        .as_u64()
        .unwrap_or_else(|| panic!("observation {path}.{name} is not u64"))
}

fn finding_codes(report: &InspectionReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

fn selected_header(report: &InspectionReport) -> Option<&str> {
    report
        .inferences
        .iter()
        .find(|inference| inference.code == "likely_active_database_header")
        .and_then(|inference| inference.subject.as_deref())
}

fn flip_bit(bytes: &mut [u8], offset: usize) {
    bytes[offset] ^= 1;
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn repair_page_checksum(bytes: &mut [u8], page_offset: usize) {
    let checksum = duckdb_checksum(&bytes[page_offset + 8..page_offset + 4096]);
    write_u64(bytes, page_offset, checksum);
}

#[test]
fn normal_official_fixture_matches_independent_manifest() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let (report, first_json) = run_json_with_args(&path, &[]);
    let (_, second_json) = run_json_with_args(&path, &[]);
    assert_eq!(first_json, second_json, "JSON output is not stable");

    let manifest = manifest();
    assert_eq!(
        report.input.file_size,
        manifest["file_size"].as_u64().unwrap_or(0)
    );
    assert_eq!(report.input.sha256.as_deref(), manifest["sha256"].as_str());
    assert_eq!(
        observation_u64(&report, "main_header", "version_number"),
        999
    );
    assert_eq!(
        observation(&report, "main_header", "magic_ascii").value,
        "DUCK"
    );
    assert_eq!(
        observation(&report, "main_header", "library_git_desc").value,
        manifest["main_library_version"]
    );
    assert_eq!(
        observation(&report, "main_header", "encrypted").value,
        false
    );
    assert!(
        finding_codes(&report).is_empty(),
        "unexpected findings: {:?}",
        finding_codes(&report)
    );
    assert!(report.checks_failed.is_empty());
    assert_eq!(selected_header(&report), Some("database_header[0]"));

    for (index, path_name) in ["main_header", "database_header[0]", "database_header[1]"]
        .iter()
        .enumerate()
    {
        let stored = observation(&report, path_name, "stored_checksum")
            .value
            .as_str()
            .unwrap_or("");
        let computed = observation(&report, path_name, "computed_checksum")
            .value
            .as_str()
            .unwrap_or("");
        assert_eq!(
            stored,
            manifest["stored_checksums"][index].as_str().unwrap_or("")
        );
        assert_eq!(stored, computed);
        assert_eq!(
            observation(&report, path_name, "checksum_status").value,
            "valid"
        );
    }

    for (index, path_name) in ["database_header[0]", "database_header[1]"]
        .iter()
        .enumerate()
    {
        for field in [
            "iteration",
            "meta_block",
            "free_list",
            "block_count",
            "block_alloc_size",
            "vector_size",
            "storage_compatibility",
        ] {
            assert_eq!(
                observation(&report, path_name, field).value,
                manifest["database_headers"][index][field],
                "field mismatch for {path_name}.{field}"
            );
        }
    }
    assert_eq!(
        observation_u64(&report, "database_header[0]", "meta_block_block_id"),
        0
    );
    assert_eq!(
        observation_u64(&report, "database_header[0]", "meta_block_metadata_index"),
        0
    );
    assert_eq!(
        observation_u64(&report, "database_header[0]", "free_list_block_id"),
        0
    );
    assert_eq!(
        observation_u64(&report, "database_header[0]", "free_list_metadata_index"),
        2
    );
    assert_eq!(
        observation_u64(&report, "database_header[0]", "free_list_file_offset"),
        12_288
    );
    assert_eq!(
        observation(&report, "geometry", "header_0_file_length_relation").value,
        "matches"
    );
    assert!(
        report
            .coverage
            .not_checked
            .iter()
            .any(|item| item.contains("WAL"))
    );
    assert!(report.checks_skipped.is_empty());
}

#[test]
fn empty_file_returns_structured_truncation() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "empty.duckdb", &[]);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"truncated_file"));
    assert_eq!(report.input.file_size, 0);
    assert!(
        report
            .checks_skipped
            .iter()
            .any(|check| check.code == "database_headers")
    );
}

#[test]
fn non_duckdb_file_does_not_panic() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let bytes = b"this is not a DuckDB database".repeat(500);
    let path = fixture(&directory, "text.duckdb", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"invalid_magic"));
    assert_eq!(selected_header(&report), None);
}

#[test]
fn main_header_bit_flip_is_a_checksum_mismatch() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    flip_bit(&mut bytes, 52);
    let path = fixture(&directory, "main-bit-flip.duckdb", &bytes);
    let report = run_json(&path);
    assert!(report.findings.iter().any(|finding| {
        finding.code == "checksum_mismatch"
            && finding.location.structure_path.as_deref() == Some("main_header.checksum")
    }));
    assert_eq!(selected_header(&report), Some("database_header[0]"));
}

#[test]
fn first_database_header_corruption_selects_second() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    flip_bit(&mut bytes, 4096 + 100);
    let path = fixture(&directory, "first-corrupt.duckdb", &bytes);
    let report = run_json(&path);
    assert_eq!(selected_header(&report), Some("database_header[1]"));
    assert!(finding_codes(&report).contains(&"checksum_mismatch"));
    assert!(report.inferences.iter().any(|inference| {
        inference.code == "possible_torn_write"
            && inference.subject.as_deref() == Some("database_header[0]")
    }));
}

#[test]
fn second_database_header_corruption_selects_first() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    flip_bit(&mut bytes, 8192 + 100);
    let path = fixture(&directory, "second-corrupt.duckdb", &bytes);
    let report = run_json(&path);
    assert_eq!(selected_header(&report), Some("database_header[0]"));
    assert!(finding_codes(&report).contains(&"checksum_mismatch"));
}

#[test]
fn both_database_headers_corrupt_reports_no_valid_header() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    flip_bit(&mut bytes, 4096 + 100);
    flip_bit(&mut bytes, 8192 + 100);
    let path = fixture(&directory, "both-corrupt.duckdb", &bytes);
    let report = run_json(&path);
    assert_eq!(selected_header(&report), None);
    assert!(finding_codes(&report).contains(&"no_valid_database_header"));
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "checksum_mismatch")
            .count(),
        2
    );
}

#[test]
fn truncated_main_file_preserves_header_selection_and_reports_geometry() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "truncated.duckdb", &NORMAL[..NORMAL.len() - 1]);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"truncated_file"));
    assert_eq!(selected_header(&report), Some("database_header[0]"));
    assert_eq!(
        observation(&report, "geometry", "header_0_file_length_relation").value,
        "truncated"
    );
}

#[test]
fn truncation_inside_database_header_does_not_panic() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "truncated-header.duckdb", &NORMAL[..5000]);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"truncated_file"));
    assert!(
        report
            .checks_skipped
            .iter()
            .any(|check| check.code == "checksum")
    );
}

#[test]
fn invalid_block_alloc_size_is_isolated_from_checksum_validation() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    write_u64(&mut bytes, 4096 + 40, 30_000);
    repair_page_checksum(&mut bytes, 4096);
    let path = fixture(&directory, "bad-block-size.duckdb", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"invalid_block_alloc_size"));
    assert!(!finding_codes(&report).contains(&"checksum_mismatch"));
    assert_eq!(selected_header(&report), Some("database_header[1]"));
}

#[test]
fn huge_block_count_does_not_overflow_or_panic() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    write_u64(&mut bytes, 4096 + 32, u64::MAX);
    repair_page_checksum(&mut bytes, 4096);
    let path = fixture(&directory, "bad-block-count.duckdb", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"invalid_block_count"));
    assert!(!finding_codes(&report).contains(&"checksum_mismatch"));
    assert_eq!(selected_header(&report), Some("database_header[1]"));
}

#[test]
fn deterministic_random_input_does_not_panic() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    let mut bytes = vec![0_u8; 16_384];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    let path = fixture(&directory, "random.duckdb", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"invalid_magic"));
    assert_eq!(report.input.file_size, 16_384);
}

#[test]
fn encrypted_flag_is_unsupported_not_checksum_mismatch() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    write_u64(&mut bytes, 20, 1);
    repair_page_checksum(&mut bytes, 0);
    let path = fixture(&directory, "encrypted-flag.duckdb", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"unsupported_encryption"));
    assert!(!finding_codes(&report).contains(&"checksum_mismatch"));
    assert!(
        observation(&report, "main_header", "encrypted")
            .value
            .as_bool()
            .unwrap_or(false)
    );
    assert!(
        report
            .observation("database_header[0]", "checksum_status")
            .is_none()
    );
}

#[test]
fn unsupported_main_version_is_not_checksum_mismatch() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut bytes = NORMAL.to_vec();
    write_u64(&mut bytes, 12, 64);
    repair_page_checksum(&mut bytes, 0);
    let path = fixture(&directory, "unsupported-version.duckdb", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"unsupported_storage_version"));
    assert!(!finding_codes(&report).contains(&"checksum_mismatch"));
    assert!(
        report
            .observation("database_header[0]", "checksum_status")
            .is_none()
    );
}

#[test]
fn text_report_contains_required_sections() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let before = sha256(NORMAL);
    let output = run(&path, &["--format", "text"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text =
        String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("non-UTF-8 text: {error}"));
    for required in [
        "Main Header",
        "Database Header 1",
        "Database Header 2",
        "Header Selection",
        "Geometry",
        "Checks Passed",
        "Checks Failed",
        "Checks Skipped",
        "Coverage",
        "Unknowns",
        "magic_bytes_hex",
        "storage_compatibility",
    ] {
        assert!(text.contains(required), "text report lacks {required}");
    }
    assert_eq!(
        before,
        sha256(&fs::read(&path).unwrap_or_else(|error| panic!("read: {error}")))
    );
}

#[test]
fn hide_path_removes_normalized_path_from_json() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonicalize: {error}"));
    let (report, json) = run_json_with_args(&path, &["--hide-path"]);
    assert_eq!(report.input.path, None);
    assert!(!json.contains(&canonical.display().to_string()));
}

#[test]
fn output_file_contains_deserializable_json_without_changing_input() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let output_path = directory.path().join("report.json");
    let output = run(
        &path,
        &[
            "--format",
            "json",
            "--output",
            output_path.to_str().unwrap_or(""),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: InspectionReport = serde_json::from_slice(
        &fs::read(&output_path).unwrap_or_else(|error| panic!("cannot read report: {error}")),
    )
    .unwrap_or_else(|error| panic!("cannot deserialize output report: {error}"));
    assert_eq!(
        report.input.sha256.as_deref(),
        manifest()["sha256"].as_str()
    );
    assert_eq!(
        sha256(NORMAL),
        sha256(&fs::read(&path).unwrap_or_else(|error| panic!("read: {error}")))
    );
}

#[test]
fn output_path_cannot_overwrite_input() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let before = sha256(NORMAL);
    let output = run(
        &path,
        &["--format", "json", "--output", path.to_str().unwrap_or("")],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite input"));
    assert_eq!(
        before,
        sha256(&fs::read(&path).unwrap_or_else(|error| panic!("read: {error}")))
    );
    assert!(serde_json::from_slice::<InspectionReport>(NORMAL).is_err());
}

#[cfg(unix)]
#[test]
fn output_hard_link_to_input_is_rejected() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let alias = directory.path().join("alias.json");
    fs::hard_link(&path, &alias).unwrap_or_else(|error| panic!("hard link: {error}"));
    let output = run(
        &path,
        &["--format", "json", "--output", alias.to_str().unwrap_or("")],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite input"));
    assert_eq!(
        sha256(NORMAL),
        sha256(&fs::read(&path).unwrap_or_else(|error| panic!("read: {error}")))
    );
    assert_eq!(
        sha256(NORMAL),
        sha256(&fs::read(&alias).unwrap_or_else(|error| panic!("read: {error}")))
    );
}
