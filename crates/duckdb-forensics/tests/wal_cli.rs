#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use duckdb_forensics::{WalInspectionLimits, inspect_wal_path_with_limits};
use duckdb_format::duckdb_checksum;
use duckdb_report::wal::{WalEntryParseStatus, WalReport, WalStatus};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NORMAL: &[u8] = include_bytes!("fixtures/normal.wal");
const NORMAL_MANIFEST: &str = include_str!("fixtures/normal.wal.manifest.json");
const ISSUE_TRUNCATED: &[u8] = include_bytes!("fixtures/issue19099_truncated.wal");
const ISSUE_ZERO_FILLED: &[u8] = include_bytes!("fixtures/issue19099_zero_filled.wal");
const ISSUE_MANIFEST: &str = include_str!("fixtures/issue19099.manifest.json");
const SCHEMA: &str = include_str!("../../../schemas/wal-report.schema.json");

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_duckdb-forensics")
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
    Command::new(binary())
        .arg("wal")
        .arg(path)
        .args(extra_args)
        .output()
        .unwrap_or_else(|error| panic!("cannot execute WAL inspector: {error}"))
}

fn run_json(path: &Path) -> WalReport {
    run_json_with_args(path, &[]).0
}

fn run_json_with_args(path: &Path, extra_args: &[&str]) -> (WalReport, String) {
    let before = sha256(&fs::read(path).expect("read input before inspection"));
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
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    let report = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("cannot deserialize report: {error}\n{stdout}"));
    let after = sha256(&fs::read(path).expect("read input after inspection"));
    assert_eq!(before, after, "WAL evidence changed");
    (report, stdout)
}

fn finding_codes(report: &WalReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

fn manifest(value: &str) -> Value {
    serde_json::from_str(value).expect("valid fixture manifest")
}

fn version_header(version: u64) -> Vec<u8> {
    let mut bytes = vec![100, 0, 98, 101, 0];
    assert!(version < 128, "test helper only needs one-byte versions");
    bytes.push(version as u8);
    bytes.extend([255, 255]);
    bytes
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend((payload.len() as u64).to_le_bytes());
    bytes.extend(duckdb_checksum(payload).to_le_bytes());
    bytes.extend(payload);
    bytes
}

#[test]
fn normal_fixture_matches_independent_offsets_hashes_flush_and_checkpoint() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.wal", NORMAL);
    let (report, first_json) = run_json_with_args(&path, &[]);
    let (_, second_json) = run_json_with_args(&path, &[]);
    assert_eq!(first_json, second_json, "unstable JSON");
    let expected = manifest(NORMAL_MANIFEST);
    assert_eq!(report.status, WalStatus::Complete);
    assert_eq!(
        report.input.file_size,
        expected["file_size"].as_u64().unwrap()
    );
    assert_eq!(report.input.sha256.as_deref(), expected["sha256"].as_str());
    assert_eq!(report.version, Some(2));
    assert_eq!(report.encrypted, Some(false));
    assert_eq!(
        report.version_header.as_ref().map(|header| header.length),
        expected["version_header_length"].as_u64()
    );
    assert_eq!(
        report.entries.len(),
        expected["entries"].as_array().unwrap().len()
    );
    for (entry, expected_entry) in report
        .entries
        .iter()
        .zip(expected["entries"].as_array().unwrap())
    {
        assert_eq!(entry.index, expected_entry["index"].as_u64().unwrap());
        assert_eq!(entry.offset, expected_entry["offset"].as_u64().unwrap());
        assert_eq!(
            entry.payload_offset,
            expected_entry["payload_offset"].as_u64()
        );
        assert_eq!(
            entry.declared_length,
            expected_entry["declared_length"].as_u64()
        );
        assert_eq!(
            entry.actual_length,
            expected_entry["actual_length"].as_u64().unwrap()
        );
        assert_eq!(
            entry.declared_frame_end,
            expected_entry["declared_frame_end"].as_u64()
        );
        assert_eq!(
            entry.actual_frame_end,
            expected_entry["actual_frame_end"].as_u64().unwrap()
        );
        assert_eq!(
            entry.stored_checksum.as_deref(),
            expected_entry["stored_checksum"].as_str()
        );
        assert_eq!(entry.stored_checksum, entry.computed_checksum);
        assert_eq!(
            entry.entry_type,
            expected_entry["entry_type"].as_str().unwrap()
        );
    }
    assert_eq!(report.summary.total_entries, 3);
    assert_eq!(report.summary.successfully_parsed_entries, 3);
    assert_eq!(report.summary.checksum_failed_entries, 0);
    assert_eq!(report.confirmed_flushes.len(), 2);
    assert_eq!(
        report.last_good_flush.map(|flush| flush.end_offset),
        expected["last_good_flush"]["end_offset"].as_u64()
    );
    let checkpoint = report.checkpoint_marker.expect("reliable checkpoint");
    assert_eq!(
        checkpoint.entry_offset,
        expected["checkpoint"]["entry_offset"].as_u64().unwrap()
    );
    assert_eq!(checkpoint.block_pointer, 42);
    assert_eq!(checkpoint.offset_within_block, 7);
    assert!(!report.unterminated_data_after_last_flush);
    assert_eq!(report.tail.length, 0);
    assert_eq!(report.coverage.scanned_percent, 100.0);
    assert!(!finding_codes(&report).contains(&"zero_filled_tail"));
}

#[test]
fn empty_wal_is_structured_and_has_empty_hash() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "empty.wal", &[]);
    let report = run_json(&path);
    assert_eq!(report.status, WalStatus::Empty);
    assert!(finding_codes(&report).contains(&"empty_wal"));
    assert_eq!(report.input.sha256.as_deref(), Some(sha256(&[]).as_str()));
    assert_eq!(report.version, None);
    assert_eq!(report.last_good_flush, None);
}

#[test]
fn wal_v1_v3_and_unknown_versions_are_explicitly_unsupported() {
    for (version, encrypted) in [(1, Some(false)), (3, Some(true)), (4, None)] {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut bytes = version_header(version);
        bytes.extend(frame(&[100, 0, 100, 255, 255]));
        let path = fixture(&directory, "unsupported.wal", &bytes);
        let report = run_json(&path);
        assert_eq!(report.status, WalStatus::Unsupported);
        assert_eq!(report.version, Some(version));
        assert_eq!(report.encrypted, encrypted);
        assert!(finding_codes(&report).contains(&"unsupported_wal_version"));
        assert!(
            report.entries.is_empty(),
            "unsupported WAL was parsed as v2"
        );
        assert_eq!(report.last_good_flush, None);
    }
}

#[test]
fn declared_length_beyond_remaining_file_is_out_of_bounds_and_truncated() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = version_header(2);
    bytes.extend(100_u64.to_le_bytes());
    bytes.extend(123_u64.to_le_bytes());
    bytes.extend([7; 10]);
    let path = fixture(&directory, "bad-length.wal", &bytes);
    let report = run_json(&path);
    let codes = finding_codes(&report);
    assert!(codes.contains(&"entry_exceeds_remaining_file"));
    assert!(codes.contains(&"truncated_entry"));
    assert_eq!(report.summary.out_of_bounds_entries, 1);
    assert_eq!(report.summary.truncated_entries, 1);
    assert_eq!(report.entries[0].declared_length, Some(100));
    assert_eq!(report.entries[0].actual_length, 10);
    assert_eq!(report.first_unparsed_offset, Some(8));
    assert_eq!(report.last_good_flush, None);
}

#[test]
fn checksum_bit_flip_does_not_become_torn_write_or_fake_flush() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    let expected = manifest(NORMAL_MANIFEST);
    let payload_offset = expected["entries"][0]["payload_offset"].as_u64().unwrap() as usize;
    bytes[payload_offset] ^= 1;
    let path = fixture(&directory, "checksum.wal", &bytes);
    let (report, json) = run_json_with_args(&path, &[]);
    assert!(finding_codes(&report).contains(&"checksum_mismatch"));
    assert_eq!(report.summary.checksum_failed_entries, 1);
    assert_eq!(report.first_checksum_mismatch_offset, Some(30));
    assert_eq!(
        report.entries[0].parse_status,
        WalEntryParseStatus::ChecksumMismatch
    );
    assert_eq!(report.entries[0].entry_type, "unknown");
    assert_eq!(
        report.confirmed_flushes.len(),
        1,
        "later physical flush remains observable"
    );
    assert_eq!(
        report.last_good_flush, None,
        "an earlier mismatch invalidates continuity"
    );
    assert!(!json.to_lowercase().contains("torn write\""));
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.code != "possible_torn_write")
    );
}

#[test]
fn zero_filled_tail_is_evidence_not_a_recovery_verdict() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes.extend([0; 32]);
    let path = fixture(&directory, "zero-tail.wal", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"zero_filled_tail"));
    assert_eq!(report.tail.all_zero, Some(true));
    assert_eq!(report.tail.zero_suffix_offset, Some(NORMAL.len() as u64));
    assert_eq!(report.tail.zero_suffix_length, 32);
    assert_eq!(
        report.last_good_flush.map(|flush| flush.end_offset),
        Some(NORMAL.len() as u64)
    );
    assert!(report.unterminated_data_after_last_flush);
    let inference = report
        .inferences
        .iter()
        .find(|inference| inference.code == "zero_filled_tail_evidence")
        .expect("inference");
    assert_eq!(inference.confidence, duckdb_report::Confidence::Low);
}

#[test]
fn nonzero_trailing_damage_is_unparsed_without_panic() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes.extend([1; 32]);
    let path = fixture(&directory, "nonzero-tail.wal", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"unparsed_trailing_data"));
    assert_eq!(report.tail.all_zero, Some(false));
    assert_eq!(report.first_unparsed_offset, Some(NORMAL.len() as u64));
    assert_eq!(
        report.last_good_flush.map(|flush| flush.end_offset),
        Some(NORMAL.len() as u64)
    );
}

#[test]
fn deterministic_random_bytes_do_not_panic_or_guess_a_version() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    let mut bytes = vec![0_u8; 4096];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    let path = fixture(&directory, "random.wal", &bytes);
    let report = run_json(&path);
    assert_eq!(report.status, WalStatus::Invalid);
    assert_eq!(report.version, None);
    assert!(finding_codes(&report).contains(&"invalid_wal_header"));
    assert_eq!(report.first_unparsed_offset, Some(0));
    assert_eq!(report.last_good_flush, None);
}

#[test]
fn huge_declared_length_does_not_overflow_allocate_or_panic() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = version_header(2);
    bytes.extend(u64::MAX.to_le_bytes());
    bytes.extend(0_u64.to_le_bytes());
    let path = fixture(&directory, "huge-length.wal", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"invalid_entry_length"));
    assert_eq!(report.entries[0].declared_length, Some(u64::MAX));
    assert_eq!(report.entries[0].declared_frame_end, None);
    assert_eq!(report.entries[0].actual_length, 0);
    assert_eq!(report.summary.out_of_bounds_entries, 1);
}

#[test]
fn zero_declared_length_is_invalid() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = version_header(2);
    bytes.extend(0_u64.to_le_bytes());
    bytes.extend(0_u64.to_le_bytes());
    let path = fixture(&directory, "zero-length.wal", &bytes);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"invalid_entry_length"));
    assert_eq!(
        report.entries[0].parse_status,
        WalEntryParseStatus::InvalidEntryLength
    );
}

#[test]
fn historical_issue_corpus_uses_the_same_cut_for_truncation_and_zero_filling() {
    let expected = manifest(ISSUE_MANIFEST);
    assert_eq!(
        ISSUE_TRUNCATED.len(),
        expected["cut_offset"].as_u64().unwrap() as usize
    );
    assert_eq!(
        ISSUE_ZERO_FILLED.len(),
        expected["original_size"].as_u64().unwrap() as usize
    );
    assert_eq!(
        sha256(ISSUE_TRUNCATED),
        expected["truncated_sha256"].as_str().unwrap()
    );
    assert_eq!(
        sha256(ISSUE_ZERO_FILLED),
        expected["zero_filled_sha256"].as_str().unwrap()
    );
    assert!(
        ISSUE_TRUNCATED
            .iter()
            .zip(ISSUE_ZERO_FILLED.iter())
            .all(|(left, right)| left == right)
    );

    let directory = tempfile::tempdir().expect("tempdir");
    let short_path = fixture(&directory, "issue-short.wal", ISSUE_TRUNCATED);
    let zero_path = fixture(&directory, "issue-zero.wal", ISSUE_ZERO_FILLED);
    let short = run_json(&short_path);
    let zero = run_json(&zero_path);
    let cut = expected["cut_offset"].as_u64().unwrap();
    let last_entry = expected["last_entry_offset"].as_u64().unwrap();
    assert_eq!(short.first_unparsed_offset, Some(last_entry));
    assert_eq!(zero.first_unparsed_offset, Some(last_entry));
    assert_eq!(
        short.entries[1].actual_length,
        expected["truncated_actual_length"].as_u64().unwrap()
    );
    assert_eq!(
        zero.entries[1].actual_length,
        expected["last_entry_declared_length"].as_u64().unwrap()
    );
    assert!(finding_codes(&short).contains(&"truncated_entry"));
    assert!(finding_codes(&short).contains(&"entry_exceeds_remaining_file"));
    assert!(finding_codes(&zero).contains(&"checksum_mismatch"));
    assert!(finding_codes(&zero).contains(&"zero_filled_tail"));
    assert_eq!(zero.tail.zero_suffix_offset, Some(cut));
    assert_eq!(
        zero.tail.zero_suffix_length,
        expected["zero_suffix_length"].as_u64().unwrap()
    );
    assert_eq!(
        short.last_good_flush.map(|flush| flush.end_offset),
        expected["last_good_flush_end"].as_u64()
    );
    assert_eq!(
        zero.last_good_flush.map(|flush| flush.end_offset),
        expected["last_good_flush_end"].as_u64()
    );
    assert!(
        !zero
            .findings
            .iter()
            .any(|finding| finding.message.contains("current DuckDB"))
    );
}

#[test]
fn malformed_flush_unknown_type_and_business_payload_are_not_guessed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut malformed = version_header(2);
    malformed.extend(frame(&[100, 0, 100, 0, 255, 255]));
    let path = fixture(&directory, "bad-flush.wal", &malformed);
    let report = run_json(&path);
    assert_eq!(report.entries[0].entry_type, "wal_flush");
    assert!(report.confirmed_flushes.is_empty());
    assert_eq!(report.last_good_flush, None);

    let mut unknown = version_header(2);
    unknown.extend(frame(&[100, 0, 200, 1, 255, 255]));
    let path = fixture(&directory, "unknown.wal", &unknown);
    let report = run_json(&path);
    assert_eq!(report.entries[0].entry_type, "unknown");
    assert_eq!(report.entries[0].raw_entry_type, Some(200));
    assert_eq!(report.summary.unknown_type_entries, 1);
    assert_eq!(report.last_good_flush, None);

    let mut insert = version_header(2);
    insert.extend(frame(&[100, 0, 26, 101, 0, 1, 2, 3, 255, 255]));
    let path = fixture(&directory, "insert.wal", &insert);
    let (report, json) = run_json_with_args(&path, &[]);
    assert_eq!(report.entries[0].entry_type, "insert_tuple");
    assert_eq!(
        report.entries[0].payload_status,
        duckdb_report::wal::WalPayloadStatus::NotDecoded
    );
    assert!(
        report
            .unknowns
            .iter()
            .any(|unknown| unknown.code == "business_payloads_not_decoded")
    );
    assert!(!json.contains("payload_bytes"));
}

#[test]
fn resource_limits_stop_cleanly_without_faking_later_flush() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "limited.wal", NORMAL);
    let before = sha256(NORMAL);
    let report = inspect_wal_path_with_limits(
        &path,
        WalInspectionLimits {
            max_entries: 2,
            ..WalInspectionLimits::default()
        },
    )
    .expect("entry limit inspection");
    assert_eq!(report.status, WalStatus::ResourceLimitReached);
    assert!(finding_codes(&report).contains(&"resource_limit_reached"));
    assert_eq!(report.summary.total_entries, 2);
    assert_eq!(
        report.last_good_flush.map(|flush| flush.end_offset),
        Some(51)
    );

    let report = inspect_wal_path_with_limits(
        &path,
        WalInspectionLimits {
            max_entry_size: 4,
            ..WalInspectionLimits::default()
        },
    )
    .expect("entry size inspection");
    assert_eq!(report.status, WalStatus::ResourceLimitReached);
    assert_eq!(
        report.entries[0].checksum_status,
        duckdb_report::wal::WalChecksumStatus::Unavailable
    );
    assert_eq!(report.last_good_flush, None);
    assert_eq!(before, sha256(&fs::read(&path).expect("read limited WAL")));
}

#[test]
fn text_output_schema_and_output_file_cover_required_fields() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.wal", NORMAL);
    let output = run(&path, &["--format", "text"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("UTF-8 text");
    for required in [
        "WAL version",
        "File size",
        "SHA-256",
        "Entries",
        "First unparsed offset",
        "Confirmed WAL_FLUSH",
        "Last verified Flush boundary",
        "Checkpoint Marker",
        "Tail and Coverage",
        "Unknowns",
    ] {
        assert!(text.contains(required), "missing text field {required}");
    }

    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON Schema");
    assert_eq!(schema["properties"]["schema_version"]["const"], "1");
    assert!(
        schema["properties"]["last_good_flush"]["anyOf"]
            .as_array()
            .unwrap()
            .len()
            == 2
    );
    assert!(
        schema["$defs"]["finding"]["properties"]["code"]["enum"]
            .as_array()
            .unwrap()
            .contains(&Value::from("resource_limit_reached"))
    );

    let output_path = directory.path().join("wal-report.json");
    let output = run(
        &path,
        &[
            "--format",
            "json",
            "--output",
            output_path.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: WalReport = serde_json::from_slice(&fs::read(&output_path).expect("read output"))
        .expect("output report");
    assert_eq!(
        report.input.sha256.as_deref(),
        Some(sha256(NORMAL).as_str())
    );
}

#[test]
fn output_cannot_overwrite_wal_or_hard_link() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.wal", NORMAL);
    let before = sha256(NORMAL);
    let output = run(
        &path,
        &["--format", "json", "--output", path.to_str().unwrap()],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite input"));
    assert_eq!(before, sha256(&fs::read(&path).expect("read WAL")));

    #[cfg(unix)]
    {
        let alias = directory.path().join("alias.json");
        fs::hard_link(&path, &alias).expect("hard link");
        let output = run(
            &path,
            &["--format", "json", "--output", alias.to_str().unwrap()],
        );
        assert!(!output.status.success());
        assert_eq!(before, sha256(&fs::read(&path).expect("read WAL")));
        assert_eq!(before, sha256(&fs::read(&alias).expect("read alias")));
    }
}

#[test]
fn mid_frame_truncation_and_short_fixed_header_both_avoid_panics() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "short-header.wal", &NORMAL[..NORMAL.len() - 19]);
    let report = run_json(&path);
    assert!(finding_codes(&report).contains(&"truncated_entry"));
    assert_eq!(report.entries.last().unwrap().declared_length, None);
    assert_eq!(
        report.last_good_flush.map(|flush| flush.end_offset),
        Some(51)
    );
}
