#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use duckdb_forensics::{
    InspectionLimits, RecoveryLimits, WalInspectionLimits, inspect_path, inspect_path_with_limits,
    inspect_wal_path, inspect_wal_path_with_limits, recover_plan_path_with_limits, verify_path,
};
use duckdb_format::duckdb_checksum;
use duckdb_report::FindingCategory;
use duckdb_report::verify::VerifyStatus;

const NORMAL_DB: &[u8] = include_bytes!("fixtures/normal.duckdb");
const NORMAL_WAL: &[u8] = include_bytes!("fixtures/normal.wal");

#[test]
fn non_regular_inputs_are_operational_errors() {
    let directory = tempfile::tempdir().expect("tempdir");
    assert!(inspect_path(directory.path(), false).is_err());
    assert!(inspect_wal_path(directory.path()).is_err());
}

#[test]
fn invalid_header_utf8_is_null_with_raw_evidence() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("invalid-utf8.duckdb");
    let mut bytes = NORMAL_DB.to_vec();
    bytes[52] = 0xff;
    let checksum = duckdb_checksum(&bytes[8..4096]);
    bytes[..8].copy_from_slice(&checksum.to_le_bytes());
    fs::write(&path, bytes).expect("write fixture");

    let report = inspect_path(&path, false).expect("inspection");
    let text = report
        .observation("main_header", "library_git_desc")
        .expect("text");
    let valid = report
        .observation("main_header", "library_git_desc_utf8_valid")
        .expect("validity");
    let raw = report
        .observation("main_header", "library_git_desc_hex")
        .expect("raw bytes");
    assert_eq!(text.value, serde_json::Value::Null);
    assert_eq!(valid.value, false);
    assert!(raw.value.as_str().is_some_and(|hex| hex.starts_with("ff")));
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.code == "checksum_mismatch"
                && finding.category == FindingCategory::Corruption)
    );
}

#[test]
fn unsupported_main_version_is_not_incomplete_verification() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("unsupported.duckdb");
    let mut bytes = NORMAL_DB.to_vec();
    bytes[12..20].copy_from_slice(&64_u64.to_le_bytes());
    let checksum = duckdb_checksum(&bytes[8..4096]);
    bytes[..8].copy_from_slice(&checksum.to_le_bytes());
    fs::write(&path, bytes).expect("write fixture");

    let report = verify_path(&path, false).expect("verification");
    assert_eq!(report.status, VerifyStatus::Unsupported);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.category == FindingCategory::Unsupported)
    );
}

#[test]
fn wal_report_retention_preserves_scan_and_flush_counts() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("retained.wal");
    let mut bytes = NORMAL_WAL[..30].to_vec();
    bytes.extend_from_slice(&NORMAL_WAL[30..51]);
    bytes.extend_from_slice(&NORMAL_WAL[30..51]);
    bytes.extend_from_slice(&NORMAL_WAL[30..51]);
    fs::write(&path, bytes).expect("write WAL");

    let report = inspect_wal_path_with_limits(
        &path,
        WalInspectionLimits {
            max_report_entries: 2,
            ..WalInspectionLimits::default()
        },
    )
    .expect("WAL inspection");
    assert_eq!(report.summary.total_entries, 3);
    assert_eq!(report.summary.reported_entries, 2);
    assert_eq!(report.summary.entries_omitted, 1);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(report.confirmed_flushes.len(), 2);
    assert_eq!(report.confirmed_flushes_omitted, 1);
    assert_eq!(
        report.last_good_flush.map(|flush| flush.end_offset),
        Some(93)
    );
    assert!(report.report_limits.contains(&"entries".to_owned()));
    assert!(
        report
            .report_limits
            .contains(&"confirmed_flushes".to_owned())
    );
}

#[test]
fn recovery_inventory_limits_are_structured_and_prevent_actions() {
    for kind in ["entries", "depth", "bytes"] {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("evidence");
        fs::create_dir(&root).expect("evidence dir");
        fs::write(root.join("evidence.duckdb"), NORMAL_DB).expect("database");
        fs::write(root.join("evidence.duckdb.wal"), NORMAL_WAL).expect("WAL");
        fs::create_dir(root.join("nested")).expect("nested dir");
        fs::write(root.join("nested/note"), [1]).expect("note");
        let mut limits = RecoveryLimits {
            max_evidence_files: 16,
            ..RecoveryLimits::default()
        };
        match kind {
            "entries" => limits.max_evidence_files = 1,
            "depth" => limits.max_evidence_depth = 0,
            "bytes" => limits.max_evidence_bytes = 1,
            _ => unreachable!(),
        }
        let report = recover_plan_path_with_limits(&root, limits).expect("limited plan");
        assert!(!report.observed_facts.inventory_complete);
        assert!(!report.observed_facts.evidence_unchanged);
        assert!(report.observed_facts.database.is_none());
        assert!(report.candidate_actions.is_empty());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.category == FindingCategory::Limit)
        );
    }
}

#[cfg(unix)]
#[test]
fn huge_sparse_files_stop_before_hashing() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("sparse.input");
    let file = fs::File::create(&path).expect("sparse file");
    file.set_len(2 * 1024 * 1024 * 1024 * 1024)
        .expect("sparse length");
    drop(file);
    let before = fs::metadata(&path).expect("metadata").len();

    let inspection = inspect_path_with_limits(
        &path,
        false,
        InspectionLimits {
            max_file_size: 1024 * 1024,
        },
    )
    .expect("limited inspection");
    assert!(inspection.input.sha256.is_none());
    assert!(
        inspection
            .findings
            .iter()
            .any(|finding| finding.category == FindingCategory::Limit)
    );

    let wal = inspect_wal_path_with_limits(
        &path,
        WalInspectionLimits {
            max_file_size: 1024 * 1024,
            ..WalInspectionLimits::default()
        },
    )
    .expect("limited WAL inspection");
    assert!(wal.input.sha256.is_none());
    assert!(wal.last_good_flush.is_none());
    assert_eq!(fs::metadata(&path).expect("metadata").len(), before);
}

#[test]
fn wal_float_report_roundtrip_regression_is_exact() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("float-roundtrip.wal");
    let mut bytes = vec![100, 0, 98, 101, 0, 2, 255, 255];
    bytes.extend(6_u64.to_le_bytes());
    bytes.extend(0_u64.to_le_bytes());
    bytes.extend([0; 5]);
    fs::write(&path, bytes).expect("write regression");
    let report = inspect_wal_path(&path).expect("WAL inspection");
    let encoded = serde_json::to_string(&report).expect("serialize report");
    let decoded: duckdb_report::wal::WalReport =
        serde_json::from_str(&encoded).expect("deserialize report");
    assert_eq!(decoded, report);
}

#[test]
fn missing_input_does_not_create_companion_wal() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("empty.duckdb");
    fs::write(&path, []).expect("empty input");
    assert!(inspect_path(&path, false).is_ok());
    assert!(!Path::new(&format!("{}.wal", path.display())).exists());
}
