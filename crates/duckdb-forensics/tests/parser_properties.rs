#![forbid(unsafe_code)]

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use duckdb_forensics::{
    InspectionLimits, VerifyLimits, WalInspectionLimits, inspect_path_with_limits,
    inspect_wal_path_with_limits, verify_path_with_limits,
};
use duckdb_format::{BLOCK_START, duckdb_checksum};
use duckdb_report::verify::VerifyReport;
use duckdb_report::wal::WalReport;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

const NORMAL_DB: &[u8] = include_bytes!("fixtures/normal.duckdb");

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 32,
        max_shrink_iters: 10_000,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

fn wal_limits() -> WalInspectionLimits {
    WalInspectionLimits {
        max_file_size: 4096,
        max_entries: 64,
        max_entry_size: 1024,
        max_report_entries: 8,
    }
}

fn verify_limits() -> VerifyLimits {
    VerifyLimits {
        inspection: InspectionLimits {
            max_file_size: 1024 * 1024,
        },
        max_meta_nodes: 8,
        max_block_issues: 4,
    }
}

fn write_input(directory: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = directory.path().join("input.bin");
    fs::write(&path, bytes).expect("write property input");
    path
}

fn assert_wal_invariants(report: &WalReport, file_size: u64) {
    assert_eq!(
        report.summary.total_entries,
        report.summary.reported_entries + report.summary.entries_omitted
    );
    assert_eq!(
        report.summary.reported_entries as usize,
        report.entries.len()
    );
    assert!(report.scan_stop_offset <= file_size);
    assert!(report.coverage.scanned_percent.is_finite());
    assert!((0.0..=100.0).contains(&report.coverage.scanned_percent));
    assert!(report.coverage.complete_frame_percent.is_finite());
    assert!((0.0..=100.0).contains(&report.coverage.complete_frame_percent));
    let mut previous = None;
    for (index, entry) in report.entries.iter().enumerate() {
        assert_eq!(entry.index, index as u64);
        assert!(entry.offset <= file_size);
        assert!(entry.actual_frame_end <= file_size);
        assert!(entry.actual_frame_end >= entry.offset);
        if let Some(declared) = entry.declared_length {
            assert!(entry.actual_length <= declared);
        }
        if let Some(previous) = previous {
            assert!(entry.offset > previous);
        }
        previous = Some(entry.offset);
    }
    if let Some(flush) = report.last_good_flush {
        assert!(flush.end_offset <= file_size);
        assert!(report.confirmed_flushes.contains(&flush) || report.confirmed_flushes_omitted > 0);
    }
    let encoded = serde_json::to_string(report).expect("serialize WAL report");
    let decoded: WalReport = serde_json::from_str(&encoded).expect("deserialize WAL report");
    assert_eq!(&decoded, report);
}

fn assert_verify_invariants(report: &VerifyReport, file_size: u64) {
    assert!(report.coverage.integrity_checked_percent.is_finite());
    assert!((0.0..=100.0).contains(&report.coverage.integrity_checked_percent));
    assert!(report.blocks.issues.len() <= 4);
    assert!(
        report
            .meta_chains
            .iter()
            .all(|chain| chain.visited_nodes <= 8)
    );
    assert!(report.input.file_size == file_size);
    let encoded = serde_json::to_string(report).expect("serialize verify report");
    let decoded: VerifyReport = serde_json::from_str(&encoded).expect("deserialize verify report");
    assert_eq!(&decoded, report);
}

fn run_all_parsers(path: &Path, file_size: u64) {
    let inspection = catch_unwind(AssertUnwindSafe(|| {
        inspect_path_with_limits(
            path,
            false,
            InspectionLimits {
                max_file_size: 4096,
            },
        )
    }));
    assert!(inspection.is_ok(), "inspect panicked");
    let inspection = inspection.expect("no panic").expect("inspection");
    let encoded = serde_json::to_string(&inspection).expect("serialize inspection");
    let decoded: duckdb_report::InspectionReport =
        serde_json::from_str(&encoded).expect("deserialize inspection");
    assert_eq!(decoded, inspection);

    let wal = catch_unwind(AssertUnwindSafe(|| {
        inspect_wal_path_with_limits(path, wal_limits())
    }));
    assert!(wal.is_ok(), "WAL parser panicked");
    let wal = wal.expect("no panic").expect("WAL inspection");
    assert_wal_invariants(&wal, file_size);

    let verify = catch_unwind(AssertUnwindSafe(|| {
        verify_path_with_limits(path, true, verify_limits())
    }));
    assert!(verify.is_ok(), "verify panicked");
    let verify = verify.expect("no panic").expect("verification");
    assert_verify_invariants(&verify, file_size);
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_files_never_panic_and_preserve_input(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_input(&directory, &bytes);
        run_all_parsers(&path, bytes.len() as u64);
        prop_assert_eq!(fs::read(&path).expect("reread input"), bytes);
    }

    #[test]
    fn extreme_wal_lengths_never_panic(
        declared in any::<u64>(),
        payload in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut bytes = vec![100, 0, 98, 101, 0, 2, 255, 255];
        bytes.extend(declared.to_le_bytes());
        bytes.extend(0_u64.to_le_bytes());
        bytes.extend(&payload);
        let path = write_input(&directory, &bytes);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            inspect_wal_path_with_limits(&path, wal_limits())
        }));
        prop_assert!(outcome.is_ok());
        let report = outcome.expect("no panic").expect("WAL inspection");
        assert_wal_invariants(&report, bytes.len() as u64);
        prop_assert_eq!(fs::read(&path).expect("reread input"), bytes);
    }

    #[test]
    fn structured_metadata_damage_never_panics(
        block_count in 0_u64..=2,
        meta_block_id in 0_u64..=3,
        meta_index in 0_u64..=65,
        free_block_id in 0_u64..=3,
        free_index in 0_u64..=65,
        next in any::<u64>(),
    ) {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut bytes = NORMAL_DB.to_vec();
        bytes[4096 + 32..4096 + 40].copy_from_slice(&block_count.to_le_bytes());
        let meta = (meta_index << 56) | meta_block_id;
        let free = (free_index << 56) | free_block_id;
        bytes[4096 + 16..4096 + 24].copy_from_slice(&meta.to_le_bytes());
        bytes[4096 + 24..4096 + 32].copy_from_slice(&free.to_le_bytes());
        let header_checksum = duckdb_checksum(&bytes[4096 + 8..8192]);
        bytes[4096..4104].copy_from_slice(&header_checksum.to_le_bytes());
        let block = BLOCK_START as usize;
        bytes[block + 8..block + 16].copy_from_slice(&next.to_le_bytes());
        let block_checksum = duckdb_checksum(&bytes[block + 8..block + 262_144]);
        bytes[block..block + 8].copy_from_slice(&block_checksum.to_le_bytes());
        let path = write_input(&directory, &bytes);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            verify_path_with_limits(&path, true, verify_limits())
        }));
        prop_assert!(outcome.is_ok());
        let report = outcome.expect("no panic").expect("verification");
        assert_verify_invariants(&report, bytes.len() as u64);
        prop_assert_eq!(fs::read(&path).expect("reread input"), bytes);
    }
}
