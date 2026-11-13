#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use duckdb_forensics::verify::{VerifyLimits, verify_path_with_limits};
use duckdb_format::{BLOCK_START, duckdb_checksum};
use duckdb_report::verify::{MetaChainStatus, VerifyReport, VerifyStatus};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NORMAL: &[u8] = include_bytes!("fixtures/normal.duckdb");
const SCHEMA: &str = include_str!("../../../schemas/verify-report.schema.json");
const MANIFEST: &str = include_str!("fixtures/normal.manifest.json");
const ALLOC: usize = 262_144;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_duckdb-forensics")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fixture(directory: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.path().join(name);
    fs::write(&path, bytes).expect("write fixture");
    path
}

fn run(path: &Path, extra: &[&str]) -> Output {
    let before = sha256(&fs::read(path).expect("read evidence"));
    let output = Command::new(binary())
        .arg("verify")
        .arg(path)
        .args(extra)
        .output()
        .expect("run verify");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "verify panicked"
    );
    assert_eq!(before, sha256(&fs::read(path).expect("reread evidence")));
    output
}

fn run_json(path: &Path, blocks: bool) -> (VerifyReport, String) {
    let mut args = vec!["--format", "json"];
    if blocks {
        args.push("--blocks");
    }
    let output = run(path, &args);
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    let report = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("invalid verify JSON: {error}\n{stdout}"));
    (report, stdout)
}

fn repair_block_checksum(bytes: &mut [u8], block_id: usize) {
    let offset = BLOCK_START as usize + block_id * ALLOC;
    let checksum = duckdb_checksum(&bytes[offset + 8..offset + ALLOC]);
    bytes[offset..offset + 8].copy_from_slice(&checksum.to_le_bytes());
}

fn repair_header_checksum(bytes: &mut [u8], page_offset: usize) {
    let checksum = duckdb_checksum(&bytes[page_offset + 8..page_offset + 4096]);
    bytes[page_offset..page_offset + 8].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn official_fixture_full_scan_verifies_blocks_and_meta_chains() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let (report, json) = run_json(&path, true);
    assert_eq!(report.status, VerifyStatus::Complete);
    assert_eq!(report.selected_header.expect("selected").block_count, 2);
    assert_eq!(report.blocks.physical_blocks_scanned, 2);
    assert_eq!(report.blocks.valid_checksums, 2);
    assert_eq!(report.blocks.checksum_mismatches, 0);
    assert_eq!(report.meta_chains.len(), 2);
    assert!(
        report
            .meta_chains
            .iter()
            .all(|chain| chain.status == MetaChainStatus::Terminated)
    );
    let manifest: Value = serde_json::from_str(MANIFEST).expect("fixture manifest");
    let expected_blocks = manifest["block_stored_checksums"]
        .as_array()
        .expect("block checksums")
        .len() as u64;
    assert_eq!(report.blocks.valid_checksums, expected_blocks);
    let metadata_size = manifest["metadata_block_size"].as_u64().expect("meta size");
    assert_eq!(report.meta_chains[0].payload_capacity, metadata_size - 8);
    assert_eq!(manifest["metadata_next_pointers"]["meta_block"], u64::MAX);
    assert_eq!(manifest["metadata_next_pointers"]["free_list"], u64::MAX);
    assert!(report.findings.is_empty());
    assert!(!json.to_lowercase().contains("orphan"));
    let schema: Value = serde_json::from_str(SCHEMA).expect("schema JSON");
    assert_eq!(schema["properties"]["schema_version"]["const"], "1");
}

#[test]
fn default_scope_marks_unvisited_blocks_not_checked() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let (report, _) = run_json(&path, false);
    assert_eq!(report.blocks.physical_blocks_scanned, 0);
    assert_eq!(report.blocks.metadata_blocks_checked, 1);
    assert!(
        report
            .coverage
            .not_checked
            .iter()
            .any(|area| area.contains("--blocks"))
    );
}

#[test]
fn block_damage_does_not_stop_later_blocks_or_panic() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes[BLOCK_START as usize + ALLOC + 100] ^= 1;
    let path = fixture(&directory, "block-damage.duckdb", &bytes);
    let (report, json) = run_json(&path, true);
    assert_eq!(report.status, VerifyStatus::Incomplete);
    assert_eq!(report.blocks.physical_blocks_scanned, 2);
    assert_eq!(report.blocks.checksum_mismatches, 1);
    assert_eq!(report.blocks.valid_checksums, 1);
    assert_eq!(report.meta_chains[0].status, MetaChainStatus::Terminated);
    assert!(!json.to_lowercase().contains("orphan"));
}

#[test]
fn partial_recorded_block_is_truncated_not_checksummed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "truncated.duckdb", &NORMAL[..NORMAL.len() - 1]);
    let (report, _) = run_json(&path, true);
    assert_eq!(report.blocks.physical_blocks_scanned, 1);
    assert_eq!(report.blocks.truncated_blocks, 1);
    assert!(
        report
            .blocks
            .issues
            .iter()
            .any(|issue| issue.kind == duckdb_report::verify::BlockIssueKind::TruncatedBlock)
    );
}

#[test]
fn extra_data_is_classified_without_orphan_or_corruption_verdict() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes.extend([7; 17]);
    let path = fixture(&directory, "tail.duckdb", &bytes);
    let (report, _) = run_json(&path, false);
    assert_eq!(report.trailing_data.residual_bytes, 17);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "trailing_data")
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.code != "checksum_mismatch")
    );
}

#[test]
fn self_cycle_and_multi_node_cycle_are_bounded() {
    for multi_node in [false, true] {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut bytes = NORMAL.to_vec();
        let root = BLOCK_START as usize + 8;
        let next = if multi_node { 1_u64 << 56 } else { 0 };
        bytes[root..root + 8].copy_from_slice(&next.to_le_bytes());
        if multi_node {
            let second = root + 4088;
            bytes[second..second + 8].copy_from_slice(&0_u64.to_le_bytes());
        }
        repair_block_checksum(&mut bytes, 0);
        let path = fixture(&directory, "cycle.duckdb", &bytes);
        let (report, _) = run_json(&path, false);
        assert_eq!(report.meta_chains[0].status, MetaChainStatus::Cycle);
        assert_eq!(
            report.meta_chains[0].visited_nodes,
            if multi_node { 2 } else { 1 }
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "meta_block_cycle")
        );
    }
}

#[test]
fn out_of_bounds_meta_pointer_is_an_isolated_finding() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes[4096 + 16..4096 + 24].copy_from_slice(&99_u64.to_le_bytes());
    repair_header_checksum(&mut bytes, 4096);
    let path = fixture(&directory, "bad-root.duckdb", &bytes);
    let (report, _) = run_json(&path, false);
    assert_eq!(
        report.meta_chains[0].status,
        MetaChainStatus::InvalidPointer
    );
    assert_eq!(report.blocks.out_of_bounds_references, 1);
    assert_eq!(report.meta_chains[1].status, MetaChainStatus::Terminated);
}

#[test]
fn shared_blocks_across_chains_are_not_cycles_or_corruption() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes[4096 + 24..4096 + 32].copy_from_slice(&0_u64.to_le_bytes());
    repair_header_checksum(&mut bytes, 4096);
    let path = fixture(&directory, "shared.duckdb", &bytes);
    let (report, _) = run_json(&path, false);
    assert!(
        report
            .meta_chains
            .iter()
            .all(|chain| chain.status == MetaChainStatus::Terminated)
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.code != "meta_block_cycle")
    );
}

#[test]
fn encrypted_regions_are_unsupported_not_plaintext_mismatches() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes[20..28].copy_from_slice(&1_u64.to_le_bytes());
    repair_header_checksum(&mut bytes, 0);
    let path = fixture(&directory, "encrypted.duckdb", &bytes);
    let (report, _) = run_json(&path, true);
    assert_eq!(report.status, VerifyStatus::Unsupported);
    assert!(report.selected_header.is_none());
    assert_eq!(report.blocks.checksum_mismatches, 0);
    assert!(!report.coverage.unsupported.is_empty());
}

#[test]
fn meta_node_budget_is_not_a_corruption_verdict() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let report = verify_path_with_limits(
        &path,
        false,
        VerifyLimits {
            max_meta_nodes: 0,
            ..VerifyLimits::default()
        },
    )
    .expect("limited verification");
    assert_eq!(report.status, VerifyStatus::ResourceLimitReached);
    assert!(
        report
            .meta_chains
            .iter()
            .all(|chain| chain.status == MetaChainStatus::ResourceLimitReached)
    );
}

#[test]
fn complete_blocks_beyond_count_are_not_orphans() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes.extend(vec![0; ALLOC]);
    let path = fixture(&directory, "extra-block.duckdb", &bytes);
    let (report, json) = run_json(&path, false);
    assert_eq!(report.blocks.complete_blocks_beyond_header_count, 1);
    assert_eq!(report.blocks.trailing_bytes, 0);
    assert_eq!(report.blocks.checksum_mismatches, 0);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "beyond_header_block_count")
    );
    assert!(!json.to_lowercase().contains("orphan"));
}

#[test]
fn failed_meta_block_checksum_prevents_trusting_next_pointer() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut bytes = NORMAL.to_vec();
    bytes[BLOCK_START as usize + 100] ^= 1;
    let path = fixture(&directory, "bad-meta-block.duckdb", &bytes);
    let (report, _) = run_json(&path, false);
    assert!(
        report
            .meta_chains
            .iter()
            .all(|chain| chain.status == MetaChainStatus::ChecksumUnavailable)
    );
    assert!(
        report
            .meta_chains
            .iter()
            .all(|chain| chain.verified_nodes == 0)
    );
}

#[test]
fn text_output_contains_coverage_and_no_health_claim() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture(&directory, "normal.duckdb", NORMAL);
    let output = run(&path, &["--format", "text"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("UTF-8 text");
    for required in [
        "Block Verification",
        "Meta Block Chains",
        "Not checked",
        "Unsupported",
        "Unavailable",
    ] {
        assert!(text.contains(required), "missing {required}");
    }
    assert!(!text.to_lowercase().contains("healthy"));
}
