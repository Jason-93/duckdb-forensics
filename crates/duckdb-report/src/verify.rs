use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::oracle::OracleReport;
use crate::{Check, Finding, Inference, InputInfo, Observation, SkippedCheck, Unknown};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    Complete,
    Incomplete,
    Unsupported,
    ResourceLimitReached,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectedHeaderReport {
    pub index: usize,
    pub iteration: u64,
    pub block_count: u64,
    pub block_alloc_size: u64,
    pub meta_block: u64,
    pub free_list: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockIssueKind {
    ChecksumMismatch,
    TruncatedBlock,
    OutOfBounds,
    TrailingData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockIssue {
    pub kind: BlockIssueKind,
    pub block_id: Option<u64>,
    pub offset: u64,
    pub expected_length: Option<u64>,
    pub actual_length: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BlockScanReport {
    pub full_scan_requested: bool,
    pub physical_blocks_scanned: u64,
    pub metadata_blocks_checked: u64,
    pub valid_checksums: u64,
    pub checksum_mismatches: u64,
    pub truncated_blocks: u64,
    pub out_of_bounds_references: u64,
    pub complete_blocks_beyond_header_count: u64,
    pub trailing_bytes: u64,
    pub issues: Vec<BlockIssue>,
    pub issues_omitted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaChainStatus {
    Terminated,
    NotPresent,
    Cycle,
    InvalidPointer,
    ChecksumUnavailable,
    Unsupported,
    ResourceLimitReached,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaChainReport {
    pub name: String,
    pub root_pointer: u64,
    pub status: MetaChainStatus,
    pub visited_nodes: u64,
    pub verified_nodes: u64,
    pub payload_capacity: u64,
    pub stop_offset: Option<u64>,
    pub cycle_pointer: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrailingDataReport {
    pub recorded_file_end: Option<u64>,
    pub complete_blocks_beyond_header_count: u64,
    pub residual_offset: Option<u64>,
    pub residual_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VerifyCoverage {
    pub file_size: u64,
    pub integrity_checked_bytes: u64,
    pub integrity_checked_percent: f64,
    pub meta_checked_bytes: u64,
    pub checked: Vec<String>,
    pub not_checked: Vec<String>,
    pub unsupported: Vec<String>,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyReport {
    pub schema_version: String,
    pub tool_version: String,
    pub status: VerifyStatus,
    pub input: InputInfo,
    pub observations: Vec<Observation>,
    pub selected_header: Option<SelectedHeaderReport>,
    pub blocks: BlockScanReport,
    pub meta_chains: Vec<MetaChainReport>,
    pub trailing_data: TrailingDataReport,
    pub coverage: VerifyCoverage,
    pub findings: Vec<Finding>,
    pub inferences: Vec<Inference>,
    pub checks_passed: Vec<Check>,
    pub checks_failed: Vec<Check>,
    pub checks_skipped: Vec<SkippedCheck>,
    pub unknowns: Vec<Unknown>,
    pub oracle: Option<OracleReport>,
}

impl VerifyReport {
    pub fn from_header_report(report: crate::InspectionReport) -> Self {
        let file_size = report.input.file_size;
        Self {
            schema_version: "1".to_owned(),
            tool_version: report.tool_version.clone(),
            status: VerifyStatus::Incomplete,
            input: report.input,
            observations: report.observations,
            selected_header: None,
            blocks: BlockScanReport::default(),
            meta_chains: Vec::new(),
            trailing_data: TrailingDataReport {
                recorded_file_end: None,
                ..TrailingDataReport::default()
            },
            coverage: VerifyCoverage {
                file_size,
                ..VerifyCoverage::default()
            },
            findings: report.findings,
            inferences: report.inferences,
            checks_passed: report.checks_passed,
            checks_failed: report.checks_failed,
            checks_skipped: report.checks_skipped,
            unknowns: report.unknowns,
            oracle: None,
        }
    }

    pub fn finalize_coverage(&mut self) {
        self.coverage.integrity_checked_percent = if self.coverage.file_size == 0 {
            0.0
        } else {
            (self.coverage.integrity_checked_bytes as f64 / self.coverage.file_size as f64) * 100.0
        };
    }
}

pub fn render_verify_text(report: &VerifyReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "DuckDB Forensics Verify Report");
    let _ = writeln!(output, "Schema version: {}", report.schema_version);
    let _ = writeln!(output, "Status: {:?}", report.status);
    let _ = writeln!(output, "\nInput");
    let _ = writeln!(
        output,
        "  Path: {}",
        report.input.path.as_deref().unwrap_or("<hidden>")
    );
    let _ = writeln!(output, "  File size: {} bytes", report.input.file_size);
    let _ = writeln!(
        output,
        "  SHA-256: {}",
        report.input.sha256.as_deref().unwrap_or("unknown")
    );
    if let Some(header) = &report.selected_header {
        let _ = writeln!(output, "\nSelected Database Header");
        let _ = writeln!(
            output,
            "  index={}, iteration={}, block_count={}, block_alloc_size={}, meta_block={}, free_list={}",
            header.index,
            header.iteration,
            header.block_count,
            header.block_alloc_size,
            header.meta_block,
            header.free_list
        );
    } else {
        let _ = writeln!(output, "\nSelected Database Header: unknown");
    }

    let _ = writeln!(output, "\nBlock Verification");
    let _ = writeln!(
        output,
        "  full_scan={}, physical_scanned={}, metadata_checked={}, valid={}, mismatches={}, truncated={}, out_of_bounds={}",
        report.blocks.full_scan_requested,
        report.blocks.physical_blocks_scanned,
        report.blocks.metadata_blocks_checked,
        report.blocks.valid_checksums,
        report.blocks.checksum_mismatches,
        report.blocks.truncated_blocks,
        report.blocks.out_of_bounds_references
    );
    let _ = writeln!(
        output,
        "  beyond_header_count={}, trailing_bytes={}, issues_omitted={}",
        report.blocks.complete_blocks_beyond_header_count,
        report.blocks.trailing_bytes,
        report.blocks.issues_omitted
    );
    for issue in &report.blocks.issues {
        let _ = writeln!(
            output,
            "  {:?}: block={:?}, offset={}, expected={:?}, actual={:?}: {}",
            issue.kind,
            issue.block_id,
            issue.offset,
            issue.expected_length,
            issue.actual_length,
            issue.message
        );
    }

    let _ = writeln!(output, "\nMeta Block Chains");
    if report.meta_chains.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for chain in &report.meta_chains {
        let _ = writeln!(
            output,
            "  {}: status={:?}, root={}, visited={}, verified={}, payload_capacity={}, stop={:?}, cycle={:?}",
            chain.name,
            chain.status,
            chain.root_pointer,
            chain.visited_nodes,
            chain.verified_nodes,
            chain.payload_capacity,
            chain.stop_offset,
            chain.cycle_pointer
        );
    }

    let _ = writeln!(output, "\nCoverage");
    let _ = writeln!(
        output,
        "  Integrity checked: {} / {} bytes ({:.2}%)",
        report.coverage.integrity_checked_bytes,
        report.coverage.file_size,
        report.coverage.integrity_checked_percent
    );
    let _ = writeln!(
        output,
        "  Meta structurally checked: {} bytes",
        report.coverage.meta_checked_bytes
    );
    let _ = writeln!(output, "  Checked: {}", report.coverage.checked.join(", "));
    let _ = writeln!(
        output,
        "  Not checked: {}",
        report.coverage.not_checked.join(", ")
    );
    let _ = writeln!(
        output,
        "  Unsupported: {}",
        report.coverage.unsupported.join(", ")
    );
    let _ = writeln!(
        output,
        "  Unavailable: {}",
        report.coverage.unavailable.join(", ")
    );

    let _ = writeln!(output, "\nFindings");
    if report.findings.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for finding in &report.findings {
        let _ = writeln!(
            output,
            "  {} [{:?}]: {} (offset={:?})",
            finding.code, finding.severity, finding.message, finding.location.file_offset
        );
    }
    let _ = writeln!(output, "\nUnknowns");
    if report.unknowns.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for unknown in &report.unknowns {
        let _ = writeln!(
            output,
            "  {} ({}): {}",
            unknown.code, unknown.structure_path, unknown.reason
        );
    }
    if let Some(oracle) = &report.oracle {
        let _ = writeln!(output, "\nOfficial DuckDB Oracle");
        let _ = writeln!(
            output,
            "  comparison={:?}: {}",
            oracle.comparison, oracle.rationale
        );
        for run in &oracle.runs {
            let _ = writeln!(
                output,
                "  {}: exit={:?}, timed_out={}, stderr={}",
                run.purpose, run.exit_code, run.timed_out, run.stderr
            );
        }
    }
    output
}
