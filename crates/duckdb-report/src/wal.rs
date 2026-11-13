use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{Finding, Inference, InputInfo, Unknown};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalStatus {
    Complete,
    Incomplete,
    Empty,
    Unsupported,
    Invalid,
    ResourceLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalChecksumStatus {
    Valid,
    Mismatch,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalPayloadStatus {
    NotDecoded,
    EmptyFlush,
    CheckpointDecoded,
    Invalid,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalEntryParseStatus {
    Complete,
    ChecksumMismatch,
    InvalidEntryLength,
    EntryExceedsRemainingFile,
    TruncatedEntry,
    ResourceLimitReached,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalVersionHeaderReport {
    pub offset: u64,
    pub length: u64,
    pub checkpoint_iteration: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalEntryReport {
    pub index: u64,
    pub offset: u64,
    pub payload_offset: Option<u64>,
    pub declared_length: Option<u64>,
    pub actual_length: u64,
    pub actual_frame_length: u64,
    pub declared_frame_end: Option<u64>,
    pub actual_frame_end: u64,
    pub stored_checksum: Option<String>,
    pub computed_checksum: Option<String>,
    pub checksum_status: WalChecksumStatus,
    pub entry_type: String,
    pub raw_entry_type: Option<u8>,
    pub entry_type_reason: Option<String>,
    pub payload_status: WalPayloadStatus,
    pub parse_status: WalEntryParseStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WalSummary {
    pub total_entries: u64,
    pub successfully_parsed_entries: u64,
    pub checksum_failed_entries: u64,
    pub out_of_bounds_entries: u64,
    pub truncated_entries: u64,
    pub unknown_type_entries: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalFlushBoundary {
    pub entry_index: u64,
    pub entry_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalCheckpointReport {
    pub entry_index: u64,
    pub entry_offset: u64,
    pub block_pointer: u64,
    pub offset_within_block: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalTailReport {
    pub offset: u64,
    pub length: u64,
    pub all_zero: Option<bool>,
    pub zero_suffix_offset: Option<u64>,
    pub zero_suffix_length: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalCoverage {
    pub file_size: u64,
    pub scanned_bytes: u64,
    pub scanned_percent: f64,
    pub complete_frame_bytes: u64,
    pub complete_frame_percent: f64,
    pub payload_decoding: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalReport {
    pub schema_version: String,
    pub tool_version: String,
    pub status: WalStatus,
    pub input: InputInfo,
    pub version: Option<u64>,
    pub encrypted: Option<bool>,
    pub version_header: Option<WalVersionHeaderReport>,
    pub entries: Vec<WalEntryReport>,
    pub summary: WalSummary,
    pub first_unparsed_offset: Option<u64>,
    pub first_checksum_mismatch_offset: Option<u64>,
    pub scan_stop_offset: u64,
    pub tail: WalTailReport,
    pub confirmed_flushes: Vec<WalFlushBoundary>,
    pub last_good_flush: Option<WalFlushBoundary>,
    pub unterminated_data_after_last_flush: bool,
    pub checkpoint_marker: Option<WalCheckpointReport>,
    pub coverage: WalCoverage,
    pub findings: Vec<Finding>,
    pub inferences: Vec<Inference>,
    pub unknowns: Vec<Unknown>,
}

impl WalReport {
    pub fn new(input: InputInfo) -> Self {
        let file_size = input.file_size;
        Self {
            schema_version: "1".to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            status: WalStatus::Invalid,
            input,
            version: None,
            encrypted: None,
            version_header: None,
            entries: Vec::new(),
            summary: WalSummary::default(),
            first_unparsed_offset: None,
            first_checksum_mismatch_offset: None,
            scan_stop_offset: 0,
            tail: WalTailReport {
                offset: 0,
                length: 0,
                all_zero: None,
                zero_suffix_offset: None,
                zero_suffix_length: 0,
            },
            confirmed_flushes: Vec::new(),
            last_good_flush: None,
            unterminated_data_after_last_flush: false,
            checkpoint_marker: None,
            coverage: WalCoverage {
                file_size,
                scanned_bytes: 0,
                scanned_percent: 0.0,
                complete_frame_bytes: 0,
                complete_frame_percent: 0.0,
                payload_decoding: "wal_type_envelope_flush_and_checkpoint_only".to_owned(),
            },
            findings: Vec::new(),
            inferences: Vec::new(),
            unknowns: Vec::new(),
        }
    }

    pub fn finalize(&mut self) {
        self.summary.total_entries = self.entries.len() as u64;
        self.coverage.scanned_bytes = self.scan_stop_offset.min(self.input.file_size);
        self.coverage.scanned_percent = percent(self.coverage.scanned_bytes, self.input.file_size);
        self.coverage.complete_frame_percent =
            percent(self.coverage.complete_frame_bytes, self.input.file_size);
        self.unterminated_data_after_last_flush = match self.last_good_flush {
            Some(flush) => flush.end_offset < self.input.file_size,
            None => !self.entries.is_empty() || self.scan_stop_offset < self.input.file_size,
        };
        self.tail.offset = self.scan_stop_offset.min(self.input.file_size);
        self.tail.length = self.input.file_size.saturating_sub(self.tail.offset);
    }
}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        100.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

pub fn render_wal_text(report: &WalReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "DuckDB Forensics WAL Report");
    let _ = writeln!(output, "Schema version: {}", report.schema_version);
    let _ = writeln!(output, "Tool version: {}", report.tool_version);
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
    let _ = writeln!(
        output,
        "  WAL version: {}",
        report
            .version
            .map_or_else(|| "unknown".to_owned(), |version| version.to_string())
    );
    let _ = writeln!(
        output,
        "  Encrypted: {}",
        report
            .encrypted
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string())
    );
    if let Some(header) = &report.version_header {
        let _ = writeln!(
            output,
            "  Version header: offset={}, length={}, checkpoint_iteration={:?}",
            header.offset, header.length, header.checkpoint_iteration
        );
    }

    let _ = writeln!(output, "\nSummary");
    let _ = writeln!(output, "  Entries: {}", report.summary.total_entries);
    let _ = writeln!(
        output,
        "  Successfully parsed: {}",
        report.summary.successfully_parsed_entries
    );
    let _ = writeln!(
        output,
        "  Checksum failures: {}",
        report.summary.checksum_failed_entries
    );
    let _ = writeln!(
        output,
        "  Out of bounds: {}",
        report.summary.out_of_bounds_entries
    );
    let _ = writeln!(output, "  Truncated: {}", report.summary.truncated_entries);
    let _ = writeln!(
        output,
        "  Unknown types: {}",
        report.summary.unknown_type_entries
    );
    let _ = writeln!(
        output,
        "  First unparsed offset: {:?}",
        report.first_unparsed_offset
    );
    let _ = writeln!(output, "  Scan stop offset: {}", report.scan_stop_offset);

    let _ = writeln!(output, "\nEntries");
    if report.entries.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for entry in &report.entries {
        let _ = writeln!(
            output,
            "  [{}] offset={}, declared_length={:?}, actual_length={}, frame_end={}, checksum={:?}, type={}, payload={:?}, status={:?}",
            entry.index,
            entry.offset,
            entry.declared_length,
            entry.actual_length,
            entry.actual_frame_end,
            entry.checksum_status,
            entry.entry_type,
            entry.payload_status,
            entry.parse_status
        );
        if let (Some(stored), Some(computed)) = (&entry.stored_checksum, &entry.computed_checksum) {
            let _ = writeln!(output, "      stored={stored}, computed={computed}");
        }
        if let Some(reason) = &entry.entry_type_reason {
            let _ = writeln!(output, "      type_reason={reason}");
        }
    }

    let _ = writeln!(output, "\nFlush and Checkpoint");
    if report.confirmed_flushes.is_empty() {
        let _ = writeln!(output, "  Confirmed WAL_FLUSH positions: none");
    } else {
        for flush in &report.confirmed_flushes {
            let _ = writeln!(
                output,
                "  Confirmed WAL_FLUSH: entry={}, entry_offset={}, end_offset={}",
                flush.entry_index, flush.entry_offset, flush.end_offset
            );
        }
    }
    if let Some(flush) = report.last_good_flush {
        let _ = writeln!(
            output,
            "  Last verified Flush boundary: entry={}, entry_offset={}, end_offset={}",
            flush.entry_index, flush.entry_offset, flush.end_offset
        );
    } else {
        let _ = writeln!(output, "  Last verified Flush boundary: null");
    }
    let _ = writeln!(
        output,
        "  Unterminated data after last Flush: {}",
        report.unterminated_data_after_last_flush
    );
    if let Some(marker) = report.checkpoint_marker {
        let _ = writeln!(
            output,
            "  Checkpoint Marker: entry={}, entry_offset={}, block_pointer={}, offset_within_block={}",
            marker.entry_index,
            marker.entry_offset,
            marker.block_pointer,
            marker.offset_within_block
        );
    } else {
        let _ = writeln!(output, "  Checkpoint Marker: null");
    }

    let _ = writeln!(output, "\nTail and Coverage");
    let _ = writeln!(
        output,
        "  Tail: offset={}, length={}, all_zero={:?}, zero_suffix_offset={:?}, zero_suffix_length={}",
        report.tail.offset,
        report.tail.length,
        report.tail.all_zero,
        report.tail.zero_suffix_offset,
        report.tail.zero_suffix_length
    );
    let _ = writeln!(
        output,
        "  Scanned: {} / {} bytes ({:.2}%)",
        report.coverage.scanned_bytes, report.coverage.file_size, report.coverage.scanned_percent
    );
    let _ = writeln!(
        output,
        "  Complete frames: {} bytes ({:.2}%)",
        report.coverage.complete_frame_bytes, report.coverage.complete_frame_percent
    );
    let _ = writeln!(
        output,
        "  Payload decoding: {}",
        report.coverage.payload_decoding
    );

    let _ = writeln!(output, "\nFindings");
    if report.findings.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for finding in &report.findings {
        let _ = writeln!(
            output,
            "  {} [{:?}]: {}",
            finding.code, finding.severity, finding.message
        );
        let _ = writeln!(
            output,
            "    offset={:?}, confidence={:?}",
            finding.location.file_offset, finding.confidence
        );
    }

    let _ = writeln!(output, "\nInferences");
    if report.inferences.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for inference in &report.inferences {
        let _ = writeln!(
            output,
            "  {} [{:?}]: {}",
            inference.code, inference.confidence, inference.message
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
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_report_round_trip_preserves_null_flush() {
        let mut report = WalReport::new(InputInfo {
            path: None,
            file_size: 0,
            sha256: Some("ab".repeat(32)),
        });
        report.status = WalStatus::Empty;
        report.finalize();
        let encoded = serde_json::to_string(&report).expect("serialize report");
        let decoded: WalReport = serde_json::from_str(&encoded).expect("deserialize report");
        assert_eq!(decoded, report);
        assert_eq!(decoded.last_good_flush, None);
        assert_eq!(decoded.coverage.scanned_percent, 100.0);
    }
}
