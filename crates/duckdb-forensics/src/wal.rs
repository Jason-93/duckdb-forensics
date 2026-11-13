use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use duckdb_format::DuckDbChecksum;
use duckdb_format::wal::{
    WAL_FRAME_HEADER_SIZE, WAL_VERSION_ENCRYPTED, WAL_VERSION_HEADER_LIMIT,
    WAL_VERSION_UNENCRYPTED, WalFrameHeader, WalType, is_confirmed_wal_flush,
    parse_wal_checkpoint_marker, parse_wal_entry_type, parse_wal_version_header,
};
use duckdb_report::wal::{
    WalCheckpointReport, WalChecksumStatus, WalEntryParseStatus, WalEntryReport, WalFlushBoundary,
    WalPayloadStatus, WalReport, WalStatus, WalTailReport, WalVersionHeaderReport,
};
use duckdb_report::{
    Confidence, Evidence, Finding, Inference, InputInfo, Location, Severity, Unknown,
};
use sha2::{Digest, Sha256};

use crate::util::{open_regular_file, path_text};

#[cfg(test)]
use duckdb_format::duckdb_checksum;

const IO_BUFFER_SIZE: usize = 1024 * 1024;
const PAYLOAD_PREFIX_LIMIT: usize = 4096;
const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 1_000_000;
const DEFAULT_MAX_ENTRY_SIZE: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_REPORT_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
pub struct WalInspectionLimits {
    pub max_file_size: u64,
    pub max_entries: u64,
    pub max_entry_size: u64,
    pub max_report_entries: usize,
}

impl Default for WalInspectionLimits {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_entry_size: DEFAULT_MAX_ENTRY_SIZE,
            max_report_entries: DEFAULT_MAX_REPORT_ENTRIES,
        }
    }
}

#[derive(Debug)]
pub enum WalInspectError {
    Canonicalize {
        path: PathBuf,
        source: io::Error,
    },
    Open {
        path: PathBuf,
        source: io::Error,
    },
    Metadata {
        path: PathBuf,
        source: io::Error,
    },
    Io {
        operation: &'static str,
        offset: u64,
        source: io::Error,
    },
}

impl Display for WalInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonicalize { path, source } => {
                write!(
                    formatter,
                    "cannot canonicalize {}: {source}",
                    path.display()
                )
            }
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "cannot open {} read-only: {source}",
                    path.display()
                )
            }
            Self::Metadata { path, source } => {
                write!(
                    formatter,
                    "cannot read metadata for {}: {source}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                offset,
                source,
            } => {
                write!(
                    formatter,
                    "failed to {operation} WAL at offset {offset}: {source}"
                )
            }
        }
    }
}

impl Error for WalInspectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonicalize { source, .. }
            | Self::Open { source, .. }
            | Self::Metadata { source, .. }
            | Self::Io { source, .. } => Some(source),
        }
    }
}

pub fn inspect_wal_path(path: &Path) -> Result<WalReport, WalInspectError> {
    inspect_wal_path_with_limits(path, WalInspectionLimits::default())
}

pub fn inspect_wal_path_with_limits(
    path: &Path,
    limits: WalInspectionLimits,
) -> Result<WalReport, WalInspectError> {
    let canonical_path = path
        .canonicalize()
        .map_err(|source| WalInspectError::Canonicalize {
            path: path.to_path_buf(),
            source,
        })?;
    let (mut file, metadata) =
        open_regular_file(&canonical_path).map_err(|source| WalInspectError::Open {
            path: canonical_path.clone(),
            source,
        })?;
    let file_size = metadata.len();
    let (path, encoding) = path_text(&canonical_path);
    let mut report = WalReport::new(InputInfo {
        path: Some(path),
        path_encoding: Some(encoding.to_owned()),
        file_size,
        sha256: None,
    });

    if file_size > limits.max_file_size {
        report.status = WalStatus::ResourceLimitReached;
        report.first_unparsed_offset = Some(0);
        resource_finding(&mut report, "file_size", file_size, limits.max_file_size, 0);
        report.retain_unknown(Unknown {
            code: "resource_limited_wal".to_owned(),
            structure_path: "input".to_owned(),
            reason: "SHA-256, version, frames, tail, and Flush boundaries were not examined."
                .to_owned(),
        });
        report.finalize();
        return Ok(report);
    }

    report.input.sha256 = Some(stream_sha256(&mut file)?);
    if file_size == 0 {
        report.status = WalStatus::Empty;
        report.retain_finding(finding(
            "empty_wal",
            Severity::Info,
            "The WAL file is empty.",
            Location::new(Some(0), "wal"),
            vec![Evidence::new("file_size", 0)],
            "Preserve the evidence; an empty WAL contains no version or Flush boundary.",
            Confidence::High,
        ));
        report.finalize();
        return Ok(report);
    }

    let prefix_len = file_size.min(WAL_VERSION_HEADER_LIMIT as u64) as usize;
    let mut prefix = vec![0_u8; prefix_len];
    let read = read_at(&mut file, 0, &mut prefix)?;
    prefix.truncate(read);
    let version_header = match parse_wal_version_header(&prefix) {
        Ok(header) => header,
        Err(error) => {
            report.status = WalStatus::Invalid;
            report.first_unparsed_offset = Some(0);
            report.scan_stop_offset = 0;
            report.retain_finding(finding(
                "invalid_wal_header",
                Severity::Error,
                "The file does not contain a supported BinaryDeserializer WAL version object.",
                Location::new(Some(0), "wal.version_header"),
                vec![
                    Evidence::new("payload_offset", error.offset as u64),
                    Evidence::new("error", format!("{:?}", error.kind)),
                ],
                "Confirm the WAL format and preserve the original bytes; do not reinterpret them as v2 frames.",
                Confidence::High,
            ));
            return finish_with_tail(report, &mut file, true);
        }
    };

    report.version = Some(version_header.version);
    report.encrypted = match version_header.version {
        WAL_VERSION_UNENCRYPTED | 1 => Some(false),
        WAL_VERSION_ENCRYPTED => Some(true),
        _ => None,
    };
    report.version_header = Some(WalVersionHeaderReport {
        offset: 0,
        length: version_header.length,
        checkpoint_iteration: version_header.checkpoint_iteration,
    });
    report.scan_stop_offset = version_header.length;

    if version_header.version != WAL_VERSION_UNENCRYPTED {
        report.status = WalStatus::Unsupported;
        let reason = match version_header.version {
            1 => "wal_v1",
            WAL_VERSION_ENCRYPTED => "wal_v3_encrypted",
            _ => "unknown_wal_version",
        };
        report.retain_finding(finding(
            "unsupported_wal_version",
            Severity::Warning,
            "Only unencrypted WAL version 2 is supported; no v2 frame parsing was attempted.",
            Location::new(Some(0), "wal.version_header.version"),
            vec![
                Evidence::new("version", version_header.version),
                Evidence::new("reason", reason),
                Evidence::new("encrypted", report.encrypted),
            ],
            "Use an inspector for the declared WAL version and encryption format; do not force v2 parsing.",
            Confidence::High,
        ));
        report.retain_unknown(Unknown {
            code: "unsupported_frames".to_owned(),
            structure_path: "wal.entries".to_owned(),
            reason: "Frames after an unsupported version header were not interpreted.".to_owned(),
        });
        report.finalize();
        return Ok(report);
    }

    scan_v2_entries(report, &mut file, version_header.length, limits)
}

fn scan_v2_entries(
    mut report: WalReport,
    file: &mut File,
    start: u64,
    limits: WalInspectionLimits,
) -> Result<WalReport, WalInspectError> {
    let file_size = report.input.file_size;
    let mut position = start;
    let mut index = 0_u64;
    let mut trusted_prefix = true;
    report.status = WalStatus::Complete;

    while position < file_size {
        if index >= limits.max_entries {
            report.status = WalStatus::ResourceLimitReached;
            report.first_unparsed_offset.get_or_insert(position);
            report.scan_stop_offset = position;
            resource_finding(
                &mut report,
                "entry_count",
                index,
                limits.max_entries,
                position,
            );
            report.finalize();
            return Ok(report);
        }

        let remaining = file_size - position;
        if remaining < WAL_FRAME_HEADER_SIZE {
            report.status = WalStatus::Incomplete;
            report.first_unparsed_offset.get_or_insert(position);
            report.scan_stop_offset = position;
            report.summary.truncated_entries += 1;
            report.retain_entry(
                WalEntryReport {
                    index,
                    offset: position,
                    payload_offset: None,
                    declared_length: None,
                    actual_length: 0,
                    actual_frame_length: remaining,
                    declared_frame_end: None,
                    actual_frame_end: file_size,
                    stored_checksum: None,
                    computed_checksum: None,
                    checksum_status: WalChecksumStatus::Unavailable,
                    entry_type: "unknown".to_owned(),
                    raw_entry_type: None,
                    entry_type_reason: Some("truncated_frame_header".to_owned()),
                    payload_status: WalPayloadStatus::Unavailable,
                    parse_status: WalEntryParseStatus::TruncatedEntry,
                },
                limits.max_report_entries,
            );
            report.retain_finding(finding(
                "truncated_entry",
                Severity::Error,
                "The file ends inside the fixed 16-byte WAL frame header.",
                Location::new(Some(position), format!("wal.entries[{index}]")),
                vec![
                    Evidence::new("remaining_bytes", remaining),
                    Evidence::new("required_header_bytes", WAL_FRAME_HEADER_SIZE),
                ],
                "Preserve the partial bytes; no following frame offset can be established.",
                Confidence::High,
            ));
            break;
        }

        let mut frame_bytes = [0_u8; WAL_FRAME_HEADER_SIZE as usize];
        read_exact_at(file, position, &mut frame_bytes)?;
        let frame = parse_wal_frame(frame_bytes, position);
        let payload_offset = frame.payload_offset().unwrap_or(file_size);
        let declared_end = frame.declared_frame_end();
        let available_payload = file_size.saturating_sub(payload_offset);
        let actual_length = frame.declared_length.min(available_payload);
        let actual_frame_end = declared_end.unwrap_or(file_size).min(file_size);
        let mut entry = WalEntryReport {
            index,
            offset: position,
            payload_offset: Some(payload_offset),
            declared_length: Some(frame.declared_length),
            actual_length,
            actual_frame_length: actual_frame_end.saturating_sub(position),
            declared_frame_end: declared_end,
            actual_frame_end,
            stored_checksum: Some(format_hex(frame.stored_checksum)),
            computed_checksum: None,
            checksum_status: WalChecksumStatus::Unavailable,
            entry_type: "unknown".to_owned(),
            raw_entry_type: None,
            entry_type_reason: None,
            payload_status: WalPayloadStatus::Unavailable,
            parse_status: WalEntryParseStatus::Complete,
        };

        if frame.declared_length == 0 || declared_end.is_none() {
            report.status = WalStatus::Incomplete;
            report.first_unparsed_offset.get_or_insert(position);
            report.scan_stop_offset = position;
            entry.parse_status = WalEntryParseStatus::InvalidEntryLength;
            entry.entry_type_reason = Some("invalid_entry_length".to_owned());
            if declared_end.is_none() {
                report.summary.out_of_bounds_entries += 1;
            }
            report.retain_entry(entry, limits.max_report_entries);
            report.retain_finding(finding(
                "invalid_entry_length",
                Severity::Error,
                "The WAL Entry has a zero length or its declared end offset overflows.",
                Location::new(
                    Some(position),
                    format!("wal.entries[{index}].declared_length"),
                ),
                vec![Evidence::new("declared_length", frame.declared_length)],
                "Do not allocate or seek using this declaration; preserve the evidence.",
                Confidence::High,
            ));
            break;
        }

        let declared_end = declared_end.unwrap_or(file_size);
        if declared_end > file_size {
            report.status = WalStatus::Incomplete;
            report.first_unparsed_offset.get_or_insert(position);
            report.scan_stop_offset = position;
            report.summary.out_of_bounds_entries += 1;
            report.summary.truncated_entries += 1;
            entry.parse_status = WalEntryParseStatus::EntryExceedsRemainingFile;
            entry.entry_type_reason = Some("entry_exceeds_remaining_file".to_owned());
            report.retain_entry(entry, limits.max_report_entries);
            let location = format!("wal.entries[{index}]");
            report.retain_finding(finding(
                "entry_exceeds_remaining_file",
                Severity::Error,
                "The declared Payload length exceeds the bytes remaining in the file.",
                Location::new(Some(position), location.clone()),
                vec![
                    Evidence::new("declared_length", frame.declared_length),
                    Evidence::new("actual_length", actual_length),
                    Evidence::new("declared_frame_end", declared_end),
                    Evidence::new("file_size", file_size),
                ],
                "Do not read beyond EOF or infer another frame boundary from this declaration.",
                Confidence::High,
            ));
            report.retain_finding(finding(
                "truncated_entry",
                Severity::Error,
                "The file ends inside this Entry's declared Payload.",
                Location::new(Some(file_size), location),
                vec![
                    Evidence::new("declared_length", frame.declared_length),
                    Evidence::new("actual_length", actual_length),
                ],
                "Preserve the truncated Entry; this report does not extend or repair it.",
                Confidence::High,
            ));
            break;
        }

        if frame.declared_length > limits.max_entry_size {
            report.status = WalStatus::ResourceLimitReached;
            report.first_unparsed_offset.get_or_insert(position);
            report.scan_stop_offset = position;
            entry.parse_status = WalEntryParseStatus::ResourceLimitReached;
            entry.entry_type_reason = Some("resource_limit_reached".to_owned());
            report.retain_entry(entry, limits.max_report_entries);
            resource_finding(
                &mut report,
                "entry_size",
                frame.declared_length,
                limits.max_entry_size,
                position,
            );
            report.finalize();
            return Ok(report);
        }

        report.coverage.complete_frame_bytes = report
            .coverage
            .complete_frame_bytes
            .saturating_add(declared_end.saturating_sub(position));
        let (computed_checksum, payload_prefix) = checksum_payload(
            file,
            payload_offset,
            frame.declared_length,
            PAYLOAD_PREFIX_LIMIT,
        )?;
        entry.computed_checksum = Some(format_hex(computed_checksum));
        if computed_checksum != frame.stored_checksum {
            report.status = WalStatus::Incomplete;
            report.summary.checksum_failed_entries += 1;
            report.first_unparsed_offset.get_or_insert(position);
            report
                .first_checksum_mismatch_offset
                .get_or_insert(position);
            trusted_prefix = false;
            entry.checksum_status = WalChecksumStatus::Mismatch;
            entry.parse_status = WalEntryParseStatus::ChecksumMismatch;
            entry.entry_type_reason = Some("checksum_mismatch".to_owned());
            report.retain_finding(finding(
                "checksum_mismatch",
                Severity::Error,
                "The stored WAL Entry checksum differs from the checksum computed over its complete Payload.",
                Location::new(Some(position + 8), format!("wal.entries[{index}].checksum")),
                vec![
                    Evidence::new("stored_checksum", format_hex(frame.stored_checksum)),
                    Evidence::new("computed_checksum", format_hex(computed_checksum)),
                    Evidence::new("payload_offset", payload_offset),
                    Evidence::new("declared_length", frame.declared_length),
                ],
                "Preserve the evidence; a checksum mismatch alone does not establish a torn write.",
                Confidence::High,
            ));
        } else {
            entry.checksum_status = WalChecksumStatus::Valid;
            match parse_wal_entry_type(&payload_prefix) {
                Err(error) => {
                    report.status = WalStatus::Incomplete;
                    report.summary.unknown_type_entries += 1;
                    report.first_unparsed_offset.get_or_insert(position);
                    trusted_prefix = false;
                    entry.entry_type_reason = Some("invalid_wal_type_envelope".to_owned());
                    entry.payload_status = WalPayloadStatus::Invalid;
                    report.retain_unknown(Unknown {
                        code: "unknown_entry_type".to_owned(),
                        structure_path: format!("wal.entries[{index}]"),
                        reason: format!("Cannot decode field 100 and its LEB128 WALType: {error}"),
                    });
                }
                Ok(parsed_type) => {
                    entry.raw_entry_type = Some(parsed_type.raw_type);
                    let Some(entry_type) = parsed_type.entry_type else {
                        report.status = WalStatus::Incomplete;
                        report.summary.unknown_type_entries += 1;
                        report.first_unparsed_offset.get_or_insert(position);
                        trusted_prefix = false;
                        entry.entry_type_reason = Some("unrecognized_wal_type".to_owned());
                        entry.payload_status = WalPayloadStatus::NotDecoded;
                        report.summary.not_decoded_entries =
                            report.summary.not_decoded_entries.saturating_add(1);
                        report.retain_unknown(Unknown {
                            code: "unknown_entry_type".to_owned(),
                            structure_path: format!("wal.entries[{index}]"),
                            reason: format!(
                                "WALType value {} is absent from the DuckDB v2.0.0 enum.",
                                parsed_type.raw_type
                            ),
                        });
                        report.retain_entry(entry, limits.max_report_entries);
                        position = declared_end;
                        report.scan_stop_offset = position;
                        index = index.saturating_add(1);
                        continue;
                    };
                    entry.entry_type = entry_type.as_str().to_owned();
                    entry.payload_status = WalPayloadStatus::NotDecoded;
                    let mut special_valid = true;
                    match entry_type {
                        WalType::WalFlush => {
                            if frame.declared_length == 5 && is_confirmed_wal_flush(&payload_prefix)
                            {
                                entry.payload_status = WalPayloadStatus::EmptyFlush;
                                let flush = WalFlushBoundary {
                                    entry_index: index,
                                    entry_offset: position,
                                    end_offset: declared_end,
                                };
                                report.retain_flush(flush, limits.max_report_entries);
                                if trusted_prefix {
                                    report.last_good_flush = Some(flush);
                                }
                            } else {
                                special_valid = false;
                                entry.payload_status = WalPayloadStatus::Invalid;
                                entry.entry_type_reason = Some("invalid_flush_envelope".to_owned());
                            }
                        }
                        WalType::Checkpoint => {
                            match parse_wal_checkpoint_marker(&payload_prefix) {
                                Ok(Some(marker))
                                    if payload_prefix.len() as u64 == frame.declared_length =>
                                {
                                    entry.payload_status = WalPayloadStatus::CheckpointDecoded;
                                    if report.checkpoint_marker.is_none() {
                                        report.checkpoint_marker = Some(WalCheckpointReport {
                                            entry_index: index,
                                            entry_offset: position,
                                            block_pointer: marker.block_pointer,
                                            offset_within_block: marker.offset,
                                        });
                                    }
                                }
                                Ok(_) => special_valid = false,
                                Err(_) => special_valid = false,
                            }
                            if !special_valid {
                                entry.payload_status = WalPayloadStatus::Invalid;
                                entry.entry_type_reason =
                                    Some("invalid_checkpoint_envelope".to_owned());
                            }
                        }
                        _ => {
                            report.summary.not_decoded_entries =
                                report.summary.not_decoded_entries.saturating_add(1);
                        }
                    }
                    if special_valid {
                        report.summary.successfully_parsed_entries += 1;
                    } else {
                        report.status = WalStatus::Incomplete;
                        report.first_unparsed_offset.get_or_insert(position);
                        trusted_prefix = false;
                        report.retain_unknown(Unknown {
                            code: "invalid_special_entry".to_owned(),
                            structure_path: format!("wal.entries[{index}]"),
                            reason: "The WAL_FLUSH or Checkpoint object does not match the v2.0.0 serialization.".to_owned(),
                        });
                    }
                }
            }
        }

        report.retain_entry(entry, limits.max_report_entries);
        position = declared_end;
        report.scan_stop_offset = position;
        index = index.saturating_add(1);
    }

    if report.last_good_flush.is_none() {
        report.retain_unknown(Unknown {
            code: "last_good_flush".to_owned(),
            structure_path: "wal.last_good_flush".to_owned(),
            reason: "No WAL_FLUSH is confirmed at the end of a continuously verified Entry prefix."
                .to_owned(),
        });
    }
    finish_with_tail(report, file, true)
}

fn finish_with_tail(
    mut report: WalReport,
    file: &mut File,
    analyze_tail: bool,
) -> Result<WalReport, WalInspectError> {
    let not_decoded = report.summary.not_decoded_entries;
    if not_decoded != 0 {
        report.retain_unknown(Unknown {
            code: "business_payloads_not_decoded".to_owned(),
            structure_path: "wal.entries[*].payload".to_owned(),
            reason: format!(
                "{not_decoded} Entry payloads were intentionally not decoded; only their WALType envelope is reported."
            ),
        });
    }
    report.finalize();
    if analyze_tail {
        let tail_origin = report
            .first_unparsed_offset
            .unwrap_or(report.scan_stop_offset)
            .min(report.input.file_size);
        report.tail = analyze_tail_bytes(file, tail_origin, report.input.file_size)?;
        if report.tail.zero_suffix_length != 0 && report.first_unparsed_offset.is_some() {
            report.retain_finding(finding(
                "zero_filled_tail",
                Severity::Warning,
                "A nonempty all-zero suffix reaches EOF in the unparsed or integrity-failed region.",
                Location::new(report.tail.zero_suffix_offset, "wal.tail"),
                vec![
                    Evidence::new("zero_suffix_offset", report.tail.zero_suffix_offset),
                    Evidence::new("zero_suffix_length", report.tail.zero_suffix_length),
                    Evidence::new("tail_all_zero", report.tail.all_zero),
                ],
                "Treat zero filling only as evidence; do not infer its physical cause or truncate automatically.",
                Confidence::High,
            ));
            report.inferences.push(Inference {
                code: "zero_filled_tail_evidence".to_owned(),
                message: "The zero suffix is compatible with several causes, including padding or an interrupted write; its cause is unknown.".to_owned(),
                subject: Some("wal.tail".to_owned()),
                evidence: vec![Evidence::new(
                    "zero_suffix_length",
                    report.tail.zero_suffix_length,
                )],
                confidence: Confidence::Low,
            });
        }
        if report.scan_stop_offset < report.input.file_size
            && report.tail.length != 0
            && report.tail.all_zero == Some(false)
            && report.status != WalStatus::ResourceLimitReached
        {
            report.retain_finding(finding(
                "unparsed_trailing_data",
                Severity::Error,
                "Nonzero bytes remain after the first structural position where frame parsing stopped.",
                Location::new(Some(report.tail.offset), "wal.tail"),
                vec![
                    Evidence::new("tail_offset", report.tail.offset),
                    Evidence::new("tail_length", report.tail.length),
                ],
                "Do not resynchronize by guessing another Entry boundary.",
                Confidence::High,
            ));
        }
    }
    Ok(report)
}

fn analyze_tail_bytes(
    file: &mut File,
    origin: u64,
    file_size: u64,
) -> Result<WalTailReport, WalInspectError> {
    let mut result = WalTailReport {
        offset: origin,
        length: file_size.saturating_sub(origin),
        all_zero: if origin == file_size {
            None
        } else {
            Some(true)
        },
        zero_suffix_offset: None,
        zero_suffix_length: 0,
    };
    let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
    let mut position = origin;
    let mut zero_run_start = None;
    while position < file_size {
        let wanted = (file_size - position).min(buffer.len() as u64) as usize;
        let count = read_at(file, position, &mut buffer[..wanted])?;
        if count == 0 {
            break;
        }
        for (index, byte) in buffer[..count].iter().enumerate() {
            let absolute = position.saturating_add(index as u64);
            if *byte == 0 {
                zero_run_start.get_or_insert(absolute);
            } else {
                result.all_zero = Some(false);
                zero_run_start = None;
            }
        }
        position = position
            .checked_add(count as u64)
            .ok_or_else(|| WalInspectError::Io {
                operation: "advance read offset",
                offset: position,
                source: io::Error::new(io::ErrorKind::InvalidData, "WAL offset overflow"),
            })?;
    }
    if let Some(start) = zero_run_start {
        result.zero_suffix_offset = Some(start);
        result.zero_suffix_length = file_size.saturating_sub(start);
    }
    Ok(result)
}

fn checksum_payload(
    file: &mut File,
    offset: u64,
    length: u64,
    prefix_limit: usize,
) -> Result<(u64, Vec<u8>), WalInspectError> {
    let mut checksum = DuckDbChecksum::new();
    let mut prefix = Vec::with_capacity(length.min(prefix_limit as u64) as usize);
    let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
    let mut position = offset;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| WalInspectError::Io {
            operation: "compute Payload end",
            offset,
            source: io::Error::new(io::ErrorKind::InvalidData, "WAL Payload end overflow"),
        })?;
    while position < end {
        let wanted = (end - position).min(buffer.len() as u64) as usize;
        let count = read_at(file, position, &mut buffer[..wanted])?;
        if count == 0 {
            return Err(WalInspectError::Io {
                operation: "read",
                offset: position,
                source: io::Error::new(io::ErrorKind::UnexpectedEof, "WAL Payload ended early"),
            });
        }
        checksum.update(&buffer[..count]);
        let prefix_remaining = prefix_limit.saturating_sub(prefix.len());
        let copied = prefix_remaining.min(count);
        prefix.extend_from_slice(&buffer[..copied]);
        position = position
            .checked_add(count as u64)
            .ok_or_else(|| WalInspectError::Io {
                operation: "advance read offset",
                offset: position,
                source: io::Error::new(io::ErrorKind::InvalidData, "WAL offset overflow"),
            })?;
    }
    Ok((checksum.finalize(), prefix))
}

fn parse_wal_frame(bytes: [u8; 16], offset: u64) -> WalFrameHeader {
    duckdb_format::wal::parse_wal_frame_header(bytes, offset)
}

fn read_at<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, WalInspectError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| WalInspectError::Io {
            operation: "seek",
            offset,
            source,
        })?;
    let mut total = 0;
    while total < buffer.len() {
        match file.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(count) => total += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(WalInspectError::Io {
                    operation: "read",
                    offset: offset.saturating_add(total as u64),
                    source,
                });
            }
        }
    }
    Ok(total)
}

fn read_exact_at<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), WalInspectError> {
    let count = read_at(file, offset, buffer)?;
    if count == buffer.len() {
        Ok(())
    } else {
        Err(WalInspectError::Io {
            operation: "read",
            offset: offset.saturating_add(count as u64),
            source: io::Error::new(io::ErrorKind::UnexpectedEof, "short WAL read"),
        })
    }
}

fn stream_sha256(file: &mut File) -> Result<String, WalInspectError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WalInspectError::Io {
            operation: "seek",
            offset: 0,
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(WalInspectError::Io {
                    operation: "read",
                    offset: 0,
                    source,
                });
            }
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn resource_finding(report: &mut WalReport, resource: &str, actual: u64, limit: u64, offset: u64) {
    report.retain_finding(finding(
        "resource_limit_reached",
        Severity::Warning,
        "A configured WAL inspection resource limit was reached; remaining structures were not examined.",
        Location::new(Some(offset), "wal.resource_limits"),
        vec![
            Evidence::new("resource", resource),
            Evidence::new("actual", actual),
            Evidence::new("limit", limit),
            Evidence::new("stop_offset", offset),
        ],
        "Resource exhaustion is not a corruption verdict; raise limits only within the available budget.",
        Confidence::High,
    ));
}

fn finding(
    code: &str,
    severity: Severity,
    message: impl Into<String>,
    location: Location,
    evidence: Vec<Evidence>,
    remediation_hint: &str,
    confidence: Confidence,
) -> Finding {
    Finding {
        code: code.to_owned(),
        category: duckdb_report::FindingCategory::for_code(code),
        severity,
        message: message.into(),
        location,
        evidence,
        remediation_hint: remediation_hint.to_owned(),
        confidence,
    }
}

fn format_hex(value: u64) -> String {
    format!("0x{value:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn version_header() -> Vec<u8> {
        vec![100, 0, 98, 101, 0, 2, 255, 255]
    }

    fn flush_frame() -> Vec<u8> {
        let payload = [100, 0, 100, 255, 255];
        let mut bytes = Vec::new();
        bytes.extend(5_u64.to_le_bytes());
        bytes.extend(duckdb_checksum(&payload).to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn resource_limit_does_not_fake_flush_or_hash() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("limited.wal");
        let mut bytes = version_header();
        bytes.extend(flush_frame());
        fs::write(&path, bytes).expect("write fixture");
        let report = inspect_wal_path_with_limits(
            &path,
            WalInspectionLimits {
                max_file_size: 3,
                ..WalInspectionLimits::default()
            },
        )
        .expect("inspection");
        assert_eq!(report.status, WalStatus::ResourceLimitReached);
        assert!(report.input.sha256.is_none());
        assert_eq!(report.last_good_flush, None);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "resource_limit_reached")
        );
    }

    #[test]
    fn entry_limit_stops_before_the_next_frame() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("entries.wal");
        let mut bytes = version_header();
        bytes.extend(flush_frame());
        bytes.extend(flush_frame());
        fs::write(&path, &bytes).expect("write fixture");
        let report = inspect_wal_path_with_limits(
            &path,
            WalInspectionLimits {
                max_entries: 1,
                ..WalInspectionLimits::default()
            },
        )
        .expect("inspection");
        assert_eq!(report.status, WalStatus::ResourceLimitReached);
        assert_eq!(report.summary.total_entries, 1);
        assert_eq!(report.scan_stop_offset, 29);
        assert_eq!(
            report.last_good_flush.map(|flush| flush.end_offset),
            Some(29)
        );
    }

    #[test]
    fn no_flush_means_null_last_good_flush() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("version-only.wal");
        fs::write(&path, version_header()).expect("write fixture");
        let report = inspect_wal_path(&path).expect("inspection");
        assert_eq!(report.last_good_flush, None);
        assert!(report.confirmed_flushes.is_empty());
    }

    #[test]
    fn payload_checksum_prefix_handles_chunked_input() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("payload.bin");
        let payload: Vec<u8> = (0..=255).collect();
        fs::write(&path, &payload).expect("write fixture");
        let mut file = File::open(&path).expect("open fixture");
        let (checksum, prefix) =
            checksum_payload(&mut file, 0, payload.len() as u64, 17).expect("checksum");
        assert_eq!(checksum, duckdb_checksum(&payload));
        assert_eq!(prefix, payload[..17]);
    }

    struct ShortReads(std::io::Cursor<Vec<u8>>);

    impl Read for ShortReads {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(2);
            self.0.read(&mut buffer[..limit])
        }
    }

    impl Seek for ShortReads {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.0.seek(position)
        }
    }

    #[test]
    fn exact_reads_join_short_reads_and_reject_early_eof() {
        let mut reader = ShortReads(std::io::Cursor::new(vec![3; 16]));
        let mut buffer = [0_u8; 16];
        read_exact_at(&mut reader, 0, &mut buffer).expect("joined short reads");
        assert_eq!(buffer, [3; 16]);

        let mut reader = ShortReads(std::io::Cursor::new(vec![3; 15]));
        let error = read_exact_at(&mut reader, 0, &mut buffer).expect_err("early EOF");
        assert!(
            matches!(error, WalInspectError::Io { source, .. } if source.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
}
