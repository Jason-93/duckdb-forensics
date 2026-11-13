use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use duckdb_format::{
    BLOCK_START, DEFAULT_BLOCK_HEADER_SIZE, FILE_HEADER_SIZE, INVALID_BLOCK, METADATA_BLOCK_COUNT,
    checked_block_location, checked_metadata_location, checked_recorded_file_end, duckdb_checksum,
    metadata_block_size, unpack_metadata_pointer,
};
use duckdb_report::verify::{
    BlockIssue, BlockIssueKind, MetaChainReport, MetaChainStatus, SelectedHeaderReport,
    VerifyReport, VerifyStatus,
};
use duckdb_report::{Confidence, Evidence, Finding, Location, Severity, Unknown};

use crate::inspect::{InspectError, InspectionLimits, inspect_path_with_limits};
use crate::oracle::{OracleError, run_oracle};

const DEFAULT_MAX_META_NODES: u64 = 1_000_000;
const DEFAULT_MAX_BLOCK_ISSUES: usize = 1_000;

#[derive(Debug, Clone, Copy)]
pub struct VerifyLimits {
    pub inspection: InspectionLimits,
    pub max_meta_nodes: u64,
    pub max_block_issues: usize,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            inspection: InspectionLimits::default(),
            max_meta_nodes: DEFAULT_MAX_META_NODES,
            max_block_issues: DEFAULT_MAX_BLOCK_ISSUES,
        }
    }
}

#[derive(Debug)]
pub enum VerifyError {
    Inspect(InspectError),
    Oracle(OracleError),
    Open {
        path: PathBuf,
        source: io::Error,
    },
    Io {
        operation: &'static str,
        offset: u64,
        source: io::Error,
    },
}

impl Display for VerifyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inspect(error) => Display::fmt(error, formatter),
            Self::Oracle(error) => Display::fmt(error, formatter),
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "cannot open {} read-only: {source}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                offset,
                source,
            } => write!(
                formatter,
                "failed to {operation} database at offset {offset}: {source}"
            ),
        }
    }
}

impl Error for VerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect(error) => Some(error),
            Self::Oracle(error) => Some(error),
            Self::Open { source, .. } | Self::Io { source, .. } => Some(source),
        }
    }
}

impl From<InspectError> for VerifyError {
    fn from(error: InspectError) -> Self {
        Self::Inspect(error)
    }
}

impl From<OracleError> for VerifyError {
    fn from(error: OracleError) -> Self {
        Self::Oracle(error)
    }
}

pub fn verify_path(path: &Path, blocks: bool) -> Result<VerifyReport, VerifyError> {
    verify_path_with_limits(path, blocks, VerifyLimits::default())
}

pub fn verify_path_with_oracle(
    path: &Path,
    blocks: bool,
    duckdb: Option<&Path>,
) -> Result<VerifyReport, VerifyError> {
    let mut report = verify_path(path, blocks)?;
    if let Some(executable) = duckdb {
        let wal = companion_wal(path);
        report.oracle = Some(run_oracle(executable, path, wal.as_deref(), &report)?);
    }
    Ok(report)
}

pub fn verify_path_with_limits(
    path: &Path,
    blocks: bool,
    limits: VerifyLimits,
) -> Result<VerifyReport, VerifyError> {
    let inspection = inspect_path_with_limits(path, false, limits.inspection)?;
    let mut report = VerifyReport::from_header_report(inspection);
    report.blocks.full_scan_requested = blocks;
    report.coverage.checked.extend([
        "main_header and database_header checksum and raw fields".to_owned(),
        "selected-header file length geometry".to_owned(),
    ]);
    report.coverage.not_checked.extend([
        "catalog and table metadata deserialization".to_owned(),
        "row groups, compression, and business data semantics".to_owned(),
        "WAL semantics".to_owned(),
    ]);

    let complete_headers = report
        .observations
        .iter()
        .filter(|observation| {
            observation.name == "available_bytes"
                && observation.value.as_u64() == Some(FILE_HEADER_SIZE)
        })
        .count() as u64;
    report.coverage.integrity_checked_bytes =
        complete_headers.saturating_mul(FILE_HEADER_SIZE - DEFAULT_BLOCK_HEADER_SIZE as u64);

    if report.input.sha256.is_none() {
        report.status = VerifyStatus::ResourceLimitReached;
        report
            .coverage
            .unavailable
            .push("all checksum and geometry regions beyond the resource budget".to_owned());
        report.finalize_coverage();
        return Ok(report);
    }

    let Some(selected) = selected_header(&report) else {
        let encrypted = report.observations.iter().any(|observation| {
            observation.structure_path == "main_header"
                && observation.name == "encrypted"
                && observation.value.as_bool() == Some(true)
        });
        let unsupported = report
            .findings
            .iter()
            .any(|finding| finding.category == duckdb_report::FindingCategory::Unsupported);
        report.status = if unsupported {
            VerifyStatus::Unsupported
        } else {
            VerifyStatus::Incomplete
        };
        if unsupported {
            report
                .coverage
                .unsupported
                .push("unsupported main/database headers and dependent block checks".to_owned());
        }
        if encrypted {
            report.coverage.unsupported.extend([
                "encrypted database headers".to_owned(),
                "encrypted blocks and metadata chains".to_owned(),
            ]);
        }
        report.coverage.unavailable.push(
            "block and metadata checks requiring a supported selected Database Header".to_owned(),
        );
        report.unknowns.push(Unknown {
            code: "block_verification_unavailable".to_owned(),
            structure_path: "blocks".to_owned(),
            reason: "No supported selected Database Header supplies trusted block geometry."
                .to_owned(),
        });
        report.finalize_coverage();
        return Ok(report);
    };
    report.selected_header = Some(selected.clone());
    report.trailing_data.recorded_file_end =
        checked_recorded_file_end(selected.block_count, selected.block_alloc_size).ok();

    let mut file = File::open(path).map_err(|source| VerifyError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    classify_file_tail(&mut report, &selected, limits.max_block_issues);
    if blocks {
        scan_all_blocks(&mut report, &mut file, &selected, limits.max_block_issues)?;
    } else {
        report.coverage.not_checked.push(
            "ordinary blocks not visited by selected meta_block/free_list chains (use --blocks)"
                .to_owned(),
        );
    }

    let mut checksum_cache = HashMap::new();
    for (name, root) in [
        ("meta_block", selected.meta_block),
        ("free_list", selected.free_list),
    ] {
        let chain = verify_meta_chain(
            &mut report,
            &mut file,
            &selected,
            name,
            root,
            &mut checksum_cache,
            limits,
        )?;
        report.meta_chains.push(chain);
    }
    if !blocks {
        report.coverage.integrity_checked_bytes =
            report.coverage.integrity_checked_bytes.saturating_add(
                (checksum_cache.len() as u64)
                    .saturating_mul(selected.block_alloc_size - DEFAULT_BLOCK_HEADER_SIZE as u64),
            );
    }

    report.coverage.checked.extend([
        "selected meta_block chain traversal attempted; see per-chain status".to_owned(),
        "selected free_list chain traversal attempted; see per-chain status".to_owned(),
    ]);
    if report
        .meta_chains
        .iter()
        .any(|chain| chain.status == MetaChainStatus::ResourceLimitReached)
    {
        report.status = VerifyStatus::ResourceLimitReached;
    } else if report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
    {
        report.status = VerifyStatus::Incomplete;
    } else {
        report.status = VerifyStatus::Complete;
    }
    report.finalize_coverage();
    Ok(report)
}

fn companion_wal(database: &Path) -> Option<PathBuf> {
    let mut path = database.as_os_str().to_os_string();
    path.push(".wal");
    let path = PathBuf::from(path);
    std::fs::symlink_metadata(&path)
        .ok()
        .filter(|metadata| metadata.file_type().is_file())?;
    Some(path)
}

fn selected_header(report: &VerifyReport) -> Option<SelectedHeaderReport> {
    let subject = report
        .inferences
        .iter()
        .find(|inference| inference.code == "likely_active_database_header")?
        .subject
        .as_deref()?;
    let index = match subject {
        "database_header[0]" => 0,
        "database_header[1]" => 1,
        _ => return None,
    };
    let value = |name: &str| {
        report
            .observations
            .iter()
            .find(|observation| observation.structure_path == subject && observation.name == name)
            .and_then(|observation| observation.value.as_u64())
    };
    let stored_alloc = value("block_alloc_size")?;
    let block_alloc_size = value("effective_block_alloc_size").unwrap_or(stored_alloc);
    Some(SelectedHeaderReport {
        index,
        iteration: value("iteration")?,
        block_count: value("block_count")?,
        block_alloc_size,
        meta_block: value("meta_block")?,
        free_list: value("free_list")?,
    })
}

fn classify_file_tail(
    report: &mut VerifyReport,
    selected: &SelectedHeaderReport,
    max_issues: usize,
) {
    let file_size = report.input.file_size;
    let alloc = selected.block_alloc_size;
    let physical_bytes = file_size.saturating_sub(BLOCK_START);
    let physical_blocks = physical_bytes / alloc;
    let residual = physical_bytes % alloc;
    let residual_offset = BLOCK_START.saturating_add(physical_blocks.saturating_mul(alloc));
    let beyond = physical_blocks.saturating_sub(selected.block_count);
    report.blocks.complete_blocks_beyond_header_count = beyond;
    report.trailing_data.complete_blocks_beyond_header_count = beyond;

    if physical_blocks < selected.block_count {
        report.blocks.truncated_blocks = selected.block_count - physical_blocks;
        let actual = residual;
        let offset = residual_offset;
        push_block_issue(
            report,
            BlockIssue {
                kind: BlockIssueKind::TruncatedBlock,
                block_id: Some(physical_blocks),
                offset,
                expected_length: Some(alloc),
                actual_length: Some(actual),
                message: "The recorded block range is not fully present in the file.".to_owned(),
            },
            "truncated_block",
            Severity::Error,
            "The file ends before the selected Database Header's recorded block range.",
            max_issues,
        );
    } else {
        if beyond != 0 {
            report.findings.push(finding(
                "beyond_header_block_count",
                Severity::Info,
                "Complete physical blocks exist beyond the selected header's block_count; DuckDB can treat these as implicitly free-listed, so their allocation and integrity are not inferred from their presence alone.",
                Location::new(
                    checked_block_location(selected.block_count, alloc).ok(),
                    "blocks.beyond_header_count",
                ),
                vec![
                    Evidence::new("complete_blocks", beyond),
                    Evidence::new("block_count", selected.block_count),
                ],
                "Preserve these bytes; their allocation and semantic contents require separate evidence.",
                Confidence::High,
            ));
        }
        if residual != 0 {
            report.blocks.trailing_bytes = residual;
            report.trailing_data.residual_offset = Some(residual_offset);
            report.trailing_data.residual_bytes = residual;
            push_block_issue(
                report,
                BlockIssue {
                    kind: BlockIssueKind::TrailingData,
                    block_id: None,
                    offset: residual_offset,
                    expected_length: None,
                    actual_length: Some(residual),
                    message:
                        "Non-allocation-aligned bytes follow the last complete physical block."
                            .to_owned(),
                },
                "trailing_data",
                Severity::Warning,
                "Bytes remain after the last complete physical block; their meaning is not established.",
                max_issues,
            );
        }
    }
}

fn scan_all_blocks(
    report: &mut VerifyReport,
    file: &mut File,
    selected: &SelectedHeaderReport,
    max_issues: usize,
) -> Result<(), VerifyError> {
    let alloc = selected.block_alloc_size;
    let physical_blocks = report.input.file_size.saturating_sub(BLOCK_START) / alloc;
    let mut buffer = vec![0_u8; alloc as usize];
    for block_id in 0..physical_blocks {
        let offset = checked_block_location(block_id, alloc).map_err(|error| VerifyError::Io {
            operation: "compute block location",
            offset: BLOCK_START,
            source: io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")),
        })?;
        read_exact_at(file, offset, &mut buffer)?;
        report.blocks.physical_blocks_scanned += 1;
        verify_block_checksum(
            report,
            block_id,
            offset,
            &buffer,
            BlockChecksumOptions {
                expected_length: alloc as usize,
                count_result: true,
                record_issue: true,
                max_issues,
            },
        )?;
    }
    report.coverage.integrity_checked_bytes = report
        .coverage
        .integrity_checked_bytes
        .saturating_add(physical_blocks.saturating_mul(alloc - DEFAULT_BLOCK_HEADER_SIZE as u64));
    report
        .coverage
        .checked
        .push("checksums of every complete physical block".to_owned());
    if report.blocks.truncated_blocks != 0 {
        report
            .coverage
            .unavailable
            .push("checksum of the incomplete recorded block and missing blocks".to_owned());
    }
    if report.blocks.trailing_bytes != 0 {
        report
            .coverage
            .unavailable
            .push("non-allocation-aligned trailing bytes".to_owned());
    }
    Ok(())
}

struct BlockChecksumOptions {
    expected_length: usize,
    count_result: bool,
    record_issue: bool,
    max_issues: usize,
}

fn verify_block_checksum(
    report: &mut VerifyReport,
    block_id: u64,
    offset: u64,
    bytes: &[u8],
    options: BlockChecksumOptions,
) -> Result<bool, VerifyError> {
    if bytes.len() != options.expected_length || bytes.len() < DEFAULT_BLOCK_HEADER_SIZE {
        return Err(VerifyError::Io {
            operation: "verify block checksum",
            offset,
            source: io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "block length differs from the configured complete block length",
            ),
        });
    }
    let stored = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| VerifyError::Io {
        operation: "read block checksum",
        offset,
        source: io::Error::new(io::ErrorKind::InvalidData, "invalid checksum field length"),
    })?);
    let computed = duckdb_checksum(&bytes[8..]);
    if stored == computed {
        if options.count_result {
            report.blocks.valid_checksums += 1;
        }
        return Ok(true);
    }
    if options.count_result {
        report.blocks.checksum_mismatches += 1;
    }
    if options.record_issue {
        push_block_issue(
            report,
            BlockIssue {
                kind: BlockIssueKind::ChecksumMismatch,
                block_id: Some(block_id),
                offset,
                expected_length: Some(bytes.len() as u64),
                actual_length: Some(bytes.len() as u64),
                message: format!(
                    "stored checksum 0x{stored:016x} differs from computed 0x{computed:016x}"
                ),
            },
            "checksum_mismatch",
            Severity::Error,
            "A complete block's stored checksum differs from its computed checksum; other blocks remain independently checkable.",
            options.max_issues,
        );
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn verify_meta_chain(
    report: &mut VerifyReport,
    file: &mut File,
    selected: &SelectedHeaderReport,
    name: &str,
    root: u64,
    checksum_cache: &mut HashMap<u64, bool>,
    limits: VerifyLimits,
) -> Result<MetaChainReport, VerifyError> {
    let mut chain = MetaChainReport {
        name: name.to_owned(),
        root_pointer: root,
        status: MetaChainStatus::Terminated,
        visited_nodes: 0,
        verified_nodes: 0,
        payload_capacity: 0,
        stop_offset: None,
        cycle_pointer: None,
    };
    if root == INVALID_BLOCK {
        chain.status = MetaChainStatus::NotPresent;
        return Ok(chain);
    }

    let alloc = selected.block_alloc_size;
    let meta_size = metadata_block_size(alloc);
    let mut visited = HashSet::new();
    let mut raw_pointer = root;
    let mut initial_offset = 0_u64;
    loop {
        if chain.visited_nodes >= limits.max_meta_nodes {
            chain.status = MetaChainStatus::ResourceLimitReached;
            report.findings.push(finding(
                "resource_limit_reached",
                Severity::Warning,
                "The metadata chain node limit was reached; the remaining chain was not followed.",
                Location::new(chain.stop_offset, format!("meta_chains.{name}")),
                vec![
                    Evidence::new("max_meta_nodes", limits.max_meta_nodes),
                    Evidence::new("visited_nodes", chain.visited_nodes),
                ],
                "Resource exhaustion is not corruption; preserve the stop offset and remaining unknown region.",
                Confidence::High,
            ));
            report.unknowns.push(Unknown {
                code: "metadata_chain_limit".to_owned(),
                structure_path: format!("meta_chains.{name}"),
                reason: "The chain exceeds the configured node budget.".to_owned(),
            });
            break;
        }

        let (block_id, metadata_index) = unpack_metadata_pointer(raw_pointer);
        if metadata_index >= METADATA_BLOCK_COUNT {
            chain.status = MetaChainStatus::InvalidPointer;
            report.blocks.out_of_bounds_references += 1;
            push_block_issue(
                report,
                BlockIssue {
                    kind: BlockIssueKind::OutOfBounds,
                    block_id: Some(block_id),
                    offset: chain.stop_offset.unwrap_or(0),
                    expected_length: None,
                    actual_length: None,
                    message: format!("metadata index {metadata_index} is outside 0..63"),
                },
                "invalid_metadata_pointer",
                Severity::Error,
                "A metadata pointer contains an index outside DuckDB's 0..63 range; the chain was not followed further.",
                limits.max_block_issues,
            );
            break;
        }
        if block_id >= selected.block_count {
            chain.status = MetaChainStatus::InvalidPointer;
            chain.stop_offset = checked_block_location(block_id, alloc).ok();
            report.blocks.out_of_bounds_references += 1;
            push_block_issue(
                report,
                BlockIssue {
                    kind: BlockIssueKind::OutOfBounds,
                    block_id: Some(block_id),
                    offset: chain.stop_offset.unwrap_or(0),
                    expected_length: Some(selected.block_count),
                    actual_length: None,
                    message: format!(
                        "block id {block_id} is outside the selected recorded count {}",
                        selected.block_count
                    ),
                },
                "block_out_of_bounds",
                Severity::Error,
                "A selected metadata chain references a block outside the selected header's recorded block count.",
                limits.max_block_issues,
            );
            break;
        }
        let location = match checked_metadata_location(block_id, metadata_index, alloc) {
            Ok(location) => location,
            Err(error) => {
                chain.status = MetaChainStatus::InvalidPointer;
                report.blocks.out_of_bounds_references += 1;
                report.findings.push(finding(
                    "block_out_of_bounds",
                    Severity::Error,
                    "Checked arithmetic cannot represent this metadata location.",
                    Location::new(None, format!("meta_chains.{name}")),
                    vec![
                        Evidence::new("block_id", block_id),
                        Evidence::new("metadata_index", metadata_index),
                        Evidence::new("arithmetic_error", format!("{error:?}")),
                    ],
                    "Do not follow the pointer or allocate from its values.",
                    Confidence::High,
                ));
                break;
            }
        };
        chain.stop_offset = Some(location);
        let block_offset = match checked_block_location(block_id, alloc) {
            Ok(offset) => offset,
            Err(_) => {
                chain.status = MetaChainStatus::InvalidPointer;
                break;
            }
        };
        let available = report.input.file_size.saturating_sub(block_offset);
        if available < alloc {
            chain.status = MetaChainStatus::InvalidPointer;
            report.blocks.truncated_blocks = report.blocks.truncated_blocks.max(1);
            push_block_issue(
                report,
                BlockIssue {
                    kind: BlockIssueKind::TruncatedBlock,
                    block_id: Some(block_id),
                    offset: block_offset,
                    expected_length: Some(alloc),
                    actual_length: Some(available),
                    message: "A metadata chain references an incomplete physical block.".to_owned(),
                },
                "truncated_block",
                Severity::Error,
                "A metadata chain cannot be read because its referenced block is truncated.",
                limits.max_block_issues,
            );
            break;
        }
        if initial_offset > meta_size {
            chain.status = MetaChainStatus::InvalidPointer;
            report.findings.push(finding(
                "invalid_metadata_pointer",
                Severity::Error,
                "The initial metadata offset exceeds the metadata sub-block capacity.",
                Location::new(Some(location), format!("meta_chains.{name}")),
                vec![
                    Evidence::new("offset", initial_offset),
                    Evidence::new("metadata_block_size", meta_size),
                ],
                "Do not read payload using this offset.",
                Confidence::High,
            ));
            break;
        }

        if !visited.insert((block_id, metadata_index)) {
            chain.status = MetaChainStatus::Cycle;
            chain.cycle_pointer = Some(raw_pointer);
            break;
        }
        chain.visited_nodes += 1;
        let checksum_valid = if let Some(valid) = checksum_cache.get(&block_id) {
            *valid
        } else {
            let mut buffer = vec![0_u8; alloc as usize];
            read_exact_at(file, block_offset, &mut buffer)?;
            let valid = verify_block_checksum(
                report,
                block_id,
                block_offset,
                &buffer,
                BlockChecksumOptions {
                    expected_length: alloc as usize,
                    count_result: !report.blocks.full_scan_requested,
                    record_issue: !report.blocks.full_scan_requested,
                    max_issues: limits.max_block_issues,
                },
            )?;
            report.blocks.metadata_blocks_checked += 1;
            checksum_cache.insert(block_id, valid);
            valid
        };
        if !checksum_valid {
            chain.status = MetaChainStatus::ChecksumUnavailable;
            report.unknowns.push(Unknown {
                code: "metadata_checksum_unavailable".to_owned(),
                structure_path: format!("meta_chains.{name}"),
                reason:
                    "The containing block checksum failed, so its next pointer was not trusted."
                        .to_owned(),
            });
            break;
        }

        let mut next_bytes = [0_u8; 8];
        read_exact_at(file, location, &mut next_bytes)?;
        let next = u64::from_le_bytes(next_bytes);
        chain.verified_nodes += 1;
        let payload_offset = initial_offset.max(8);
        chain.payload_capacity = chain
            .payload_capacity
            .saturating_add(meta_size.saturating_sub(payload_offset));
        report.coverage.meta_checked_bytes =
            report.coverage.meta_checked_bytes.saturating_add(meta_size);
        initial_offset = 0;
        if next == INVALID_BLOCK {
            chain.status = MetaChainStatus::Terminated;
            break;
        }
        if visited.contains(&unpack_metadata_pointer(next)) {
            chain.status = MetaChainStatus::Cycle;
            chain.cycle_pointer = Some(next);
            report.findings.push(finding(
                "meta_block_cycle",
                Severity::Error,
                "A metadata next pointer returns to a node already visited by this chain.",
                Location::new(Some(location), format!("meta_chains.{name}")),
                vec![
                    Evidence::new("next_pointer", next),
                    Evidence::new("visited_nodes", chain.visited_nodes),
                ],
                "Stop following this chain; repeated references across independent chains are not themselves corruption.",
                Confidence::High,
            ));
            break;
        }
        raw_pointer = next;
    }
    Ok(chain)
}

fn push_block_issue(
    report: &mut VerifyReport,
    issue: BlockIssue,
    code: &str,
    severity: Severity,
    message: &str,
    max_issues: usize,
) {
    if report.blocks.issues.len() >= max_issues {
        report.blocks.issues_omitted += 1;
        return;
    }
    report.findings.push(finding(
        code,
        severity,
        message,
        Location::new(Some(issue.offset), "blocks"),
        vec![
            Evidence::new("block_id", issue.block_id),
            Evidence::new("expected_length", issue.expected_length),
            Evidence::new("actual_length", issue.actual_length),
        ],
        "Preserve the original evidence; this verifier does not rewrite blocks or checksums.",
        Confidence::High,
    ));
    report.blocks.issues.push(issue);
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

fn read_exact_at<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), VerifyError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| VerifyError::Io {
            operation: "seek",
            offset,
            source,
        })?;
    let mut total = 0;
    while total < buffer.len() {
        match file.read(&mut buffer[total..]) {
            Ok(0) => {
                return Err(VerifyError::Io {
                    operation: "read",
                    offset: offset.saturating_add(total as u64),
                    source: io::Error::new(io::ErrorKind::UnexpectedEof, "short block read"),
                });
            }
            Ok(count) => total += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(VerifyError::Io {
                    operation: "read",
                    offset: offset.saturating_add(total as u64),
                    source,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn block_reads_join_short_reads_and_reject_early_eof() {
        let mut reader = ShortReads(std::io::Cursor::new(vec![3; 16]));
        let mut buffer = [0_u8; 16];
        read_exact_at(&mut reader, 0, &mut buffer).expect("joined short reads");
        assert_eq!(buffer, [3; 16]);

        let mut reader = ShortReads(std::io::Cursor::new(vec![3; 15]));
        let error = read_exact_at(&mut reader, 0, &mut buffer).expect_err("early EOF");
        assert!(
            matches!(error, VerifyError::Io { source, .. } if source.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
}
