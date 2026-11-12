use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use duckdb_format::{
    BlockAllocSizeError, ChecksumObservation, DatabaseHeader, FILE_HEADER_SIZE, FormatError,
    GeometryError, INVALID_BLOCK, MAIN_HEADER_VERSION_DEPRECATED, MAXIMUM_BLOCK, MainHeader,
    STANDARD_VECTOR_SIZE, STORAGE_VERSION_V2_0_0, checked_block_location,
    checked_recorded_file_end, read_header_page, verify_block_alloc_size,
};
use duckdb_report::{
    Check, Confidence, Coverage, Evidence, Finding, Inference, InputInfo, InspectionReport,
    Location, Observation, Severity, SkipReason, SkippedCheck, Unknown,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const HASH_BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct InspectionLimits {
    pub max_file_size: u64,
}

impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }
}

#[derive(Debug)]
pub enum InspectError {
    Canonicalize { path: PathBuf, source: io::Error },
    Open { path: PathBuf, source: io::Error },
    Metadata { path: PathBuf, source: io::Error },
    Hash(io::Error),
    Format(FormatError),
}

impl Display for InspectError {
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
            Self::Hash(source) => write!(formatter, "cannot stream input for SHA-256: {source}"),
            Self::Format(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for InspectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonicalize { source, .. }
            | Self::Open { source, .. }
            | Self::Metadata { source, .. }
            | Self::Hash(source) => Some(source),
            Self::Format(source) => Some(source),
        }
    }
}

impl From<FormatError> for InspectError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

pub fn inspect_path(path: &Path, hide_path: bool) -> Result<InspectionReport, InspectError> {
    inspect_path_with_limits(path, hide_path, InspectionLimits::default())
}

pub fn inspect_path_with_limits(
    path: &Path,
    hide_path: bool,
    limits: InspectionLimits,
) -> Result<InspectionReport, InspectError> {
    let canonical_path = path
        .canonicalize()
        .map_err(|source| InspectError::Canonicalize {
            path: path.to_path_buf(),
            source,
        })?;
    let mut file = File::open(&canonical_path).map_err(|source| InspectError::Open {
        path: canonical_path.clone(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| InspectError::Metadata {
        path: canonical_path.clone(),
        source,
    })?;
    let file_size = metadata.len();
    let input = InputInfo {
        path: if hide_path {
            None
        } else {
            Some(canonical_path.display().to_string())
        },
        file_size,
        sha256: None,
    };
    let mut report = InspectionReport::new(input);
    report.coverage = base_coverage();
    report.coverage.checked.push("input.file_size".to_owned());

    if file_size > limits.max_file_size {
        report.findings.push(finding(
            "limit_reached",
            Severity::Warning,
            "The file exceeds the configured inspection size limit; hashing and header parsing were stopped.",
            Location::new(None, "input"),
            vec![
                Evidence::new("file_size", file_size),
                Evidence::new("max_file_size", limits.max_file_size),
            ],
            "Raise the documented limit only if hashing this evidence is within the available resource budget.",
            Confidence::High,
        ));
        report.checks_skipped.push(
            SkippedCheck::new(
                "resource_budget",
                "SHA-256 and header checks were not attempted.",
                SkipReason::LimitReached,
            )
            .in_structure("input"),
        );
        report.unknowns.push(Unknown {
            code: "sha256_unavailable".to_owned(),
            structure_path: "input".to_owned(),
            reason: "The resource limit was reached before streaming the file.".to_owned(),
        });
        return Ok(report);
    }

    report.input.sha256 = Some(stream_sha256(&mut file)?);
    report.coverage.checked.push("input.sha256".to_owned());

    let main_page = read_header_page(&mut file, 0)?;
    report.observations.push(Observation::new(
        "available_bytes",
        "main_header",
        Some(0),
        main_page.available as u64,
    ));
    report
        .coverage
        .checked
        .push("main_header.availability".to_owned());

    if !main_page.is_complete() {
        report_truncated_page(&mut report, "main_header", 0, main_page.available);
        if main_page.available >= 12 {
            let magic = &main_page.bytes()[8..12];
            observe_magic(&mut report, magic);
            if magic != b"DUCK" {
                report_invalid_magic(&mut report, magic);
            }
        } else {
            report.checks_skipped.push(
                SkippedCheck::new(
                    "magic_bytes",
                    "The file is too short to contain the complete magic field.",
                    SkipReason::Unavailable,
                )
                .in_structure("main_header.magic_bytes"),
            );
        }
        skip_database_headers(&mut report, SkipReason::PrerequisiteFailed);
        report.coverage.not_checked.push(
            "main_header.checksum (incomplete page); main_header.fields (incomplete page)"
                .to_owned(),
        );
        return Ok(report);
    }

    let main_checksum = main_page.checksum()?;
    observe_checksum(&mut report, "main_header", 0, main_checksum);
    report
        .coverage
        .checked
        .push("main_header.checksum".to_owned());
    if main_checksum.matches {
        report.checks_passed.push(
            Check::new(
                "main_header_checksum",
                "The Main Header checksum matches the stored value.",
            )
            .in_structure("main_header"),
        );
    } else {
        report_checksum_mismatch(&mut report, "main_header", 0, main_checksum);
        report.unknowns.push(Unknown {
            code: "main_header_fields_untrusted".to_owned(),
            structure_path: "main_header".to_owned(),
            reason: "Raw fields are shown, but their interpretation is not integrity-confirmed."
                .to_owned(),
        });
    }

    let main_header = MainHeader::parse(&main_page)?;
    observe_main_header(&mut report, &main_header);
    report
        .coverage
        .checked
        .push("main_header.raw_fields".to_owned());

    if !main_header.magic_is_valid() {
        report_invalid_magic(&mut report, &main_header.magic_bytes);
    } else {
        report.checks_passed.push(
            Check::new("magic_bytes", "The magic bytes are DUCK.").in_structure("main_header"),
        );
    }

    let version_supported = main_header.version_number == MAIN_HEADER_VERSION_DEPRECATED;
    if version_supported {
        report.checks_passed.push(
            Check::new(
                "main_header_version_marker",
                "The Main Header contains the v2.0.0 deprecated-version marker (999).",
            )
            .in_structure("main_header.version_number"),
        );
    } else {
        report.findings.push(finding(
            "unsupported_storage_version",
            Severity::Warning,
            "The Main Header version marker is not the v2.0.0 marker (999); Database Header semantics are unsupported.",
            Location::new(Some(12), "main_header.version_number"),
            vec![Evidence::new("version_number", main_header.version_number).at_offset(12)],
            "Use an inspector built for the actual DuckDB storage version; do not treat 999 as the real storage version.",
            Confidence::High,
        ));
        report.checks_skipped.push(
            SkippedCheck::new(
                "main_header_version_marker",
                "Only the v2.0.0 deprecated-version marker (999) is supported.",
                SkipReason::Unsupported,
            )
            .in_structure("main_header.version_number"),
        );
    }

    if main_header.is_encrypted() {
        report.findings.push(finding(
            "unsupported_encryption",
            Severity::Warning,
            "The encrypted-database flag is set; encrypted Database Headers and blocks are not decoded.",
            Location::new(Some(20), "main_header.flags[0]"),
            vec![Evidence::new("flags_0", main_header.flags[0]).at_offset(20)],
            "Use a trusted DuckDB v2.0.0 environment with the correct key on a copy; this tool does not decrypt evidence.",
            Confidence::High,
        ));
        skip_database_headers(&mut report, SkipReason::Unsupported);
        report.coverage.not_checked.push(
            "database_headers.encrypted_checksums_and_fields; encrypted block contents".to_owned(),
        );
        report.unknowns.push(Unknown {
            code: "encrypted_database_headers".to_owned(),
            structure_path: "database_header[*]".to_owned(),
            reason: "DuckDB decrypts these pages before checksum validation; plaintext checksum parsing would be invalid."
                .to_owned(),
        });
        return Ok(report);
    }

    if !main_header.magic_is_valid() || !version_supported {
        skip_database_headers(&mut report, SkipReason::PrerequisiteFailed);
        return Ok(report);
    }

    inspect_database_headers(&mut report, &mut file, file_size)?;
    Ok(report)
}

#[derive(Debug)]
struct HeaderAssessment {
    index: usize,
    path: String,
    offset: u64,
    checksum: Option<ChecksumObservation>,
    header: Option<DatabaseHeader>,
    eligible: bool,
}

fn inspect_database_headers(
    report: &mut InspectionReport,
    file: &mut File,
    file_size: u64,
) -> Result<(), InspectError> {
    let mut assessments = Vec::with_capacity(2);
    for (index, offset) in [FILE_HEADER_SIZE, FILE_HEADER_SIZE * 2]
        .into_iter()
        .enumerate()
    {
        let path = format!("database_header[{index}]");
        let page = read_header_page(file, offset)?;
        report.observations.push(Observation::new(
            "available_bytes",
            path.clone(),
            Some(offset),
            page.available as u64,
        ));

        let mut assessment = HeaderAssessment {
            index,
            path: path.clone(),
            offset,
            checksum: None,
            header: None,
            eligible: false,
        };

        if !page.is_complete() {
            report_truncated_page(report, &path, offset, page.available);
            assessments.push(assessment);
            continue;
        }

        let checksum = page.checksum()?;
        observe_checksum(report, &path, offset, checksum);
        assessment.checksum = Some(checksum);
        if !checksum.matches {
            report_checksum_mismatch(report, &path, offset, checksum);
        }

        let header = DatabaseHeader::parse(&page)?;
        observe_database_header(report, &path, offset, &header);
        assessment.eligible = checksum.matches;
        if checksum.matches {
            validate_database_header(report, &mut assessment, &header, file_size);
        } else {
            report.checks_skipped.push(
                SkippedCheck::new(
                    "field_validation_and_geometry",
                    "Raw fields are available, but semantic validation and geometry require a valid header checksum.",
                    SkipReason::PrerequisiteFailed,
                )
                .in_structure(path.clone()),
            );
        }
        assessment.header = Some(header);
        assessments.push(assessment);
    }

    report
        .coverage
        .checked
        .push("database_header[*].availability".to_owned());
    report
        .coverage
        .checked
        .push("database_header[*].checksum".to_owned());
    report
        .coverage
        .checked
        .push("database_header[*].raw_fields".to_owned());
    report
        .coverage
        .checked
        .push("geometry.recorded_file_end".to_owned());

    select_database_header(report, &assessments);
    Ok(())
}

fn validate_database_header(
    report: &mut InspectionReport,
    assessment: &mut HeaderAssessment,
    header: &DatabaseHeader,
    file_size: u64,
) {
    let path = assessment.path.clone();
    let offset = assessment.offset;
    if header.storage_compatibility != STORAGE_VERSION_V2_0_0 {
        report.findings.push(finding(
            "unsupported_storage_version",
            Severity::Warning,
            "This Database Header does not declare storage compatibility 69 and is not eligible for v2.0.0 selection.",
            Location::new(Some(offset + 56), format!("{path}.storage_compatibility")),
            vec![Evidence::new("storage_compatibility", header.storage_compatibility)
                .at_offset(offset + 56)],
            "Use an inspector supporting the declared storage version.",
            Confidence::High,
        ));
        report.checks_skipped.push(
            SkippedCheck::new(
                "storage_compatibility",
                "Only storage compatibility 69 is supported.",
                SkipReason::Unsupported,
            )
            .in_structure(path.clone()),
        );
        assessment.eligible = false;
    } else if assessment.checksum.is_some_and(|checksum| checksum.matches) {
        report.checks_passed.push(
            Check::new(
                "storage_compatibility",
                "Storage compatibility is 69 (DuckDB v2.0.0).",
            )
            .in_structure(path.clone()),
        );
    }

    let effective_alloc = header.effective_block_alloc_size();
    if effective_alloc != header.block_alloc_size {
        report.observations.push(Observation::new(
            "effective_block_alloc_size",
            path.clone(),
            Some(offset + 40),
            effective_alloc,
        ));
    }
    if let Err(error) = verify_block_alloc_size(effective_alloc) {
        let message = match error {
            BlockAllocSizeError::NotPowerOfTwo(value) => {
                format!("Block allocation size {value} is not a nonzero power of two.")
            }
            BlockAllocSizeError::TooSmall(value) => {
                format!("Block allocation size {value} is below DuckDB's minimum of 16384.")
            }
            BlockAllocSizeError::TooLarge(value) => {
                format!("Block allocation size {value} exceeds DuckDB's maximum of 262144.")
            }
        };
        report.findings.push(finding(
            "invalid_block_alloc_size",
            Severity::Error,
            message,
            Location::new(Some(offset + 40), format!("{path}.block_alloc_size")),
            vec![Evidence::new("effective_block_alloc_size", effective_alloc)
                .at_offset(offset + 40)],
            "Preserve the evidence and compare both Database Headers; do not rewrite the size in place.",
            Confidence::High,
        ));
        report.checks_failed.push(
            Check::new("block_alloc_size", "Invalid block allocation size.")
                .in_structure(path.clone()),
        );
        assessment.eligible = false;
    } else if assessment.checksum.is_some_and(|checksum| checksum.matches) {
        report.checks_passed.push(
            Check::new(
                "block_alloc_size",
                "Block allocation size satisfies DuckDB v2.0.0 bounds and power-of-two rules.",
            )
            .in_structure(path.clone()),
        );
    }

    let effective_vector_size = header.effective_vector_size();
    if effective_vector_size != header.vector_size {
        report.observations.push(Observation::new(
            "effective_vector_size",
            path.clone(),
            Some(offset + 48),
            effective_vector_size,
        ));
    }
    if effective_vector_size != STANDARD_VECTOR_SIZE {
        report.findings.push(finding(
            "unsupported_vector_size",
            Severity::Warning,
            "The Database Header vector size differs from the supported DuckDB v2.0.0 default of 2048.",
            Location::new(Some(offset + 48), format!("{path}.vector_size")),
            vec![Evidence::new("effective_vector_size", effective_vector_size)
                .at_offset(offset + 48)],
            "Use a DuckDB build and inspector matching the file's vector size.",
            Confidence::High,
        ));
        report.checks_skipped.push(
            SkippedCheck::new(
                "vector_size",
                "Only vector size 2048 is supported.",
                SkipReason::Unsupported,
            )
            .in_structure(path.clone()),
        );
        assessment.eligible = false;
    } else if assessment.checksum.is_some_and(|checksum| checksum.matches) {
        report
            .checks_passed
            .push(Check::new("vector_size", "Vector size is 2048.").in_structure(path.clone()));
    }

    if header.block_count > MAXIMUM_BLOCK {
        report.findings.push(finding(
            "invalid_block_count",
            Severity::Error,
            "The block count exceeds DuckDB v2.0.0's MAXIMUM_BLOCK bound.",
            Location::new(Some(offset + 32), format!("{path}.block_count")),
            vec![
                Evidence::new("block_count", header.block_count).at_offset(offset + 32),
                Evidence::new("maximum_block", MAXIMUM_BLOCK),
            ],
            "Preserve the evidence and compare the alternate Database Header; do not allocate based on this count.",
            Confidence::High,
        ));
        report.checks_failed.push(
            Check::new("block_count", "Block count exceeds MAXIMUM_BLOCK.")
                .in_structure(path.clone()),
        );
        assessment.eligible = false;
    } else if assessment.checksum.is_some_and(|checksum| checksum.matches) {
        report.checks_passed.push(
            Check::new("block_count", "Block count is within MAXIMUM_BLOCK.")
                .in_structure(path.clone()),
        );
    }

    if verify_block_alloc_size(effective_alloc).is_ok() {
        let geometry = checked_recorded_file_end(header.block_count, effective_alloc);
        match geometry {
            Ok(expected_file_end) => {
                report.observations.push(Observation::new(
                    format!("header_{}_expected_file_end", assessment.index),
                    "geometry",
                    None,
                    expected_file_end,
                ));
                let relation = if file_size < expected_file_end {
                    "truncated"
                } else if file_size == expected_file_end {
                    "matches"
                } else {
                    "beyond_header_block_count"
                };
                report.observations.push(Observation::new(
                    format!("header_{}_file_length_relation", assessment.index),
                    "geometry",
                    None,
                    relation,
                ));
                if file_size < expected_file_end {
                    report.findings.push(finding(
                        "truncated_file",
                        Severity::Error,
                        "The actual file ends before the blocks recorded by this Database Header.",
                        Location::new(Some(file_size), format!("{path}.block_count")),
                        vec![
                            Evidence::new("file_size", file_size),
                            Evidence::new("expected_file_end", expected_file_end),
                        ],
                        "Locate an earlier or intact copy; do not extend or truncate the evidence to force a match.",
                        Confidence::High,
                    ));
                    report.checks_failed.push(
                        Check::new(
                            "recorded_block_geometry",
                            "The file is shorter than the recorded block geometry.",
                        )
                        .in_structure(path.clone()),
                    );
                } else {
                    report.checks_passed.push(
                        Check::new(
                            "recorded_block_geometry",
                            if file_size == expected_file_end {
                                "File length exactly matches the recorded block geometry."
                            } else {
                                "All recorded blocks are present; bytes beyond block_count are reported separately, not called corruption."
                            },
                        )
                        .in_structure(path.clone()),
                    );
                }
            }
            Err(GeometryError::BlockCountTooLarge(_)) => {}
            Err(error @ (GeometryError::ByteLengthOverflow | GeometryError::FileEndOverflow)) => {
                report.findings.push(finding(
                    "geometry_overflow",
                    Severity::Error,
                    "Checked arithmetic cannot represent the file end declared by this Database Header.",
                    Location::new(Some(offset + 32), format!("{path}.block_count")),
                    vec![
                        Evidence::new("block_count", header.block_count),
                        Evidence::new("block_alloc_size", effective_alloc),
                        Evidence::new("arithmetic_error", format!("{error:?}")),
                    ],
                    "Do not use this header for offsets or allocation; compare the alternate header on a preserved copy.",
                    Confidence::High,
                ));
                report.checks_failed.push(
                    Check::new(
                        "recorded_block_geometry",
                        "Geometry calculation overflowed.",
                    )
                    .in_structure(path.clone()),
                );
                assessment.eligible = false;
            }
        }
    }

    if verify_block_alloc_size(effective_alloc).is_ok() {
        for (name, raw_pointer, field_offset) in [
            ("meta_block", header.meta_block, offset + 16),
            ("free_list", header.free_list, offset + 24),
        ] {
            if raw_pointer != INVALID_BLOCK {
                observe_metadata_pointer(
                    report,
                    assessment,
                    name,
                    raw_pointer,
                    field_offset,
                    file_size,
                    effective_alloc,
                );
            }
        }
    }
}

fn observe_metadata_pointer(
    report: &mut InspectionReport,
    assessment: &mut HeaderAssessment,
    name: &str,
    raw_pointer: u64,
    field_offset: u64,
    file_size: u64,
    block_alloc_size: u64,
) {
    let block_id = raw_pointer & 0x00ff_ffff_ffff_ffff;
    let metadata_index = raw_pointer >> 56;
    report.observations.extend([
        Observation::new(
            format!("{name}_block_id"),
            assessment.path.clone(),
            Some(field_offset),
            block_id,
        ),
        Observation::new(
            format!("{name}_metadata_index"),
            assessment.path.clone(),
            Some(field_offset),
            metadata_index,
        ),
    ]);
    if metadata_index >= 64 {
        report.findings.push(finding(
            "invalid_metadata_pointer",
            Severity::Error,
            format!("The packed {name} metadata index is outside DuckDB's 0..63 range."),
            Location::new(
                Some(field_offset),
                format!("{}.{name}", assessment.path),
            ),
            vec![Evidence::new("metadata_index", metadata_index)],
            "Do not follow this metadata pointer; compare the alternate Database Header on a preserved copy.",
            Confidence::High,
        ));
        report.checks_failed.push(
            Check::new(
                format!("{name}_metadata_index"),
                "Metadata index is 64 or greater.",
            )
            .in_structure(assessment.path.clone()),
        );
        assessment.eligible = false;
        return;
    }
    observe_block_reference(
        report,
        assessment,
        name,
        block_id,
        field_offset,
        file_size,
        block_alloc_size,
    );
}

fn observe_block_reference(
    report: &mut InspectionReport,
    assessment: &mut HeaderAssessment,
    name: &str,
    block_id: u64,
    field_offset: u64,
    file_size: u64,
    block_alloc_size: u64,
) {
    match checked_block_location(block_id, block_alloc_size) {
        Ok(block_offset) => {
            report.observations.push(Observation::new(
                format!("{name}_file_offset"),
                assessment.path.clone(),
                Some(field_offset),
                block_offset,
            ));
            if block_offset >= file_size {
                report.observations.push(Observation::new(
                    format!("{name}_availability"),
                    assessment.path.clone(),
                    Some(field_offset),
                    "beyond_actual_file_length",
                ));
            }
        }
        Err(error) => {
            report.findings.push(finding(
                "invalid_block_reference",
                Severity::Error,
                format!("The {name} block ID cannot be converted to a checked file offset."),
                Location::new(
                    Some(field_offset),
                    format!("{}.{name}", assessment.path),
                ),
                vec![
                    Evidence::new("block_id", block_id),
                    Evidence::new("arithmetic_error", format!("{error:?}")),
                ],
                "Do not follow this block reference; compare the alternate Database Header on a preserved copy.",
                Confidence::High,
            ));
            report.checks_failed.push(
                Check::new(
                    "block_reference",
                    format!("Invalid {name} block reference."),
                )
                .in_structure(assessment.path.clone()),
            );
            assessment.eligible = false;
        }
    }
}

fn select_database_header(report: &mut InspectionReport, assessments: &[HeaderAssessment]) {
    let eligible: Vec<&HeaderAssessment> = assessments
        .iter()
        .filter(|assessment| assessment.eligible)
        .collect();
    let selected = match eligible.as_slice() {
        [] => None,
        [only] => Some(*only),
        [first, second] => {
            let first_iteration = first.header.map(|header| header.iteration).unwrap_or(0);
            let second_iteration = second.header.map(|header| header.iteration).unwrap_or(0);
            if first_iteration > second_iteration {
                Some(*first)
            } else {
                Some(*second)
            }
        }
        _ => None,
    };

    if let Some(selected) = selected {
        let iteration = selected.header.map(|header| header.iteration).unwrap_or(0);
        let only_candidate = eligible.len() == 1;
        report.inferences.push(Inference {
            code: "likely_active_database_header".to_owned(),
            message: if only_candidate {
                "This is the only Database Header passing checksum and supported-field checks.".to_owned()
            } else {
                "Selected by DuckDB's rule: greater iteration wins, and header 2 wins an iteration tie.".to_owned()
            },
            subject: Some(selected.path.clone()),
            evidence: vec![
                Evidence::new("header_index", selected.index as u64),
                Evidence::new("iteration", iteration).at_offset(selected.offset + 8),
                Evidence::new("eligible_header_count", eligible.len() as u64),
            ],
            confidence: if only_candidate {
                Confidence::Medium
            } else {
                Confidence::High
            },
        });
        report.checks_passed.push(
            Check::new(
                "database_header_selection",
                "At least one Database Header is eligible for active-header selection.",
            )
            .in_structure(selected.path.clone()),
        );

        if eligible.len() == 2
            && let [first, second] = eligible.as_slice()
        {
            let first_iteration = first.header.map(|header| header.iteration).unwrap_or(0);
            let second_iteration = second.header.map(|header| header.iteration).unwrap_or(0);
            if first_iteration != second_iteration {
                let stale = if selected.index == first.index {
                    second
                } else {
                    first
                };
                report.inferences.push(Inference {
                    code: "possible_stale_header".to_owned(),
                    message:
                        "This valid header has the lower iteration and is not selected as active."
                            .to_owned(),
                    subject: Some(stale.path.clone()),
                    evidence: vec![Evidence::new(
                        "iteration",
                        stale.header.map(|header| header.iteration).unwrap_or(0),
                    )],
                    confidence: Confidence::High,
                });
            }
        }
    } else {
        let has_v2_candidate = assessments.iter().any(|assessment| {
            assessment
                .header
                .is_some_and(|header| header.storage_compatibility == STORAGE_VERSION_V2_0_0)
        });
        let has_checksum_mismatch = assessments.iter().any(|assessment| {
            assessment
                .checksum
                .is_some_and(|checksum| !checksum.matches)
        });
        if has_v2_candidate || has_checksum_mismatch {
            report.findings.push(finding(
                "no_valid_database_header",
                Severity::Error,
                "No Database Header passes the v2.0.0 checksum, field, and geometry requirements.",
                Location::new(Some(FILE_HEADER_SIZE), "database_header[*]"),
                vec![Evidence::new(
                    "checksum_statuses",
                    json!(assessments
                        .iter()
                        .map(|assessment| assessment
                            .checksum
                            .map(|checksum| if checksum.matches { "valid" } else { "mismatch" })
                            .unwrap_or("unavailable"))
                        .collect::<Vec<_>>()),
                )],
                "Preserve the file and compare header-level evidence; this phase does not reconstruct headers.",
                Confidence::High,
            ));
            report.checks_failed.push(
                Check::new(
                    "database_header_selection",
                    "No eligible v2.0.0 Database Header is available.",
                )
                .in_structure("database_header[*]"),
            );
        } else {
            let has_complete_header = assessments
                .iter()
                .any(|assessment| assessment.header.is_some());
            let reason = if has_complete_header {
                SkipReason::Unsupported
            } else {
                SkipReason::Unavailable
            };
            report.checks_skipped.push(
                SkippedCheck::new(
                    "database_header_selection",
                    if has_complete_header {
                        "No header declares supported storage compatibility 69."
                    } else {
                        "No complete Database Header is available for supported-version selection."
                    },
                    reason,
                )
                .in_structure("database_header[*]"),
            );
        }
        report.unknowns.push(Unknown {
            code: "active_database_header".to_owned(),
            structure_path: "database_header[*]".to_owned(),
            reason: "No supported candidate passed all applicable checks.".to_owned(),
        });
    }

    let mismatched: Vec<&HeaderAssessment> = assessments
        .iter()
        .filter(|assessment| {
            assessment
                .checksum
                .is_some_and(|checksum| !checksum.matches)
        })
        .collect();
    if mismatched.len() == 1 && eligible.len() == 1 {
        report.inferences.push(Inference {
            code: "possible_torn_write".to_owned(),
            message: "One Database Header fails checksum while the other is usable; a torn write is only one possible explanation."
                .to_owned(),
            subject: Some(mismatched[0].path.clone()),
            evidence: vec![
                Evidence::new("usable_header", eligible[0].path.clone()),
                Evidence::new("mismatched_header", mismatched[0].path.clone()),
            ],
            confidence: Confidence::Low,
        });
    }
}

fn observe_main_header(report: &mut InspectionReport, header: &MainHeader) {
    observe_magic(report, &header.magic_bytes);
    report.observations.extend([
        Observation::new(
            "version_number",
            "main_header",
            Some(12),
            header.version_number,
        ),
        Observation::new("flags", "main_header", Some(20), json!(header.flags)),
        Observation::new(
            "library_git_desc",
            "main_header",
            Some(52),
            fixed_text(&header.library_git_desc),
        ),
        Observation::new(
            "library_git_hash",
            "main_header",
            Some(84),
            fixed_text(&header.library_git_hash),
        ),
        Observation::new(
            "encryption_metadata_hex",
            "main_header",
            Some(116),
            hex(&header.encryption_metadata),
        ),
        Observation::new(
            "db_identifier_hex",
            "main_header",
            Some(124),
            hex(&header.db_identifier),
        ),
        Observation::new("encrypted", "main_header", Some(20), header.is_encrypted()),
    ]);
}

fn observe_magic(report: &mut InspectionReport, magic: &[u8]) {
    report.observations.push(Observation::new(
        "magic_bytes_hex",
        "main_header",
        Some(8),
        hex(magic),
    ));
    if magic == b"DUCK" {
        report.observations.push(Observation::new(
            "magic_ascii",
            "main_header",
            Some(8),
            "DUCK",
        ));
    }
}

fn observe_database_header(
    report: &mut InspectionReport,
    path: &str,
    offset: u64,
    header: &DatabaseHeader,
) {
    report.observations.extend([
        Observation::new("iteration", path, Some(offset + 8), header.iteration),
        Observation::new("meta_block", path, Some(offset + 16), header.meta_block),
        Observation::new("free_list", path, Some(offset + 24), header.free_list),
        Observation::new("block_count", path, Some(offset + 32), header.block_count),
        Observation::new(
            "block_alloc_size",
            path,
            Some(offset + 40),
            header.block_alloc_size,
        ),
        Observation::new("vector_size", path, Some(offset + 48), header.vector_size),
        Observation::new(
            "storage_compatibility",
            path,
            Some(offset + 56),
            header.storage_compatibility,
        ),
    ]);
}

fn observe_checksum(
    report: &mut InspectionReport,
    path: &str,
    offset: u64,
    checksum: ChecksumObservation,
) {
    report.observations.extend([
        Observation::new(
            "stored_checksum",
            path,
            Some(offset),
            format_hex_u64(checksum.stored_checksum),
        ),
        Observation::new(
            "computed_checksum",
            path,
            Some(offset + 8),
            format_hex_u64(checksum.computed_checksum),
        ),
        Observation::new(
            "checksum_status",
            path,
            Some(offset),
            if checksum.matches {
                "valid"
            } else {
                "mismatch"
            },
        ),
    ]);
}

fn report_checksum_mismatch(
    report: &mut InspectionReport,
    path: &str,
    offset: u64,
    checksum: ChecksumObservation,
) {
    report.findings.push(finding(
        "checksum_mismatch",
        Severity::Error,
        "The stored checksum differs from the checksum computed over bytes 8 through 4095 of this header page.",
        Location::new(Some(offset), format!("{path}.checksum")),
        vec![
            Evidence::new("stored_checksum", format_hex_u64(checksum.stored_checksum))
                .at_offset(offset),
            Evidence::new("computed_checksum", format_hex_u64(checksum.computed_checksum))
                .at_offset(offset + 8),
        ],
        "Preserve the original file and compare alternate headers or copies; do not recompute the stored checksum in place.",
        Confidence::High,
    ));
    report
        .checks_failed
        .push(Check::new("checksum", "Header checksum mismatch.").in_structure(path));
}

fn report_invalid_magic(report: &mut InspectionReport, magic: &[u8]) {
    report.findings.push(finding(
        "invalid_magic",
        Severity::Error,
        "The bytes at file offset 8 are not DuckDB's DUCK magic.",
        Location::new(Some(8), "main_header.magic_bytes"),
        vec![Evidence::new("magic_bytes_hex", hex(magic)).at_offset(8)],
        "Confirm that the input is a native single-file DuckDB database; do not relabel or edit the evidence.",
        Confidence::High,
    ));
    report
        .checks_failed
        .push(Check::new("magic_bytes", "Invalid DuckDB magic bytes.").in_structure("main_header"));
}

fn report_truncated_page(report: &mut InspectionReport, path: &str, offset: u64, available: usize) {
    report.findings.push(finding(
        "truncated_file",
        Severity::Error,
        "The file ends before this complete 4096-byte header page is available.",
        Location::new(Some(offset), path),
        vec![
            Evidence::new("expected_page_bytes", FILE_HEADER_SIZE),
            Evidence::new("available_page_bytes", available as u64),
        ],
        "Preserve the evidence and locate a complete copy; this tool will not pad or extend the file.",
        Confidence::High,
    ));
    report.checks_failed.push(
        Check::new("complete_header_page", "Incomplete 4096-byte header page.").in_structure(path),
    );
    report.checks_skipped.push(
        SkippedCheck::new(
            "checksum",
            "A checksum requires the complete 4096-byte header page.",
            SkipReason::Unavailable,
        )
        .in_structure(path),
    );
}

fn skip_database_headers(report: &mut InspectionReport, reason: SkipReason) {
    report.checks_skipped.push(
        SkippedCheck::new(
            "database_headers",
            "Database Header checksums, raw-field interpretation, selection, and geometry are not checked.",
            reason,
        )
        .in_structure("database_header[*]"),
    );
    report
        .coverage
        .not_checked
        .push("database_headers; active-header selection; block geometry".to_owned());
}

fn base_coverage() -> Coverage {
    Coverage {
        checked: Vec::new(),
        not_checked: vec![
            "catalog deserialization".to_owned(),
            "meta_block and free_list payload contents".to_owned(),
            "row groups and column compression".to_owned(),
            "block payload checksums and contents".to_owned(),
            "WAL discovery and semantics".to_owned(),
            "business data".to_owned(),
            "repair or recovery".to_owned(),
        ],
    }
}

#[allow(clippy::too_many_arguments)]
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
        severity,
        message: message.into(),
        location,
        evidence,
        remediation_hint: remediation_hint.to_owned(),
        confidence,
    }
}

fn stream_sha256(file: &mut File) -> Result<String, InspectError> {
    use std::io::{Seek, SeekFrom};

    file.seek(SeekFrom::Start(0)).map_err(InspectError::Hash)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InspectError::Hash(error)),
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn fixed_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn format_hex_u64(value: u64) -> String {
    format!("0x{value:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_reached_is_not_corruption() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("failed to create temporary directory: {error}"),
        };
        let path = directory.path().join("input.duckdb");
        if let Err(error) = std::fs::write(&path, b"DUCK") {
            panic!("failed to write test input: {error}");
        }
        let report =
            match inspect_path_with_limits(&path, false, InspectionLimits { max_file_size: 3 }) {
                Ok(report) => report,
                Err(error) => panic!("inspection failed: {error}"),
            };
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "limit_reached")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == "checksum_mismatch")
        );
        assert!(report.input.sha256.is_none());
    }
}
