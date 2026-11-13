use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use duckdb_report::oracle::OracleComparison;
use duckdb_report::recovery::{
    CandidateAction, EvidenceFileReport, ObservedFacts, PossibleDataLoss, RecoveryPlanReport,
    RecoveryPlanStatus, RecoveryRisk,
};
use duckdb_report::verify::VerifyReport;
use duckdb_report::wal::{WalReport, WalStatus};
use duckdb_report::{Confidence, Evidence, Finding, Location, Severity, Unknown};
use sha2::{Digest, Sha256};

use crate::oracle::{OracleError, run_oracle};
use crate::util::path_text;
use crate::verify::{VerifyError, VerifyLimits, verify_path_with_limits};
use crate::wal::{WalInspectError, WalInspectionLimits, inspect_wal_path_with_limits};

const HASH_BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_EVIDENCE_FILES: usize = 100_000;
const DEFAULT_MAX_EVIDENCE_DEPTH: usize = 64;
const DEFAULT_MAX_EVIDENCE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct RecoveryLimits {
    pub verify: VerifyLimits,
    pub wal: WalInspectionLimits,
    pub max_evidence_files: usize,
    pub max_evidence_depth: usize,
    pub max_evidence_bytes: u64,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            verify: VerifyLimits::default(),
            wal: WalInspectionLimits::default(),
            max_evidence_files: DEFAULT_MAX_EVIDENCE_FILES,
            max_evidence_depth: DEFAULT_MAX_EVIDENCE_DEPTH,
            max_evidence_bytes: DEFAULT_MAX_EVIDENCE_BYTES,
        }
    }
}

struct Inventory {
    files: Vec<EvidenceFileReport>,
    complete: bool,
    limit: Option<(&'static str, u64)>,
}

#[derive(Debug)]
pub enum RecoverError {
    Canonicalize { path: PathBuf, source: io::Error },
    Inventory { path: PathBuf, source: io::Error },
    InventoryLimit { resource: &'static str, limit: u64 },
    Verify(VerifyError),
    Wal(WalInspectError),
    Oracle(OracleError),
}

impl Display for RecoverError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonicalize { path, source } => write!(
                formatter,
                "cannot canonicalize evidence directory {}: {source}",
                path.display()
            ),
            Self::Inventory { path, source } => write!(
                formatter,
                "cannot inventory or hash evidence file {}: {source}",
                path.display()
            ),
            Self::InventoryLimit { resource, limit } => write!(
                formatter,
                "evidence inventory exceeds the {resource} limit of {limit}"
            ),
            Self::Verify(error) => Display::fmt(error, formatter),
            Self::Wal(error) => Display::fmt(error, formatter),
            Self::Oracle(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for RecoverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonicalize { source, .. } | Self::Inventory { source, .. } => Some(source),
            Self::InventoryLimit { .. } => None,
            Self::Verify(error) => Some(error),
            Self::Wal(error) => Some(error),
            Self::Oracle(error) => Some(error),
        }
    }
}

impl From<VerifyError> for RecoverError {
    fn from(error: VerifyError) -> Self {
        Self::Verify(error)
    }
}

impl From<WalInspectError> for RecoverError {
    fn from(error: WalInspectError) -> Self {
        Self::Wal(error)
    }
}

impl From<OracleError> for RecoverError {
    fn from(error: OracleError) -> Self {
        Self::Oracle(error)
    }
}

pub fn recover_plan_path(path: &Path) -> Result<RecoveryPlanReport, RecoverError> {
    recover_plan_path_with_limits(path, RecoveryLimits::default())
}

pub fn recover_plan_path_with_limits(
    path: &Path,
    limits: RecoveryLimits,
) -> Result<RecoveryPlanReport, RecoverError> {
    recover_plan_with_options(path, None, limits)
}

pub fn recover_plan_with_options(
    path: &Path,
    duckdb: Option<&Path>,
    limits: RecoveryLimits,
) -> Result<RecoveryPlanReport, RecoverError> {
    let canonical = path
        .canonicalize()
        .map_err(|source| RecoverError::Canonicalize {
            path: path.to_path_buf(),
            source,
        })?;
    let before = inventory(
        &canonical,
        limits.max_evidence_files,
        limits.max_evidence_depth,
        limits.max_evidence_bytes,
    )?;
    let mut report = RecoveryPlanReport {
        schema_version: "1".to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        status: RecoveryPlanStatus::Complete,
        evidence_dir: canonical.display().to_string(),
        observed_facts: ObservedFacts {
            files: before.files.clone(),
            inventory_complete: before.complete,
            evidence_unchanged: before.complete,
            database: None,
            wal: None,
            oracle: None,
        },
        findings: Vec::new(),
        inferences: Vec::new(),
        unknowns: Vec::new(),
        candidate_actions: Vec::new(),
        risks: vec![RecoveryRisk {
            code: "advisory_only".to_owned(),
            message: "No recovery operation is executed or guaranteed; preserve the original evidence and work only on a copy.".to_owned(),
        }],
    };

    if !before.complete {
        report.status = RecoveryPlanStatus::Incomplete;
        report.observed_facts.evidence_unchanged = false;
        if let Some((resource, limit)) = before.limit {
            report
                .findings
                .push(recovery_limit_finding(resource, limit));
        }
        report.unknowns.push(Unknown {
            code: "evidence_inventory_limit".to_owned(),
            structure_path: "evidence_dir".to_owned(),
            reason: "The evidence inventory is partial; analysis and candidate actions were not attempted.".to_owned(),
        });
        return Ok(report);
    }

    let databases = top_level_databases(&canonical, limits.max_evidence_files)?;
    if databases.len() != 1 {
        report.status = RecoveryPlanStatus::Incomplete;
        report.unknowns.push(Unknown {
            code: "database_selection".to_owned(),
            structure_path: "evidence_dir".to_owned(),
            reason: format!(
                "Expected exactly one top-level regular .duckdb file, found {}.",
                databases.len()
            ),
        });
        report.findings.push(recovery_finding(
            "evidence_incomplete",
            "The evidence directory does not identify one unambiguous main database; no recovery action is proposed.",
            vec![Evidence::new("database_candidates", databases.len() as u64)],
        ));
    } else {
        let database_path = &databases[0];
        let verification = verify_path_with_limits(database_path, false, limits.verify)?;
        append_verification(&mut report, &verification);
        report.observed_facts.database = Some(verification);

        let wal_path = wal_path(database_path);
        let wal_present = is_regular_file(&wal_path);
        if wal_present {
            let wal = inspect_wal_path_with_limits(&wal_path, limits.wal)?;
            append_wal(&mut report, &wal);
            if let Some(action) = candidate_wal_truncation(&wal_path, &wal) {
                report.risks.push(RecoveryRisk {
                    code: "possible_post_flush_data_loss".to_owned(),
                    message: "Truncating at a verified Flush discards every later byte, including potentially valid Entries that have no later verified Flush. This is not a lossless recovery claim.".to_owned(),
                });
                report.risks.push(RecoveryRisk {
                    code: "mandatory_reverification".to_owned(),
                    message: "A candidate result can still disagree with DuckDB or contain unsupported structures; rerun main-file, WAL, and optional Oracle checks on the copied result.".to_owned(),
                });
                report.candidate_actions.push(action);
            }
            report.observed_facts.wal = Some(wal);
        } else {
            report.status = RecoveryPlanStatus::Incomplete;
            report.unknowns.push(Unknown {
                code: "wal_missing".to_owned(),
                structure_path: "wal".to_owned(),
                reason: "The exact companion .wal file is absent, so no WAL Flush boundary can be established."
                    .to_owned(),
            });
        }

        if let Some(executable) = duckdb
            && let Some(verification) = report.observed_facts.database.as_ref()
        {
            let oracle = run_oracle(
                executable,
                database_path,
                wal_present.then_some(wal_path.as_path()),
                verification,
            )?;
            match oracle.comparison {
                OracleComparison::Disagreement => {
                    report.status = RecoveryPlanStatus::Incomplete;
                    report.findings.push(recovery_finding(
                        "oracle_disagreement",
                        &oracle.rationale,
                        Vec::new(),
                    ));
                }
                OracleComparison::NotComparable => {
                    report.unknowns.push(Unknown {
                        code: "oracle_not_comparable".to_owned(),
                        structure_path: "oracle".to_owned(),
                        reason: oracle.rationale.clone(),
                    });
                }
                OracleComparison::Agreement => {}
            }
            if let Some(database) = report.observed_facts.database.as_mut() {
                database.oracle = Some(oracle.clone());
            }
            report.observed_facts.oracle = Some(oracle);
        }
    }

    let after = inventory(
        &canonical,
        limits.max_evidence_files,
        limits.max_evidence_depth,
        limits.max_evidence_bytes,
    )?;
    report.observed_facts.inventory_complete = after.complete;
    report.observed_facts.evidence_unchanged = after.complete && before.files == after.files;
    if let Some((resource, limit)) = after.limit {
        report
            .findings
            .push(recovery_limit_finding(resource, limit));
        report.candidate_actions.clear();
    }
    if !report.observed_facts.evidence_unchanged {
        report.status = RecoveryPlanStatus::Incomplete;
        report.candidate_actions.clear();
        report.findings.push(recovery_finding(
            "evidence_changed_during_analysis",
            "The original evidence file set or hashes changed during analysis; external modification cannot be ruled out.",
            Vec::new(),
        ));
    }
    Ok(report)
}

fn candidate_wal_truncation(path: &Path, wal: &WalReport) -> Option<CandidateAction> {
    if wal.status == WalStatus::ResourceLimitReached {
        return None;
    }
    let flush = wal.last_good_flush?;
    let file_size = wal.input.file_size;
    if flush.end_offset >= file_size {
        return None;
    }
    let sha256 = wal.input.sha256.clone()?;
    Some(CandidateAction {
        action: "candidate_wal_truncation".to_owned(),
        target_wal: path.display().to_string(),
        target_offset: flush.end_offset,
        evidence: vec![
            Evidence::new("wal_sha256", sha256),
            Evidence::new("flush_entry_index", flush.entry_index),
            Evidence::new("flush_entry_offset", flush.entry_offset).at_offset(flush.entry_offset),
            Evidence::new("verified_flush_end_offset", flush.end_offset)
                .at_offset(flush.end_offset),
            Evidence::new("wal_file_size", file_size),
            Evidence::new(
                "continuity",
                "complete checksum-valid type-validated prefix ending in an exact WAL_FLUSH",
            ),
        ],
        possible_data_loss: PossibleDataLoss {
            start_offset: flush.end_offset,
            end_offset: file_size,
            byte_length: file_size - flush.end_offset,
            description: "All bytes from the verified Flush end through EOF may be lost. This range can include complete Entries without a later verified Flush; transaction and row counts are unknown.".to_owned(),
        },
        must_execute_on_copy: true,
        must_reverify_result: true,
        manual_steps: vec![
            "Preserve the original evidence and copy the database and WAL to a separate working directory.".to_owned(),
            "If a human accepts the possible data loss, truncate only the copied WAL at target_offset; never modify the original.".to_owned(),
            "Reopen only the copied result and rerun verify, WAL analysis, and the optional official DuckDB Oracle before drawing any conclusion.".to_owned(),
        ],
    })
}

fn append_verification(report: &mut RecoveryPlanReport, verification: &VerifyReport) {
    for finding in &verification.findings {
        report.findings.push(finding.clone());
    }
    for inference in &verification.inferences {
        report.inferences.push(inference.clone());
    }
    for unknown in &verification.unknowns {
        report.unknowns.push(unknown.clone());
    }
    if verification.status != duckdb_report::verify::VerifyStatus::Complete {
        report.status = RecoveryPlanStatus::Incomplete;
    }
}

fn append_wal(report: &mut RecoveryPlanReport, wal: &WalReport) {
    report.findings.extend(wal.findings.clone());
    report.inferences.extend(wal.inferences.clone());
    report.unknowns.extend(wal.unknowns.clone());
    if wal.status != WalStatus::Complete && wal.status != WalStatus::Empty {
        report.status = RecoveryPlanStatus::Incomplete;
    }
}

fn recovery_limit_finding(resource: &str, limit: u64) -> Finding {
    Finding {
        code: "resource_limit_reached".to_owned(),
        category: duckdb_report::FindingCategory::Limit,
        severity: Severity::Warning,
        message: "The evidence inventory resource limit was reached; the inventory and recovery analysis are incomplete.".to_owned(),
        location: Location::new(None, "evidence_dir"),
        evidence: vec![
            Evidence::new("resource", resource),
            Evidence::new("limit", limit),
        ],
        remediation_hint: "Preserve the evidence and retry with an explicitly affordable budget; this is not a corruption verdict.".to_owned(),
        confidence: Confidence::High,
    }
}

fn recovery_finding(code: &str, message: &str, evidence: Vec<Evidence>) -> Finding {
    Finding {
        code: code.to_owned(),
        category: duckdb_report::FindingCategory::for_code(code),
        severity: Severity::Warning,
        message: message.to_owned(),
        location: Location::new(None, "evidence_dir"),
        evidence,
        remediation_hint:
            "Supply a preserved, unambiguous evidence set; do not rename files to force a match."
                .to_owned(),
        confidence: Confidence::High,
    }
}

fn top_level_databases(directory: &Path, max_entries: usize) -> Result<Vec<PathBuf>, RecoverError> {
    let entries = sorted_entries(directory, max_entries)?;
    Ok(entries
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            (file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "duckdb"))
            .then_some(path)
        })
        .collect())
}

fn wal_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_os_string();
    name.push(".wal");
    PathBuf::from(name)
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn inventory(
    directory: &Path,
    max_files: usize,
    max_depth: usize,
    max_bytes: u64,
) -> Result<Inventory, RecoverError> {
    let mut paths = Vec::new();
    match collect_regular_files(directory, &mut paths, max_files, max_depth) {
        Ok(()) => {}
        Err(RecoverError::InventoryLimit { resource, limit }) => {
            return Ok(Inventory {
                files: Vec::new(),
                complete: false,
                limit: Some((resource, limit)),
            });
        }
        Err(error) => return Err(error),
    }
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    let mut total_bytes = 0_u64;
    for path in paths {
        let metadata = fs::metadata(&path).map_err(|source| RecoverError::Inventory {
            path: path.clone(),
            source,
        })?;
        let Some(next_total) = total_bytes.checked_add(metadata.len()) else {
            return Ok(Inventory {
                files,
                complete: false,
                limit: Some(("evidence_bytes", max_bytes)),
            });
        };
        if next_total > max_bytes {
            return Ok(Inventory {
                files,
                complete: false,
                limit: Some(("evidence_bytes", max_bytes)),
            });
        }
        let relative = path.strip_prefix(directory).unwrap_or(&path);
        let (path_text, encoding) = path_text(relative);
        let normalized_path = if std::path::MAIN_SEPARATOR == '\\' {
            path_text.replace('\\', "/")
        } else {
            path_text
        };
        let sha256 = match stream_sha256(&path, max_bytes - total_bytes) {
            Ok(hash) => hash,
            Err(RecoverError::InventoryLimit { resource, limit }) => {
                return Ok(Inventory {
                    files,
                    complete: false,
                    limit: Some((resource, limit)),
                });
            }
            Err(error) => return Err(error),
        };
        files.push(EvidenceFileReport {
            path: normalized_path,
            path_encoding: encoding.to_owned(),
            file_size: metadata.len(),
            sha256,
        });
        total_bytes = next_total;
    }
    Ok(Inventory {
        files,
        complete: true,
        limit: None,
    })
}

fn collect_regular_files(
    directory: &Path,
    output: &mut Vec<PathBuf>,
    max_entries: usize,
    max_depth: usize,
) -> Result<(), RecoverError> {
    let mut pending = vec![(directory.to_path_buf(), 0_usize)];
    let mut seen_entries = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        let entries = sorted_entries(&directory, max_entries.saturating_sub(seen_entries))?;
        seen_entries =
            seen_entries
                .checked_add(entries.len())
                .ok_or(RecoverError::InventoryLimit {
                    resource: "directory_entries",
                    limit: max_entries as u64,
                })?;
        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|source| RecoverError::Inventory {
                    path: path.clone(),
                    source,
                })?;
            if file_type.is_dir() {
                if depth >= max_depth {
                    return Err(RecoverError::InventoryLimit {
                        resource: "directory_depth",
                        limit: max_depth as u64,
                    });
                }
                pending.push((path, depth + 1));
            } else if file_type.is_file() {
                output.push(path);
            }
        }
    }
    Ok(())
}

fn sorted_entries(directory: &Path, max_entries: usize) -> Result<Vec<fs::DirEntry>, RecoverError> {
    let reader = fs::read_dir(directory).map_err(|source| RecoverError::Inventory {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    for entry in reader {
        if entries.len() >= max_entries {
            return Err(RecoverError::InventoryLimit {
                resource: "directory_entries",
                limit: max_entries as u64,
            });
        }
        entries.push(entry.map_err(|source| RecoverError::Inventory {
            path: directory.to_path_buf(),
            source,
        })?);
    }
    entries.sort_by_key(|entry| entry.path());
    Ok(entries)
}

fn stream_sha256(path: &Path, max_bytes: u64) -> Result<String, RecoverError> {
    let mut file = File::open(path).map_err(|source| RecoverError::Inventory {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    let mut hashed = 0_u64;
    loop {
        let remaining = max_bytes.saturating_sub(hashed);
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let result = if wanted == 0 {
            file.read(&mut buffer[..1])
        } else {
            file.read(&mut buffer[..wanted])
        };
        match result {
            Ok(0) => break,
            Ok(count) if hashed.saturating_add(count as u64) <= max_bytes => {
                hasher.update(&buffer[..count]);
                hashed += count as u64;
            }
            Ok(_) => {
                return Err(RecoverError::InventoryLimit {
                    resource: "evidence_bytes",
                    limit: max_bytes,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(RecoverError::Inventory {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}
