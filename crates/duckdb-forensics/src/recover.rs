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
use crate::verify::{VerifyError, VerifyLimits, verify_path_with_limits};
use crate::wal::{WalInspectError, WalInspectionLimits, inspect_wal_path_with_limits};

const HASH_BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_EVIDENCE_FILES: usize = 100_000;

#[derive(Debug, Clone, Copy)]
pub struct RecoveryLimits {
    pub verify: VerifyLimits,
    pub wal: WalInspectionLimits,
    pub max_evidence_files: usize,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            verify: VerifyLimits::default(),
            wal: WalInspectionLimits::default(),
            max_evidence_files: DEFAULT_MAX_EVIDENCE_FILES,
        }
    }
}

#[derive(Debug)]
pub enum RecoverError {
    Canonicalize { path: PathBuf, source: io::Error },
    Inventory { path: PathBuf, source: io::Error },
    TooManyFiles { limit: usize },
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
            Self::TooManyFiles { limit } => write!(
                formatter,
                "evidence directory exceeds the {limit} regular-file inventory limit"
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
            Self::TooManyFiles { .. } => None,
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
    let before = inventory(&canonical, limits.max_evidence_files)?;
    let databases = top_level_databases(&canonical)?;
    let mut report = RecoveryPlanReport {
        schema_version: "1".to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        status: RecoveryPlanStatus::Complete,
        evidence_dir: canonical.display().to_string(),
        observed_facts: ObservedFacts {
            files: before.clone(),
            evidence_unchanged: true,
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

    let after = inventory(&canonical, limits.max_evidence_files)?;
    report.observed_facts.evidence_unchanged = before == after;
    if !report.observed_facts.evidence_unchanged {
        report.status = RecoveryPlanStatus::Incomplete;
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

fn recovery_finding(code: &str, message: &str, evidence: Vec<Evidence>) -> Finding {
    Finding {
        code: code.to_owned(),
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

fn top_level_databases(directory: &Path) -> Result<Vec<PathBuf>, RecoverError> {
    let entries = sorted_entries(directory)?;
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

fn inventory(directory: &Path, max_files: usize) -> Result<Vec<EvidenceFileReport>, RecoverError> {
    let mut paths = Vec::new();
    collect_regular_files(directory, &mut paths)?;
    if paths.len() > max_files {
        return Err(RecoverError::TooManyFiles { limit: max_files });
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative = path.strip_prefix(directory).unwrap_or(&path);
            let metadata = fs::metadata(&path).map_err(|source| RecoverError::Inventory {
                path: path.clone(),
                source,
            })?;
            Ok(EvidenceFileReport {
                path: relative.to_string_lossy().replace('\\', "/"),
                file_size: metadata.len(),
                sha256: stream_sha256(&path)?,
            })
        })
        .collect()
}

fn collect_regular_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), RecoverError> {
    for entry in sorted_entries(directory)? {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| RecoverError::Inventory {
                path: path.clone(),
                source,
            })?;
        if file_type.is_dir() {
            collect_regular_files(&path, output)?;
        } else if file_type.is_file() {
            output.push(path);
        }
    }
    Ok(())
}

fn sorted_entries(directory: &Path) -> Result<Vec<fs::DirEntry>, RecoverError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| RecoverError::Inventory {
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RecoverError::Inventory {
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.path());
    Ok(entries)
}

fn stream_sha256(path: &Path) -> Result<String, RecoverError> {
    let mut file = File::open(path).map_err(|source| RecoverError::Inventory {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
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
