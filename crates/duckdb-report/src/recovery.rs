use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::oracle::OracleReport;
use crate::verify::VerifyReport;
use crate::wal::WalReport;
use crate::{Evidence, Finding, Inference, Unknown};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPlanStatus {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceFileReport {
    pub path: String,
    pub file_size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedFacts {
    pub files: Vec<EvidenceFileReport>,
    pub evidence_unchanged: bool,
    pub database: Option<VerifyReport>,
    pub wal: Option<WalReport>,
    pub oracle: Option<OracleReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PossibleDataLoss {
    pub start_offset: u64,
    pub end_offset: u64,
    pub byte_length: u64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateAction {
    pub action: String,
    pub target_wal: String,
    pub target_offset: u64,
    pub evidence: Vec<Evidence>,
    pub possible_data_loss: PossibleDataLoss,
    pub must_execute_on_copy: bool,
    pub must_reverify_result: bool,
    pub manual_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRisk {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPlanReport {
    pub schema_version: String,
    pub tool_version: String,
    pub status: RecoveryPlanStatus,
    pub evidence_dir: String,
    pub observed_facts: ObservedFacts,
    pub findings: Vec<Finding>,
    pub inferences: Vec<Inference>,
    pub unknowns: Vec<Unknown>,
    pub candidate_actions: Vec<CandidateAction>,
    pub risks: Vec<RecoveryRisk>,
}

pub fn render_recovery_plan_text(report: &RecoveryPlanReport) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "DuckDB Forensics Recovery Plan (advisory only; nothing executed)"
    );
    let _ = writeln!(output, "Schema version: {}", report.schema_version);
    let _ = writeln!(output, "Status: {:?}", report.status);
    let _ = writeln!(output, "Evidence directory: {}", report.evidence_dir);

    let _ = writeln!(output, "\nObserved Facts");
    let _ = writeln!(output, "  Files: {}", report.observed_facts.files.len());
    for file in &report.observed_facts.files {
        let _ = writeln!(
            output,
            "  {}: size={}, sha256={}",
            file.path, file.file_size, file.sha256
        );
    }
    let _ = writeln!(
        output,
        "  Evidence unchanged during analysis: {}",
        report.observed_facts.evidence_unchanged
    );
    if let Some(database) = &report.observed_facts.database {
        let _ = writeln!(
            output,
            "  Main-file verification: {:?}, selected_header={:?}",
            database.status,
            database.selected_header.as_ref().map(|header| header.index)
        );
    } else {
        let _ = writeln!(output, "  Main-file verification: unavailable");
    }
    if let Some(wal) = &report.observed_facts.wal {
        let _ = writeln!(
            output,
            "  WAL: status={:?}, entries={}, last_good_flush_end={:?}",
            wal.status,
            wal.summary.total_entries,
            wal.last_good_flush.map(|flush| flush.end_offset)
        );
    } else {
        let _ = writeln!(output, "  WAL: unavailable");
    }
    if let Some(oracle) = &report.observed_facts.oracle {
        let _ = writeln!(
            output,
            "  Oracle: {:?}: {}",
            oracle.comparison, oracle.rationale
        );
    }

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

    let _ = writeln!(output, "\nCandidate Actions");
    if report.candidate_actions.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for action in &report.candidate_actions {
        let _ = writeln!(
            output,
            "  {}: target={}, offset={}",
            action.action, action.target_wal, action.target_offset
        );
        let _ = writeln!(
            output,
            "    possible loss=[{}, {}), {} bytes: {}",
            action.possible_data_loss.start_offset,
            action.possible_data_loss.end_offset,
            action.possible_data_loss.byte_length,
            action.possible_data_loss.description
        );
        let _ = writeln!(
            output,
            "    must_execute_on_copy={}, must_reverify_result={}",
            action.must_execute_on_copy, action.must_reverify_result
        );
        for step in &action.manual_steps {
            let _ = writeln!(output, "    step: {step}");
        }
    }

    let _ = writeln!(output, "\nRisks");
    if report.risks.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for risk in &report.risks {
        let _ = writeln!(output, "  {}: {}", risk.code, risk.message);
    }
    output
}
