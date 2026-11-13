#![forbid(unsafe_code)]

pub mod oracle;
pub mod recovery;
pub mod verify;
pub mod wal;

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputInfo {
    pub path: Option<String>,
    pub file_size: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub name: String,
    pub structure_path: String,
    pub file_offset: Option<u64>,
    pub value: Value,
}

impl Observation {
    pub fn new(
        name: impl Into<String>,
        structure_path: impl Into<String>,
        file_offset: Option<u64>,
        value: impl Into<Value>,
    ) -> Self {
        Self {
            name: name.into(),
            structure_path: structure_path.into(),
            file_offset,
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub name: String,
    pub value: Value,
    pub file_offset: Option<u64>,
    pub structure_path: Option<String>,
}

impl Evidence {
    pub fn new(name: impl Into<String>, value: impl Into<Value>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            file_offset: None,
            structure_path: None,
        }
    }

    pub fn at_offset(mut self, file_offset: u64) -> Self {
        self.file_offset = Some(file_offset);
        self
    }

    pub fn in_structure(mut self, structure_path: impl Into<String>) -> Self {
        self.structure_path = Some(structure_path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub file_offset: Option<u64>,
    pub structure_path: Option<String>,
}

impl Location {
    pub fn new(file_offset: Option<u64>, structure_path: impl Into<String>) -> Self {
        Self {
            file_offset,
            structure_path: Some(structure_path.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    pub evidence: Vec<Evidence>,
    pub remediation_hint: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inference {
    pub code: String,
    pub message: String,
    pub subject: Option<String>,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub code: String,
    pub message: String,
    pub structure_path: Option<String>,
}

impl Check {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            structure_path: None,
        }
    }

    pub fn in_structure(mut self, structure_path: impl Into<String>) -> Self {
        self.structure_path = Some(structure_path.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Unsupported,
    PrerequisiteFailed,
    Unavailable,
    LimitReached,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkippedCheck {
    pub code: String,
    pub message: String,
    pub reason: SkipReason,
    pub structure_path: Option<String>,
}

impl SkippedCheck {
    pub fn new(code: impl Into<String>, message: impl Into<String>, reason: SkipReason) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            reason,
            structure_path: None,
        }
    }

    pub fn in_structure(mut self, structure_path: impl Into<String>) -> Self {
        self.structure_path = Some(structure_path.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub checked: Vec<String>,
    pub not_checked: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unknown {
    pub code: String,
    pub structure_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InspectionReport {
    pub schema_version: String,
    pub tool_version: String,
    pub input: InputInfo,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub inferences: Vec<Inference>,
    pub checks_passed: Vec<Check>,
    pub checks_failed: Vec<Check>,
    pub checks_skipped: Vec<SkippedCheck>,
    pub coverage: Coverage,
    pub unknowns: Vec<Unknown>,
}

impl InspectionReport {
    pub fn new(input: InputInfo) -> Self {
        Self {
            schema_version: "1".to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            input,
            observations: Vec::new(),
            findings: Vec::new(),
            inferences: Vec::new(),
            checks_passed: Vec::new(),
            checks_failed: Vec::new(),
            checks_skipped: Vec::new(),
            coverage: Coverage::default(),
            unknowns: Vec::new(),
        }
    }

    pub fn observation(&self, structure_path: &str, name: &str) -> Option<&Observation> {
        self.observations.iter().find(|observation| {
            observation.structure_path == structure_path && observation.name == name
        })
    }
}

pub fn render_text(report: &InspectionReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "DuckDB Forensics Inspection Report");
    let _ = writeln!(output, "Schema version: {}", report.schema_version);
    let _ = writeln!(output, "Tool version: {}", report.tool_version);
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

    let _ = writeln!(output, "\nMain Header");
    write_structure_observations(&mut output, report, "main_header");

    for (index, path) in ["database_header[0]", "database_header[1]"]
        .iter()
        .enumerate()
    {
        let _ = writeln!(output, "\nDatabase Header {}", index + 1);
        write_structure_observations(&mut output, report, path);
    }

    let _ = writeln!(output, "\nHeader Selection and Inferences");
    if report.inferences.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for inference in &report.inferences {
        let subject = inference.subject.as_deref().unwrap_or("none");
        let _ = writeln!(
            output,
            "  {}: {} (subject: {}, confidence: {:?})",
            inference.code, inference.message, subject, inference.confidence
        );
    }

    let _ = writeln!(output, "\nGeometry");
    write_structure_observations(&mut output, report, "geometry");

    let _ = writeln!(output, "\nOther Observations");
    for observation in &report.observations {
        if matches!(
            observation.structure_path.as_str(),
            "main_header" | "database_header[0]" | "database_header[1]" | "geometry"
        ) {
            continue;
        }
        write_observation(&mut output, observation);
    }

    write_checks(&mut output, "Checks Passed", &report.checks_passed);
    write_checks(&mut output, "Checks Failed", &report.checks_failed);

    let _ = writeln!(output, "\nChecks Skipped");
    if report.checks_skipped.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for check in &report.checks_skipped {
        let _ = writeln!(
            output,
            "  {}: {} (reason: {:?}, structure: {})",
            check.code,
            check.message,
            check.reason,
            check.structure_path.as_deref().unwrap_or("none")
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
        let _ = writeln!(
            output,
            "    location: offset={:?}, structure={}",
            finding.location.file_offset,
            finding.location.structure_path.as_deref().unwrap_or("none")
        );
        let _ = writeln!(
            output,
            "    confidence: {:?}; remediation: {}",
            finding.confidence, finding.remediation_hint
        );
        for evidence in &finding.evidence {
            let _ = writeln!(
                output,
                "    evidence: {} = {}",
                evidence.name, evidence.value
            );
        }
    }

    let _ = writeln!(output, "\nCoverage");
    let _ = writeln!(output, "  Checked: {}", report.coverage.checked.join(", "));
    let _ = writeln!(
        output,
        "  Not checked: {}",
        report.coverage.not_checked.join(", ")
    );

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

fn write_structure_observations(output: &mut String, report: &InspectionReport, path: &str) {
    let mut found = false;
    for observation in &report.observations {
        if observation.structure_path == path {
            write_observation(output, observation);
            found = true;
        }
    }
    if !found {
        let _ = writeln!(output, "  unavailable");
    }
}

fn write_observation(output: &mut String, observation: &Observation) {
    let offset = observation
        .file_offset
        .map_or_else(|| "none".to_owned(), |offset| offset.to_string());
    let _ = writeln!(
        output,
        "  {} = {} (offset: {})",
        observation.name, observation.value, offset
    );
}

fn write_checks(output: &mut String, title: &str, checks: &[Check]) {
    let _ = writeln!(output, "\n{title}");
    if checks.is_empty() {
        let _ = writeln!(output, "  none");
    }
    for check in checks {
        let _ = writeln!(
            output,
            "  {}: {} (structure: {})",
            check.code,
            check.message,
            check.structure_path.as_deref().unwrap_or("none")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_round_trip_preserves_diagnostic_categories() {
        let mut report = InspectionReport::new(InputInfo {
            path: None,
            file_size: 42,
            sha256: Some("ab".repeat(32)),
        });
        report.observations.push(Observation::new(
            "file_size",
            "input",
            None,
            Value::from(42),
        ));
        report.findings.push(Finding {
            code: "example".to_owned(),
            severity: Severity::Warning,
            message: "example finding".to_owned(),
            location: Location::new(Some(8), "main_header"),
            evidence: vec![Evidence::new("stored", 1)],
            remediation_hint: "inspect a copy".to_owned(),
            confidence: Confidence::High,
        });
        report.inferences.push(Inference {
            code: "possible_stale_header".to_owned(),
            message: "example inference".to_owned(),
            subject: Some("database_header[0]".to_owned()),
            evidence: Vec::new(),
            confidence: Confidence::Medium,
        });

        let encoded = match serde_json::to_string(&report) {
            Ok(encoded) => encoded,
            Err(error) => panic!("report serialization failed: {error}"),
        };
        let decoded: InspectionReport = match serde_json::from_str(&encoded) {
            Ok(decoded) => decoded,
            Err(error) => panic!("report deserialization failed: {error}"),
        };
        assert_eq!(decoded, report);
        assert_eq!(decoded.observations.len(), 1);
        assert_eq!(decoded.findings.len(), 1);
        assert_eq!(decoded.inferences.len(), 1);
    }
}
