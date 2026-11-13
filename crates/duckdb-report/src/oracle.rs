use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleComparison {
    Agreement,
    Disagreement,
    NotComparable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleRunReport {
    pub purpose: String,
    pub argv: Vec<String>,
    pub working_directory: String,
    pub timeout_ms: u64,
    pub output_limit_bytes: usize,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub killed: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleReport {
    pub executable: String,
    pub version: Option<String>,
    pub runs: Vec<OracleRunReport>,
    pub comparison: OracleComparison,
    pub rationale: String,
    pub copy_hashes_match: Option<bool>,
}
