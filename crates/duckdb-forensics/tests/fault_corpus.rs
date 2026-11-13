#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use duckdb_forensics::{
    InspectionLimits, VerifyLimits, WalInspectionLimits, inspect_wal_path_with_limits,
    verify_path_with_limits,
};
use jsonschema::Resource;
use serde_json::Value;

const SCHEMAS: &[&str] = &[
    include_str!("../../../schemas/report-common.schema.json"),
    include_str!("../../../schemas/inspection-report.schema.json"),
    include_str!("../../../schemas/wal-report.schema.json"),
    include_str!("../../../schemas/verify-report.schema.json"),
    include_str!("../../../schemas/recovery-plan.schema.json"),
];

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_duckdb-forensics")
}

fn validate(command: &str, value: &Value) {
    let schema_name = match command {
        "inspect" => "inspection-report",
        "wal" => "wal-report",
        "verify" => "verify-report",
        _ => panic!("unknown corpus command"),
    };
    let schema_text = SCHEMAS
        .iter()
        .map(|contents| serde_json::from_str::<Value>(contents).expect("schema JSON"))
        .find(|schema| {
            schema["$id"]
                .as_str()
                .is_some_and(|id| id.contains(schema_name))
        })
        .expect("target schema");
    let mut options = jsonschema::options();
    for contents in SCHEMAS {
        let schema: Value = serde_json::from_str(contents).expect("schema JSON");
        let id = schema["$id"].as_str().expect("schema ID").to_owned();
        options = options.with_resource(
            id,
            Resource::from_contents(schema).expect("schema resource"),
        );
    }
    let validator = options.build(&schema_text).expect("compile schema");
    let errors = validator.iter_errors(value).collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
}

fn run_cli(command: &str, path: &Path) -> Value {
    let output = Command::new(binary())
        .arg(command)
        .arg(path)
        .args(["--format", "json"])
        .output()
        .expect("run corpus CLI");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON")
}

fn run_case(root: &Path, generated: &Path, case: &Value) {
    let command = case["command"].as_str().expect("command");
    let path = generated.join(case["file"].as_str().expect("file"));
    let before = fs::read(&path).expect("input before");
    let limits = case.get("limits").cloned();
    let report = match (command, limits) {
        ("wal", Some(limits)) => {
            let max_report_entries = limits["max_report_entries"].as_u64().unwrap_or(10_000);
            serde_json::to_value(
                inspect_wal_path_with_limits(
                    &path,
                    WalInspectionLimits {
                        max_report_entries: max_report_entries as usize,
                        ..WalInspectionLimits::default()
                    },
                )
                .expect("limited WAL inspection"),
            )
            .expect("WAL JSON")
        }
        ("verify", Some(limits)) => {
            let max_meta_nodes = limits["max_meta_nodes"].as_u64().unwrap_or(1_000_000);
            serde_json::to_value(
                verify_path_with_limits(
                    &path,
                    false,
                    VerifyLimits {
                        inspection: InspectionLimits::default(),
                        max_meta_nodes,
                        max_block_issues: 1_000,
                    },
                )
                .expect("limited verification"),
            )
            .expect("verify JSON")
        }
        _ => run_cli(command, &path),
    };
    assert_eq!(fs::read(&path).expect("input after"), before);
    validate(command, &report);

    let expected = &case["expected"];
    if let Some(status) = expected["status"].as_str() {
        assert_eq!(report["status"], status, "{}", case["name"]);
    }
    if let Some(offset) = expected["first_unparsed_offset"].as_u64() {
        assert_eq!(report["first_unparsed_offset"], offset);
    }
    for code in expected["codes"].as_array().into_iter().flatten() {
        let code = code.as_str().expect("expected code");
        assert!(
            report["findings"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|finding| finding["code"] == code),
            "missing {code} in {}",
            case["name"]
        );
    }
    for (code, category) in expected["categories"].as_object().into_iter().flatten() {
        assert!(
            report["findings"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|finding| {
                    finding["code"].as_str() == Some(code.as_str())
                        && finding["category"].as_str() == category.as_str()
                }),
            "wrong category for {code} in {}",
            case["name"]
        );
    }
    for (name, expected_value) in expected["observations"].as_object().into_iter().flatten() {
        assert!(
            report["observations"]
                .as_array()
                .into_iter()
                .flatten()
                .any(
                    |observation| observation["name"].as_str() == Some(name.as_str())
                        && observation["value"] == *expected_value
                ),
            "wrong observation {name}"
        );
    }
    for field in ["total_entries", "reported_entries", "entries_omitted"] {
        if let Some(expected_value) = expected.get(field) {
            assert_eq!(&report["summary"][field], expected_value);
        }
    }
    let _ = root;
}

#[test]
fn public_fault_corpus_reproduces_expected_diagnostics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().expect("tempdir");
    let output = Command::new("python3")
        .arg(root.join("scripts/generate_fault_corpus.py"))
        .arg("--output")
        .arg(directory.path())
        .output()
        .expect("run corpus generator");
    assert!(
        output.status.success(),
        "generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value = serde_json::from_slice(
        &fs::read(directory.path().join("manifest.json")).expect("generated manifest"),
    )
    .expect("manifest JSON");
    let cases = manifest["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 15);
    for case in cases {
        run_case(&root, directory.path(), case);
    }
}
