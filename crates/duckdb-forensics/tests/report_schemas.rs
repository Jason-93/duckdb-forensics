#![forbid(unsafe_code)]

use std::fs;

use duckdb_forensics::{
    RecoveryLimits, inspect_path, inspect_wal_path, recover_plan_path_with_limits, verify_path,
};
use jsonschema::{Resource, Validator};
use serde_json::Value;

const NORMAL_DB: &[u8] = include_bytes!("fixtures/normal.duckdb");
const NORMAL_WAL: &[u8] = include_bytes!("fixtures/normal.wal");
const SCHEMAS: &[(&str, &str)] = &[
    (
        "report-common",
        include_str!("../../../schemas/report-common.schema.json"),
    ),
    (
        "inspection-report",
        include_str!("../../../schemas/inspection-report.schema.json"),
    ),
    (
        "wal-report",
        include_str!("../../../schemas/wal-report.schema.json"),
    ),
    (
        "verify-report",
        include_str!("../../../schemas/verify-report.schema.json"),
    ),
    (
        "recovery-plan",
        include_str!("../../../schemas/recovery-plan.schema.json"),
    ),
];

fn validator(name: &str) -> Validator {
    let mut options = jsonschema::options();
    for (_, contents) in SCHEMAS {
        let value: Value = serde_json::from_str(contents).expect("schema JSON");
        let id = value["$id"].as_str().expect("schema ID").to_owned();
        options =
            options.with_resource(id, Resource::from_contents(value).expect("schema resource"));
    }
    let (_, contents) = SCHEMAS
        .iter()
        .find(|(resource_name, _)| *resource_name == name)
        .expect("target schema");
    let schema: Value = serde_json::from_str(contents).expect("target schema JSON");
    options.build(&schema).expect("compile schema")
}

fn assert_valid(name: &str, value: &Value) {
    let validator = validator(name);
    let errors = validator.iter_errors(value).collect::<Vec<_>>();
    assert!(errors.is_empty(), "{name} validation failed: {errors:#?}");
}

#[test]
fn all_normal_reports_validate_against_their_schema() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("evidence.duckdb");
    let wal = directory.path().join("evidence.duckdb.wal");
    fs::write(&database, NORMAL_DB).expect("database");
    fs::write(&wal, NORMAL_WAL).expect("WAL");

    let inspection = inspect_path(&database, false).expect("inspection");
    let inspection_json = serde_json::to_value(&inspection).expect("inspection JSON");
    assert_valid("inspection-report", &inspection_json);
    assert_eq!(
        serde_json::to_string(&inspection).expect("first inspection"),
        serde_json::to_string(&inspect_path(&database, false).expect("second inspection"))
            .expect("second inspection JSON")
    );

    let wal_report = inspect_wal_path(&wal).expect("WAL inspection");
    assert_valid(
        "wal-report",
        &serde_json::to_value(wal_report).expect("WAL JSON"),
    );

    let verification = verify_path(&database, true).expect("verification");
    assert_valid(
        "verify-report",
        &serde_json::to_value(verification).expect("verify JSON"),
    );

    let plan = recover_plan_path_with_limits(directory.path(), RecoveryLimits::default())
        .expect("recovery plan");
    assert_valid(
        "recovery-plan",
        &serde_json::to_value(plan).expect("recovery JSON"),
    );
}

#[test]
fn corrupted_and_limited_reports_also_validate() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("huge.wal");
    let mut bytes = vec![100, 0, 98, 101, 0, 2, 255, 255];
    bytes.extend(u64::MAX.to_le_bytes());
    bytes.extend(0_u64.to_le_bytes());
    fs::write(&path, bytes).expect("WAL fixture");
    let wal = inspect_wal_path(&path).expect("WAL inspection");
    assert_eq!(wal.entries[0].declared_length, Some(u64::MAX));
    let value = serde_json::to_value(&wal).expect("WAL JSON");
    assert_valid("wal-report", &value);

    let root = directory.path().join("evidence");
    fs::create_dir(&root).expect("evidence dir");
    fs::write(root.join("a"), [1]).expect("first file");
    fs::write(root.join("b"), [2]).expect("second file");
    let plan = recover_plan_path_with_limits(
        &root,
        RecoveryLimits {
            max_evidence_files: 1,
            ..RecoveryLimits::default()
        },
    )
    .expect("limited plan");
    assert_valid(
        "recovery-plan",
        &serde_json::to_value(plan).expect("limited plan JSON"),
    );
}

#[test]
fn schema_rejects_missing_core_required_fields() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("normal.wal");
    fs::write(&path, NORMAL_WAL).expect("WAL");
    let report = inspect_wal_path(&path).expect("WAL inspection");
    let mut value = serde_json::to_value(report).expect("WAL JSON");
    value
        .as_object_mut()
        .expect("report object")
        .remove("status");
    assert!(!validator("wal-report").is_valid(&value));
}

#[test]
fn version_one_additive_fields_accept_legacy_wal_json() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("normal.wal");
    fs::write(&path, NORMAL_WAL).expect("WAL");
    let report = inspect_wal_path(&path).expect("WAL inspection");
    let mut value = serde_json::to_value(report).expect("WAL JSON");
    value["input"]
        .as_object_mut()
        .expect("input object")
        .remove("path_encoding");
    for field in ["reported_entries", "entries_omitted", "not_decoded_entries"] {
        value["summary"]
            .as_object_mut()
            .expect("summary object")
            .remove(field);
    }
    for field in [
        "confirmed_flushes_omitted",
        "findings_omitted",
        "unknowns_omitted",
        "report_limits",
    ] {
        value.as_object_mut().expect("report object").remove(field);
    }
    assert_valid("wal-report", &value);
    let decoded: duckdb_report::wal::WalReport =
        serde_json::from_value(value).expect("legacy WAL report");
    assert_eq!(
        decoded.summary.reported_entries,
        decoded.summary.total_entries
    );
    assert_eq!(decoded.summary.entries_omitted, 0);
    assert!(decoded.report_limits.is_empty());
}
