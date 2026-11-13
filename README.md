# duckdb-forensics

**English** | [简体中文](README.zh-CN.md)

A read-only, offline crash-site inspector for DuckDB database files. Phase 1 examines the DuckDB v2.0.0 main file, its three fixed header pages, and basic block geometry. It produces offset-backed observations, findings, and explicitly separated inferences in text or JSON.

The parser is implemented in Rust without `duckdb-rs`, DuckDB C++, or `unsafe` code. It never opens the evidence through DuckDB.

## Supported scope

- Official DuckDB **v2.0.0** native single-file `.duckdb` databases.
- Storage compatibility **69** and the v2.0.0 Main Header version marker **999**.
- Confirmed little-endian, unencrypted files with the default eight-byte header layout.
- Main Header magic, raw fields, and checksum.
- Raw fields and independent checksums for both Database Headers.
- Iteration-based likely-active-header selection with damage-aware diagnostics.
- Block allocation size/count validation and checked file-length geometry.
- Streaming file SHA-256 and normalized or hidden input path.

Encrypted files are identified from the Main Header. Their encrypted Database Headers and blocks are marked `unsupported`, not tested as plaintext checksums.

## Non-goals

This phase does not support DuckDB v1.x, encrypted-content decoding, big-endian files, alternate block-header sizes, DuckLake, Parquet, MotherDuck, Catalog deserialization, free-list/meta-block payload decoding, Row Groups, column compression, business-data output, row recovery, WAL parsing, recovery plans, automatic repair, checkpointing, truncation, or replacement database generation.

A passing report is not a claim that the database is healthy or that DuckDB can open it. See [FORMAT_NOTES.md](FORMAT_NOTES.md) for source-backed layout details and unchecked areas.

## Build

A stable Rust toolchain with Cargo is required.

```sh
cargo build --workspace
```

The CLI binary is `target/debug/duckdb-forensics`.

## Inspect

```sh
duckdb-forensics inspect <DB_PATH> [--format text|json] [--output PATH] [--hide-path]
```

Examples:

```sh
# Human-readable report on stdout
duckdb-forensics inspect evidence.duckdb

# JSON report on stdout without the normalized input path
duckdb-forensics inspect evidence.duckdb --format json --hide-path

# Write a text report to a separate file
duckdb-forensics inspect evidence.duckdb --output inspection.txt
```

The inspector returns exit code 0 when an inspection completes, including reports containing corruption or unsupported-feature findings. Usage, input I/O, serialization, and output-safety failures return exit code 2.

## Report model

JSON uses schema version `1` and contains:

- `input`: optional normalized path, file size, and streaming SHA-256 (`null` when unavailable);
- `observations`: direct values with `name`, `structure_path`, and optional `file_offset`;
- `findings`: stable code, severity, message, location, evidence, remediation hint, and confidence;
- `inferences`: separate confidence-rated interpretations such as likely active header, possible stale header, or possible torn write;
- `checks_passed`, `checks_failed`, and `checks_skipped`;
- `coverage`: checked and explicitly unchecked areas;
- `unknowns`: facts that cannot be established under the current evidence or support scope.

`--hide-path` sets `input.path` to `null`; it does not suppress file size, hashes, offsets, or diagnostics. Reports contain header metadata only, not table rows.

Stable finding codes include `invalid_magic`, `checksum_mismatch`, `truncated_file`, `unsupported_storage_version`, `unsupported_encryption`, `invalid_block_alloc_size`, `invalid_block_count`, `invalid_metadata_pointer`, `invalid_block_reference`, `geometry_overflow`, `no_valid_database_header`, and `limit_reached`.

## Read-only and output safety

- `DB_PATH` is opened read-only. The inspector does not invoke DuckDB, create a WAL, or trigger a checkpoint.
- The only optional write is the report supplied through `--output`.
- An output path that resolves to the input is rejected. Symlink resolution and Unix device/inode checks also protect existing aliases and hard links. The opened output identity is checked again before truncation.
- Remediation text is advisory only and is never executed.
- Corrupt, empty, random, truncated, unsupported, and overflow-inducing inputs produce structured diagnostics rather than parser panics.

Always preserve the original evidence and perform any separate database operation on a copy.

## Resource limits

The inspector reads at most three fixed 4096-byte header pages and streams SHA-256 through a 1 MiB buffer. It does not load the whole database or allocate memory based on file-provided lengths.

The default file-size budget is 1 TiB. A larger input stops before hashing and header parsing with `limit_reached`; SHA-256 and unchecked fields remain unknown. Resource exhaustion is not reported as corruption.

## Reproducible fixture generation

The only committed binary fixture is a small official v2.0.0 database (536,576 bytes) with a two-row test table. Corruption variants are generated in temporary directories during tests and are not committed.

Regenerate it with:

```sh
python3 scripts/generate_fixture.py
```

The generator downloads the platform's official v2.0.0 CLI release archive, verifies its pinned SHA-256, verifies `SELECT version()`, and writes `normal.duckdb` plus an independent provenance/expectations manifest. An existing official binary can be used instead:

```sh
python3 scripts/generate_fixture.py --duckdb /path/to/duckdb-v2.0.0
```

DuckDB generates a random database identifier, so a regenerated database is structurally equivalent but not byte-for-byte identical. The manifest records each generated fixture's own hash and raw header values. Tests never require network access or DuckDB.

## Test and lint

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Tests cover the official normal fixture, empty/non-DuckDB/random files, Main Header bit flips, either/both Database Headers corrupted, truncation, invalid block allocation size, huge block counts, unsupported encryption/version behavior, stable JSON deserialization, text output, hidden paths, output files, and direct/hard-link overwrite attempts. CLI helpers verify that input SHA-256 is unchanged and that no WAL appears.

## Workspace

- `crates/duckdb-format`: fixed-page reads, scalar parsing, DuckDB checksum, checked geometry, and format errors.
- `crates/duckdb-report`: observation/finding/inference model, JSON schema types, and text rendering.
- `crates/duckdb-forensics`: inspection pipeline, CLI, streaming SHA-256, and safe report output.
