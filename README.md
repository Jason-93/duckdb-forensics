# duckdb-forensics

**English** | [简体中文](README.zh-CN.md)

A read-only, offline crash-site inspector for DuckDB database and WAL files. Phase 1 examines the DuckDB v2.0.0 main file, its three fixed header pages, and basic block geometry. Phase 2 examines unencrypted WAL v2 frames without replay. Reports provide offset-backed observations, findings, explicitly separated inferences, and coverage in text or JSON.

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

For `wal`, the supported scope is narrower:

- Official DuckDB **v2.0.0** unencrypted **WAL version 2**, little-endian framing.
- The unframed BinarySerializer version object and framed `length + checksum + Payload` Entries.
- Streaming Entry checksums, declared/actual lengths, structural error offsets, and zero/nonzero tail evidence.
- Source-defined WALType envelopes, exact empty WAL_FLUSH objects, and reliably decoded Checkpoint Markers.
- Confirmed Flush positions and a separate continuously verified `last_good_flush`.
- No business Payload output: ordinary Insert/Update/Catalog Payloads remain `not_decoded`.

WAL v1, encrypted WAL v3, and unknown WAL versions return `unsupported_wal_version`; they are never forced through the v2 parser.

Encrypted database files are identified from the Main Header. Their encrypted Database Headers and blocks are marked `unsupported`, not tested as plaintext checksums.

## Non-goals

These phases do not support DuckDB v1.x main files, WAL v1/v3 framing, encrypted-content decoding, big-endian files, alternate block-header sizes, DuckLake, Parquet, MotherDuck, Catalog deserialization, free-list/meta-block payload decoding, Row Groups, column compression, business-data output, row recovery, WAL replay, recovery plans, automatic repair, checkpointing, truncation, or replacement database generation.

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

## Inspect a WAL without replay

```sh
duckdb-forensics wal <WAL_PATH> [--format text|json] [--output PATH]
```

Examples:

```sh
duckdb-forensics wal evidence.duckdb.wal
duckdb-forensics wal evidence.duckdb.wal --format json --output wal-report.json
```

This command reads only the supplied WAL. It does not open the original database through DuckDB, replay Entries, write to the WAL, or truncate it. The WAL JSON contract is documented in [`schemas/wal-report.schema.json`](schemas/wal-report.schema.json).

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

WAL JSON independently uses schema version `1` and reports version/encryption status, version-header length, file size and SHA-256, per-Entry offsets and lengths, checksum status and type, summary counts, the first unparsed and checksum-failed offsets, scan coverage, unknowns, tail zero evidence, confirmed Flushes, `last_good_flush`, data after that boundary, and an optional Checkpoint Marker. `actual_length` means available Payload bytes capped at `declared_length`.

`last_good_flush` requires a continuously complete, checksum-valid, type-validated prefix ending in an exact WAL_FLUSH. It is not necessarily the last commit acknowledged by the application and is not a safe recovery point. `confirmed_flushes` can additionally contain later physically valid Flush objects after an earlier error; they do not restore continuity. Checksum mismatch alone does not prove torn write, and a zero-filled tail is only evidence.

Stable main-file finding codes include `invalid_magic`, `checksum_mismatch`, `truncated_file`, `unsupported_storage_version`, `unsupported_encryption`, `invalid_block_alloc_size`, `invalid_block_count`, `invalid_metadata_pointer`, `invalid_block_reference`, `geometry_overflow`, `no_valid_database_header`, and `limit_reached`.

WAL finding codes are `empty_wal`, `unsupported_wal_version`, `invalid_wal_header`, `invalid_entry_length`, `entry_exceeds_remaining_file`, `checksum_mismatch`, `truncated_entry`, `zero_filled_tail`, `unparsed_trailing_data`, and `resource_limit_reached`. A declaration that exceeds EOF can carry both the out-of-bounds and truncated classifications.

## Read-only and output safety

- `DB_PATH` and `WAL_PATH` are opened read-only. The inspector does not invoke DuckDB, create a WAL, trigger a checkpoint, replay a WAL, or modify either input.
- The only optional write is the report supplied through `--output`.
- An output path that resolves to the input is rejected. Symlink resolution and Unix device/inode checks also protect existing aliases and hard links. The opened output identity is checked again before truncation.
- Remediation text is advisory only and is never executed.
- Corrupt, empty, random, truncated, unsupported, and overflow-inducing inputs produce structured diagnostics rather than parser panics.

Always preserve the original evidence and perform any separate database operation on a copy.

## Resource limits

The inspector reads at most three fixed 4096-byte header pages and streams SHA-256 through a 1 MiB buffer. It does not load the whole database or allocate memory based on file-provided lengths.

The default main-file size budget is 1 TiB. A larger input stops before hashing and header parsing with `limit_reached`; SHA-256 and unchecked fields remain unknown. Resource exhaustion is not reported as corruption.

WAL inspection defaults to 1 TiB per file, 1,000,000 Entry candidates, and 256 MiB declared Payload per Entry. Payload checksum and tail reads use fixed 1 MiB chunks; memory is never allocated from an unchecked declared Entry length. WAL budget exhaustion produces `resource_limit_reached` and preserves the stop offset. If the initial file budget stops processing, SHA-256 is `null`.

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

DuckDB generates a random database identifier, so a regenerated database is structurally equivalent but not byte-for-byte identical. The manifest records each generated fixture's own hash and raw header values.

Generate the deterministic WAL fixtures separately:

```sh
python3 scripts/generate_wal_fixtures.py
```

This stdlib-only generator does not invoke DuckDB or the Rust parser. It writes `normal.wal`, independent per-Entry expectations, and the Issue #19099 historical corpus: one file truncated at a fixed in-Entry offset and another zero-filled from that same offset to the original EOF. The corpus makes no claim that current DuckDB still has the historical bug.

Tests never require network access or DuckDB.

## Test and lint

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Main-file tests cover the official normal fixture, empty/non-DuckDB/random files, Main Header bit flips, either/both Database Headers corrupted, truncation, invalid block allocation size, huge block counts, unsupported encryption/version behavior, stable JSON deserialization, text output, hidden paths, output files, and direct/hard-link overwrite attempts. CLI helpers verify that input SHA-256 is unchanged and that no WAL appears.

WAL tests cover normal/empty/unsupported files, out-of-bounds and huge lengths, mid-Entry and fixed-header truncation, checksum bit flips, zero and nonzero tails, random bytes, unknown types, malformed Flush objects, Checkpoint decoding, resource limits, JSON Schema/Text/output files, and the historical same-cut truncation/zero-fill pair. Independent manifests verify offsets and lengths. Tests assert no Panic, unchanged input SHA-256, and `last_good_flush=null` whenever no continuously verified Flush exists.

## Workspace

- `crates/duckdb-format`: fixed-page reads, scalar parsing, DuckDB checksum, checked geometry, WAL v2 frame/envelope parsing, and format errors.
- `crates/duckdb-report`: observation/finding/inference model, main-file and WAL JSON types, and text rendering.
- `crates/duckdb-forensics`: main-file and WAL inspection pipelines, CLI, streaming SHA-256/checksums, resource limits, and safe report output.
- `schemas/wal-report.schema.json`: WAL JSON Schema version 1.
