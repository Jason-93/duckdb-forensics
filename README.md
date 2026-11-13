# duckdb-forensics

**English** | [简体中文](README.zh-CN.md)

A read-only, offline crash-site inspector for DuckDB database and WAL files. It examines DuckDB v2.0.0 headers, block geometry/checksums, metadata chains, and unencrypted WAL v2 frames without replay. It can also produce advisory recovery plans and compare Rust analysis with an explicitly supplied official DuckDB v2.0.0 executable on temporary copies. Reports provide offset-backed observations, findings, explicitly separated inferences, and coverage in text or JSON.

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

For `verify`, the supported scope additionally includes:

- Streaming checksums for complete plaintext blocks, with isolated per-block diagnostics.
- Truncated and out-of-bounds blocks, recorded-count geometry, and non-aligned trailing data.
- Bounded `meta_block` and `free_list` chain traversal with pointer bounds, length, and cycle checks.
- Explicit checked, unchecked, unsupported, and unavailable coverage. Unvisited blocks are not called healthy or assigned an allocation verdict.

For `wal`, the supported scope is narrower:

- Official DuckDB **v2.0.0** unencrypted **WAL version 2**, little-endian framing.
- The unframed BinarySerializer version object and framed `length + checksum + Payload` Entries.
- Streaming Entry checksums, declared/actual lengths, structural error offsets, and zero/nonzero tail evidence.
- Source-defined WALType envelopes, exact empty WAL_FLUSH objects, and reliably decoded Checkpoint Markers.
- Confirmed Flush positions and a separate continuously verified `last_good_flush`.
- No business Payload output: ordinary Insert/Update/Catalog Payloads remain `not_decoded`.

WAL v1, encrypted WAL v3, and unknown WAL versions return `unsupported_wal_version`; they are never forced through the v2 parser.

Encrypted database files are identified from the Main Header. Their encrypted Database Headers and blocks are marked `unsupported`, not tested as plaintext checksums.

## Support and verification matrix

| Capability | Support status | Verification boundary |
|---|---|---|
| Main Header, Database Headers, checked geometry | Supported for DuckDB v2.0.0 / storage 69 | Official fixture, deterministic damage Corpus, proptest, exact checksum tests |
| Plaintext Block checksums and bounded metadata chains | Supported for the default eight-byte header layout | Full/default scans, short reads, cycles, bounds, sparse-file and resource-limit tests |
| Unencrypted WAL v2 framing, Flush and Checkpoint envelopes | Supported; business Payloads remain undecoded | Independent manifests, arbitrary bytes/lengths, exact JSON round trips |
| `recover-plan` candidate actions | Experimental, advisory only | Tested as data suggestions, never executed or claimed lossless |
| Official DuckDB Oracle | Experimental auxiliary evidence | Mock process tests are required; a real engine run requires explicit `DUCKDB_V2_0_0` |
| Other DuckDB versions, encryption, big-endian/alternate layouts | Unsupported | Reported as `unsupported` or `unknown`, never guessed |

Linux, macOS and Windows are built and tested by the CI matrix. A local run on one platform is not evidence that the other platform jobs passed.

## Non-goals

These phases do not support DuckDB v1.x main files, WAL v1/v3 framing, encrypted-content decoding, big-endian files, alternate block-header sizes, DuckLake, Parquet, MotherDuck, Catalog deserialization, free-list/meta-block payload decoding, Row Groups, column compression, business-data output, row recovery, WAL replay, automatic repair, checkpointing, truncation, or replacement database generation. Recovery plans are advisory only; no candidate action is executed by the tool.

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

The inspection JSON contract is documented in [`schemas/inspection-report.schema.json`](schemas/inspection-report.schema.json).

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

## Verify a main file

```sh
duckdb-forensics verify <DB_PATH> [--blocks] [--format text|json] [--duckdb PATH]
```

The default verifies headers, selected-header geometry, and the selected `meta_block`/`free_list` chains, including checksums for blocks those chains visit. `--blocks` additionally streams and checksums every complete physical block. A damaged block does not stop independent later checks. Extra blocks after `block_count` are reported separately because DuckDB can treat them as implicitly free-listed; unvisited blocks are never assigned an allocation verdict. Repeated references are not automatically corruption, and cycle detection is local to each chain.

The report distinguishes truncated blocks, out-of-bounds references, trailing bytes, unsupported encrypted regions, and unavailable coverage. A `complete` status or valid checksum is not a claim that DuckDB can open the database or that catalog/business contents are healthy. See [`schemas/verify-report.schema.json`](schemas/verify-report.schema.json).

## Generate an advisory recovery plan

```sh
duckdb-forensics recover-plan <EVIDENCE_DIR> [--format text|json] [--duckdb PATH]
```

The command inventories and hashes every regular file recursively, analyzes one unambiguous top-level `.duckdb` and its exact companion `.wal`, then rechecks the original inventory and hashes. It never executes recovery. Its JSON always separates `observed_facts`, `findings`, `inferences`, `unknowns`, `candidate_actions`, and `risks`; see [`schemas/recovery-plan.schema.json`](schemas/recovery-plan.schema.json).

When a continuously verified `last_good_flush` ends before EOF, a `candidate_wal_truncation` suggestion records the target offset, WAL hash and Flush evidence, and the possible loss interval `[target_offset, wal_file_size)`. That interval can contain complete Entries without a later Flush, so transaction/row loss is unknown. The action requires execution on a copy and full reverification. No boundary, an EOF boundary, resource-limited analysis, missing files, or ambiguous databases produce no such action. The tool never truncates, deletes, renames, or overwrites evidence and never claims lossless recovery.

## Optional official DuckDB Oracle

Both new commands accept `--duckdb PATH` only for an explicitly supplied official DuckDB v2.0.0 executable. There is no automatic discovery or download. The tool first checks `SELECT version()` in `:memory:`, copies the database and associated WAL to a temporary workspace, disables known-extension autoinstall/autoload through controlled initialization, and only then opens the copy with `ATTACH ... (READ_ONLY)` and a minimal read-only query. Original paths are never passed to DuckDB.

Every invocation records its full argv, exit status, stderr/stdout (bounded to 64 KiB per stream with truncation flags and explicit UTF-8 validity/raw hex), and a default 30-second timeout. JSON field order and schemas are stable, but byte-for-byte comparisons across Oracle runs must account for temporary workspace paths and external process output. Timeout processes are killed and reaped. The comparison is `agreement`, `disagreement`, or `not_comparable` with a rationale. Oracle success does not override checksum findings or prove unvisited content healthy; unexplained Rust/Oracle differences are reported as `disagreement` rather than hidden.

The inspector returns exit code 0 when an inspection completes, including reports containing corruption or unsupported-feature findings. Usage, input I/O, serialization, and output-safety failures return exit code 2.

## Report model

JSON uses schema version `1` and contains the following fields. Newly added version 1 metadata is always emitted by this build but is optional when reading older reports; core fields such as `status` remain required.

- `input`: optional normalized path and explicit path encoding, file size, and streaming SHA-256 (`null` when unavailable);
- `observations`: direct values with `name`, `structure_path`, and optional `file_offset`; invalid fixed-text UTF-8 is `null` with raw hex and a validity flag;
- `findings`: stable code, category (`corruption`, `unsupported`, `limit`, `unknown`, or `informational`), severity, message, location, evidence, remediation hint, and confidence;
- `inferences`: separate confidence-rated interpretations such as likely active header, possible stale header, or possible torn write;
- `checks_passed`, `checks_failed`, and `checks_skipped`;
- `coverage`: checked and explicitly unchecked areas;
- `unknowns`: facts that cannot be established under the current evidence or support scope.

`--hide-path` sets `input.path` to `null`; it does not suppress file size, hashes, offsets, or diagnostics. Reports contain header metadata only, not table rows. Non-Unicode paths use an explicit reversible hex encoding rather than silent replacement. JSON integers can cover the full `u64` range: consumers must use 64-bit integers, because JavaScript's default Number loses precision above 2^53.

WAL JSON independently uses schema version `1` and reports version/encryption status, version-header length, file size and SHA-256, per-Entry offsets and lengths, checksum status and type, summary counts, the first unparsed and checksum-failed offsets, scan coverage, unknowns, tail zero evidence, confirmed Flushes, `last_good_flush`, data after that boundary, and an optional Checkpoint Marker. `actual_length` means available Payload bytes capped at `declared_length`.

`last_good_flush` requires a continuously complete, checksum-valid, type-validated prefix ending in an exact WAL_FLUSH. It is not necessarily the last commit acknowledged by the application and is not a safe recovery point. `confirmed_flushes` can additionally contain later physically valid Flush objects after an earlier error; they do not restore continuity. Checksum mismatch alone does not prove torn write, and a zero-filled tail is only evidence.

Verify JSON independently uses schema version `1` and adds selected-header details, bounded block anomalies, metadata-chain termination/capacity/cycle status, trailing-data classification, and explicit integrity coverage. Recovery-plan JSON independently uses schema version `1`; its candidate actions are data objects, not executable instructions. All four report contracts, including `inspect`, are validated in tests.

Stable main-file finding codes include `invalid_magic`, `checksum_mismatch`, `truncated_file`, `unsupported_storage_version`, `unsupported_encryption`, `invalid_block_alloc_size`, `invalid_block_count`, `invalid_metadata_pointer`, `invalid_block_reference`, `geometry_overflow`, `no_valid_database_header`, and `limit_reached`.

WAL finding codes are `empty_wal`, `unsupported_wal_version`, `invalid_wal_header`, `invalid_entry_length`, `entry_exceeds_remaining_file`, `checksum_mismatch`, `truncated_entry`, `zero_filled_tail`, `unparsed_trailing_data`, and `resource_limit_reached`. A declaration that exceeds EOF can carry both the out-of-bounds and truncated classifications.

Additional verify findings include `truncated_block`, `block_out_of_bounds`, `trailing_data`, `beyond_header_block_count`, and `meta_block_cycle`. Recovery/Oracle findings include `evidence_incomplete`, `evidence_changed_during_analysis`, and `oracle_disagreement`.

## Read-only and output safety

- `DB_PATH`, `WAL_PATH`, and `EVIDENCE_DIR` inputs are opened read-only. Without `--duckdb`, the tool does not invoke DuckDB, create a WAL, trigger a checkpoint, replay a WAL, or modify any input.
- Oracle writes are confined to a temporary copy workspace. The original evidence is hashed again after recovery-plan analysis.
- For `inspect` and `wal`, the only optional write is the report supplied through `--output`. `verify` and `recover-plan` write reports only to stdout.
- An output path that resolves to the input is rejected. Symlink resolution and opened-file identity checks protect existing aliases and hard links on Unix and Windows. The opened output identity is checked again before truncation; non-regular inputs and outputs are rejected.
- Remediation text is advisory only and is never executed.
- Corrupt, empty, random, truncated, unsupported, and overflow-inducing inputs produce structured diagnostics rather than parser panics.

### Threat model and disclaimer

The parser treats file bytes, declared lengths, pointers, directory depth and text encoding as untrusted. Resource budgets limit accidental denial of service; they are not a wall-clock or memory sandbox, and hashing an in-budget sparse file still requires linear I/O. Detection of concurrent modification is best-effort, not protection against a malicious local process. A user-supplied Oracle executable must already be trusted: the tool confines its documented evidence writes to copies but does not sandbox arbitrary native code.

No report guarantees database health, application commit durability, complete corruption detection, recoverability, or lossless recovery. Preserve original evidence and perform every separate database operation on a copy. `corruption` means a structural/integrity violation, not a proven physical cause; `unknown`, `unsupported`, and `limit` are separate from that verdict.

## Resource limits

The inspector reads at most three fixed 4096-byte header pages and streams SHA-256 through a 1 MiB buffer. It does not load the whole database or allocate memory based on file-provided lengths.

The default main-file size budget is 1 TiB. A larger input stops before hashing and header parsing with `limit_reached`; SHA-256 and unchecked fields remain unknown. Resource exhaustion is not reported as corruption.

WAL inspection defaults to 1 TiB per file, 1,000,000 Entry candidates, and 256 MiB declared Payload per Entry. Reports retain at most 10,000 Entries and confirmed Flushes by default, and at most 1,000 Findings plus 1,000 Unknowns. Scan totals, retained totals, omitted totals, and `report_limits` are separate; omitted Entries are not called absent or healthy. Payload checksum and tail reads use fixed 1 MiB chunks; memory is never allocated from an unchecked declared Entry length. WAL budget exhaustion produces `resource_limit_reached` and preserves the stop offset. If the initial file budget stops processing, SHA-256 is `null`.

Verify uses bounded 16–256 KiB block buffers, at most 1,000,000 nodes per metadata chain, and at most 1,000 retained block issues. Normal blocks are counted rather than accumulated in the report. Recovery iteratively inventories at most 100,000 directory entries, depth 64, and 1 TiB total hashed bytes, stopping as soon as a budget is exceeded. Incomplete inventories suppress candidate actions. Oracle defaults to 30 seconds and 64 KiB retained output per stream. Resource/report limits preserve omitted counts or unknown coverage and are not corruption verdicts.

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

Generate the public fault Corpus with:

```sh
python3 scripts/generate_fault_corpus.py --output target/fault-corpus
# Optional: create the 2 TiB sparse resource-limit case without reading it.
python3 scripts/generate_fault_corpus.py --output target/fault-corpus-sparse --include-sparse
```

`corpus/manifest.json` stores independent source/output hashes, byte patches, expected categories, and offsets. Generated files go to a separate output directory, never over evidence. The default omits only the huge sparse case; the other 15 cases are small patch-derived files.

Tests never require network access or DuckDB. Python 3 is required for the public Corpus integration test. An additional real-Oracle test runs only when `DUCKDB_V2_0_0=/path/to/duckdb` is explicitly set; mocked Oracle tests cover failure, timeout, output limits, and copy isolation without DuckDB.

## Test and lint

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Property tests use proptest with file-based failure persistence and shrinking. Re-run one parser property with:

```sh
cargo test -p duckdb-forensics --test parser_properties extreme_wal_lengths_never_panic -- --exact
```

On failure, preserve the minimized case and generated `proptest-regressions` entry; add a deterministic regression or public Corpus case after diagnosis. Do not delete, ignore, or weaken an unexplained failure. JSON Schema tests validate real reports, and an exact floating-point round-trip regression guards against lossy percent parsing.

Main-file tests cover the official normal fixture, empty/non-DuckDB/random files, Main Header bit flips, either/both Database Headers corrupted, truncation, invalid block allocation size, huge block counts, unsupported encryption/version behavior, stable JSON deserialization, text output, hidden paths, output files, and direct/hard-link overwrite attempts. CLI helpers verify that input SHA-256 is unchanged and that no WAL appears.

WAL tests cover normal/empty/unsupported files, out-of-bounds and huge lengths, mid-Entry and fixed-header truncation, checksum bit flips, zero and nonzero tails, random bytes, unknown types, malformed Flush objects, Checkpoint decoding, resource limits, JSON Schema/Text/output files, and the historical same-cut truncation/zero-fill pair. Independent manifests verify offsets and lengths. Tests assert no Panic, unchanged input SHA-256, and `last_good_flush=null` whenever no continuously verified Flush exists.

Verify tests cover full/default scans, isolated block damage, truncation, extra data, metadata cycles/bounds/checksum failures, legitimate shared blocks, encryption, and resource limits. Recovery and Oracle tests check all six report sections, candidate loss ranges, missing/ambiguous evidence, version mismatch, disagreement, output truncation, timeout, and read-only copy execution. End-to-end helpers compare every original evidence file's SHA-256 and the complete file set before and after execution, including an Oracle that deliberately modifies its temporary copy.

## Workspace

- `crates/duckdb-format`: fixed-page reads, scalar parsing, DuckDB checksum, checked block/metadata geometry, WAL v2 frame/envelope parsing, and format errors.
- `crates/duckdb-report`: observation/finding/inference model, main-file, verification, recovery, Oracle, and WAL JSON types and text rendering.
- `crates/duckdb-forensics`: read-only analysis pipelines, advisory recovery planning, isolated Oracle execution, CLI, streaming hashes/checksums, and resource limits.
- `schemas/inspection-report.schema.json`, `schemas/wal-report.schema.json`, `schemas/verify-report.schema.json`, and `schemas/recovery-plan.schema.json`: independent JSON Schema version 1 contracts, with shared definitions in `schemas/report-common.schema.json`.
