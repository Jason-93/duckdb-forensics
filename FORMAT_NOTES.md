# DuckDB v2.0.0 Format Notes

## Provenance and rule of implementation

The implemented layout is based on the official DuckDB release tag **`v2.0.0`**, commit **`d54cbbe3df17e8e5ce68312f483b4155836112aa`**. Source URLs below use the immutable release tag. The release commit was also confirmed by the official GitHub release API and by the `library_git_hash` value in the generated fixture.

No binary layout is taken from another database, a storage article, or an assumption based on prior DuckDB releases. Where the source does not establish a safe check, the inspector reports `unknown`, `unsupported`, or skipped coverage.

Primary sources:

- [`src/include/duckdb/storage/storage_info.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/storage_info.hpp)
- [`src/storage/storage_info.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/storage_info.cpp)
- [`src/include/duckdb/storage/single_file_block_manager.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/single_file_block_manager.hpp)
- [`src/storage/single_file_block_manager.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/single_file_block_manager.cpp)
- [`src/common/checksum.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/common/checksum.cpp)
- [`src/include/duckdb/common/checksum.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/checksum.hpp)
- [`src/include/duckdb/common/vector_size.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/vector_size.hpp)
- [`src/include/duckdb/common/serializer/write_stream.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/serializer/write_stream.hpp)
- [`src/include/duckdb/common/serializer/read_stream.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/serializer/read_stream.hpp)
- [`src/include/duckdb/common/helper.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/helper.hpp)
- [`src/include/duckdb/storage/block.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/block.hpp)
- [`src/include/duckdb/storage/metadata/metadata_manager.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/metadata/metadata_manager.hpp)
- [`src/storage/metadata/metadata_manager.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/metadata/metadata_manager.cpp)
- [`src/include/duckdb/storage/metadata/metadata_reader.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/metadata/metadata_reader.hpp)
- [`src/storage/metadata/metadata_reader.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/metadata/metadata_reader.cpp)
- [`src/include/duckdb/storage/metadata/metadata_writer.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/metadata/metadata_writer.hpp)
- [`src/storage/metadata/metadata_writer.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/metadata/metadata_writer.cpp)
- [`src/storage/checkpoint_manager.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/checkpoint_manager.cpp)

WAL-specific sources:

- [`src/storage/write_ahead_log.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/write_ahead_log.cpp)
- [`src/storage/wal_replay.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/wal_replay.cpp)
- [`src/include/duckdb/storage/write_ahead_log.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/write_ahead_log.hpp)
- [`src/include/duckdb/storage/wal_entry.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/storage/wal_entry.hpp)
- [`src/include/duckdb/common/enums/wal_type.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/enums/wal_type.hpp)
- [`src/common/serializer/binary_serializer.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/common/serializer/binary_serializer.cpp)
- [`src/common/serializer/binary_deserializer.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/common/serializer/binary_deserializer.cpp)
- [`src/include/duckdb/common/serializer/binary_deserializer.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/serializer/binary_deserializer.hpp)
- [`src/include/duckdb/common/serializer/serialization_traits.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/serializer/serialization_traits.hpp)
- [`src/include/duckdb/common/serializer/encoding_util.hpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/include/duckdb/common/serializer/encoding_util.hpp)
- [`src/storage/serialization/serialize_wal.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/serialization/serialize_wal.cpp)
- [`src/storage/serialization/serialize_storage.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/serialization/serialize_storage.cpp)

## Scalar representation

`WriteStream::Write<T>` writes the in-memory representation of a standard-layout scalar. `ReadStream::Read<T>` reads that representation directly, and `Load<T>` uses `memcpy`. These functions do not perform byte-order conversion.

The inspector implements **little-endian** decoding for the confirmed v2.0.0 files used on the supported little-endian fixture platform. Big-endian database files are not implemented or claimed. The parser never reads unaligned native integers directly; it copies exactly eight bytes and uses explicit little-endian conversion.

## Constants and page geometry

Confirmed symbols:

- `Storage::FILE_HEADER_SIZE = 4096`.
- `SingleFileBlockManager::BLOCK_START = Storage::FILE_HEADER_SIZE * 3 = 12288`.
- `Storage::DEFAULT_BLOCK_HEADER_SIZE = sizeof(idx_t) = 8` on the confirmed build.
- `DEFAULT_BLOCK_HEADER_STORAGE_SIZE = 8`.
- `MainHeader::MAGIC_BYTE_OFFSET = Storage::DEFAULT_BLOCK_HEADER_SIZE = 8`.
- `MainHeader::DEPRECATED_VERSION_NUMBER = StorageVersion::DEPRECATED = 999`.
- `StorageVersion::V2_0_0 = 69`; `VERSION_NUMBER = 69` in `storage_info.cpp`.
- `DEFAULT_BLOCK_ALLOC_SIZE = 262144`, `MIN_BLOCK_ALLOC_SIZE = 16384`, and `MAX_BLOCK_ALLOC_SIZE = 262144`.
- `DEFAULT_STANDARD_VECTOR_SIZE = 2048`; without a compile-time override, `STANDARD_VECTOR_SIZE` has the same value.
- `MAXIMUM_BLOCK = 4611686018427388000LL`.
- `INVALID_BLOCK = -1`; when stored through `idx_t`, its raw value is `0xffffffffffffffff`.

Block `id` starts at `BLOCK_START + id * block_alloc_size`, as implemented by `SingleFileBlockManager::GetBlockLocation`. The Rust implementation uses checked multiplication and addition. It also rejects a count above the exact `MAXIMUM_BLOCK` constant rather than relying on the nearby approximate comment.

## Main Header

`MainHeader::Write`, `MainHeader::Read`, `SerializeVersionNumber`, `SerializeEncryptionMetadata`, `SerializeDBIdentifier`, `SerializeIV`, and `SerializeTag` establish this order. The page starts with a checksum inserted by `ChecksumAndWrite`; the serialized `MainHeader` begins at page offset 8.

| Absolute file offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Stored checksum |
| 8 | 4 | Magic bytes, ASCII `DUCK` |
| 12 | 8 | `version_number` |
| 20 | 32 | Four `uint64_t` flags |
| 52 | 32 | `library_git_desc`, zero-padded version text |
| 84 | 32 | `library_git_hash`, zero-padded source text |
| 116 | 8 | Encryption metadata |
| 124 | 16 | Database identifier / optional encryption salt |
| 140 | 8 | Encrypted canary |
| 148 | 12 | Canary IV |
| 160 | 16 | Canary tag |
| 176 | 3920 | Remaining bytes in the checksummed header page |

`MainHeader::Write` changes a version at least v2.0.0 to 999 before serialization. Therefore **999 is a deprecated main-version marker, not the real storage compatibility version**. The real v2.0.0 compatibility value is read from each Database Header.

`MainHeader::IsEncrypted` tests bit 0 (`ENCRYPTED_DATABASE_FLAG = 1`) of `flags[0]`. The inspector reports the raw flags and this Boolean. It does not output canary, IV, or tag contents by default.

The Main Header remains plaintext for an encrypted database. Other headers are decrypted before checksum verification in `ReadAndChecksum`; consequently, this phase stops before Database Header checksum/field interpretation whenever the encryption flag is set. It does not report plaintext checksum mismatches for encrypted pages.

## Database Headers

`CreateNewDatabase` places Database Header 1 at 4096 and Database Header 2 at 8192. `DatabaseHeader::Write` and `DatabaseHeader::Read` serialize seven 64-bit values after the page checksum. The relative offsets below add 4096 or 8192 for absolute file offsets.

| Page-relative offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Stored checksum |
| 8 | 8 | `iteration` |
| 16 | 8 | `meta_block` (packed metadata pointer) |
| 24 | 8 | `free_list` (packed metadata pointer) |
| 32 | 8 | `block_count` |
| 40 | 8 | `block_alloc_size` |
| 48 | 8 | `vector_size` |
| 56 | 8 | `storage_compatibility` |
| 64 | 4032 | Remaining bytes in the checksummed header page |

For v2.0.0, `DatabaseHeader::Write` writes `storage_compatibility` directly rather than using the older serialization-version mapping. This inspector accepts only 69.

`DatabaseHeader::Read` interprets a zero block allocation size as 262144 and a zero vector size as 2048 for backward compatibility. The report preserves the stored zero and separately exposes the effective value. All nonzero values must pass the applicable checks; only vector size 2048 is supported in this phase.

`Storage::VerifyBlockAllocSize` requires a power of two in the inclusive range 16384 through 262144. The inspector applies these exact rules after the source-defined zero substitution.

### Packed metadata pointers

`SingleFileCheckpointWriter::CreateCheckpoint` assigns `header.meta_block = meta_block.block_pointer`, and `SingleFileCheckpointReader::LoadFromStorage` constructs a `MetaBlockPointer` from that raw value. `SingleFileBlockManager::LoadFreeList` likewise constructs `MetaBlockPointer(free_list_id, 0)`. Thus **both** `meta_block` and `free_list` use the packed representation.

`MetaBlockPointer::GetBlockId` masks off the high eight bits, and `GetBlockIndex` shifts right by 56. `MetadataManager::FromDiskPointerInternal` requires an index below `METADATA_BLOCK_COUNT = 64`.

For either non-sentinel raw pointer:

- `block_id = raw_pointer & 0x00ffffffffffffff`;
- `metadata_index = raw_pointer >> 56`;
- `0xffffffffffffffff` is the invalid/no-pointer sentinel;
- the block-id portion, not the packed raw integer, is used for checked block-offset arithmetic.

This distinction was verified against the official normal fixture. Its first header has raw `meta_block = 0` (block id 0, metadata index 0) and raw `free_list = 0x0200000000000000` (block id 0, metadata index 2). Neither pointer's payload is decoded in phase 1.

## Checksum algorithm and coverage

`SingleFileBlockManager::CheckChecksum` and `ChecksumAndWrite` establish the default, unencrypted eight-byte block-header case:

- stored checksum: little-endian `uint64_t` at page offset 0;
- computed checksum: `Checksum(page[8..4096])`, exactly 4088 bytes;
- a partial page cannot be checksum-validated and is reported as unavailable/truncated.

`src/common/checksum.cpp` defines the algorithm:

1. Start with `result = 5381`.
2. For each complete little-endian 64-bit word, XOR `result` with `word * 0xbf58476d1ce4e5b9`, using wrapping 64-bit multiplication.
3. If 0–7 trailing bytes remain, XOR in `ChecksumRemainder`.
4. `ChecksumRemainder` uses multiplier `0xc6a4a7935bd1e995`, seed `0xe17a1465`, right shift 47, little-endian complete words, the source's fall-through byte ordering, and the same final avalanche steps.

The Rust implementation reproduces the complete-word and remainder paths. All three stored checksums in the official fixture match independently recorded values and the computed checksums.

Alternate block-header sizes introduce a `delta` in DuckDB's checksum functions. They are not supported by this phase; the inspector does not guess that layout.

## Ordinary Block verification

`SingleFileBlockManager::CheckChecksum` applies the same algorithm to ordinary unencrypted blocks. For the supported eight-byte block-header layout, the stored checksum is at the block offset and the computed range is exactly `block_alloc_size - 8` bytes after that field. `verify --blocks` walks every complete physical block sequentially with a bounded buffer. The default `verify` checks only blocks needed by selected metadata chains and marks other blocks `not_checked`.

A complete block with a checksum mismatch is an isolated integrity finding; it does not prevent later independent blocks from being checked. An incomplete block has `unavailable` checksum status rather than a fabricated mismatch. A reference outside the selected header's recorded count or actual EOF is reported as out of bounds with its pointer evidence. No block is inferred to be unused merely because the current parser did not visit it, and duplicate references are not automatically corruption because DuckDB explicitly tracks multi-use blocks.

For a selected valid header, recorded geometry remains `12288 + block_count * block_alloc_size`. Complete physical blocks beyond that end can be implicitly free-listed according to the source comment and are classified separately. Non-allocation-aligned residual bytes are trailing data, not a valid complete block. With `--blocks`, complete beyond-count blocks receive checksum checks without changing their allocation interpretation.

## Metadata sub-block chains

`MetadataManager::GetMetadataBlockSize` computes `AlignValueFloor(GetBlockSize() / 64)`, where `GetBlockSize() = block_alloc_size - 8` in the supported layout. With the default allocation size this yields 4088 bytes per metadata sub-block. The sub-block location is:

`block_offset + 8 + metadata_index * metadata_block_size`

The packed pointer's low 56 bits identify the physical block and its high eight bits identify the sub-block. An index at least 64 is invalid. `MetadataReader::ReadNextBlock` reads an eight-byte next pointer at the start of each sub-block. `u64::MAX` terminates the chain; otherwise the packed next pointer is followed with offset zero. An initial offset below eight is raised to eight, and one above the sub-block capacity is rejected.

`verify` independently traverses the selected header's `meta_block` and `free_list` roots. It checks pointer arithmetic, recorded/physical bounds, containing-block checksum, sub-block capacity, visited/verified node counts, payload capacity, and termination position. A containing-block checksum failure stops that chain before its next pointer is trusted. Each chain has its own visited set: returning to a node in the same chain is a cycle, while sharing a node across independent chains is only an observation. A per-chain node budget leaves the remainder explicitly unknown.

Chain validation establishes pointer structure only. It does not decode Catalog, free-list counts, table metadata, or business payloads and does not claim those contents are healthy.

## Active-header selection and diagnostics

For intact supported files, `LoadExistingDatabase` selects the header with the greater `iteration`; if iterations are equal, it selects header 2. `WriteHeader` alternates headers and increments the iteration on checkpoint.

DuckDB's own loader checksum-reads the headers directly and can throw on corruption. The inspector's damaged-file behavior is deliberately a **diagnostic extension**, not a claim about DuckDB recovery:

- raw fields are shown for complete pages even after checksum failure;
- semantic validation and geometry are skipped for a header whose checksum failed;
- only checksum-valid headers with supported compatibility/vector size and valid checked geometry are eligible;
- one eligible header is reported as the likely active header with medium confidence;
- with two eligible headers, greater iteration wins and header 2 wins a tie;
- one mismatched and one usable header can produce low-confidence `possible_torn_write`; it is not an observed cause;
- a lower-iteration eligible header can produce `possible_stale_header`;
- no eligible v2.0.0 candidate produces `no_valid_database_header` when corruption evidence exists.

## File-length geometry

For a candidate with valid allocation size and count, the inspector computes:

`expected_recorded_file_end = 12288 + block_count * effective_block_alloc_size`

All arithmetic is checked. A shorter actual file produces `truncated_file`. Equality is a passed geometry check.

The `DatabaseHeader::block_count` source comment explicitly states that blocks after `block_count` are implicitly part of the free list when the file is larger. Thus `file_size > expected_recorded_file_end` is reported as `beyond_header_block_count`, not automatically called corruption. The original `inspect` command does not validate those blocks; `verify --blocks` can check their checksums while preserving the separate allocation unknown.

The decoded meta-block and free-list block ids are converted to offsets only with checked arithmetic. Their targets and contents are not followed.

## Fixture provenance

`crates/duckdb-forensics/tests/fixtures/normal.duckdb` was generated by `scripts/generate_fixture.py` using the official `duckdb-cli-osx-arm64.tar.gz` v2.0.0 release asset. The generator verifies the asset SHA-256 and `SELECT version()` before creating a two-row test table and checkpointing it.

The independently generated `normal.manifest.json` records the release URL, asset digest, fixture SHA-256, raw header fields, and stored checksums. DuckDB generates a random database identifier, so regeneration is procedurally repeatable but is not expected to be byte-for-byte identical.

`normal.wal` and the Issue #19099 corpus are generated deterministically by `scripts/generate_wal_fixtures.py`. That independent stdlib-only generator implements the source-defined field IDs, LEB128, frame layout, and checksum without invoking DuckDB or the Rust parser. `normal.wal.manifest.json` records every expected Entry offset, declared/actual length, checksum, Flush boundary, and Checkpoint field. The historical manifest records the common cut and both hashes. Tests use these independent expectations rather than expectations produced by the Rust parser.

## Unframed WAL version object

DuckDB v2.0.0 defines `WAL_VERSION_NUMBER = 2` and `WAL_ENCRYPTED_VERSION_NUMBER = 3` in `write_ahead_log.cpp`. The first WAL object is **not** a v2 length/checksum frame and explicitly has no checksum. `WriteAheadLog::WriteHeader` serializes it directly to the file writer:

| Order | Encoding | Meaning |
|---:|---|---|
| 1 | little-endian `uint16_t` field ID 100 | `wal_type` property |
| 2 | unsigned LEB128 `uint8_t` value 98 | `WALType::WAL_VERSION` |
| 3 | little-endian `uint16_t` field ID 101 | `version` property |
| 4 | unsigned LEB128 `uint64_t` | WAL version |
| 5 | optional field ID 102, LEB128 list length 16, sixteen LEB128 bytes | database identifier for the v2.0.0 writer |
| 6 | optional field ID 103 and LEB128 `optional_idx` | checkpoint iteration; `UINT64_MAX` means unset |
| 7 | little-endian `uint16_t` `0xffff` | root object terminator |

The parser determines the first frame offset from the consumed object length, not a fixed header size. It accepts only version 2 for framed analysis. Version 1, encrypted version 3, and other versions produce `unsupported_wal_version` with `status=unsupported`; their following bytes are not parsed as v2. A malformed initial object produces `invalid_wal_header` rather than a guessed version.

`field_id_t` is `uint16_t` and `MESSAGE_TERMINATOR_FIELD_ID` is `0xffff` in `serialization_traits.hpp`. `BinarySerializer::OnPropertyBegin` writes the raw field ID. `BinaryDeserializer::ReadUnsignedInt8` and `ReadUnsignedInt64` use `EncodingUtil::DecodeLEB128`. This is why the first Payload byte is **not** the `WALType`.

## WAL v2 frames and checksum

`ChecksumWriter::Flush` and `WriteAheadLogDeserializer::GetEntryDeserializer` establish this unencrypted v2 layout:

| Frame-relative offset | Size | Field |
|---:|---:|---|
| 0 | 8 | little-endian declared Payload length |
| 8 | 8 | little-endian stored checksum |
| 16 | declared length | serialized Payload |

The checksum is the same `Checksum` algorithm documented above, computed over exactly the Payload and excluding both 8-byte frame fields. The inspector streams the Payload through 1 MiB buffers and never allocates the declared Entry length. Its `actual_length` is the number of Payload bytes physically present, capped at the declaration. `actual_frame_length` includes available frame-header bytes. All end-offset calculations use checked arithmetic.

A zero declaration or overflowing end is `invalid_entry_length`. Fewer than 16 remaining bytes is `truncated_entry`. A complete header whose declaration exceeds the remaining file produces `entry_exceeds_remaining_file`; when the file ends inside the Payload, `truncated_entry` is also reported. A complete frame with a different computed checksum produces `checksum_mismatch`. These are structural or integrity observations, not proof of a particular physical failure.

After a structural error the scanner does not guess a new frame boundary. A complete frame with a checksum/type error can be skipped by its declared physical length for further observations, but the trusted sequential prefix ends at the first such Entry. Reports distinguish `first_unparsed_offset`, `first_checksum_mismatch_offset`, and the physical `scan_stop_offset`.

## WALType envelope and supported Payload decoding

Every regular Entry starts with field ID 100 followed by the LEB128-encoded underlying `uint8_t` enum value. The root object ends with field ID `0xffff`; other properties occur between the type and that terminator. The inspector decodes only this envelope for ordinary entries and sets `payload_status=not_decoded`. It does not emit Insert, Update, Catalog, or other business Payload contents. If field 100, the LEB128 value, or the enum mapping cannot be decoded reliably, `entry_type=unknown` and the offset/length/checksum evidence remains available.

The v2.0.0 `wal_type.hpp` mapping is:

| Value | Name | Value | Name |
|---:|---|---:|---|
| 0 | INVALID | 20 | ALTER_INFO |
| 1 | CREATE_TABLE | 21 | CREATE_TABLE_MACRO |
| 2 | DROP_TABLE | 22 | DROP_TABLE_MACRO |
| 3 | CREATE_SCHEMA | 23 | CREATE_INDEX |
| 4 | DROP_SCHEMA | 24 | DROP_INDEX |
| 5 | CREATE_VIEW | 25 | USE_TABLE |
| 6 | DROP_VIEW | 26 | INSERT_TUPLE |
| 8 | CREATE_SEQUENCE | 27 | DELETE_TUPLE |
| 9 | DROP_SEQUENCE | 28 | UPDATE_TUPLE |
| 10 | SEQUENCE_VALUE | 29 | ROW_GROUP_DATA |
| 11 | CREATE_MACRO | 30 | CREATE_TRIGGER |
| 12 | DROP_MACRO | 31 | DROP_TRIGGER |
| 13 | CREATE_TYPE | 98 | WAL_VERSION |
| 14 | DROP_TYPE | 99 | CHECKPOINT |
| 100 | WAL_FLUSH | | |

`WriteAheadLog::Flush` writes an otherwise empty `WAL_FLUSH` object and then syncs the writer. The inspector confirms a Flush only for a checksum-valid five-byte Payload containing field 100, value 100, and the root terminator. A type marker with additional or malformed content is not a confirmed Flush.

`confirmed_flushes` records physical Entry and end offsets. `last_good_flush` is stricter: every frame from the version object through that Flush must be complete, checksum-valid, and have a trusted type envelope, and the Flush itself must pass the exact check. A later valid Flush cannot repair continuity after an earlier error. If no such boundary exists, `last_good_flush` is `null`; it is never fabricated from a length or type guess.

The last verified Flush is **not** claimed to be the last successful commit acknowledged by the application. `unterminated_data_after_last_flush` reports bytes beyond that boundary, including complete Entries without a later Flush. It is not by itself a proven safe recovery point. `recover-plan` can present this boundary as a candidate action with an explicit possible-loss interval, but never executes it.

## Checkpoint Marker

`WALCheckpoint::Deserialize` reads required property 101 as a nested `MetaBlockPointer`. `serialize_storage.cpp` defines its optional properties 100 (`block_pointer`, `idx_t`) and 101 (`offset`, `uint32_t`), followed by nested and root object terminators. The inspector outputs `checkpoint_marker` only when this complete shape and the frame checksum validate. It reports the packed `block_pointer` and `offset_within_block`; it does not follow the pointer or decode Catalog/storage contents. Otherwise the marker is `null` with an unknown or invalid-Payload diagnostic.

## Tail evidence and trailing data

The tail report distinguishes the unparsed/integrity-failed region from the physical scan stop. It records whether that region is entirely zero and independently locates a nonempty all-zero suffix reaching EOF. `zero_filled_tail` is direct byte evidence plus a low-confidence inference about possible explanations; it does not prove torn write, filesystem behavior, or a recovery action. Nonzero bytes left after structural parsing stops produce `unparsed_trailing_data`. A zero-length tail has `all_zero=null` and produces neither finding.

The committed Issue #19099 corpus contains two files derived from the same bytes at the same in-Entry cut: one is truncated there, and the other is zero-filled from there to the original EOF. Their shared offset and hashes are independently recorded. This is historical test data only; no assertion is made that the Issue still exists in current DuckDB.

## WAL coverage, unknowns, and resource limits

The WAL JSON Schema is `schemas/wal-report.schema.json`. Coverage separates bytes consumed by frame scanning from bytes belonging to physically complete frames; neither percentage claims business Payload decoding. Unknowns identify unknown types, intentionally undecoded Payloads, unavailable integrity results, and missing trusted Flush boundaries.

Defaults are a 1 TiB file budget, 1,000,000 Entry candidates, and 256 MiB declared Payload per Entry. Hashing and Payload checksum reads are chunked. Reaching a budget produces `resource_limit_reached` and a stop offset, not a corruption verdict. A file rejected by the initial size budget has `sha256=null`; later fields and tail facts remain unknown.

## Advisory recovery plans and official-engine Oracle

`recover-plan` separates direct evidence, findings, inferences, unknowns, candidate actions, and risks. A `candidate_wal_truncation` is emitted only when a continuously verified `last_good_flush` ends before EOF and the WAL hash is available without a resource-limit stop. Its possible-loss interval is exactly `[flush.end_offset, wal_file_size)`. Complete but unflushed Entries in that interval cannot be converted into a certain transaction or row count. The action requires a copy and subsequent verification; equality with EOF, no verified boundary, or incomplete/ambiguous evidence produces no action.

An official engine is invoked only through an explicit `--duckdb PATH`. The executable must report exactly `v2.0.0` in an in-memory preflight. Evidence is copied to a temporary directory and original paths are not passed to the engine. Controlled initialization disables known-extension autoinstall/autoload before a copy is attached `READ_ONLY`. Commands, bounded outputs, exit status, and timeout state are observations. Oracle behavior is compared with the limited Rust checks as `agreement`, `disagreement`, or `not_comparable`; successful opening is not a complete database-health verdict and does not erase structural findings.

## Confirmed but deliberately not implemented

- Encrypted Database Header decryption, encrypted checksum validation, and encrypted blocks.
- DuckDB v1.x storage versions and the deprecated serialization-version mapping.
- Big-endian scalar representation.
- Alternate/encrypted block-header sizes and the checksum `delta` path.
- Full Catalog deserialization.
- Meta-block/free-list payload deserialization beyond the pointer-chain checks above.
- Semantic block content validation beyond the supported checksum coverage.
- Row Groups, column compression, and row-level data.
- WAL replay, transaction reconstruction, business Payload decoding, or Catalog/Row Group semantics.
- WAL v1 framing, encrypted WAL v3 decryption, and unknown WAL versions.
- Repair, truncation, checkpointing, recovery, or generation of a replacement database.

The source files `wal_replay.cpp` and `wal_entry.hpp` are used only to establish the offline frame/envelope behavior documented above. The inspector never invokes DuckDB replay.

## Unknown or not asserted

- Whether any trailing region contains valid blocks or merely unallocated bytes.
- Whether a referenced meta/free-list block contains valid metadata.
- The physical cause of a checksum mismatch; `possible_torn_write` remains low-confidence inference.
- Whether the database can be opened successfully by DuckDB. Passing the limited header checks is not a database-health verdict.
- Any file larger than the inspector's configured 1 TiB resource budget: processing stops with `limit_reached`, and SHA-256/header results remain unknown.
