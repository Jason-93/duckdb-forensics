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
- [`src/storage/checkpoint_manager.cpp`](https://github.com/duckdb/duckdb/blob/v2.0.0/src/storage/checkpoint_manager.cpp)

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

The `DatabaseHeader::block_count` source comment explicitly states that blocks after `block_count` are implicitly part of the free list when the file is larger. Thus `file_size > expected_recorded_file_end` is reported as `beyond_header_block_count`, not automatically called corruption. No payload or trailing-block validation is performed.

The decoded meta-block and free-list block ids are converted to offsets only with checked arithmetic. Their targets and contents are not followed.

## Fixture provenance

`crates/duckdb-forensics/tests/fixtures/normal.duckdb` was generated by `scripts/generate_fixture.py` using the official `duckdb-cli-osx-arm64.tar.gz` v2.0.0 release asset. The generator verifies the asset SHA-256 and `SELECT version()` before creating a two-row test table and checkpointing it.

The independently generated `normal.manifest.json` records the release URL, asset digest, fixture SHA-256, raw header fields, and stored checksums. DuckDB generates a random database identifier, so regeneration is procedurally repeatable but is not expected to be byte-for-byte identical.

## Confirmed but deliberately not implemented

- Encrypted Database Header decryption, encrypted checksum validation, and encrypted blocks.
- DuckDB v1.x storage versions and the deprecated serialization-version mapping.
- Big-endian scalar representation.
- Alternate/encrypted block-header sizes and the checksum `delta` path.
- Full Catalog deserialization.
- Meta-block/free-list payload parsing beyond the packed-pointer geometry above.
- Block payload checksums and content validation.
- Row Groups, column compression, and row-level data.
- WAL discovery, replay, or WAL entry semantics.
- Repair, truncation, checkpointing, recovery, or generation of a replacement database.

The source files `wal_replay.cpp` and `wal_entry.hpp` are intentionally not used to infer any phase-1 structure. No WAL parser is implemented.

## Unknown or not asserted

- Whether any trailing region contains valid blocks or merely unallocated bytes.
- Whether a referenced meta/free-list block contains valid metadata.
- The physical cause of a checksum mismatch; `possible_torn_write` remains low-confidence inference.
- Whether the database can be opened successfully by DuckDB. Passing the limited header checks is not a database-health verdict.
- Any file larger than the inspector's configured 1 TiB resource budget: processing stops with `limit_reached`, and SHA-256/header results remain unknown.
