#![forbid(unsafe_code)]

use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};

use duckdb_format::wal::{
    WalFrameHeader, parse_wal_checkpoint_marker, parse_wal_entry_type, parse_wal_version_header,
};
use duckdb_format::{
    BLOCK_START, DuckDbChecksum, FILE_HEADER_SIZE, MainHeader, checked_block_location,
    checked_metadata_location, checked_recorded_file_end, duckdb_checksum, read_header_page,
};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 64,
        max_shrink_iters: 10_000,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn wal_parsers_do_not_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let version = catch_unwind(AssertUnwindSafe(|| parse_wal_version_header(&bytes)));
        let entry = catch_unwind(AssertUnwindSafe(|| parse_wal_entry_type(&bytes)));
        let checkpoint = catch_unwind(AssertUnwindSafe(|| parse_wal_checkpoint_marker(&bytes)));
        prop_assert!(version.is_ok());
        prop_assert!(entry.is_ok());
        prop_assert!(checkpoint.is_ok());
    }

    #[test]
    fn frame_and_block_geometry_never_overflow(
        offset in any::<u64>(),
        declared_length in any::<u64>(),
        block_count in any::<u64>(),
        block_alloc_size in any::<u64>(),
        metadata_index in any::<u64>(),
    ) {
        let frame = WalFrameHeader {
            offset,
            declared_length,
            stored_checksum: 0,
        };
        if let Some(end) = frame.declared_frame_end() {
            prop_assert!(end >= offset);
            prop_assert_eq!(end - offset, 16 + declared_length);
        }
        let file_end = catch_unwind(AssertUnwindSafe(|| {
            checked_recorded_file_end(block_count, block_alloc_size)
        }));
        let block = catch_unwind(AssertUnwindSafe(|| {
            checked_block_location(block_count, block_alloc_size)
        }));
        let metadata = catch_unwind(AssertUnwindSafe(|| {
            checked_metadata_location(block_count, metadata_index, block_alloc_size)
        }));
        prop_assert!(file_end.is_ok());
        prop_assert!(block.is_ok());
        prop_assert!(metadata.is_ok());
        if let Ok(location) = checked_block_location(block_count, block_alloc_size) {
            prop_assert!(location >= BLOCK_START);
        }
    }

    #[test]
    fn checksum_is_identical_for_arbitrary_chunking(
        bytes in prop::collection::vec(any::<u8>(), 0..1024),
        chunk_size in 1_usize..65,
    ) {
        let expected = duckdb_checksum(&bytes);
        let mut streaming = DuckDbChecksum::new();
        for chunk in bytes.chunks(chunk_size) {
            streaming.update(chunk);
        }
        prop_assert_eq!(streaming.finalize(), expected);
    }

    #[test]
    fn header_parsing_handles_every_short_length(bytes in prop::collection::vec(any::<u8>(), 0..5000)) {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut cursor = Cursor::new(&bytes);
            let page = read_header_page(&mut cursor, 0)?;
            let parsed = MainHeader::parse(&page);
            Ok::<_, duckdb_format::FormatError>((page.available, parsed))
        }));
        prop_assert!(outcome.is_ok());
        let (available, parsed) = outcome.expect("no panic").expect("in-memory read");
        prop_assert!(available <= FILE_HEADER_SIZE as usize);
        prop_assert_eq!(parsed.is_ok(), available >= MainHeader::SERIALIZED_END);
    }
}
