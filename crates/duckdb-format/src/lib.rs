#![forbid(unsafe_code)]

pub mod wal;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Seek, SeekFrom};

pub const FILE_HEADER_SIZE: u64 = 4096;
pub const BLOCK_START: u64 = FILE_HEADER_SIZE * 3;
pub const DEFAULT_BLOCK_HEADER_SIZE: usize = 8;
pub const MAIN_HEADER_VERSION_DEPRECATED: u64 = 999;
pub const STORAGE_VERSION_V2_0_0: u64 = 69;
pub const DEFAULT_BLOCK_ALLOC_SIZE: u64 = 262_144;
pub const MIN_BLOCK_ALLOC_SIZE: u64 = 16_384;
pub const MAX_BLOCK_ALLOC_SIZE: u64 = 262_144;
pub const STANDARD_VECTOR_SIZE: u64 = 2048;
pub const MAXIMUM_BLOCK: u64 = 4_611_686_018_427_388_000;
pub const INVALID_BLOCK: u64 = u64::MAX;
pub const METADATA_BLOCK_COUNT: u64 = 64;

const CHECKSUM_WORD_MULTIPLIER: u64 = 0xbf58_476d_1ce4_e5b9;
const CHECKSUM_REMAINDER_MULTIPLIER: u64 = 0xc6a4_a793_5bd1_e995;
const CHECKSUM_REMAINDER_SEED: u64 = 0xe17a_1465;
const CHECKSUM_REMAINDER_SHIFT: u32 = 47;

#[derive(Debug)]
pub enum FormatError {
    Io {
        operation: &'static str,
        offset: u64,
        source: io::Error,
    },
    InsufficientData {
        structure: &'static str,
        offset: u64,
        needed: usize,
        available: usize,
    },
}

impl Display for FormatError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io {
                operation,
                offset,
                source,
            } => write!(
                formatter,
                "failed to {operation} at file offset {offset}: {source}"
            ),
            Self::InsufficientData {
                structure,
                offset,
                needed,
                available,
            } => write!(
                formatter,
                "insufficient data for {structure} at file offset {offset}: need {needed} bytes, have {available}"
            ),
        }
    }
}

impl Error for FormatError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InsufficientData { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeaderPage {
    pub offset: u64,
    pub available: usize,
    bytes: [u8; FILE_HEADER_SIZE as usize],
}

impl HeaderPage {
    pub fn is_complete(&self) -> bool {
        self.available == FILE_HEADER_SIZE as usize
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.available]
    }

    pub fn checksum(&self) -> Result<ChecksumObservation, FormatError> {
        if !self.is_complete() {
            return Err(FormatError::InsufficientData {
                structure: "header checksum",
                offset: self.offset,
                needed: FILE_HEADER_SIZE as usize,
                available: self.available,
            });
        }
        let stored_checksum = read_u64(&self.bytes, 0, self.available, "stored checksum")?;
        let computed_checksum = duckdb_checksum(&self.bytes[DEFAULT_BLOCK_HEADER_SIZE..]);
        Ok(ChecksumObservation {
            stored_checksum,
            computed_checksum,
            matches: stored_checksum == computed_checksum,
        })
    }
}

pub fn read_header_page<R: Read + Seek>(
    file: &mut R,
    offset: u64,
) -> Result<HeaderPage, FormatError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| FormatError::Io {
            operation: "seek",
            offset,
            source,
        })?;

    let mut bytes = [0_u8; FILE_HEADER_SIZE as usize];
    let mut available = 0_usize;
    while available < bytes.len() {
        match file.read(&mut bytes[available..]) {
            Ok(0) => break,
            Ok(count) => {
                available = available
                    .checked_add(count)
                    .ok_or(FormatError::InsufficientData {
                        structure: "header read length",
                        offset,
                        needed: bytes.len(),
                        available,
                    })?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(FormatError::Io {
                    operation: "read",
                    offset: offset.saturating_add(available as u64),
                    source,
                });
            }
        }
    }

    Ok(HeaderPage {
        offset,
        available,
        bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumObservation {
    pub stored_checksum: u64,
    pub computed_checksum: u64,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeader {
    pub magic_bytes: [u8; 4],
    pub version_number: u64,
    pub flags: [u64; 4],
    pub library_git_desc: [u8; 32],
    pub library_git_hash: [u8; 32],
    pub encryption_metadata: [u8; 8],
    pub db_identifier: [u8; 16],
    pub encrypted_canary: [u8; 8],
    pub canary_iv: [u8; 12],
    pub canary_tag: [u8; 16],
}

impl MainHeader {
    pub const SERIALIZED_END: usize = 176;

    pub fn parse(page: &HeaderPage) -> Result<Self, FormatError> {
        let available = page.available;
        let bytes = &page.bytes;
        Ok(Self {
            magic_bytes: read_array(bytes, 8, available, "magic bytes")?,
            version_number: read_u64(bytes, 12, available, "main header version")?,
            flags: [
                read_u64(bytes, 20, available, "main header flag 0")?,
                read_u64(bytes, 28, available, "main header flag 1")?,
                read_u64(bytes, 36, available, "main header flag 2")?,
                read_u64(bytes, 44, available, "main header flag 3")?,
            ],
            library_git_desc: read_array(bytes, 52, available, "library version")?,
            library_git_hash: read_array(bytes, 84, available, "library source hash")?,
            encryption_metadata: read_array(bytes, 116, available, "encryption metadata")?,
            db_identifier: read_array(bytes, 124, available, "database identifier")?,
            encrypted_canary: read_array(bytes, 140, available, "encrypted canary")?,
            canary_iv: read_array(bytes, 148, available, "canary IV")?,
            canary_tag: read_array(bytes, 160, available, "canary tag")?,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags[0] & 1 != 0
    }

    pub fn magic_is_valid(&self) -> bool {
        self.magic_bytes == *b"DUCK"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseHeader {
    pub iteration: u64,
    pub meta_block: u64,
    pub free_list: u64,
    pub block_count: u64,
    pub block_alloc_size: u64,
    pub vector_size: u64,
    pub storage_compatibility: u64,
}

impl DatabaseHeader {
    pub const SERIALIZED_END: usize = 64;

    pub fn parse(page: &HeaderPage) -> Result<Self, FormatError> {
        let available = page.available;
        let bytes = &page.bytes;
        Ok(Self {
            iteration: read_u64(bytes, 8, available, "database header iteration")?,
            meta_block: read_u64(bytes, 16, available, "meta block")?,
            free_list: read_u64(bytes, 24, available, "free list")?,
            block_count: read_u64(bytes, 32, available, "block count")?,
            block_alloc_size: read_u64(bytes, 40, available, "block allocation size")?,
            vector_size: read_u64(bytes, 48, available, "vector size")?,
            storage_compatibility: read_u64(bytes, 56, available, "storage compatibility")?,
        })
    }

    pub fn effective_block_alloc_size(&self) -> u64 {
        if self.block_alloc_size == 0 {
            DEFAULT_BLOCK_ALLOC_SIZE
        } else {
            self.block_alloc_size
        }
    }

    pub fn effective_vector_size(&self) -> u64 {
        if self.vector_size == 0 {
            STANDARD_VECTOR_SIZE
        } else {
            self.vector_size
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAllocSizeError {
    NotPowerOfTwo(u64),
    TooSmall(u64),
    TooLarge(u64),
}

pub fn verify_block_alloc_size(block_alloc_size: u64) -> Result<(), BlockAllocSizeError> {
    if !block_alloc_size.is_power_of_two() {
        return Err(BlockAllocSizeError::NotPowerOfTwo(block_alloc_size));
    }
    if block_alloc_size < MIN_BLOCK_ALLOC_SIZE {
        return Err(BlockAllocSizeError::TooSmall(block_alloc_size));
    }
    if block_alloc_size > MAX_BLOCK_ALLOC_SIZE {
        return Err(BlockAllocSizeError::TooLarge(block_alloc_size));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryError {
    BlockCountTooLarge(u64),
    ByteLengthOverflow,
    FileEndOverflow,
}

pub fn checked_recorded_file_end(
    block_count: u64,
    block_alloc_size: u64,
) -> Result<u64, GeometryError> {
    if block_count > MAXIMUM_BLOCK {
        return Err(GeometryError::BlockCountTooLarge(block_count));
    }
    let byte_length = block_count
        .checked_mul(block_alloc_size)
        .ok_or(GeometryError::ByteLengthOverflow)?;
    BLOCK_START
        .checked_add(byte_length)
        .ok_or(GeometryError::FileEndOverflow)
}

pub fn checked_block_location(block_id: u64, block_alloc_size: u64) -> Result<u64, GeometryError> {
    if block_id > MAXIMUM_BLOCK {
        return Err(GeometryError::BlockCountTooLarge(block_id));
    }
    let relative_offset = block_id
        .checked_mul(block_alloc_size)
        .ok_or(GeometryError::ByteLengthOverflow)?;
    BLOCK_START
        .checked_add(relative_offset)
        .ok_or(GeometryError::FileEndOverflow)
}

pub fn unpack_metadata_pointer(raw_pointer: u64) -> (u64, u64) {
    (raw_pointer & 0x00ff_ffff_ffff_ffff, raw_pointer >> 56)
}

pub fn metadata_block_size(block_alloc_size: u64) -> u64 {
    (block_alloc_size.saturating_sub(DEFAULT_BLOCK_HEADER_SIZE as u64) / METADATA_BLOCK_COUNT) & !7
}

pub fn checked_metadata_location(
    block_id: u64,
    metadata_index: u64,
    block_alloc_size: u64,
) -> Result<u64, GeometryError> {
    let block_offset = checked_block_location(block_id, block_alloc_size)?;
    let relative_offset = metadata_index
        .checked_mul(metadata_block_size(block_alloc_size))
        .ok_or(GeometryError::ByteLengthOverflow)?;
    block_offset
        .checked_add(DEFAULT_BLOCK_HEADER_SIZE as u64)
        .and_then(|offset| offset.checked_add(relative_offset))
        .ok_or(GeometryError::FileEndOverflow)
}

pub fn duckdb_checksum(buffer: &[u8]) -> u64 {
    let mut checksum = DuckDbChecksum::new();
    checksum.update(buffer);
    checksum.finalize()
}

#[derive(Debug, Clone)]
pub struct DuckDbChecksum {
    result: u64,
    remainder: [u8; 8],
    remainder_len: usize,
}

impl Default for DuckDbChecksum {
    fn default() -> Self {
        Self::new()
    }
}

impl DuckDbChecksum {
    pub fn new() -> Self {
        Self {
            result: 5381,
            remainder: [0; 8],
            remainder_len: 0,
        }
    }

    pub fn update(&mut self, mut buffer: &[u8]) {
        if self.remainder_len != 0 {
            let needed = 8 - self.remainder_len;
            let copied = needed.min(buffer.len());
            self.remainder[self.remainder_len..self.remainder_len + copied]
                .copy_from_slice(&buffer[..copied]);
            self.remainder_len += copied;
            buffer = &buffer[copied..];
            if self.remainder_len == 8 {
                let word = u64::from_le_bytes(self.remainder);
                self.result ^= word.wrapping_mul(CHECKSUM_WORD_MULTIPLIER);
                self.remainder_len = 0;
            }
        }
        if self.remainder_len != 0 {
            return;
        }

        let (chunks, remainder) = buffer.as_chunks::<8>();
        for chunk in chunks {
            let word = u64::from_le_bytes(*chunk);
            self.result ^= word.wrapping_mul(CHECKSUM_WORD_MULTIPLIER);
        }
        self.remainder[..remainder.len()].copy_from_slice(remainder);
        self.remainder_len = remainder.len();
    }

    pub fn finalize(mut self) -> u64 {
        if self.remainder_len != 0 {
            self.result ^= checksum_remainder(&self.remainder[..self.remainder_len]);
        }
        self.result
    }
}

fn checksum_remainder(buffer: &[u8]) -> u64 {
    let length = buffer.len();
    let mut hash =
        CHECKSUM_REMAINDER_SEED ^ (length as u64).wrapping_mul(CHECKSUM_REMAINDER_MULTIPLIER);
    let (chunks, remainder) = buffer.as_chunks::<8>();
    for chunk in chunks {
        let mut word = u64::from_le_bytes(*chunk);
        word = word.wrapping_mul(CHECKSUM_REMAINDER_MULTIPLIER);
        word ^= word >> CHECKSUM_REMAINDER_SHIFT;
        word = word.wrapping_mul(CHECKSUM_REMAINDER_MULTIPLIER);
        hash ^= word;
        hash = hash.wrapping_mul(CHECKSUM_REMAINDER_MULTIPLIER);
    }

    for (index, byte) in remainder.iter().enumerate() {
        hash ^= u64::from(*byte) << (index * 8);
    }
    if !remainder.is_empty() {
        hash = hash.wrapping_mul(CHECKSUM_REMAINDER_MULTIPLIER);
    }
    hash ^= hash >> CHECKSUM_REMAINDER_SHIFT;
    hash = hash.wrapping_mul(CHECKSUM_REMAINDER_MULTIPLIER);
    hash ^= hash >> CHECKSUM_REMAINDER_SHIFT;
    hash
}

fn read_u64(
    bytes: &[u8; FILE_HEADER_SIZE as usize],
    offset: usize,
    available: usize,
    structure: &'static str,
) -> Result<u64, FormatError> {
    let end = offset.checked_add(8).ok_or(FormatError::InsufficientData {
        structure,
        offset: offset as u64,
        needed: 8,
        available,
    })?;
    if end > available {
        return Err(FormatError::InsufficientData {
            structure,
            offset: offset as u64,
            needed: 8,
            available: available.saturating_sub(offset),
        });
    }
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..end]);
    Ok(u64::from_le_bytes(value))
}

fn read_array<const N: usize>(
    bytes: &[u8; FILE_HEADER_SIZE as usize],
    offset: usize,
    available: usize,
    structure: &'static str,
) -> Result<[u8; N], FormatError> {
    let end = offset.checked_add(N).ok_or(FormatError::InsufficientData {
        structure,
        offset: offset as u64,
        needed: N,
        available,
    })?;
    if end > available {
        return Err(FormatError::InsufficientData {
            structure,
            offset: offset as u64,
            needed: N,
            available: available.saturating_sub(offset),
        });
    }
    let mut value = [0_u8; N];
    value.copy_from_slice(&bytes[offset..end]);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_empty_and_complete_words_match_source_definition() {
        assert_eq!(duckdb_checksum(&[]), 5381);
        assert_eq!(duckdb_checksum(&[0; 8]), 5381);
        assert_eq!(
            duckdb_checksum(&1_u64.to_le_bytes()),
            5381 ^ CHECKSUM_WORD_MULTIPLIER
        );
    }

    #[test]
    fn streaming_checksum_matches_one_shot_for_every_split() {
        let bytes: Vec<u8> = (0..=255).collect();
        let expected = duckdb_checksum(&bytes);
        for split in 0..=bytes.len() {
            let mut checksum = DuckDbChecksum::new();
            checksum.update(&bytes[..split]);
            checksum.update(&bytes[split..]);
            assert_eq!(checksum.finalize(), expected, "split {split}");
        }
        let mut bytewise = DuckDbChecksum::new();
        for byte in &bytes {
            bytewise.update(&[*byte]);
        }
        assert_eq!(bytewise.finalize(), expected);
    }

    #[test]
    fn block_alloc_size_rules_match_duckdb() {
        assert!(verify_block_alloc_size(16_384).is_ok());
        assert!(verify_block_alloc_size(262_144).is_ok());
        assert_eq!(
            verify_block_alloc_size(30_000),
            Err(BlockAllocSizeError::NotPowerOfTwo(30_000))
        );
        assert_eq!(
            verify_block_alloc_size(8192),
            Err(BlockAllocSizeError::TooSmall(8192))
        );
        assert_eq!(
            verify_block_alloc_size(524_288),
            Err(BlockAllocSizeError::TooLarge(524_288))
        );
        assert_eq!(
            verify_block_alloc_size(0),
            Err(BlockAllocSizeError::NotPowerOfTwo(0))
        );
    }

    #[test]
    fn metadata_geometry_matches_v2_layout() {
        assert_eq!(metadata_block_size(DEFAULT_BLOCK_ALLOC_SIZE), 4088);
        assert_eq!(unpack_metadata_pointer(0x0200_0000_0000_0000), (0, 2));
        assert_eq!(
            checked_metadata_location(0, 2, DEFAULT_BLOCK_ALLOC_SIZE),
            Ok(20_472)
        );
        assert_eq!(metadata_block_size(0), 0);
    }

    #[test]
    fn geometry_uses_checked_arithmetic() {
        assert_eq!(checked_recorded_file_end(0, 262_144), Ok(12_288));
        assert_eq!(checked_recorded_file_end(2, 262_144), Ok(12_288 + 524_288));
        assert_eq!(
            checked_recorded_file_end(u64::MAX, 262_144),
            Err(GeometryError::BlockCountTooLarge(u64::MAX))
        );
        assert_eq!(
            checked_recorded_file_end(MAXIMUM_BLOCK, 262_144),
            Err(GeometryError::ByteLengthOverflow)
        );
        assert_eq!(
            checked_block_location(MAXIMUM_BLOCK, 262_144),
            Err(GeometryError::ByteLengthOverflow)
        );
    }

    struct ShortReads {
        cursor: std::io::Cursor<Vec<u8>>,
    }

    impl Read for ShortReads {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(3);
            self.cursor.read(&mut buffer[..limit])
        }
    }

    impl Seek for ShortReads {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.cursor.seek(position)
        }
    }

    #[test]
    fn header_reads_join_short_reads_and_report_real_eof() {
        let mut reader = ShortReads {
            cursor: std::io::Cursor::new(vec![7; FILE_HEADER_SIZE as usize]),
        };
        let page = read_header_page(&mut reader, 0).expect("complete page");
        assert!(page.is_complete());
        assert_eq!(page.available, FILE_HEADER_SIZE as usize);

        let mut reader = ShortReads {
            cursor: std::io::Cursor::new(vec![7; 17]),
        };
        let page = read_header_page(&mut reader, 0).expect("partial page");
        assert_eq!(page.available, 17);
        assert!(!page.is_complete());
    }
}
