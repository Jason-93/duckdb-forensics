use std::error::Error;
use std::fmt::{Display, Formatter};

pub const WAL_VERSION_UNENCRYPTED: u64 = 2;
pub const WAL_VERSION_ENCRYPTED: u64 = 3;
pub const WAL_FRAME_HEADER_SIZE: u64 = 16;
pub const WAL_VERSION_HEADER_LIMIT: usize = 4096;

const WAL_TYPE_FIELD: u16 = 100;
const WAL_VERSION_FIELD: u16 = 101;
const WAL_DB_IDENTIFIER_FIELD: u16 = 102;
const WAL_CHECKPOINT_ITERATION_FIELD: u16 = 103;
const MESSAGE_TERMINATOR: u16 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalVersionHeader {
    pub version: u64,
    pub length: u64,
    pub database_identifier: Option<[u8; 16]>,
    pub checkpoint_iteration: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalFrameHeader {
    pub offset: u64,
    pub declared_length: u64,
    pub stored_checksum: u64,
}

impl WalFrameHeader {
    pub fn payload_offset(self) -> Option<u64> {
        self.offset.checked_add(WAL_FRAME_HEADER_SIZE)
    }

    pub fn declared_frame_end(self) -> Option<u64> {
        self.payload_offset()?.checked_add(self.declared_length)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalType {
    Invalid,
    CreateTable,
    DropTable,
    CreateSchema,
    DropSchema,
    CreateView,
    DropView,
    CreateSequence,
    DropSequence,
    SequenceValue,
    CreateMacro,
    DropMacro,
    CreateType,
    DropType,
    AlterInfo,
    CreateTableMacro,
    DropTableMacro,
    CreateIndex,
    DropIndex,
    UseTable,
    InsertTuple,
    DeleteTuple,
    UpdateTuple,
    RowGroupData,
    CreateTrigger,
    DropTrigger,
    WalVersion,
    Checkpoint,
    WalFlush,
}

impl WalType {
    pub fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Invalid,
            1 => Self::CreateTable,
            2 => Self::DropTable,
            3 => Self::CreateSchema,
            4 => Self::DropSchema,
            5 => Self::CreateView,
            6 => Self::DropView,
            8 => Self::CreateSequence,
            9 => Self::DropSequence,
            10 => Self::SequenceValue,
            11 => Self::CreateMacro,
            12 => Self::DropMacro,
            13 => Self::CreateType,
            14 => Self::DropType,
            20 => Self::AlterInfo,
            21 => Self::CreateTableMacro,
            22 => Self::DropTableMacro,
            23 => Self::CreateIndex,
            24 => Self::DropIndex,
            25 => Self::UseTable,
            26 => Self::InsertTuple,
            27 => Self::DeleteTuple,
            28 => Self::UpdateTuple,
            29 => Self::RowGroupData,
            30 => Self::CreateTrigger,
            31 => Self::DropTrigger,
            98 => Self::WalVersion,
            99 => Self::Checkpoint,
            100 => Self::WalFlush,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::CreateTable => "create_table",
            Self::DropTable => "drop_table",
            Self::CreateSchema => "create_schema",
            Self::DropSchema => "drop_schema",
            Self::CreateView => "create_view",
            Self::DropView => "drop_view",
            Self::CreateSequence => "create_sequence",
            Self::DropSequence => "drop_sequence",
            Self::SequenceValue => "sequence_value",
            Self::CreateMacro => "create_macro",
            Self::DropMacro => "drop_macro",
            Self::CreateType => "create_type",
            Self::DropType => "drop_type",
            Self::AlterInfo => "alter_info",
            Self::CreateTableMacro => "create_table_macro",
            Self::DropTableMacro => "drop_table_macro",
            Self::CreateIndex => "create_index",
            Self::DropIndex => "drop_index",
            Self::UseTable => "use_table",
            Self::InsertTuple => "insert_tuple",
            Self::DeleteTuple => "delete_tuple",
            Self::UpdateTuple => "update_tuple",
            Self::RowGroupData => "row_group_data",
            Self::CreateTrigger => "create_trigger",
            Self::DropTrigger => "drop_trigger",
            Self::WalVersion => "wal_version",
            Self::Checkpoint => "checkpoint",
            Self::WalFlush => "wal_flush",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalEntryType {
    pub raw_type: u8,
    pub entry_type: Option<WalType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalCheckpointMarker {
    pub block_pointer: u64,
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalPayloadErrorKind {
    UnexpectedEnd,
    UnexpectedField,
    InvalidVarInt,
    IntegerOverflow,
    InvalidIdentifierLength,
    TrailingData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalPayloadError {
    pub offset: usize,
    pub kind: WalPayloadErrorKind,
}

impl Display for WalPayloadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid WAL serialization at payload offset {}: {:?}",
            self.offset, self.kind
        )
    }
}

impl Error for WalPayloadError {}

pub fn parse_wal_version_header(bytes: &[u8]) -> Result<WalVersionHeader, WalPayloadError> {
    let mut cursor = Cursor::new(bytes);
    cursor.expect_field(WAL_TYPE_FIELD)?;
    let wal_type = cursor.read_u8()?;
    if WalType::from_raw(wal_type) != Some(WalType::WalVersion) {
        return Err(cursor.error(WalPayloadErrorKind::UnexpectedField));
    }
    cursor.expect_field(WAL_VERSION_FIELD)?;
    let version = cursor.read_u64()?;

    let mut database_identifier = None;
    if cursor.peek_field()? == WAL_DB_IDENTIFIER_FIELD {
        cursor.read_field()?;
        let count = cursor.read_u64()?;
        if count != 16 {
            return Err(cursor.error(WalPayloadErrorKind::InvalidIdentifierLength));
        }
        let mut identifier = [0_u8; 16];
        for byte in &mut identifier {
            *byte = cursor.read_u8()?;
        }
        database_identifier = Some(identifier);
    }

    let mut checkpoint_iteration = None;
    if cursor.peek_field()? == WAL_CHECKPOINT_ITERATION_FIELD {
        cursor.read_field()?;
        let raw_iteration = cursor.read_u64()?;
        if raw_iteration != u64::MAX {
            checkpoint_iteration = Some(raw_iteration);
        }
    }
    cursor.expect_field(MESSAGE_TERMINATOR)?;

    Ok(WalVersionHeader {
        version,
        length: cursor.position as u64,
        database_identifier,
        checkpoint_iteration,
    })
}

pub fn parse_wal_frame_header(bytes: [u8; 16], offset: u64) -> WalFrameHeader {
    let mut length = [0_u8; 8];
    length.copy_from_slice(&bytes[..8]);
    let mut checksum = [0_u8; 8];
    checksum.copy_from_slice(&bytes[8..]);
    WalFrameHeader {
        offset,
        declared_length: u64::from_le_bytes(length),
        stored_checksum: u64::from_le_bytes(checksum),
    }
}

pub fn parse_wal_entry_type(bytes: &[u8]) -> Result<WalEntryType, WalPayloadError> {
    let mut cursor = Cursor::new(bytes);
    cursor.expect_field(WAL_TYPE_FIELD)?;
    let raw_type = cursor.read_u8()?;
    Ok(WalEntryType {
        raw_type,
        entry_type: WalType::from_raw(raw_type),
    })
}

pub fn is_confirmed_wal_flush(bytes: &[u8]) -> bool {
    if parse_wal_entry_type(bytes)
        .ok()
        .and_then(|entry| entry.entry_type)
        != Some(WalType::WalFlush)
    {
        return false;
    }
    bytes.len() == 5 && bytes[3..5] == MESSAGE_TERMINATOR.to_le_bytes()
}

pub fn parse_wal_checkpoint_marker(
    bytes: &[u8],
) -> Result<Option<WalCheckpointMarker>, WalPayloadError> {
    let mut cursor = Cursor::new(bytes);
    cursor.expect_field(WAL_TYPE_FIELD)?;
    let raw_type = cursor.read_u8()?;
    if WalType::from_raw(raw_type) != Some(WalType::Checkpoint) {
        return Ok(None);
    }
    cursor.expect_field(WAL_VERSION_FIELD)?;

    let mut block_pointer = 0_u64;
    if cursor.peek_field()? == WAL_TYPE_FIELD {
        cursor.read_field()?;
        block_pointer = cursor.read_u64()?;
    }
    let mut offset = 0_u32;
    if cursor.peek_field()? == WAL_VERSION_FIELD {
        cursor.read_field()?;
        offset = cursor.read_u32()?;
    }
    cursor.expect_field(MESSAGE_TERMINATOR)?;
    cursor.expect_field(MESSAGE_TERMINATOR)?;
    if !cursor.is_empty() {
        return Err(cursor.error(WalPayloadErrorKind::TrailingData));
    }
    Ok(Some(WalCheckpointMarker {
        block_pointer,
        offset,
    }))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn error(&self, kind: WalPayloadErrorKind) -> WalPayloadError {
        WalPayloadError {
            offset: self.position,
            kind,
        }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_byte(&mut self) -> Result<u8, WalPayloadError> {
        let Some(byte) = self.bytes.get(self.position).copied() else {
            return Err(self.error(WalPayloadErrorKind::UnexpectedEnd));
        };
        self.position += 1;
        Ok(byte)
    }

    fn read_field(&mut self) -> Result<u16, WalPayloadError> {
        let low = self.read_byte()?;
        let high = self.read_byte()?;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn peek_field(&self) -> Result<u16, WalPayloadError> {
        let Some(bytes) = self
            .bytes
            .get(self.position..self.position.saturating_add(2))
        else {
            return Err(self.error(WalPayloadErrorKind::UnexpectedEnd));
        };
        if bytes.len() != 2 {
            return Err(self.error(WalPayloadErrorKind::UnexpectedEnd));
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn expect_field(&mut self, expected: u16) -> Result<(), WalPayloadError> {
        let actual = self.read_field()?;
        if actual != expected {
            return Err(self.error(WalPayloadErrorKind::UnexpectedField));
        }
        Ok(())
    }

    fn read_u64(&mut self) -> Result<u64, WalPayloadError> {
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = self.read_byte()?;
            let payload = u64::from(byte & 0x7f);
            if index == 9 && payload > 1 {
                return Err(self.error(WalPayloadErrorKind::IntegerOverflow));
            }
            value |= payload << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(self.error(WalPayloadErrorKind::InvalidVarInt))
    }

    fn read_u8(&mut self) -> Result<u8, WalPayloadError> {
        let value = self.read_u64()?;
        u8::try_from(value).map_err(|_| self.error(WalPayloadErrorKind::IntegerOverflow))
    }

    fn read_u32(&mut self) -> Result<u32, WalPayloadError> {
        let value = self.read_u64()?;
        u32::try_from(value).map_err(|_| self.error(WalPayloadErrorKind::IntegerOverflow))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_header(version: u64) -> Vec<u8> {
        let mut bytes = vec![100, 0, 98, 101, 0];
        bytes.extend(match version {
            1 => vec![1],
            2 => vec![2],
            3 => vec![3],
            _ => unreachable!(),
        });
        bytes.extend([255, 255]);
        bytes
    }

    #[test]
    fn version_header_is_not_a_framed_entry() {
        let bytes = version_header(2);
        let header = parse_wal_version_header(&bytes).expect("valid version header");
        assert_eq!(header.version, 2);
        assert_eq!(header.length as usize, bytes.len());
        assert_eq!(&bytes[..2], &100_u16.to_le_bytes());
        assert_eq!(bytes[2], 98);
    }

    #[test]
    fn frame_header_uses_little_endian_length_and_checksum() {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&42_u64.to_le_bytes());
        bytes[8..].copy_from_slice(&123_u64.to_le_bytes());
        let header = parse_wal_frame_header(bytes, 99);
        assert_eq!(header.declared_length, 42);
        assert_eq!(header.stored_checksum, 123);
        assert_eq!(header.payload_offset(), Some(115));
        assert_eq!(header.declared_frame_end(), Some(157));
    }

    #[test]
    fn entry_type_follows_field_id_and_uses_leb128() {
        let entry = parse_wal_entry_type(&[100, 0, 100, 255, 255]).expect("valid type");
        assert_eq!(entry.raw_type, 100);
        assert_eq!(entry.entry_type, Some(WalType::WalFlush));
        assert!(is_confirmed_wal_flush(&[100, 0, 100, 255, 255]));
        assert!(!is_confirmed_wal_flush(&[100, 0, 100, 0, 255, 255]));
    }

    #[test]
    fn checkpoint_requires_complete_nested_object() {
        let payload = [
            100, 0, 99, 101, 0, 100, 0, 42, 101, 0, 7, 255, 255, 255, 255,
        ];
        let marker = parse_wal_checkpoint_marker(&payload)
            .expect("valid checkpoint")
            .expect("checkpoint present");
        assert_eq!(marker.block_pointer, 42);
        assert_eq!(marker.offset, 7);
        assert!(parse_wal_checkpoint_marker(&payload[..payload.len() - 1]).is_err());
    }

    #[test]
    fn malformed_varints_and_random_bytes_return_errors() {
        for bytes in [&[][..], &[100][..], &[100, 0, 128][..]] {
            assert!(parse_wal_entry_type(bytes).is_err());
        }
        let mut overflow = vec![100, 0];
        overflow.extend([0x80; 9]);
        overflow.push(2);
        assert!(parse_wal_entry_type(&overflow).is_err());
        assert!(parse_wal_version_header(&[0; 32]).is_err());
    }
}
