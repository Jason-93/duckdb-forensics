#!/usr/bin/env python3
"""Generate deterministic DuckDB v2.0.0 WAL frame fixtures without DuckDB or Rust."""

import hashlib
import json
import struct
from pathlib import Path

MASK = (1 << 64) - 1
WORD_MULTIPLIER = 0xBF58476D1CE4E5B9
REMAINDER_MULTIPLIER = 0xC6A4A7935BD1E995
REMAINDER_SEED = 0xE17A1465


def uleb128(value):
    if value < 0:
        raise ValueError("unsigned LEB128 cannot encode a negative value")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def field(field_id):
    return struct.pack("<H", field_id)


def checksum_remainder(data):
    value = REMAINDER_SEED ^ ((len(data) * REMAINDER_MULTIPLIER) & MASK)
    for index, byte in enumerate(data):
        value ^= byte << (index * 8)
    if data:
        value = (value * REMAINDER_MULTIPLIER) & MASK
    value ^= value >> 47
    value = (value * REMAINDER_MULTIPLIER) & MASK
    value ^= value >> 47
    return value & MASK


def duckdb_checksum(data):
    result = 5381
    complete = len(data) - len(data) % 8
    for offset in range(0, complete, 8):
        word = struct.unpack_from("<Q", data, offset)[0]
        result ^= (word * WORD_MULTIPLIER) & MASK
    if complete != len(data):
        result ^= checksum_remainder(data[complete:])
    return result & MASK


def version_header(version=2, with_identifier=True):
    payload = field(100) + uleb128(98) + field(101) + uleb128(version)
    if with_identifier:
        payload += field(102) + uleb128(16) + bytes(range(16))
        payload += field(103) + uleb128(7)
    return payload + field(0xFFFF)


def flush_payload():
    return field(100) + uleb128(100) + field(0xFFFF)


def checkpoint_payload(block_pointer=42, offset=7):
    return (
        field(100)
        + uleb128(99)
        + field(101)
        + field(100)
        + uleb128(block_pointer)
        + field(101)
        + uleb128(offset)
        + field(0xFFFF)
        + field(0xFFFF)
    )


def frame(payload):
    return struct.pack("<QQ", len(payload), duckdb_checksum(payload)) + payload


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def entry_manifest(entries, offset, payload, entry_type):
    end = offset + 16 + len(payload)
    entries.append(
        {
            "index": len(entries),
            "offset": offset,
            "payload_offset": offset + 16,
            "declared_length": len(payload),
            "actual_length": len(payload),
            "declared_frame_end": end,
            "actual_frame_end": end,
            "stored_checksum": f"0x{duckdb_checksum(payload):016x}",
            "entry_type": entry_type,
        }
    )
    return end


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    output = Path(__file__).resolve().parent.parent / "crates/duckdb-forensics/tests/fixtures"
    output.mkdir(parents=True, exist_ok=True)
    header = version_header()
    entries = []
    normal = bytearray(header)
    offset = entry_manifest(entries, len(normal), flush_payload(), "wal_flush")
    normal.extend(frame(flush_payload()))
    first_flush_end = offset
    offset = entry_manifest(entries, offset, checkpoint_payload(), "checkpoint")
    normal.extend(frame(checkpoint_payload()))
    checkpoint_offset = entries[-1]["offset"]
    offset = entry_manifest(entries, offset, flush_payload(), "wal_flush")
    normal.extend(frame(flush_payload()))
    assert offset == len(normal)
    normal = bytes(normal)
    (output / "normal.wal").write_bytes(normal)
    write_json(
        output / "normal.wal.manifest.json",
        {
            "duckdb_source_tag": "v2.0.0",
            "duckdb_source_commit": "d54cbbe3df17e8e5ce68312f483b4155836112aa",
            "generator": "scripts/generate_wal_fixtures.py",
            "file_size": len(normal),
            "sha256": sha256(normal),
            "version": 2,
            "version_header_length": len(header),
            "checkpoint_iteration": 7,
            "entries": entries,
            "confirmed_flush_offsets": [entries[0]["offset"], entries[2]["offset"]],
            "last_good_flush": {
                "entry_index": 2,
                "entry_offset": entries[2]["offset"],
                "end_offset": entries[2]["actual_frame_end"],
            },
            "first_flush_end": first_flush_end,
            "checkpoint": {
                "entry_index": 1,
                "entry_offset": checkpoint_offset,
                "block_pointer": 42,
                "offset_within_block": 7,
            },
        },
    )

    historical = bytearray(version_header(with_identifier=False))
    historical.extend(frame(flush_payload()))
    last_entry_offset = len(historical)
    large_payload = (
        field(100)
        + uleb128(26)
        + field(101)
        + bytes((index * 37 + 11) % 251 + 1 for index in range(128))
        + field(0xFFFF)
    )
    historical.extend(frame(large_payload))
    historical = bytes(historical)
    cut = last_entry_offset + 16 + 64
    truncated = historical[:cut]
    zero_filled = historical[:cut] + bytes(len(historical) - cut)
    (output / "issue19099_truncated.wal").write_bytes(truncated)
    (output / "issue19099_zero_filled.wal").write_bytes(zero_filled)
    write_json(
        output / "issue19099.manifest.json",
        {
            "reference_issue": 19099,
            "purpose": "Historical test corpus only; no claim about current DuckDB behavior.",
            "generator": "scripts/generate_wal_fixtures.py",
            "original_size": len(historical),
            "original_sha256": sha256(historical),
            "last_entry_offset": last_entry_offset,
            "last_entry_declared_length": len(large_payload),
            "last_entry_payload_offset": last_entry_offset + 16,
            "cut_offset": cut,
            "truncated_size": len(truncated),
            "truncated_sha256": sha256(truncated),
            "truncated_actual_length": cut - (last_entry_offset + 16),
            "zero_filled_size": len(zero_filled),
            "zero_filled_sha256": sha256(zero_filled),
            "zero_suffix_offset": cut,
            "zero_suffix_length": len(historical) - cut,
            "last_good_flush_end": last_entry_offset,
        },
    )
    print(f"generated normal.wal ({len(normal)} bytes, sha256={sha256(normal)})")
    print(f"generated Issue #19099 corpus at shared cut offset {cut}")


if __name__ == "__main__":
    main()
