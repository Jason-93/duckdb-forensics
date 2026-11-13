#!/usr/bin/env python3
"""Materialize the deterministic public fault corpus without DuckDB or Rust."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

MASK = (1 << 64) - 1
WORD_MULTIPLIER = 0xBF58476D1CE4E5B9
REMAINDER_MULTIPLIER = 0xC6A4A7935BD1E995
REMAINDER_SEED = 0xE17A1465
ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "corpus" / "manifest.json"


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


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def repair(data, region):
    starts = {"main": 0, "database0": 4096, "block0": 12288}
    lengths = {"main": 4096, "database0": 4096, "block0": 262144}
    start = starts[region]
    end = start + lengths[region]
    if end > len(data):
        raise ValueError(f"cannot repair {region}: input is truncated")
    data[start:start + 8] = struct.pack("<Q", duckdb_checksum(data[start + 8:end]))


def random_bytes(size, seed):
    state = seed
    output = bytearray(size)
    for index in range(size):
        state ^= (state << 13) & MASK
        state ^= state >> 7
        state ^= (state << 17) & MASK
        state &= MASK
        output[index] = state & 0xFF
    return bytes(output)


def materialize(case, sources):
    if "random_size" in case:
        data = bytearray(random_bytes(case["random_size"], case["random_seed"]))
    elif "base" in case:
        data = bytearray(sources[case["base"]])
    else:
        data = bytearray()
    for operation in case.get("operations", []):
        kind = operation["op"]
        if kind == "truncate":
            data = data[:operation["length"]]
        elif kind == "write_u8":
            data[operation["offset"]] = operation["value"]
        elif kind == "write_u64":
            offset = operation["offset"]
            data[offset:offset + 8] = struct.pack("<Q", operation["value"])
        elif kind == "append_slice":
            data.extend(data[operation["start"]:operation["end"]])
        elif kind == "repair":
            repair(data, operation["region"])
        else:
            raise ValueError(f"unknown operation: {kind}")
    return bytes(data)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "target" / "fault-corpus")
    parser.add_argument("--include-sparse", action="store_true")
    parser.add_argument("--write-hashes", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    sources = {}
    for name, source in manifest["sources"].items():
        data = (ROOT / source["path"]).read_bytes()
        if sha256(data) != source["sha256"]:
            raise ValueError(f"source hash mismatch: {source['path']}")
        sources[name] = data
    args.output.mkdir(parents=True, exist_ok=True)
    generated = []
    for case in manifest["cases"]:
        if "sparse_size" in case:
            if not args.include_sparse:
                continue
            output = args.output / f"{case['name']}.duckdb"
            with output.open("wb") as stream:
                stream.truncate(case["sparse_size"])
            case["sha256"] = None
        else:
            data = materialize(case, sources)
            digest = sha256(data)
            if not args.write_hashes and case.get("sha256") not in (None, digest):
                raise ValueError(f"generated hash mismatch for {case['name']}")
            case["sha256"] = digest
            extension = ".wal" if case["command"] == "wal" else ".duckdb"
            output = args.output / f"{case['name']}{extension}"
            output.write_bytes(data)
        generated_case = dict(case)
        generated_case["file"] = output.name
        generated.append(generated_case)
    write_json(
        args.output / "manifest.json",
        {"schema_version": 1, "generator": manifest["generator"], "cases": generated},
    )
    if args.write_hashes:
        write_json(MANIFEST, manifest)
    print(f"generated {len(generated)} fault cases in {args.output}")


if __name__ == "__main__":
    main()
