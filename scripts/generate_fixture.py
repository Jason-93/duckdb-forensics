#!/usr/bin/env python3
"""Generate the small, committed normal fixture with official DuckDB v2.0.0."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import urllib.request
import tarfile

VERSION = "v2.0.0"
ASSET_SHA256 = {
    "duckdb-cli-linux-amd64.tar.gz": "c6507206baf7793c6013dbd82368469a45f20dc0e17a6f92f204602f652ed2bc",
    "duckdb-cli-linux-arm64.tar.gz": "859e1875d2a9515fbb4bf8871061437a14af82320da68c753f094c4b776348fe",
    "duckdb-cli-osx-amd64.tar.gz": "fbc7013ba09d117396dabf16783281c2add47fc01cdac4855464a03526dc96ee",
    "duckdb-cli-osx-arm64.tar.gz": "188a36fe8883ef52e69165a0cbb6031ef679c8e6c448a1ce22951964149b7f96",
    "duckdb-cli-windows-amd64.tar.gz": "91663c2f36c2a334b0e5e639006d8c29c29e013af0c477d80bb931df68870312",
    "duckdb-cli-windows-arm64.tar.gz": "4b5d1e4611debf676a693a8a6896dc29b352a9c3b11b706e7421d1d6082e05fd",
}
SQL = """CREATE TABLE fixture (id INTEGER, label VARCHAR);
INSERT INTO fixture VALUES (1, 'alpha'), (2, 'beta');
CHECKPOINT;
"""


def asset_name():
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Darwin" and machine in ("x86_64", "amd64"):
        return "duckdb-cli-osx-amd64.tar.gz"
    if system == "Darwin" and machine in ("aarch64", "arm64"):
        return "duckdb-cli-osx-arm64.tar.gz"
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "duckdb-cli-linux-amd64.tar.gz"
    if system == "Linux" and machine in ("aarch64", "arm64"):
        return "duckdb-cli-linux-arm64.tar.gz"
    if system == "Windows" and machine in ("x86_64", "amd64"):
        return "duckdb-cli-windows-amd64.tar.gz"
    if system == "Windows" and machine in ("aarch64", "arm64"):
        return "duckdb-cli-windows-arm64.tar.gz"
    raise RuntimeError(f"no official CLI mapping configured for {system}/{machine}")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_cli(work_dir):
    name = asset_name()
    url = f"https://github.com/duckdb/duckdb/releases/download/{VERSION}/{name}"
    archive = work_dir / name
    with urllib.request.urlopen(url) as response, archive.open("wb") as destination:
        shutil.copyfileobj(response, destination)
    archive_digest = sha256(archive)
    expected_digest = ASSET_SHA256[name]
    if archive_digest != expected_digest:
        raise RuntimeError(
            f"SHA-256 mismatch for {name}: expected {expected_digest}, got {archive_digest}"
        )
    executable_name = "duckdb.exe" if platform.system() == "Windows" else "duckdb"
    executable = work_dir / executable_name
    with tarfile.open(archive, "r:gz") as archive_file:
        members = [
            member
            for member in archive_file.getmembers()
            if member.isfile() and Path(member.name).name == executable_name
        ]
        if len(members) != 1:
            raise RuntimeError(f"expected one {executable_name} in {name}, found {len(members)}")
        source = archive_file.extractfile(members[0])
        if source is None:
            raise RuntimeError(f"cannot read {executable_name} from {name}")
        with source, executable.open("wb") as destination:
            shutil.copyfileobj(source, destination)
    executable.chmod(0o700)
    return executable, url, archive_digest


def duckdb_version(executable):
    result = subprocess.run(
        [str(executable), "-csv", "-noheader", ":memory:", "SELECT version();"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def read_header(data, page_offset):
    fields = struct.unpack_from("<7Q", data, page_offset + 8)
    names = (
        "iteration",
        "meta_block",
        "free_list",
        "block_count",
        "block_alloc_size",
        "vector_size",
        "storage_compatibility",
    )
    return dict(zip(names, fields))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duckdb", type=Path, help="existing official DuckDB v2.0.0 CLI")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "crates/duckdb-forensics/tests/fixtures",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="duckdb-forensics-fixture-") as temporary:
        work_dir = Path(temporary)
        if args.duckdb:
            executable = args.duckdb.resolve()
            url = None
            asset_digest = None
        else:
            executable, url, asset_digest = download_cli(work_dir)

        version = duckdb_version(executable)
        if version != VERSION:
            raise RuntimeError(f"expected DuckDB {VERSION}, got {version!r}")

        database = work_dir / "normal.duckdb"
        subprocess.run([str(executable), str(database)], input=SQL, text=True, check=True)
        if not database.is_file():
            raise RuntimeError("DuckDB did not create the normal fixture")

        data = database.read_bytes()
        if len(data) < 12_288 or data[8:12] != b"DUCK":
            raise RuntimeError("generated file does not have the confirmed v2.0.0 header geometry")
        main_version = struct.unpack_from("<Q", data, 12)[0]
        headers = [read_header(data, 4096), read_header(data, 8192)]
        if main_version != 999:
            raise RuntimeError(f"expected deprecated main version 999, got {main_version}")
        for header in headers:
            if header["storage_compatibility"] != 69:
                raise RuntimeError(f"expected storage compatibility 69, got {header}")
            if header["block_alloc_size"] != 262_144:
                raise RuntimeError(f"expected block allocation size 262144, got {header}")
            if header["vector_size"] != 2048:
                raise RuntimeError(f"expected vector size 2048, got {header}")

        active_header = headers[0] if headers[0]["iteration"] > headers[1]["iteration"] else headers[1]
        block_alloc_size = active_header["block_alloc_size"]
        metadata_block_size = ((block_alloc_size - 8) // 64) & ~7
        metadata_next_pointers = {}
        for name in ("meta_block", "free_list"):
            pointer = active_header[name]
            block_id = pointer & 0x00FFFFFFFFFFFFFF
            metadata_index = pointer >> 56
            location = 12_288 + block_id * block_alloc_size + 8 + metadata_index * metadata_block_size
            metadata_next_pointers[name] = struct.unpack_from("<Q", data, location)[0]

        fixture = args.output_dir / "normal.duckdb"
        manifest_path = args.output_dir / "normal.manifest.json"
        fixture_tmp = args.output_dir / ".normal.duckdb.tmp"
        manifest_tmp = args.output_dir / ".normal.manifest.json.tmp"
        shutil.copyfile(database, fixture_tmp)
        manifest = {
            "duckdb_version": version,
            "release_url": f"https://github.com/duckdb/duckdb/releases/tag/{VERSION}",
            "cli_asset_url": url,
            "cli_asset_sha256": asset_digest,
            "generator": "scripts/generate_fixture.py",
            "sql": SQL,
            "file_size": len(data),
            "sha256": sha256(database),
            "main_version": main_version,
            "main_library_version": data[52:84].split(b"\0", 1)[0].decode("ascii"),
            "block_stored_checksums": [
                f"0x{struct.unpack_from('<Q', data, 12_288 + block_id * block_alloc_size)[0]:016x}"
                for block_id in range(active_header["block_count"])
            ],
            "metadata_block_size": metadata_block_size,
            "metadata_next_pointers": metadata_next_pointers,
            "stored_checksums": [
                f"0x{struct.unpack_from('<Q', data, offset)[0]:016x}"
                for offset in (0, 4096, 8192)
            ],
            "database_headers": headers,
        }
        manifest_tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        os.replace(fixture_tmp, fixture)
        os.replace(manifest_tmp, manifest_path)
        print(f"generated {fixture} ({len(data)} bytes) with DuckDB {version}")
        print(f"fixture SHA-256: {manifest['sha256']}")


if __name__ == "__main__":
    main()
