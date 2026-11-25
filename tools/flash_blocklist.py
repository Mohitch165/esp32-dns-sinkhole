#!/usr/bin/env python3
"""Validate and optionally write the NBL1 image to the raw blocklist partition."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKETCH_DIR = ROOT / "firmware" / "ESP32DnsSinkhole"
DEFAULT_IMAGE = ROOT / "outputs" / "pro-plus-fnv40.nbl"
DEFAULT_MANIFEST = ROOT / "outputs" / "pro-plus-fnv40.manifest.json"
HEADER_FORMAT = ">4sBBBBII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
FLASH_SECTOR_SIZE = 0x1000


def find_partition() -> tuple[int, int]:
    table = SKETCH_DIR / "partitions.csv"
    with table.open(newline="", encoding="utf-8") as csv_file:
        for row in csv.reader(csv_file):
            if not row or row[0].lstrip().startswith("#"):
                continue
            values = [column.strip() for column in row]
            if values[0] == "blocklist":
                return int(values[3], 0), int(values[4], 0)
    raise ValueError(f"No blocklist partition found in {table}")


def locate_esptool(explicit: Path | None) -> list[str]:
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"esptool not found: {explicit}")
        return [str(explicit)]

    on_path = shutil.which("esptool")
    if on_path:
        return [on_path]

    tool_root = Path.home() / "Library" / "Arduino15" / "packages" / "esp32" / "tools" / "esptool_py"
    versions: list[tuple[tuple[int, ...], Path]] = []
    if tool_root.is_dir():
        for folder in tool_root.iterdir():
            executable = folder / "esptool"
            if not executable.is_file():
                continue
            try:
                version = tuple(int(part) for part in folder.name.split("."))
            except ValueError:
                continue
            versions.append((version, executable))
    if not versions:
        raise FileNotFoundError("Could not find esptool; install it or pass --esptool PATH")
    versions.sort()
    return [str(versions[-1][1])]


def validate_image(image: Path, manifest_path: Path, partition_size: int) -> tuple[bytes, str]:
    blob = image.read_bytes()
    if len(blob) < HEADER_SIZE:
        raise ValueError("image is shorter than the NBL1 header")
    magic, version, algorithm, hash_bytes, flags, count, expected_crc = struct.unpack(
        HEADER_FORMAT, blob[:HEADER_SIZE]
    )
    payload = blob[HEADER_SIZE:]
    if (magic, version, algorithm, hash_bytes, flags) != (b"NBL1", 1, 1, 5, 0):
        raise ValueError("unsupported NBL1 header")
    if count == 0 or len(payload) != count * hash_bytes:
        raise ValueError("header count does not match the hash payload length")
    if (zlib.crc32(payload) & 0xFFFFFFFF) != expected_crc:
        raise ValueError("payload CRC32 does not match the header")
    padded_length = (len(blob) + FLASH_SECTOR_SIZE - 1) & ~(FLASH_SECTOR_SIZE - 1)
    if padded_length > partition_size:
        raise ValueError(
            f"image needs {padded_length} bytes after flash-sector padding, "
            f"partition is {partition_size} bytes"
        )

    digest = hashlib.sha256(blob).hexdigest()
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_digest = manifest.get("binary_sha256")
        if expected_digest and digest != expected_digest:
            raise ValueError("image SHA-256 differs from the build manifest")
    return blob, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--port", help="serial port, for example /dev/cu.usbserial-XXXX")
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--esptool", type=Path, help="optional path to esptool executable")
    parser.add_argument("--flash", action="store_true", help="write after validation and confirmation")
    args = parser.parse_args()

    try:
        offset, partition_size = find_partition()
        blob, digest = validate_image(args.image, args.manifest, partition_size)
        print(f"Image: {args.image}")
        print(f"Partition: blocklist at 0x{offset:X}, size 0x{partition_size:X}")
        print(f"Image bytes: {len(blob)}; SHA-256: {digest}")
        if not args.flash:
            print("Dry run only. To write this data partition, rerun with --port PORT --flash.")
            return 0
        if not args.port:
            raise ValueError("--port is required with --flash")
        esptool = locate_esptool(args.esptool)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"blocklist flash preparation failed: {exc}", file=sys.stderr)
        return 1

    confirmation = input(
        "This writes only the blocklist data partition and resets the ESP32. "
        "Close Serial Monitor first. Type FLASH LIST to continue: "
    )
    if confirmation != "FLASH LIST":
        print("Cancelled; no flash command was run.")
        return 1

    command = esptool + [
        "--chip", "esp32",
        "--port", args.port,
        "--baud", str(args.baud),
        "--before", "default-reset",
        "--after", "hard-reset",
        "write-flash",
        hex(offset),
        str(args.image.resolve()),
    ]
    print("Writing the blocklist partition. The application and OTA slots are not targeted.")
    result = subprocess.run(command, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
