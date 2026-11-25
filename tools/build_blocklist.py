#!/usr/bin/env python3
"""Build a compact, sorted 40-bit hash table from a domains-only feed."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path


SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
    "wildcard/pro.plus-onlydomains.txt"
)
MAGIC = b"NBL1"
FORMAT_VERSION = 1
HASH_ALGORITHM_ID = 1  # FNV-1a 64-bit, truncated to its low 40 bits
HASH_BYTES = 5
HEADER_FORMAT = ">4sBBBBII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
HASH_MASK = (1 << 40) - 1
FNV_OFFSET_BASIS_64 = 14695981039346656037
FNV_PRIME_64 = 1099511628211


def canonicalize_domain(value: str, line_number: int) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain:
        raise ValueError(f"line {line_number}: empty domain")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"line {line_number}: domain is not ASCII/IDNA: {value!r}") from exc

    if len(domain) > 253:
        raise ValueError(f"line {line_number}: domain exceeds 253 bytes")
    labels = domain.split(".")
    for label in labels:
        if not 1 <= len(label) <= 63:
            raise ValueError(f"line {line_number}: invalid label length in {value!r}")
        if label[0] == "-" or label[-1] == "-":
            raise ValueError(f"line {line_number}: label starts or ends with hyphen: {value!r}")
        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise ValueError(f"line {line_number}: invalid character in {value!r}")
    return domain


def fnv1a40(domain: str) -> int:
    value = FNV_OFFSET_BASIS_64
    for byte in domain.encode("ascii"):
        value ^= byte
        value = (value * FNV_PRIME_64) & 0xFFFFFFFFFFFFFFFF
    return value & HASH_MASK


def parse_source(path: Path) -> tuple[list[str], str | None, int | None]:
    domains: set[str] = set()
    version: str | None = None
    declared_count: int | None = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("# Version:"):
                version = stripped.partition(":")[2].strip()
            elif stripped.startswith("# Number of entries:"):
                raw_count = stripped.partition(":")[2].strip()
                if raw_count.isdecimal():
                    declared_count = int(raw_count)
            continue
        domains.add(canonicalize_domain(stripped, line_number))
    if not domains:
        raise ValueError("the source contains no domain entries")
    return sorted(domains), version, declared_count


def build(source: Path, output: Path, manifest_path: Path, partition_bytes: int) -> dict[str, object]:
    domains, source_version, declared_count = parse_source(source)
    hash_to_domain: dict[int, str] = {}
    collisions: list[dict[str, str]] = []
    for domain in domains:
        hashed = fnv1a40(domain)
        existing = hash_to_domain.get(hashed)
        if existing is not None and existing != domain:
            collisions.append({"hash40_hex": f"{hashed:010x}", "domain_a": existing, "domain_b": domain})
        else:
            hash_to_domain[hashed] = domain

    sorted_hashes = sorted(hash_to_domain)
    payload = b"".join(value.to_bytes(HASH_BYTES, "big") for value in sorted_hashes)
    payload_crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        FORMAT_VERSION,
        HASH_ALGORITHM_ID,
        HASH_BYTES,
        0,
        len(sorted_hashes),
        payload_crc32,
    )
    blob = header + payload
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_suffix(output.suffix + ".tmp")
    temporary_output.write_bytes(blob)
    temporary_output.replace(output)

    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    binary_sha256 = hashlib.sha256(blob).hexdigest()
    max_hash_entries = max(0, (partition_bytes - HEADER_SIZE) // HASH_BYTES)
    report: dict[str, object] = {
        "source_url": SOURCE_URL,
        "source_file": str(source),
        "source_version": source_version,
        "source_declared_entries": declared_count,
        "unique_domains": len(domains),
        "duplicate_domain_lines_removed": None,
        "hash_algorithm": "FNV-1a 64-bit, low 40 bits",
        "hash_bytes": HASH_BYTES,
        "hash_byte_order": "big-endian",
        "hash_count_after_collision_deduplication": len(sorted_hashes),
        "distinct_hash_collisions": len(collisions),
        "collisions": collisions,
        "header_bytes": HEADER_SIZE,
        "payload_bytes": len(payload),
        "binary_bytes": len(blob),
        "partition_bytes_assumed": partition_bytes,
        "partition_bytes_remaining": partition_bytes - len(blob),
        "maximum_hash_entries_in_assumed_partition": max_hash_entries,
        "additional_hash_entries_capacity": max(0, max_hash_entries - len(sorted_hashes)),
        "fits_assumed_raw_partition": len(blob) <= partition_bytes,
        "payload_crc32": f"{payload_crc32:08x}",
        "source_sha256": source_sha256,
        "binary_sha256": binary_sha256,
    }
    # Duplicate lines are not retained in parse_source; derive the count separately
    # to keep the report useful without retaining the full source in memory twice.
    raw_domains = sum(
        1
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    report["duplicate_domain_lines_removed"] = raw_domains - len(domains)

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_manifest = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    temporary_manifest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary_manifest.replace(manifest_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("outputs/hagezi-pro-plus-onlydomains.txt"))
    parser.add_argument("--output", type=Path, default=Path("outputs/pro-plus-fnv40.nbl"))
    parser.add_argument("--manifest", type=Path, default=Path("outputs/pro-plus-fnv40.manifest.json"))
    parser.add_argument("--partition-bytes", type=lambda value: int(value, 0), default=0x160000)
    args = parser.parse_args()
    try:
        report = build(args.source, args.output, args.manifest, args.partition_bytes)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"blocklist build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report["fits_assumed_raw_partition"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
