#!/usr/bin/env python3
"""Review the last 48 hours and safely deliver a verified blocklist by OTA."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
OUTPUTS = ROOT / "outputs"
RUNTIME = OUTPUTS / "runtime"
OTA_DIR = RUNTIME / "blocklist-ota"
IMAGES_DIR = OTA_DIR / "images"
BACKUP_DIR = OUTPUTS / "backups"
LOG_DIR = OUTPUTS / "logs"
STATE_PATH = RUNTIME / "blocklist-automation-state.json"
LOCK_PATH = RUNTIME / "blocklist-automation.lock"
ACTIVE_SOURCE = RUNTIME / "active-blocklist-source.txt"
ACTIVE_IMAGE = RUNTIME / "active-blocklist.nbl"
REFERENCE = RUNTIME / "hagezi-pro-plus-onlydomains.txt"
REVIEW_DIR = OUTPUTS / "candidates"
HEADER = struct.Struct(">4sBBBBII")
PARTITION_BYTES = 0x160000
API_SUFFIX = "/api/v1/telemetry/batches"
DEVICE_ID = "esp32-dns-sinkhole"
RETRY_SECONDS = 6 * 60 * 60
POLL_SECONDS = 5
INSTALL_WAIT_SECONDS = 180


class UpdateError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_stamp(value: datetime | None = None) -> str:
    return (value or utc_now()).strftime("%Y%m%dT%H%M%SZ")


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def go_environment(environment: dict[str, str]) -> dict[str, str]:
    result = environment.copy()
    go_cache = RUNTIME / "go-build-cache"
    go_module_cache = RUNTIME / "go-module-cache"
    ensure_private_dir(go_cache)
    ensure_private_dir(go_module_cache)
    result.setdefault("GOCACHE", str(go_cache))
    result.setdefault("GOMODCACHE", str(go_module_cache))
    return result


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    ensure_private_dir(path.parent)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def read_json(path: Path, fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path.exists():
        return fallback or {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise UpdateError(f"state file is not a JSON object: {path}")
    return value


def configure_logging() -> logging.Logger:
    ensure_private_dir(LOG_DIR)
    log_path = LOG_DIR / "automatic-blocklist-update.log"
    handler = RotatingFileHandler(log_path, maxBytes=5 << 20, backupCount=5, encoding="utf-8")
    os.chmod(log_path, 0o600)
    handler.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    handler.formatter.converter = time.gmtime
    logger = logging.getLogger("blocklist-update")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise UpdateError(f"missing local API configuration: {path}")
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise UpdateError(f"invalid .env.local line {line_number}; expected KEY=value")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise UpdateError(f"invalid .env.local key at line {line_number}")
        try:
            parsed = shlex.split(raw_value, comments=True, posix=True)
        except ValueError as exc:
            raise UpdateError(f"invalid .env.local value at line {line_number}: {exc}") from exc
        values[key] = " ".join(parsed)
    return values


def header_string_macro(path: Path, name: str) -> str:
    if not path.is_file():
        raise UpdateError(f"missing ESP32 local configuration: {path}")
    text = path.read_text(encoding="utf-8")
    match = re.search(rf'^\s*#define\s+{re.escape(name)}\s+"((?:\\.|[^"\\])*)"', text, re.M)
    if not match:
        raise UpdateError(f"firmware configuration is missing {name}")
    return bytes(match.group(1), "utf-8").decode("unicode_escape")


def load_config() -> dict[str, Any]:
    env_file = BACKEND / ".env.local"
    env = parse_env_file(env_file)
    secrets = ROOT / "firmware" / "ESP32DnsSinkhole" / "secrets.h"
    firmware_url = header_string_macro(secrets, "TELEMETRY_API_URL")
    firmware_token = header_string_macro(secrets, "TELEMETRY_API_TOKEN")
    configured_token = env.get("DEVICE_API_TOKEN", "")
    if not firmware_token or not configured_token or not hmac.compare_digest(firmware_token, configured_token):
        raise UpdateError("DEVICE_API_TOKEN in backend/.env.local does not match the ESP32 firmware token")
    if not firmware_url.startswith("https://") or not firmware_url.endswith(API_SUFFIX):
        raise UpdateError("TELEMETRY_API_URL must be HTTPS and end with " + API_SUFFIX)
    api_base = firmware_url[: -len(API_SUFFIX)]
    ca_file = BACKEND / "certs" / "ca.crt"
    if not ca_file.is_file():
        raise UpdateError(f"missing HTTPS CA certificate: {ca_file}")
    ssl_context = ssl.create_default_context(cafile=str(ca_file))
    host = os.environ.get("BLOCKLIST_DEVICE_HOST", env.get("BLOCKLIST_DEVICE_HOST", "esp32-dns-sinkhole.local"))
    device_id = os.environ.get("BLOCKLIST_DEVICE_ID", env.get("BLOCKLIST_DEVICE_ID", DEVICE_ID))
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", device_id):
        raise UpdateError("BLOCKLIST_DEVICE_ID contains unsupported characters")
    return {
        "env": env,
        "database_url": env.get("DATABASE_URL", ""),
        "api_base": api_base,
        "api_token": firmware_token,
        "ssl_context": ssl_context,
        "device_host": host,
        "device_id": device_id,
        "ca_file": ca_file,
    }


def api_request(config: dict[str, Any], method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + config["api_token"], "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(config["api_base"] + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, context=config["ssl_context"], timeout=15) as response:
            data = response.read(4 << 20)
            if response.status not in (200, 202):
                raise UpdateError(f"API returned HTTP {response.status} for {path}")
            if not data:
                return {}
            return json.loads(data.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(512).decode("utf-8", errors="replace").strip()
        raise UpdateError(f"API HTTP {exc.code} for {path}: {detail or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError) as exc:
        raise UpdateError(f"API request {path} failed: {exc}") from exc


def api_health(config: dict[str, Any], ready: bool = False) -> bool:
    path = "/readyz" if ready else "/healthz"
    request = urllib.request.Request(config["api_base"] + path, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, context=config["ssl_context"], timeout=3) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, ssl.SSLError):
        return False


def require_ota_api(config: dict[str, Any]) -> None:
    try:
        manifest = api_request(config, "GET", "/api/v1/blocklist/manifest")
    except UpdateError as exc:
        raise UpdateError("Go API is reachable but does not expose the blocklist OTA routes; restart it from the root project checkout") from exc
    if not isinstance(manifest, dict) or "available" not in manifest:
        raise UpdateError("Go API returned an invalid blocklist manifest response")


def ensure_api(config: dict[str, Any], logger: logging.Logger) -> None:
    if api_health(config, ready=True):
        require_ota_api(config)
        return
    if api_health(config, ready=False):
        logger.info("API process is responding; waiting for PostgreSQL readiness")
        for _ in range(30):
            time.sleep(2)
            if api_health(config, ready=True):
                require_ota_api(config)
                return
        raise UpdateError("Go API is running but PostgreSQL did not become ready")

    go = shutil.which("go") or "/usr/local/go/bin/go"
    if not Path(go).is_file():
        raise UpdateError("Go is not installed or not in PATH; cannot start the local API")
    log_out = LOG_DIR / "api.stdout.log"
    log_err = LOG_DIR / "api.stderr.log"
    logger.info("API health check failed; starting Go telemetry API from the root project checkout")
    stdout = open(log_out, "ab", buffering=0)
    stderr = open(log_err, "ab", buffering=0)
    os.chmod(log_out, 0o600)
    os.chmod(log_err, 0o600)
    child_env = os.environ.copy()
    child_env.update(config["env"])
    child_env["BLOCKLIST_UPDATE_DIR"] = str(OTA_DIR)
    child_env = go_environment(child_env)
    subprocess.Popen(
        [go, "run", "./cmd/server"], cwd=BACKEND, env=child_env,
        stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        start_new_session=True, close_fds=True,
    )
    for _ in range(45):
        time.sleep(1)
        if api_health(config, ready=True):
            require_ota_api(config)
            logger.info("Go telemetry API is healthy and PostgreSQL is ready")
            return
    raise UpdateError(f"local API did not become healthy; inspect {log_err}")


def run_command(command: list[str], cwd: Path, env: dict[str, str], logger: logging.Logger) -> str:
    logger.info("Running: %s", " ".join(shlex.quote(part) for part in command))
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    for line in result.stdout.splitlines():
        logger.info("command stdout: %s", line)
    for line in result.stderr.splitlines():
        logger.error("command stderr: %s", line)
    if result.returncode != 0:
        raise UpdateError(f"command exited with status {result.returncode}: {Path(command[0]).name}")
    return result.stdout


def parse_domains(path: Path) -> set[str]:
    domains: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        if len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
            raise UpdateError(f"invalid domain on line {line_no} in {path}")
        domains.add(value)
    if not domains:
        raise UpdateError(f"no domains found in {path}")
    return domains


def validate_image(path: Path) -> dict[str, Any]:
    blob = path.read_bytes()
    if len(blob) < HEADER.size:
        raise UpdateError(f"NBL image is shorter than its header: {path}")
    magic, version, algorithm, hash_bytes, flags, count, expected_crc = HEADER.unpack(blob[:HEADER.size])
    payload = blob[HEADER.size:]
    if (magic, version, algorithm, hash_bytes, flags) != (b"NBL1", 1, 1, 5, 0):
        raise UpdateError("unsupported blocklist image header")
    if count == 0 or len(payload) != count * hash_bytes:
        raise UpdateError("blocklist count does not match exact payload length")
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise UpdateError("blocklist payload CRC32 does not match its NBL1 header")
    if len(blob) > PARTITION_BYTES:
        raise UpdateError(f"image size {len(blob)} exceeds the ESP32 partition ({PARTITION_BYTES} bytes)")
    previous = -1
    for offset in range(0, len(payload), hash_bytes):
        current = int.from_bytes(payload[offset:offset + hash_bytes], "big")
        if current <= previous:
            raise UpdateError(f"hash list is not strictly sorted at entry {offset // hash_bytes}")
        previous = current
    return {
        "entry_count": count,
        "payload_crc32": f"{actual_crc:08x}",
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_bytes": len(blob),
    }


def build_image(source: Path, output: Path, manifest: Path, logger: logging.Logger) -> dict[str, Any]:
    command = [
        sys.executable, str(ROOT / "tools" / "build_blocklist.py"),
        "--source", str(source), "--output", str(output), "--manifest", str(manifest),
        "--partition-bytes", hex(PARTITION_BYTES),
    ]
    run_command(command, ROOT, os.environ.copy(), logger)
    report = json.loads(manifest.read_text(encoding="utf-8"))
    if not report.get("fits_assumed_raw_partition") or report.get("distinct_hash_collisions", 0) != 0:
        raise UpdateError("builder reported a partition overflow or hash collision")
    verified = validate_image(output)
    if report.get("binary_sha256") != verified["image_sha256"]:
        raise UpdateError("image SHA-256 differs from the builder manifest")
    return verified


def is_covered(domain: str, domains: set[str]) -> bool:
    if domain in domains:
        return True
    labels = domain.split(".")
    for index in range(1, len(labels) - 1):
        if ".".join(labels[index:]) in domains:
            return True
    return False


def seed_active(logger: logging.Logger) -> dict[str, Any]:
    ensure_private_dir(RUNTIME)
    if not ACTIVE_SOURCE.is_file():
        source = OUTPUTS / "installed-pro-plus-onlydomains.txt"
        if not source.is_file():
            raise UpdateError(f"missing installed blocklist source snapshot: {source}")
        atomic_write(ACTIVE_SOURCE, source.read_bytes())
        logger.info("Seeded local active source from the preserved installed-list snapshot")
    if not ACTIVE_IMAGE.is_file():
        build_image(ACTIVE_SOURCE, ACTIVE_IMAGE, RUNTIME / "active-blocklist.manifest.json", logger)
    metadata = validate_image(ACTIVE_IMAGE)
    expected_image = RUNTIME / "active-blocklist-rebuilt.nbl"
    expected_manifest = RUNTIME / "active-blocklist-rebuilt.manifest.json"
    rebuilt = build_image(ACTIVE_SOURCE, expected_image, expected_manifest, logger)
    if rebuilt["image_sha256"] != metadata["image_sha256"]:
        raise UpdateError("saved active source and NBL image do not match; refusing to update")
    expected_image.unlink(missing_ok=True)
    expected_manifest.unlink(missing_ok=True)
    return metadata


def api_device_status(config: dict[str, Any], request_id: str) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({"device_id": config["device_id"], "request_id": request_id})
    try:
        result = api_request(config, "GET", "/api/v1/blocklist/status?" + query)
        return result if isinstance(result, dict) else None
    except UpdateError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise


def verify_device_current(config: dict[str, Any], metadata: dict[str, Any], logger: logging.Logger) -> None:
    current = api_device_status(config, "current")
    if current is None:
        raise UpdateError("ESP32 has not reported current blocklist status; deploy the OTA receiver firmware once over Wi-Fi first")
    if current.get("stage") != "ready":
        raise UpdateError("ESP32 current blocklist is not ready: " + str(current.get("message", current.get("stage"))))
    if current.get("entry_count") != metadata["entry_count"] or current.get("payload_crc32") != metadata["payload_crc32"]:
        raise UpdateError("Mac backup does not match the ESP32 blocklist count/CRC; refusing to overwrite it")
    reported_sha = current.get("image_sha256", "")
    if reported_sha and reported_sha != metadata["image_sha256"]:
        raise UpdateError("Mac backup SHA-256 does not match the ESP32 current image")
    logger.info("Verified active Mac backup against ESP32 status: %s entries CRC32=%s",
                metadata["entry_count"], metadata["payload_crc32"])


def save_backup(run_id: str, metadata: dict[str, Any], logger: logging.Logger) -> dict[str, str]:
    directory = BACKUP_DIR / run_id
    ensure_private_dir(directory)
    source_path = directory / "installed-source.txt"
    image_path = directory / "installed-image.nbl"
    atomic_write(source_path, ACTIVE_SOURCE.read_bytes())
    atomic_write(image_path, ACTIVE_IMAGE.read_bytes())
    write_json(directory / "backup-manifest.json", {
        "created_at": utc_now().isoformat(), "image_sha256": metadata["image_sha256"],
        "payload_crc32": metadata["payload_crc32"], "entry_count": metadata["entry_count"],
        "image_bytes": metadata["image_bytes"],
    })
    logger.info("Created local rollback backup at %s", directory)
    return {"source": str(source_path), "image": str(image_path)}


def read_dns_response(domain: str, target_ip: str, timeout: float = 3.0) -> tuple[int, int]:
    labels = domain.rstrip(".").split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise UpdateError(f"invalid DNS smoke-test domain: {domain!r}")
    query_id = int.from_bytes(os.urandom(2), "big")
    qname = b"".join(bytes([len(label.encode("ascii"))]) + label.encode("ascii") for label in labels) + b"\0"
    packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(packet, (target_ip, 53))
        response, _ = client.recvfrom(4096)
    if len(response) < 12:
        raise UpdateError("DNS smoke test received a response shorter than a DNS header")
    response_id, flags, _, answer_count, _, _ = struct.unpack(">HHHHHH", response[:12])
    if response_id != query_id or not (flags & 0x8000):
        raise UpdateError("DNS smoke test received a mismatched or non-response packet")
    return flags & 0x000F, answer_count


def device_ip(config: dict[str, Any]) -> str:
    try:
        return socket.gethostbyname(config["device_host"])
    except OSError as exc:
        raise UpdateError(f"could not resolve ESP32 host {config['device_host']}: {exc}") from exc


def check_old_block_still_works(config: dict[str, Any], old_probe: str, logger: logging.Logger) -> None:
    ip = device_ip(config)
    code, _ = read_dns_response(old_probe, ip)
    if code != 3:
        raise UpdateError(f"current known-blocked domain {old_probe} returned DNS RCODE {code}, expected NXDOMAIN")
    logger.info("ESP32 DNS smoke check passed for an existing blocked domain")


def check_candidate_baseline(config: dict[str, Any], probe: str, logger: logging.Logger) -> None:
    ip = device_ip(config)
    code, _ = read_dns_response(probe, ip)
    if code != 0:
        raise UpdateError(f"candidate probe {probe} was not allowed before update (DNS RCODE {code}); refusing to deploy")
    logger.info("Candidate DNS probe was allowed before update as expected")


def check_candidate_blocked(config: dict[str, Any], probe: str, logger: logging.Logger) -> None:
    ip = device_ip(config)
    last_error: Exception | None = None
    for _ in range(3):
        try:
            code, _ = read_dns_response(probe, ip)
            if code == 3:
                logger.info("New candidate is blocked after OTA: %s", probe)
                return
            last_error = UpdateError(f"candidate probe returned DNS RCODE {code}, expected NXDOMAIN")
        except (OSError, UpdateError) as exc:
            last_error = exc
        time.sleep(2)
    raise UpdateError(f"post-OTA candidate smoke check failed: {last_error}")


def expected_status_matches(status: dict[str, Any] | None, metadata: dict[str, Any]) -> bool:
    return bool(status and status.get("stage") in ("installed", "unchanged") and
                status.get("entry_count") == metadata["entry_count"] and
                status.get("payload_crc32") == metadata["payload_crc32"] and
                (not status.get("image_sha256") or status.get("image_sha256") == metadata["image_sha256"]))


def current_matches(config: dict[str, Any], metadata: dict[str, Any], logger: logging.Logger) -> bool:
    current = api_device_status(config, "current")
    if not current or current.get("stage") != "ready":
        return False
    if current.get("entry_count") != metadata["entry_count"] or current.get("payload_crc32") != metadata["payload_crc32"]:
        return False
    reported_sha = current.get("image_sha256", "")
    if reported_sha and reported_sha != metadata["image_sha256"]:
        return False
    return True


def publish_manifest(request_id: str, version: str, image_path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    destination = IMAGES_DIR / (metadata["image_sha256"] + ".nbl")
    ensure_private_dir(IMAGES_DIR)
    if not destination.exists():
        atomic_write(destination, image_path.read_bytes())
    elif validate_image(destination)["image_sha256"] != metadata["image_sha256"]:
        raise UpdateError("immutable OTA image path already contains different content")
    manifest = {
        "available": True,
        "request_id": request_id,
        "version": version,
        "image_sha256": metadata["image_sha256"],
        "payload_crc32": metadata["payload_crc32"],
        "image_bytes": metadata["image_bytes"],
        "entry_count": metadata["entry_count"],
        "published_at": utc_now().isoformat().replace("+00:00", "Z"),
    }
    write_json(OTA_DIR / "manifest.json", manifest)
    return manifest


def clear_manifest() -> None:
    write_json(OTA_DIR / "manifest.json", {"available": False})


def wait_for_device(config: dict[str, Any], request_id: str, metadata: dict[str, Any], logger: logging.Logger,
                    timeout_seconds: int) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    last_stage = "waiting for ESP32 status"
    while time.monotonic() < deadline:
        try:
            status = api_device_status(config, request_id)
            if status:
                stage = str(status.get("stage", "unknown"))
                if stage != last_stage:
                    logger.info("ESP32 OTA stage %s: %s", stage, status.get("message", ""))
                    last_stage = stage
                if stage == "failed":
                    return False, str(status.get("message", "ESP32 reported a blocklist OTA failure"))
                if expected_status_matches(status, metadata):
                    for _ in range(12):
                        if current_matches(config, metadata, logger):
                            return True, "ESP32 reports the expected image as current and ready"
                        time.sleep(1)
                    return False, "ESP32 acknowledged installation but current status did not match the staged image"
        except UpdateError as exc:
            logger.error("Status poll error for %s: %s", request_id, exc)
            last_stage = str(exc)
        time.sleep(POLL_SECONDS)
    return False, f"timed out after {timeout_seconds}s ({last_stage})"


def promote_active(source_path: Path, image_path: Path) -> None:
    atomic_write(ACTIVE_SOURCE, source_path.read_bytes())
    atomic_write(ACTIVE_IMAGE, image_path.read_bytes())


def rollback_pending(state: dict[str, Any], config: dict[str, Any], logger: logging.Logger,
                     reason: str) -> bool:
    pending = state.get("pending")
    if not pending:
        return False
    logger.error("Starting OTA rollback because the update failed: %s", reason)
    backup_image = Path(pending["backup"]["image"])
    backup_source = Path(pending["backup"]["source"])
    metadata = validate_image(backup_image)
    if pending.get("phase") != "rollback":
        rollback_id = "rollback-" + utc_stamp()
        pending.update({
            "phase": "rollback",
            "rollback_request_id": rollback_id,
            "rollback_started_at": utc_now().isoformat(),
            "rollback_reason": reason[:500],
            "rollback_metadata": metadata,
        })
        write_json(STATE_PATH, state)
        publish_manifest(rollback_id, "rollback-" + metadata["image_sha256"][:12], backup_image, metadata)
    else:
        rollback_id = pending["rollback_request_id"]
        publish_manifest(rollback_id, "rollback-" + metadata["image_sha256"][:12], backup_image, metadata)
    ok, rollback_message = wait_for_device(config, rollback_id, metadata, logger, INSTALL_WAIT_SECONDS)
    if not ok:
        logger.error("Rollback has not been confirmed; it remains published for the ESP32 to retry: %s", rollback_message)
        state["last_failure"] = f"{reason}; rollback pending: {rollback_message}"
        write_json(STATE_PATH, state)
        return False
    try:
        old_domains = parse_domains(backup_source)
        old_probe = sorted(old_domains)[0]
        check_old_block_still_works(config, old_probe, logger)
    except Exception as exc:
        logger.error("Rollback CRC/count was confirmed, but the local DNS smoke check failed: %s", exc)
        state["last_failure"] = f"{reason}; rollback verified by ESP32 status but DNS smoke failed: {exc}"
        state["retry_after"] = (utc_now() + timedelta(seconds=RETRY_SECONDS)).isoformat()
        clear_manifest()
        state["pending"] = None
        write_json(STATE_PATH, state)
        return False
    clear_manifest()
    state["pending"] = None
    state["last_failure"] = f"{reason}; prior blocklist restored successfully"
    state["retry_after"] = (utc_now() + timedelta(seconds=RETRY_SECONDS)).isoformat()
    write_json(STATE_PATH, state)
    logger.info("Rollback confirmed: previous list is restored and DNS filtering is active")
    return True


def finish_pending(state: dict[str, Any], config: dict[str, Any], logger: logging.Logger) -> bool:
    pending = state.get("pending")
    if not pending:
        return True
    if pending.get("phase") == "rollback":
        return rollback_pending(state, config, logger, pending.get("rollback_reason", "continuing rollback"))
    staged_image = Path(pending["staged_image"])
    staged_source = Path(pending["staged_source"])
    metadata = validate_image(staged_image)
    publish_manifest(pending["request_id"], pending["version"], staged_image, metadata)
    ok, message = wait_for_device(config, pending["request_id"], metadata, logger, INSTALL_WAIT_SECONDS)
    if ok:
        try:
            check_candidate_blocked(config, pending["candidate_probe"], logger)
            old_domains = parse_domains(Path(pending["backup"]["source"]))
            check_old_block_still_works(config, sorted(old_domains)[0], logger)
        except Exception as exc:
            return rollback_pending(state, config, logger, str(exc))
        promote_active(staged_source, staged_image)
        clear_manifest()
        state["pending"] = None
        state["last_success"] = utc_now().isoformat()
        state.pop("retry_after", None)
        state["last_failure"] = ""
        state["last_image_sha256"] = metadata["image_sha256"]
        write_json(STATE_PATH, state)
        logger.info("OTA update complete; new blocklist is active and verified")
        return True
    return rollback_pending(state, config, logger, message)


def validate_merge(active_domains: set[str], candidate_domains: list[str], merged_path: Path) -> set[str]:
    merged = parse_domains(merged_path)
    if not active_domains.issubset(merged):
        raise UpdateError("merged source dropped domains from the current installed snapshot")
    if not set(candidate_domains).issubset(merged):
        raise UpdateError("merged source is missing one or more reviewed candidates")
    unexpected = merged - active_domains - set(candidate_domains)
    if unexpected:
        raise UpdateError(f"merged source unexpectedly added {len(unexpected)} domains")
    for candidate in candidate_domains:
        if is_covered(candidate, active_domains):
            raise UpdateError(f"candidate {candidate} is already covered by the installed snapshot")
    if len(merged) < len(active_domains):
        raise UpdateError("merged source is smaller than the installed snapshot")
    return merged


def do_update(args: argparse.Namespace, state: dict[str, Any], config: dict[str, Any], logger: logging.Logger) -> bool:
    active_meta = seed_active(logger)
    if not args.dry_run:
        ensure_api(config, logger)
        verify_device_current(config, active_meta, logger)

    run_id = utc_stamp()
    review_env = os.environ.copy()
    if config["database_url"]:
        review_env["DATABASE_URL"] = config["database_url"]
    else:
        raise UpdateError("DATABASE_URL is missing from backend/.env.local")
    review_env = go_environment(review_env)
    if not REFERENCE.exists():
        atomic_write(REFERENCE, (OUTPUTS / "hagezi-pro-plus-onlydomains.txt").read_bytes())
    ensure_private_dir(REVIEW_DIR)
    reference_before = REFERENCE.read_bytes()
    candidate_path = REVIEW_DIR / f"served-domains-{run_id}.txt"
    merged_path = REVIEW_DIR / f"blocklist-source-{run_id}.txt"
    report_path = REVIEW_DIR / f"served-domains-{run_id}.report.json"
    command = [
        "go", "run", "./cmd/review-blocklist", "--lookback", "48h",
        "--refresh-reference", "--output-key", run_id,
        "--reference", str(REFERENCE), "--installed", str(ACTIVE_SOURCE),
        "--out-dir", str(REVIEW_DIR),
    ]
    go = shutil.which("go") or "/usr/local/go/bin/go"
    command[0] = go
    try:
        run_command(command, BACKEND, review_env, logger)
    except Exception:
        if not REFERENCE.exists():
            atomic_write(REFERENCE, reference_before)
        raise
    report = json.loads(report_path.read_text(encoding="utf-8"))
    candidates = report.get("candidates", [])
    if not isinstance(candidates, list) or any(not isinstance(value, str) for value in candidates):
        raise UpdateError("review report contains an invalid candidate list")
    active_domains = parse_domains(ACTIVE_SOURCE)
    if not candidates:
        if not args.dry_run:
            state["last_success"] = utc_now().isoformat()
            state.pop("retry_after", None)
            state["last_failure"] = ""
            write_json(STATE_PATH, state)
        state["last_review"] = str(report_path)
        state["last_candidate_count"] = 0
        logger.info("Review completed: no new candidates; no OTA flash was needed")
        return True

    probes = report.get("candidate_probe_domains", {})
    candidate_probe = next((probes.get(candidate) for candidate in candidates if probes.get(candidate)), None)
    if not candidate_probe:
        raise UpdateError("review report did not include a previously resolved DNS probe for the candidate")
    merged_domains = validate_merge(active_domains, candidates, merged_path)
    logger.info("Merged list validation passed: %d existing domains plus %d candidates", len(active_domains), len(merged_domains) - len(active_domains))

    staged_image = REVIEW_DIR / f"blocklist-{run_id}.nbl"
    staged_manifest = REVIEW_DIR / f"blocklist-{run_id}.manifest.json"
    staged_meta = build_image(merged_path, staged_image, staged_manifest, logger)
    if staged_meta["entry_count"] < active_meta["entry_count"]:
        raise UpdateError("built candidate image has fewer hashes than the currently active image")
    if staged_meta["image_sha256"] == active_meta["image_sha256"]:
        raise UpdateError("candidate source produced the same image as the installed list")
    candidate_probe_text = str(candidate_probe)
    old_probe = sorted(active_domains)[0]
    if not args.dry_run:
        check_old_block_still_works(config, old_probe, logger)
        check_candidate_baseline(config, candidate_probe_text, logger)

    backup = save_backup(run_id, active_meta, logger)
    if args.dry_run:
        logger.info("Dry run complete: review, merge, partition capacity, hash order, CRC, and SHA checks passed; no OTA manifest was published")
        return True

    request_id = "update-" + run_id
    version = f"hagezi-pro-plus-{run_id}-{staged_meta['image_sha256'][:8]}"
    pending = {
        "phase": "install", "request_id": request_id, "version": version,
        "staged_source": str(merged_path), "staged_image": str(staged_image),
        "candidate_probe": candidate_probe_text, "backup": backup,
        "image_sha256": staged_meta["image_sha256"], "payload_crc32": staged_meta["payload_crc32"],
        "entry_count": staged_meta["entry_count"], "started_at": utc_now().isoformat(),
        "review_report": str(report_path),
    }
    state["pending"] = pending
    state["last_review"] = str(report_path)
    state["last_candidate_count"] = len(candidates)
    write_json(STATE_PATH, state)
    publish_manifest(request_id, version, staged_image, staged_meta)
    logger.info("Published OTA blocklist request %s with %d candidates", request_id, len(candidates))
    result = finish_pending(state, config, logger)
    if not result:
        state["retry_after"] = (utc_now() + timedelta(seconds=RETRY_SECONDS)).isoformat()
        state["last_failure"] = "OTA update/rollback did not finish; see preceding log entries"
        write_json(STATE_PATH, state)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="run now, bypassing the 48-hour schedule gate")
    parser.add_argument("--dry-run", action="store_true", help="review, merge, build, and validate without contacting or flashing the ESP32")
    args = parser.parse_args()
    os.umask(0o077)
    logger = configure_logging()
    ensure_private_dir(RUNTIME)
    with open(LOCK_PATH, "a", encoding="utf-8") as lock:
        os.chmod(LOCK_PATH, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.info("Another automated blocklist update is already running; skipping duplicate launch")
            return 0
        try:
            state = read_json(STATE_PATH)
            config = load_config()
            if not args.dry_run:
                ensure_api(config, logger)
            if state.get("pending") and not args.dry_run:
                logger.info("Resuming pending %s request %s", state["pending"].get("phase"), state["pending"].get("request_id"))
                return 0 if finish_pending(state, config, logger) else 1
            if not args.force and not args.dry_run and state.get("retry_after"):
                retry_after = datetime.fromisoformat(state["retry_after"])
                if utc_now() < retry_after:
                    logger.info("Retry window has not arrived; next attempt after %s", retry_after.isoformat())
                    return 0
            if not args.force and not args.dry_run and state.get("last_success"):
                last_success = datetime.fromisoformat(state["last_success"])
                if utc_now() - last_success < timedelta(hours=48):
                    logger.info("48-hour schedule gate has not elapsed; last successful review/update was %s", last_success.isoformat())
                    return 0
            success = do_update(args, state, config, logger)
            return 0 if success else 1
        except Exception as exc:
            logger.exception("Automated blocklist run failed: %s", exc)
            state = locals().get("state", {})
            if isinstance(state, dict):
                state["last_failure"] = str(exc)[:1000]
                state["retry_after"] = (utc_now() + timedelta(seconds=RETRY_SECONDS)).isoformat()
                with contextlib.suppress(Exception):
                    write_json(STATE_PATH, state)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
