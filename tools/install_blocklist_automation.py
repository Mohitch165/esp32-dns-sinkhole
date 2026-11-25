#!/usr/bin/env python3
"""Install or remove the macOS launchd job for the automated blocklist workflow."""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

from update_blocklist import ROOT, load_config


LABEL = "com.mohit.esp32-dns-sinkhole-blocklist"
PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
UPDATER = ROOT / "tools" / "update_blocklist.py"


def run_launchctl(arguments: list[str]) -> None:
    try:
        subprocess.run(["launchctl", *arguments], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass


def install() -> None:
    load_config()  # Validates that local env, firmware token, and CA are present without printing them.
    if not shutil.which("go") and not Path("/usr/local/go/bin/go").is_file():
        raise RuntimeError("Go is not installed or not in PATH")
    if not UPDATER.is_file():
        raise RuntimeError(f"missing updater: {UPDATER}")

    launch_agents = PLIST.parent
    launch_agents.mkdir(parents=True, exist_ok=True, mode=0o700)
    PLIST.parent.chmod(0o700)
    stdout_path = ROOT / "outputs" / "logs" / "launchd-updater.stdout.log"
    stderr_path = ROOT / "outputs" / "logs" / "launchd-updater.stderr.log"
    (ROOT / "outputs" / "logs").mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROOT / "outputs" / "logs", 0o700)
    go_path = shutil.which("go") or "/usr/local/go/bin/go"
    environment_path = ":".join(filter(None, [
        str(Path(go_path).parent), "/opt/homebrew/bin", "/usr/local/bin",
        "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]))
    document = {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, str(UPDATER)],
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": True,
        "StartInterval": 3600,
        "ProcessType": "Background",
        "ThrottleInterval": 30,
        "EnvironmentVariables": {"PATH": environment_path},
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
    }
    run_launchctl(["bootout", f"gui/{os.getuid()}", str(PLIST)])
    temporary = PLIST.with_suffix(".plist.tmp")
    with temporary.open("wb") as stream:
        plistlib.dump(document, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    temporary.replace(PLIST)
    run_launchctl(["bootstrap", f"gui/{os.getuid()}", str(PLIST)])
    result = subprocess.run(
        ["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{LABEL}"],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("launchd job was written but could not be started; run: launchctl bootstrap gui/$(id -u) " + str(PLIST))
    print(f"Installed {LABEL}: runs at login and checks hourly; updates only when due (every 48 hours).")
    print(f"Updater log: {ROOT / 'outputs' / 'logs' / 'automatic-blocklist-update.log'}")
    print("Manual run: python3 tools/update_blocklist.py --force")
    print("Dry run: python3 tools/update_blocklist.py --dry-run")


def uninstall() -> None:
    run_launchctl(["bootout", f"gui/{os.getuid()}", str(PLIST)])
    PLIST.unlink(missing_ok=True)
    print(f"Removed {LABEL}.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--install", action="store_true", help="install and start the login/hourly scheduler")
    action.add_argument("--uninstall", action="store_true", help="stop and remove the scheduler")
    args = parser.parse_args()
    try:
        if args.install:
            install()
        else:
            uninstall()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"automation setup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
