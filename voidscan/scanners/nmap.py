"""Nmap scanning engine for VoidScan."""

import logging
import os
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass

from voidscan.errors import ScanTimeout
from voidscan.process import run_command

logger = logging.getLogger("voidscan.scanners.nmap")

NMAP_TIMEOUT = 300


SCAN_PROFILES = {
    "quick": ["-T4", "-F"],
    "standard": ["-sS", "-sV", "-T4"],
    "full": ["-sS", "-sV", "-O", "-A", "-T4"],
}

# SYN scanning and OS detection require root privileges. Non-root users
# get a TCP connect scan instead so the menu options always work.
NON_ROOT_SCAN_PROFILES = {
    "quick": ["-T4", "-F"],
    "standard": ["-sT", "-sV", "-T4"],
    "full": ["-sT", "-sV", "-sC", "-T4"],
}


@dataclass
class NmapResult:
    """Represent the result of an Nmap scan."""

    target: str
    command: list[str]
    output: str
    return_code: int
    success: bool


def nmap_installed() -> bool:
    """Return True when Nmap is available on the system."""

    return shutil.which("nmap") is not None


def has_root_privileges() -> bool:
    """Return True when the current process can run privileged scans."""

    return hasattr(os, "geteuid") and os.geteuid() == 0


def build_nmap_command(target: str, profile: str) -> list[str]:
    """Build the Nmap command for the requested scan profile."""

    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {profile}")

    profiles = (
        SCAN_PROFILES if has_root_privileges() else NON_ROOT_SCAN_PROFILES
    )

    return ["nmap", *profiles[profile], target]


def run_nmap(
    target: str,
    profile: str = "standard",
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> NmapResult:
    """Run Nmap against a validated target."""

    if not nmap_installed():
        raise RuntimeError(
            "Nmap is not installed or could not be found in PATH."
        )

    command = build_nmap_command(target, profile)
    resolved_timeout = NMAP_TIMEOUT if timeout is None else timeout

    logger.info("Running Nmap command: %s", " ".join(command))

    try:
        process = run_command(
            command,
            timeout=resolved_timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )
    except ScanTimeout as exc:
        logger.warning("Nmap scan timed out for target %s", target)
        raise ScanTimeout(
            f"Nmap scan timed out after {resolved_timeout:g} seconds.",
            timeout=resolved_timeout,
            stdout=exc.stdout,
            stderr=exc.stderr,
        ) from exc
    except OSError as exc:
        logger.error("Failed to execute Nmap: %s", exc)
        raise RuntimeError(f"Failed to execute Nmap: {exc}") from exc

    output = process.stdout

    if process.stderr:
        output += f"\n{process.stderr}"

    logger.info(
        "Nmap finished with exit code %s for target %s",
        process.return_code,
        target,
    )

    return NmapResult(
        target=target,
        command=command,
        output=output,
        return_code=process.return_code,
        success=process.return_code == 0,
    )
