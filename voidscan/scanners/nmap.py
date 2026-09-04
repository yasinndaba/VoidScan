"""Nmap scanning engine for VoidScan."""

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class NmapResult:
    """Represent the result of an Nmap scan."""

    target: str
    command: list[str]
    output: str
    return_code: int
    success: bool


SCAN_PROFILES = {
    "quick": ["-T4", "-F"],
    "standard": ["-sS", "-sV", "-T4"],
    "full": ["-sS", "-sV", "-O", "-A", "-T4"],
}


def nmap_installed() -> bool:
    """Return True when Nmap is available on the system."""

    return shutil.which("nmap") is not None


def run_nmap(target: str, profile: str = "standard") -> NmapResult:
    """Run Nmap against a validated target."""

    if not nmap_installed():
        raise RuntimeError(
            "Nmap is not installed or could not be found in PATH."
        )

    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {profile}")

    command = [
        "nmap",
        *SCAN_PROFILES[profile],
        target,
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Nmap scan timed out after 300 seconds."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to execute Nmap: {exc}"
        ) from exc

    output = process.stdout

    if process.stderr:
        output += f"\n{process.stderr}"

    return NmapResult(
        target=target,
        command=command,
        output=output,
        return_code=process.returncode,
        success=process.returncode == 0,
    )