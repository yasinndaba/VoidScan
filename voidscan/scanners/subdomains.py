"""Subdomain enumeration engine for VoidScan."""

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class SubdomainResult:
    """Represent the result of a subdomain enumeration."""

    domain: str
    engine: str
    subdomains: list[str]
    return_code: int
    success: bool


SUPPORTED_ENGINES = {
    "subfinder": "subfinder",
    "amass": "amass",
}


def tool_installed(engine: str) -> bool:
    """Return True when the selected enumeration tool is available."""

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Unsupported enumeration engine: {engine}")

    return shutil.which(SUPPORTED_ENGINES[engine]) is not None


def run_subfinder(domain: str) -> SubdomainResult:
    """Run Subfinder against a domain."""

    command = [
        "subfinder",
        "-d",
        domain,
        "-silent",
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
            "Subfinder enumeration timed out after 300 seconds."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to execute Subfinder: {exc}"
        ) from exc

    subdomains = sorted(
        {
            line.strip()
            for line in process.stdout.splitlines()
            if line.strip()
        }
    )

    return SubdomainResult(
        domain=domain,
        engine="subfinder",
        subdomains=subdomains,
        return_code=process.returncode,
        success=process.returncode == 0,
    )


def run_amass(domain: str) -> SubdomainResult:
    """Run Amass against a domain."""

    command = [
        "amass",
        "enum",
        "-passive",
        "-d",
        domain,
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
            "Amass enumeration timed out after 300 seconds."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to execute Amass: {exc}"
        ) from exc

    subdomains = sorted(
        {
            line.strip()
            for line in process.stdout.splitlines()
            if line.strip()
        }
    )

    return SubdomainResult(
        domain=domain,
        engine="amass",
        subdomains=subdomains,
        return_code=process.returncode,
        success=process.returncode == 0,
    )


def enumerate_subdomains(
    domain: str,
    engine: str = "subfinder",
) -> SubdomainResult:
    """Enumerate subdomains using the selected engine."""

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Unsupported enumeration engine: {engine}")

    if not tool_installed(engine):
        raise RuntimeError(
            f"{engine} is not installed or could not be found in PATH."
        )

    if engine == "subfinder":
        return run_subfinder(domain)

    return run_amass(domain)