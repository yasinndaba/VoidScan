"""Subdomain enumeration engine for VoidScan."""

import logging
import shutil
import subprocess
from dataclasses import dataclass

from voidscan.validators import is_valid_hostname


logger = logging.getLogger("voidscan.scanners.subdomains")

SUBFINDER_TIMEOUT = 300
AMASS_TIMEOUT = 900
AMASS_PROGRESS_TIMEOUT_MINUTES = 5


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


def parse_subdomains(output: str) -> list[str]:
    """Extract valid hostnames from enumeration tool output.

    Some tools (notably Amass) print banner and session lines to stdout,
    so raw output cannot be used directly.
    """

    subdomains = set()

    for line in output.splitlines():
        candidate = line.strip().lower().rstrip(".")

        if candidate and is_valid_hostname(candidate):
            subdomains.add(candidate)

    return sorted(subdomains)


def run_subfinder(domain: str) -> SubdomainResult:
    """Run Subfinder against a domain."""

    command = [
        "subfinder",
        "-d",
        domain,
        "-silent",
    ]

    logger.info("Running Subfinder command: %s", " ".join(command))

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SUBFINDER_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Subfinder timed out for domain %s", domain)
        raise RuntimeError(
            f"Subfinder enumeration timed out after "
            f"{SUBFINDER_TIMEOUT} seconds."
        ) from exc
    except OSError as exc:
        logger.error("Failed to execute Subfinder: %s", exc)
        raise RuntimeError(
            f"Failed to execute Subfinder: {exc}"
        ) from exc

    subdomains = parse_subdomains(process.stdout)

    logger.info(
        "Subfinder finished with exit code %s and %s result(s)",
        process.returncode,
        len(subdomains),
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
        "-timeout",
        str(AMASS_PROGRESS_TIMEOUT_MINUTES),
        "-d",
        domain,
    ]

    logger.info("Running Amass command: %s", " ".join(command))

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=AMASS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Amass timed out for domain %s", domain)
        raise RuntimeError(
            f"Amass enumeration timed out after "
            f"{AMASS_TIMEOUT} seconds. Try a smaller domain or use "
            f"Subfinder for faster results."
        ) from exc
    except OSError as exc:
        logger.error("Failed to execute Amass: %s", exc)
        raise RuntimeError(
            f"Failed to execute Amass: {exc}"
        ) from exc

    subdomains = parse_subdomains(process.stdout)

    logger.info(
        "Amass finished with exit code %s and %s result(s)",
        process.returncode,
        len(subdomains),
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
