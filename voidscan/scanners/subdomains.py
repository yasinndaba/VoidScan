"""Subdomain enumeration engine for VoidScan."""

import json
import logging
import math
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass

from voidscan.errors import ScanTimeout
from voidscan.process import run_command
from voidscan.validators import is_valid_hostname

logger = logging.getLogger("voidscan.scanners.subdomains")

SUBFINDER_TIMEOUT = 300
AMASS_TIMEOUT = 900


@dataclass
class SubdomainResult:
    """Represent the result of a subdomain enumeration."""

    domain: str
    engine: str
    subdomains: list[str]
    return_code: int
    success: bool
    timed_out: bool = False


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

    Subfinder's JSON output is parsed when present. Amass and older tool
    versions still emit banner and session lines to stdout, so plain text
    lines are used as a fallback.
    """

    subdomains = set()

    for raw in output.splitlines():
        candidate = raw.strip()

        if not candidate:
            continue

        if candidate.startswith("{"):
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                payload = None

            if isinstance(payload, dict):
                host = payload.get("host") or payload.get("name")
                if not isinstance(host, str):
                    continue
                candidate = host

        candidate = candidate.lower().rstrip(".")

        if candidate and is_valid_hostname(candidate):
            subdomains.add(candidate)

    return sorted(subdomains)


def run_subfinder(
    domain: str,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> SubdomainResult:
    """Run Subfinder against a domain."""

    resolved_timeout = SUBFINDER_TIMEOUT if timeout is None else timeout

    command = [
        "subfinder",
        "-d",
        domain,
        "-silent",
        "-json",
    ]

    logger.info("Running Subfinder command: %s", " ".join(command))

    try:
        process = run_command(
            command,
            timeout=resolved_timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )
    except ScanTimeout as exc:
        logger.warning("Subfinder timed out for domain %s", domain)
        raise ScanTimeout(
            f"Subfinder enumeration timed out after "
            f"{resolved_timeout:g} seconds.",
            timeout=resolved_timeout,
            stdout=exc.stdout,
            stderr=exc.stderr,
        ) from exc
    except OSError as exc:
        logger.error("Failed to execute Subfinder: %s", exc)
        raise RuntimeError(f"Failed to execute Subfinder: {exc}") from exc

    subdomains = parse_subdomains(process.stdout)

    logger.info(
        "Subfinder finished with exit code %s and %s result(s)",
        process.return_code,
        len(subdomains),
    )

    return SubdomainResult(
        domain=domain,
        engine="subfinder",
        subdomains=subdomains,
        return_code=process.return_code,
        success=process.return_code == 0,
    )


def run_amass(
    domain: str,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> SubdomainResult:
    """Run Amass against a domain.

    Amass is allowed to time out gracefully: whatever hostnames were printed
    before the timeout are returned as partial results instead of being lost.
    """

    resolved_timeout = AMASS_TIMEOUT if timeout is None else timeout
    amass_minutes = max(1, math.ceil(resolved_timeout / 60))

    command = [
        "amass",
        "enum",
        "-passive",
        "-timeout",
        str(amass_minutes),
        "-d",
        domain,
    ]

    logger.info("Running Amass command: %s", " ".join(command))

    try:
        process = run_command(
            command,
            timeout=resolved_timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )
    except ScanTimeout as exc:
        subdomains = parse_subdomains(f"{exc.stdout}\n{exc.stderr}")

        logger.warning(
            "Amass timed out for domain %s with %s partial result(s)",
            domain,
            len(subdomains),
        )

        return SubdomainResult(
            domain=domain,
            engine="amass",
            subdomains=subdomains,
            return_code=exc.return_code,
            success=False,
            timed_out=True,
        )
    except OSError as exc:
        logger.error("Failed to execute Amass: %s", exc)
        raise RuntimeError(f"Failed to execute Amass: {exc}") from exc

    subdomains = parse_subdomains(process.stdout)

    logger.info(
        "Amass finished with exit code %s and %s result(s)",
        process.return_code,
        len(subdomains),
    )

    return SubdomainResult(
        domain=domain,
        engine="amass",
        subdomains=subdomains,
        return_code=process.return_code,
        success=process.return_code == 0,
    )


def merge_subdomain_results(
    primary: SubdomainResult,
    secondary: SubdomainResult,
) -> SubdomainResult:
    """Merge two enumeration results, preserving every unique hostname."""

    engines = "+".join(dict.fromkeys((primary.engine, secondary.engine)))

    return SubdomainResult(
        domain=primary.domain,
        engine=engines,
        subdomains=sorted(set(primary.subdomains) | set(secondary.subdomains)),
        return_code=(
            secondary.return_code if secondary.success else primary.return_code
        ),
        success=primary.success or secondary.success,
        timed_out=primary.timed_out or secondary.timed_out,
    )


def enumerate_subdomains(
    domain: str,
    engine: str = "subfinder",
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> SubdomainResult:
    """Enumerate subdomains using the selected engine."""

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Unsupported enumeration engine: {engine}")

    if not tool_installed(engine):
        raise RuntimeError(
            f"{engine} is not installed or could not be found in PATH."
        )

    if engine == "subfinder":
        return run_subfinder(
            domain,
            timeout=timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )

    return run_amass(
        domain,
        timeout=timeout,
        cancel_event=cancel_event,
        on_heartbeat=on_heartbeat,
    )
