"""Directory enumeration engine for VoidScan."""

import logging
import re
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from voidscan.errors import ScanTimeout
from voidscan.process import run_command


logger = logging.getLogger("voidscan.scanners.directories")

DEFAULT_WORDLIST = Path("/usr/share/dirb/wordlists/common.txt")
FFUF_TIMEOUT = 300
DIRB_TIMEOUT = 300

DIRB_RESULT_PATTERN = re.compile(r"^\+\s+(https?://\S+)")


@dataclass
class DirectoryResult:
    """Represent the result of a directory enumeration."""

    target: str
    engine: str
    wordlist: str
    results: list[str]
    return_code: int
    success: bool


SUPPORTED_ENGINES = {
    "ffuf": "ffuf",
    "dirb": "dirb",
}


def tool_installed(engine: str) -> bool:
    """Return True when the selected enumeration tool is installed."""

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Unsupported enumeration engine: {engine}")

    return shutil.which(SUPPORTED_ENGINES[engine]) is not None


def validate_wordlist(wordlist: str | Path) -> Path:
    """Validate and return an existing, readable wordlist path."""

    path = Path(wordlist).expanduser()

    if not path.is_file():
        raise ValueError(f"Wordlist not found: {path}")

    try:
        with path.open("r"):
            pass
    except OSError as exc:
        raise ValueError(f"Wordlist is not readable: {path}") from exc

    return path


def run_ffuf(
    target: str,
    wordlist: str | Path,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> DirectoryResult:
    """Run FFUF directory enumeration against a target."""

    wordlist_path = validate_wordlist(wordlist)
    url = target.rstrip("/") + "/FUZZ"
    resolved_timeout = FFUF_TIMEOUT if timeout is None else timeout

    command = [
        "ffuf",
        "-u",
        url,
        "-w",
        str(wordlist_path),
        "-mc",
        "200,204,301,302,307,401,403",
        "-s",
    ]

    logger.info("Running FFUF command: %s", " ".join(command))

    try:
        process = run_command(
            command,
            timeout=resolved_timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )
    except ScanTimeout as exc:
        logger.warning("FFUF enumeration timed out for target %s", target)
        raise ScanTimeout(
            f"FFUF directory enumeration timed out after "
            f"{resolved_timeout:g} seconds.",
            timeout=resolved_timeout,
            stdout=exc.stdout,
            stderr=exc.stderr,
        ) from exc
    except OSError as exc:
        logger.error("Failed to execute FFUF: %s", exc)
        raise RuntimeError(
            f"Failed to execute FFUF: {exc}"
        ) from exc

    results = sorted({
        url.replace("FUZZ", word.strip())
        for word in process.stdout.splitlines()
        if word.strip()
    })

    logger.info(
        "FFUF finished with exit code %s and %s result(s)",
        process.return_code,
        len(results),
    )

    return DirectoryResult(
        target=target,
        engine="ffuf",
        wordlist=str(wordlist_path),
        results=results,
        return_code=process.return_code,
        success=process.return_code == 0,
    )


def parse_dirb_results(output: str) -> list[str]:
    """Extract discovered URLs from DIRB output."""

    return sorted({
        match.group(1)
        for line in output.splitlines()
        if (match := DIRB_RESULT_PATTERN.match(line.strip()))
    })


def run_dirb(
    target: str,
    wordlist: str | Path,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> DirectoryResult:
    """Run DIRB directory enumeration against a target."""

    wordlist_path = validate_wordlist(wordlist)
    resolved_timeout = DIRB_TIMEOUT if timeout is None else timeout

    command = [
        "dirb",
        target,
        str(wordlist_path),
        "-S",
    ]

    logger.info("Running DIRB command: %s", " ".join(command))

    try:
        process = run_command(
            command,
            timeout=resolved_timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )
    except ScanTimeout as exc:
        logger.warning("DIRB enumeration timed out for target %s", target)
        raise ScanTimeout(
            f"DIRB directory enumeration timed out after "
            f"{resolved_timeout:g} seconds.",
            timeout=resolved_timeout,
            stdout=exc.stdout,
            stderr=exc.stderr,
        ) from exc
    except OSError as exc:
        logger.error("Failed to execute DIRB: %s", exc)
        raise RuntimeError(
            f"Failed to execute DIRB: {exc}"
        ) from exc

    results = parse_dirb_results(process.stdout)

    logger.info(
        "DIRB finished with exit code %s and %s result(s)",
        process.return_code,
        len(results),
    )

    return DirectoryResult(
        target=target,
        engine="dirb",
        wordlist=str(wordlist_path),
        results=results,
        return_code=process.return_code,
        success=process.return_code == 0,
    )


def enumerate_directories(
    target: str,
    engine: str = "ffuf",
    wordlist: str | Path = DEFAULT_WORDLIST,
    *,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
) -> DirectoryResult:
    """Run directory enumeration using the selected engine."""

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Unsupported enumeration engine: {engine}")

    if not tool_installed(engine):
        raise RuntimeError(
            f"{engine} is not installed or could not be found in PATH."
        )

    wordlist_path = validate_wordlist(wordlist)

    if engine == "ffuf":
        return run_ffuf(
            target,
            wordlist_path,
            timeout=timeout,
            cancel_event=cancel_event,
            on_heartbeat=on_heartbeat,
        )

    return run_dirb(
        target,
        wordlist_path,
        timeout=timeout,
        cancel_event=cancel_event,
        on_heartbeat=on_heartbeat,
    )
