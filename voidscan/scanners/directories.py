"""Directory enumeration engine for VoidScan."""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_WORDLIST = Path("/usr/share/dirb/wordlists/common.txt")


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
) -> DirectoryResult:
    """Run FFUF directory enumeration against a target."""

    wordlist_path = validate_wordlist(wordlist)
    url = target.rstrip("/") + "/FUZZ"

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
            "FFUF directory enumeration timed out after 300 seconds."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to execute FFUF: {exc}"
        ) from exc

    results = sorted({
        line.strip()
        for line in process.stdout.splitlines()
        if line.strip()
    })

    return DirectoryResult(
        target=target,
        engine="ffuf",
        wordlist=str(wordlist_path),
        results=results,
        return_code=process.returncode,
        success=process.returncode == 0,
    )


def run_dirb(
    target: str,
    wordlist: str | Path,
) -> DirectoryResult:
    """Run DIRB directory enumeration against a target."""

    wordlist_path = validate_wordlist(wordlist)

    command = [
        "dirb",
        target,
        str(wordlist_path),
        "-S",
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
            "DIRB directory enumeration timed out after 300 seconds."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Failed to execute DIRB: {exc}"
        ) from exc

    results = sorted({
        line.strip()
        for line in process.stdout.splitlines()
        if line.strip()
    })

    return DirectoryResult(
        target=target,
        engine="dirb",
        wordlist=str(wordlist_path),
        results=results,
        return_code=process.returncode,
        success=process.returncode == 0,
    )


def enumerate_directories(
    target: str,
    engine: str = "ffuf",
    wordlist: str | Path = DEFAULT_WORDLIST,
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
        return run_ffuf(target, wordlist_path)

    return run_dirb(target, wordlist_path)