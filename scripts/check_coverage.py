"""Enforce coverage thresholds for the quality gate.

Run ``pytest --cov`` first so that a ``.coverage`` data file exists, then
run this script. The overall threshold lives in ``pyproject.toml``; this
script adds the stricter per-package thresholds.
"""

from __future__ import annotations

import sys

from coverage import Coverage

GLOBAL_THRESHOLD = 85.0
PACKAGE_THRESHOLD = 90.0

PACKAGES = {
    "scanners": ("voidscan/scanners/",),
    "reporters": (
        "voidscan/reporter.py",
        "voidscan/html_reporter.py",
    ),
}


def _matches(filename: str, prefixes: tuple[str, ...]) -> bool:
    """Return True when a measured file belongs to a package."""

    normalized = filename.replace("\\", "/")
    return any(prefix in normalized for prefix in prefixes)


def _percentage(
    coverage: Coverage,
    prefixes: tuple[str, ...] | None,
) -> tuple[int, int]:
    """Return covered and total statement counts for a file group."""

    measured = coverage.get_data().measured_files()
    files = (
        [name for name in measured if _matches(name, prefixes)]
        if prefixes is not None
        else list(measured)
    )

    covered = 0
    total = 0

    for filename in files:
        _, statements, _, missing, _ = coverage.analysis2(filename)
        total += len(statements)
        covered += len(statements) - len(missing)

    return covered, total


def _check(
    label: str,
    coverage: Coverage,
    prefixes: tuple[str, ...] | None,
    threshold: float,
) -> bool:
    """Report one threshold check and return whether it passed."""

    covered, total = _percentage(coverage, prefixes)

    if total == 0:
        print(f"{label}: no coverage data")
        return False

    percent = 100.0 * covered / total
    passed = percent >= threshold
    status = "ok" if passed else "FAIL"

    print(f"{label}: {percent:.1f}% [{status}] (minimum {threshold:.0f}%)")

    return passed


def main() -> int:
    """Check global and per-package coverage thresholds."""

    coverage = Coverage()

    try:
        coverage.load()
    except Exception:
        print(
            "No coverage data found. Run `pytest --cov` first.",
            file=sys.stderr,
        )
        return 2

    passed = _check("overall", coverage, None, GLOBAL_THRESHOLD)

    for name, prefixes in PACKAGES.items():
        passed = _check(name, coverage, prefixes, PACKAGE_THRESHOLD) and passed

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
