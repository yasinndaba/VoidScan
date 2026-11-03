"""Directory enumeration security findings analyzer for VoidScan."""

from voidscan.findings import Confidence, Finding
from voidscan.scanners.directories import DirectoryResult
from voidscan.severity import DIRECTORY_SEVERITY


def analyze_directory_result(result: DirectoryResult) -> list[Finding]:
    """Convert a directory enumeration result into structured findings."""

    if not result.success:
        return []

    if not result.results:
        return []

    return [
        Finding(
            title="Web Resources Discovered",
            severity=DIRECTORY_SEVERITY,
            description=(
                f"{len(result.results)} web resource(s) were discovered "
                f"on the target."
            ),
            evidence="\n".join(result.results),
            recommendation=(
                "Review discovered resources and remove unnecessary "
                "exposed files or directories. Verify that accessible "
                "resources are properly secured."
            ),
            confidence=Confidence.HIGH,
            why_it_matters=(
                "Exposed files and directories can reveal sensitive data, "
                "backups, or administrative interfaces."
            ),
        )
    ]
