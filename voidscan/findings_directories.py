"""Directory enumeration security findings analyzer for VoidScan."""

from voidscan.findings import Finding, Severity
from voidscan.scanners.directories import DirectoryResult


def analyze_directory_result(result: DirectoryResult) -> list[Finding]:
    """Convert a directory enumeration result into structured findings."""

    if not result.success:
        return []

    if not result.results:
        return []

    return [
        Finding(
            title="Web Resources Discovered",
            severity=Severity.INFO,
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
        )
    ]
