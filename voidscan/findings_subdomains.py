"""Subdomain security findings analyzer for VoidScan."""

from voidscan.findings import Finding, Severity
from voidscan.scanners.subdomains import SubdomainResult


def analyze_subdomain_result(result: SubdomainResult) -> list[Finding]:
    """Convert a subdomain enumeration result into structured findings."""

    if not result.success:
        return []

    findings: list[Finding] = []

    if not result.subdomains:
        return findings

    findings.append(
        Finding(
            title="Subdomains Discovered",
            severity=Severity.INFO,
            description=(
                f"{len(result.subdomains)} subdomain(s) were discovered "
                f"for the target domain."
            ),
            evidence="\n".join(result.subdomains),
            recommendation=(
                "Review discovered subdomains and verify that each exposed "
                "service is required and appropriately secured."
            ),
        )
    )

    return findings
