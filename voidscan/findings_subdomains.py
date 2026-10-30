"""Subdomain security findings analyzer for VoidScan."""

from voidscan.findings import Finding
from voidscan.scanners.subdomains import SubdomainResult
from voidscan.severity import SUBDOMAIN_SEVERITY


def analyze_subdomain_result(result: SubdomainResult) -> list[Finding]:
    """Convert a subdomain enumeration result into structured findings."""

    if not (result.success or result.subdomains):
        return []

    findings: list[Finding] = []

    if not result.subdomains:
        return findings

    description = (
        f"{len(result.subdomains)} subdomain(s) were discovered "
        f"for the target domain."
    )

    if result.timed_out:
        description += (
            " The enumeration timed out, so these results may be incomplete."
        )

    findings.append(
        Finding(
            title="Subdomains Discovered",
            severity=SUBDOMAIN_SEVERITY,
            description=description,
            evidence="\n".join(result.subdomains),
            recommendation=(
                "Review discovered subdomains and verify that each exposed "
                "service is required and appropriately secured."
            ),
        )
    )

    return findings
