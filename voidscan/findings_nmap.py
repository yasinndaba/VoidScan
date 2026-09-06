"""Nmap security findings analyzer for VoidScan."""

import re

from voidscan.findings import Finding, Severity
from voidscan.scanners.nmap import NmapResult


SERVICE_RULES = {
    "ssh": (
        "SSH Service Detected",
        "An SSH service was detected on the target.",
        "Review whether SSH exposure is required and restrict access where appropriate.",
    ),
    "http": (
        "HTTP Service Detected",
        "An HTTP web service was detected on the target.",
        "Review the web service configuration and ensure sensitive traffic uses HTTPS.",
    ),
    "https": (
        "HTTPS Service Detected",
        "An HTTPS web service was detected on the target.",
        "Verify that TLS is correctly configured and kept up to date.",
    ),
}


def analyze_nmap_result(result: NmapResult) -> list[Finding]:
    """Convert an Nmap result into structured security findings."""

    if not result.success:
        return []

    findings: list[Finding] = []

    for line in result.output.splitlines():
        match = re.search(
            r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        service = match.group(3).lower()

        if service not in SERVICE_RULES:
            continue

        title, description, recommendation = SERVICE_RULES[service]

        findings.append(
            Finding(
                title=title,
                severity=Severity.INFO,
                description=description,
                evidence=line.strip(),
                recommendation=recommendation,
            )
        )

    return findings