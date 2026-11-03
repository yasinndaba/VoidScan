"""Nmap security findings analyzer for VoidScan."""

import re
from collections.abc import Iterator

from voidscan.findings import Confidence, Finding
from voidscan.scanners.nmap import NmapResult
from voidscan.severity import rule_for_service

OPEN_PORT_PATTERN = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)",
    re.IGNORECASE,
)


def _port_entries(
    result: NmapResult,
) -> Iterator[tuple[int, str, str, str, str, Confidence]]:
    """Yield port details from structured output or parse text."""

    if result.ports:
        for entry in result.ports:
            evidence = (
                f"{entry.port}/{entry.protocol} {entry.state} {entry.service}"
            )

            if entry.version:
                evidence += f" {entry.version}"

            yield (
                entry.port,
                entry.protocol,
                entry.state,
                entry.service,
                evidence,
                Confidence.HIGH,
            )

        return

    for line in result.output.splitlines():
        match = OPEN_PORT_PATTERN.search(line)

        if not match:
            continue

        yield (
            int(match.group(1)),
            match.group(2),
            match.group(3),
            match.group(4),
            line.strip(),
            Confidence.MEDIUM,
        )


def analyze_nmap_result(result: NmapResult) -> list[Finding]:
    """Convert an Nmap result into structured security findings."""

    if not result.success:
        return []

    findings: list[Finding] = []

    for (
        port,
        protocol,
        state,
        service,
        evidence,
        confidence,
    ) in _port_entries(result):
        state = state.lower()

        if not state.startswith("open"):
            continue

        service = service.lower()
        rule = rule_for_service(port, service)

        findings.append(
            Finding(
                title=rule.title,
                severity=rule.severity,
                description=(
                    f"{rule.description} "
                    f"Detected {protocol.upper()} port {port} "
                    f"({service}, {state})."
                ),
                evidence=evidence,
                recommendation=rule.recommendation,
                confidence=confidence,
                why_it_matters=rule.why_it_matters,
            )
        )

    return findings
