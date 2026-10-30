"""Security finding models for VoidScan."""

from collections.abc import Sequence
from dataclasses import dataclass

from voidscan.severity import Severity

__all__ = ["Finding", "Severity", "deduplicate_findings", "merge_evidence"]


@dataclass
class Finding:
    """Represent a security assessment finding."""

    title: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str


def merge_evidence(*chunks: str) -> str:
    """Combine evidence blocks, keeping each unique non-empty line once."""

    lines: list[str] = []
    seen: set[str] = set()

    for chunk in chunks:
        for line in str(chunk).splitlines():
            normalized = line.strip()

            if not normalized or normalized in seen:
                continue

            seen.add(normalized)
            lines.append(line.rstrip())

    return "\n".join(lines)


def deduplicate_findings(
    findings: Sequence[Finding],
) -> list[Finding]:
    """Collapse identical findings while preserving all evidence."""

    merged: dict[tuple[str, Severity, str, str], Finding] = {}
    ordered_keys: list[tuple[str, Severity, str, str]] = []

    for finding in findings:
        key = (
            finding.title,
            finding.severity,
            finding.description,
            finding.recommendation,
        )

        existing = merged.get(key)

        if existing is None:
            copy = Finding(
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
            )
            merged[key] = copy
            ordered_keys.append(key)
            continue

        existing.evidence = merge_evidence(
            existing.evidence,
            finding.evidence,
        )

    return [merged[key] for key in ordered_keys]
