"""Security finding models for VoidScan."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from voidscan.severity import Severity

__all__ = [
    "CONFIDENCE_COLORS",
    "CONFIDENCE_ORDER",
    "CONFIDENCE_RANK",
    "Confidence",
    "Finding",
    "Severity",
    "deduplicate_findings",
    "merge_evidence",
]


class Confidence(str, Enum):
    """How certain a finding is, based on the evidence behind it."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Most confident first, for display and for future sorting.
CONFIDENCE_ORDER = (
    Confidence.HIGH,
    Confidence.MEDIUM,
    Confidence.LOW,
)

CONFIDENCE_RANK = {
    confidence.value: index
    for index, confidence in enumerate(CONFIDENCE_ORDER)
}

CONFIDENCE_COLORS = {
    "HIGH": "green",
    "MEDIUM": "yellow",
    "LOW": "red",
}


@dataclass
class Finding:
    """Represent a security assessment finding."""

    title: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str
    confidence: Confidence = Confidence.MEDIUM
    why_it_matters: str = ""


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

    key_type = tuple[str, Severity, str, str, Confidence, str]
    merged: dict[key_type, Finding] = {}
    ordered_keys: list[key_type] = []

    for finding in findings:
        key: key_type = (
            finding.title,
            finding.severity,
            finding.description,
            finding.recommendation,
            finding.confidence,
            finding.why_it_matters,
        )

        existing = merged.get(key)

        if existing is None:
            copy = Finding(
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                confidence=finding.confidence,
                why_it_matters=finding.why_it_matters,
            )
            merged[key] = copy
            ordered_keys.append(key)
            continue

        existing.evidence = merge_evidence(
            existing.evidence,
            finding.evidence,
        )

    return [merged[key] for key in ordered_keys]
