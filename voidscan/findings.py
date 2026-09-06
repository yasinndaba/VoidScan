"""Security finding models for VoidScan."""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Severity levels for security findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """Represent a security assessment finding."""

    title: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str