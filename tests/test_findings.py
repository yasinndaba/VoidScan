"""Tests for VoidScan findings."""

from voidscan.findings import Finding, Severity


def test_severity_values():
    """Test that all supported severity levels exist."""

    assert Severity.INFO.value == "INFO"
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_finding_creation():
    """Test creating a security finding."""

    finding = Finding(
        title="SSH Service Detected",
        severity=Severity.INFO,
        description="An SSH service was detected on the target.",
        evidence="22/tcp open ssh",
        recommendation="Review whether SSH exposure is required.",
    )

    assert finding.title == "SSH Service Detected"
    assert finding.severity == Severity.INFO
    assert finding.description == (
        "An SSH service was detected on the target."
    )
    assert finding.evidence == "22/tcp open ssh"
    assert finding.recommendation == (
        "Review whether SSH exposure is required."
    )


def test_finding_severity_is_enum():
    """Test that finding severity uses the Severity enum."""

    finding = Finding(
        title="Test Finding",
        severity=Severity.LOW,
        description="Test description.",
        evidence="Test evidence.",
        recommendation="Test recommendation.",
    )

    assert isinstance(finding.severity, Severity)