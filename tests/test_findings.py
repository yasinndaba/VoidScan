"""Tests for VoidScan findings."""

from voidscan.findings import (
    CONFIDENCE_COLORS,
    CONFIDENCE_ORDER,
    CONFIDENCE_RANK,
    Confidence,
    Finding,
    Severity,
    deduplicate_findings,
    merge_evidence,
)


def make_finding(**overrides) -> Finding:
    values = {
        "title": "SSH Service Detected",
        "severity": Severity.INFO,
        "description": "An SSH service was detected on the target.",
        "evidence": "22/tcp open ssh",
        "recommendation": "Restrict SSH access.",
        "confidence": Confidence.HIGH,
        "why_it_matters": "Remote access expands the attack surface.",
    }
    values.update(overrides)

    return Finding(**values)


def test_severity_values():
    """Test that all supported severity levels exist."""

    assert Severity.INFO.value == "INFO"
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_confidence_values():
    """Test that all supported confidence levels exist."""

    assert Confidence.LOW.value == "LOW"
    assert Confidence.MEDIUM.value == "MEDIUM"
    assert Confidence.HIGH.value == "HIGH"


def test_confidence_order_is_most_confident_first():
    assert CONFIDENCE_ORDER == (
        Confidence.HIGH,
        Confidence.MEDIUM,
        Confidence.LOW,
    )
    assert CONFIDENCE_RANK == {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def test_every_confidence_level_has_a_color():
    assert set(CONFIDENCE_COLORS) == {level.value for level in Confidence}
    assert all(CONFIDENCE_COLORS.values())


def test_finding_defaults_to_medium_confidence_without_context():
    finding = Finding(
        title="Open Port Detected",
        severity=Severity.INFO,
        description="An open port was detected.",
        evidence="65000/tcp open unknown",
        recommendation="Review the port.",
    )

    assert finding.confidence is Confidence.MEDIUM
    assert finding.why_it_matters == ""


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


def test_merge_evidence_keeps_unique_lines_in_order():
    merged = merge_evidence(
        "22/tcp open ssh\n80/tcp open http",
        "80/tcp open http\n443/tcp open https",
    )

    assert merged == ("22/tcp open ssh\n80/tcp open http\n443/tcp open https")


def test_deduplicate_findings_merges_evidence():
    findings = [
        make_finding(evidence="22/tcp open ssh"),
        make_finding(evidence="2222/tcp open ssh"),
    ]

    deduplicated = deduplicate_findings(findings)

    assert len(deduplicated) == 1
    assert deduplicated[0].evidence == ("22/tcp open ssh\n2222/tcp open ssh")


def test_deduplicate_findings_keeps_distinct_findings():
    findings = [
        make_finding(),
        make_finding(
            title="HTTP Service Detected",
            severity=Severity.LOW,
            description="An HTTP service was detected.",
            evidence="80/tcp open http",
            recommendation="Enable HTTPS.",
        ),
    ]

    deduplicated = deduplicate_findings(findings)

    assert [finding.title for finding in deduplicated] == [
        "SSH Service Detected",
        "HTTP Service Detected",
    ]


def test_deduplicate_findings_keeps_different_confidence_apart():
    findings = [
        make_finding(confidence=Confidence.HIGH),
        make_finding(
            confidence=Confidence.LOW,
            evidence="2222/tcp open ssh",
        ),
    ]

    deduplicated = deduplicate_findings(findings)

    assert len(deduplicated) == 2
    assert [finding.confidence for finding in deduplicated] == [
        Confidence.HIGH,
        Confidence.LOW,
    ]


def test_deduplicate_findings_keeps_different_context_apart():
    findings = [
        make_finding(why_it_matters="Context one."),
        make_finding(
            why_it_matters="Context two.",
            evidence="2222/tcp open ssh",
        ),
    ]

    deduplicated = deduplicate_findings(findings)

    assert len(deduplicated) == 2
    assert [finding.why_it_matters for finding in deduplicated] == [
        "Context one.",
        "Context two.",
    ]


def test_deduplicate_findings_preserves_confidence_and_context():
    findings = [
        make_finding(
            confidence=Confidence.MEDIUM,
            why_it_matters="Context.",
            evidence="22/tcp open ssh",
        ),
        make_finding(
            confidence=Confidence.MEDIUM,
            why_it_matters="Context.",
            evidence="2222/tcp open ssh",
        ),
    ]

    deduplicated = deduplicate_findings(findings)

    assert len(deduplicated) == 1
    assert deduplicated[0].confidence is Confidence.MEDIUM
    assert deduplicated[0].why_it_matters == "Context."


def test_deduplicate_findings_does_not_mutate_input():
    original = make_finding()
    duplicate = make_finding(evidence="2222/tcp open ssh")

    deduplicate_findings([original, duplicate])

    assert original.evidence == "22/tcp open ssh"
