"""Tests for VoidScan Nmap findings."""

from voidscan.findings import Severity
from voidscan.findings_nmap import analyze_nmap_result
from voidscan.scanners.nmap import NmapResult


def test_analyze_nmap_detects_ssh():
    """Test that an SSH service produces an informational finding."""

    result = NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="22/tcp open ssh",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "SSH Service Detected"
    assert findings[0].severity == Severity.INFO
    assert "22/tcp open ssh" in findings[0].evidence


def test_analyze_nmap_detects_http():
    """Test that an HTTP service produces an informational finding."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output="80/tcp open http",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "HTTP Service Detected"
    assert findings[0].severity == Severity.INFO


def test_analyze_nmap_detects_multiple_services():
    """Test that multiple recognized services produce findings."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output=(
            "22/tcp open ssh\n"
            "80/tcp open http\n"
            "443/tcp open https"
        ),
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 3

    titles = {finding.title for finding in findings}

    assert titles == {
        "SSH Service Detected",
        "HTTP Service Detected",
        "HTTPS Service Detected",
    }


def test_analyze_nmap_failed_scan_returns_no_findings():
    """Test that a failed Nmap scan produces no findings."""

    result = NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="Nmap failed",
        return_code=1,
        success=False,
    )

    findings = analyze_nmap_result(result)

    assert findings == []


def test_analyze_nmap_unknown_service_returns_no_finding():
    """Test that an unrecognized service produces no finding."""

    result = NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="9999/tcp open unknown-service",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert findings == []
def test_analyze_nmap_detects_https_without_http():
    """Test that HTTPS does not incorrectly produce an HTTP finding."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output="443/tcp open https",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "HTTPS Service Detected"


def test_analyze_nmap_uses_specific_line_as_evidence():
    """Test that findings contain the matching Nmap line as evidence."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output=(
            "22/tcp open ssh\n"
            "80/tcp open http"
        ),
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    ssh_finding = next(
        finding
        for finding in findings
        if finding.title == "SSH Service Detected"
    )

    assert ssh_finding.evidence == "22/tcp open ssh"
