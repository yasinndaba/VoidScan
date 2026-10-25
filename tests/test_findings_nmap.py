"""Tests for VoidScan Nmap findings."""

from voidscan.findings import Severity
from voidscan.findings_nmap import analyze_nmap_result
from voidscan.scanners.nmap import NmapPort, NmapResult


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
        output=("22/tcp open ssh\n80/tcp open http\n443/tcp open https"),
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


def test_analyze_nmap_unknown_service_still_reports_open_port():
    """Test that every open port produces at least a generic finding."""

    result = NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="9999/tcp open unknown-service",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Open Port Detected"
    assert findings[0].severity == Severity.INFO
    assert "9999/tcp" in findings[0].evidence


def test_analyze_nmap_detects_http_proxy_as_http():
    """Test that HTTP-like service names are recognized as HTTP."""

    result = NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="8080/tcp open http-proxy",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "HTTP Service Detected"
    assert findings[0].severity == Severity.INFO


def test_analyze_nmap_escalates_risky_services():
    """Test that risky exposed services get an appropriate severity."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output=(
            "23/tcp open telnet\n"
            "3306/tcp open mysql\n"
            "445/tcp open microsoft-ds"
        ),
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    severities = {finding.title: finding.severity for finding in findings}

    assert severities["Telnet Service Detected"] == Severity.HIGH
    assert severities["Database Service Detected"] == Severity.MEDIUM
    assert severities["SMB Service Detected"] == Severity.MEDIUM


def test_analyze_nmap_uses_port_fallback():
    """Test that a known port is classified when the service is unclear."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output="3389/tcp open tcpwrapped",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Remote Desktop Service Detected"


def test_analyze_nmap_handles_open_filtered_ports():
    """Test that open|filtered ports are still reported."""

    result = NmapResult(
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        output="68/udp open|filtered dhcpc",
        return_code=0,
        success=True,
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert "open|filtered" in findings[0].evidence


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
        output=("22/tcp open ssh\n80/tcp open http"),
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


def test_analyze_nmap_prefers_structured_ports():
    result = NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="ignored text output",
        return_code=0,
        success=True,
        ports=[
            NmapPort(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
                version="OpenSSH 8.9p1",
            ),
            NmapPort(
                port=443,
                protocol="tcp",
                state="filtered",
                service="https",
            ),
        ],
    )

    findings = analyze_nmap_result(result)

    assert len(findings) == 1
    assert findings[0].title == "SSH Service Detected"
    assert "22/tcp open ssh OpenSSH 8.9p1" in findings[0].evidence
