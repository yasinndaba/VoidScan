"""Tests for VoidScan IP information findings."""

from voidscan.findings import Severity
from voidscan.findings_ip_info import analyze_ip_info_result
from voidscan.scanners.ip_info import IPInfoResult


def test_analyze_ip_info_detects_private_address():
    result = IPInfoResult(
        address="192.168.1.10",
        version="IPv4",
        is_private=True,
        is_loopback=False,
        is_reserved=False,
        is_multicast=False,
        reverse_dns=None,
    )

    findings = analyze_ip_info_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Private IP Address Identified"
    assert findings[0].severity == Severity.INFO
    assert findings[0].evidence == "192.168.1.10"


def test_analyze_ip_info_detects_reverse_dns():
    result = IPInfoResult(
        address="192.168.1.10",
        version="IPv4",
        is_private=True,
        is_loopback=False,
        is_reserved=False,
        is_multicast=False,
        reverse_dns="server.example.com",
    )

    findings = analyze_ip_info_result(result)

    assert len(findings) == 2
    titles = {finding.title for finding in findings}

    assert titles == {
        "Private IP Address Identified",
        "Reverse DNS Record Identified",
    }


def test_analyze_ip_info_detects_loopback():
    result = IPInfoResult(
        address="127.0.0.1",
        version="IPv4",
        is_private=True,
        is_loopback=True,
        is_reserved=False,
        is_multicast=False,
        reverse_dns=None,
    )

    findings = analyze_ip_info_result(result)

    titles = {finding.title for finding in findings}

    assert "Private IP Address Identified" in titles
    assert "Loopback IP Address Identified" in titles


def test_analyze_ip_info_detects_reserved_address():
    result = IPInfoResult(
        address="240.0.0.1",
        version="IPv4",
        is_private=False,
        is_loopback=False,
        is_reserved=True,
        is_multicast=False,
        reverse_dns=None,
    )

    findings = analyze_ip_info_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Reserved IP Address Identified"


def test_analyze_ip_info_detects_multicast_address():
    result = IPInfoResult(
        address="224.0.0.1",
        version="IPv4",
        is_private=False,
        is_loopback=False,
        is_reserved=False,
        is_multicast=True,
        reverse_dns=None,
    )

    findings = analyze_ip_info_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Multicast IP Address Identified"


def test_analyze_ip_info_with_no_special_properties_returns_no_findings():
    result = IPInfoResult(
        address="8.8.8.8",
        version="IPv4",
        is_private=False,
        is_loopback=False,
        is_reserved=False,
        is_multicast=False,
        reverse_dns=None,
    )

    findings = analyze_ip_info_result(result)

    assert findings == []
