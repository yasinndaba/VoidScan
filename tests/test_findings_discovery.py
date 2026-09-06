"""Tests for VoidScan host discovery findings."""

from voidscan.findings import Severity
from voidscan.findings_discovery import analyze_discovery_result
from voidscan.scanners.discovery import HostDiscoveryResult


def test_analyze_discovery_detects_reachable_hosts():
    result = HostDiscoveryResult(
        network="192.168.1.0/24",
        hosts=[
            "192.168.1.1",
            "192.168.1.10",
            "192.168.1.20",
        ],
        scanned=254,
        reachable=3,
    )

    findings = analyze_discovery_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Reachable Hosts Discovered"
    assert findings[0].severity == Severity.INFO
    assert "192.168.1.10" in findings[0].evidence


def test_analyze_discovery_with_no_hosts_returns_no_findings():
    result = HostDiscoveryResult(
        network="192.168.1.0/24",
        hosts=[],
        scanned=254,
        reachable=0,
    )

    findings = analyze_discovery_result(result)

    assert findings == []


def test_analyze_discovery_uses_reachable_count():
    result = HostDiscoveryResult(
        network="10.0.0.0/24",
        hosts=["10.0.0.5", "10.0.0.10"],
        scanned=254,
        reachable=2,
    )

    findings = analyze_discovery_result(result)

    assert "2 reachable host(s)" in findings[0].description
