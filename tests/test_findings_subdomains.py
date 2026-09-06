"""Tests for VoidScan subdomain findings."""

from voidscan.findings import Severity
from voidscan.findings_subdomains import analyze_subdomain_result
from voidscan.scanners.subdomains import SubdomainResult


def test_analyze_subdomains_detects_discovered_subdomains():
    result = SubdomainResult(
        domain="example.com",
        engine="subfinder",
        subdomains=[
            "api.example.com",
            "mail.example.com",
            "dev.example.com",
        ],
        return_code=0,
        success=True,
    )

    findings = analyze_subdomain_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Subdomains Discovered"
    assert findings[0].severity == Severity.INFO
    assert "api.example.com" in findings[0].evidence
    assert "dev.example.com" in findings[0].evidence


def test_analyze_subdomains_with_no_results_returns_no_findings():
    result = SubdomainResult(
        domain="example.com",
        engine="subfinder",
        subdomains=[],
        return_code=0,
        success=True,
    )

    findings = analyze_subdomain_result(result)

    assert findings == []


def test_analyze_subdomains_failed_scan_returns_no_findings():
    result = SubdomainResult(
        domain="example.com",
        engine="subfinder",
        subdomains=[],
        return_code=1,
        success=False,
    )

    findings = analyze_subdomain_result(result)

    assert findings == []
