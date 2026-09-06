"""Tests for VoidScan directory findings."""

from voidscan.findings import Severity
from voidscan.findings_directories import analyze_directory_result
from voidscan.scanners.directories import DirectoryResult


def test_analyze_directories_detects_web_resources():
    result = DirectoryResult(
        target="http://example.com",
        engine="ffuf",
        wordlist="/usr/share/wordlists/common.txt",
        results=[
            "http://example.com/admin",
            "http://example.com/login",
            "http://example.com/backup",
        ],
        return_code=0,
        success=True,
    )

    findings = analyze_directory_result(result)

    assert len(findings) == 1
    assert findings[0].title == "Web Resources Discovered"
    assert findings[0].severity == Severity.INFO
    assert "admin" in findings[0].evidence
    assert "backup" in findings[0].evidence


def test_analyze_directories_with_no_results_returns_no_findings():
    result = DirectoryResult(
        target="http://example.com",
        engine="ffuf",
        wordlist="/usr/share/wordlists/common.txt",
        results=[],
        return_code=0,
        success=True,
    )

    findings = analyze_directory_result(result)

    assert findings == []


def test_analyze_directories_failed_scan_returns_no_findings():
    result = DirectoryResult(
        target="http://example.com",
        engine="ffuf",
        wordlist="/usr/share/wordlists/common.txt",
        results=[],
        return_code=1,
        success=False,
    )

    findings = analyze_directory_result(result)

    assert findings == []
