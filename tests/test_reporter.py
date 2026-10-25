"""Tests for VoidScan reporting utilities."""

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest

from voidscan.findings import Finding, Severity
from voidscan.reporter import (
    REPORT_SCHEMA_VERSION,
    build_report_summary,
    create_report,
    display_findings,
    display_report_summary,
    save_json_report,
    save_scan_report,
)


@dataclass
class MockScanResult:
    success: bool
    findings: list[str]


def make_finding(**overrides) -> Finding:
    values = {
        "title": "SSH Service Detected",
        "severity": Severity.INFO,
        "description": "An SSH service was detected on the target.",
        "evidence": "22/tcp open ssh",
        "recommendation": "Restrict SSH access where possible.",
    }
    values.update(overrides)
    return Finding(**values)


def test_create_report_with_dataclass():
    result = MockScanResult(
        success=True,
        findings=["Port 22 open"],
    )

    report = create_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
    )

    assert report["tool"] == "VoidScan"
    assert report["version"] == "0.2.0"
    assert report["scan_type"] == "Network Scan"
    assert report["target"] == "192.168.1.10"
    assert "timestamp" in report

    assert report["result"]["success"] is True
    assert report["result"]["findings"] == ["Port 22 open"]


def test_report_schema_shape_is_locked():
    result = MockScanResult(success=True, findings=[])

    report = create_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
        findings=[make_finding()],
    )

    assert REPORT_SCHEMA_VERSION == 1
    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert list(report) == [
        "tool",
        "schema_version",
        "version",
        "scan_type",
        "target",
        "timestamp",
        "result",
        "findings",
    ]


def test_create_report_with_dictionary():
    result = {
        "status": "success",
        "findings": ["Example finding"],
    }

    report = create_report(
        scan_type="Test Scan",
        target="example.com",
        result=result,
    )

    assert report["result"] == result


def test_create_report_rejects_invalid_result():
    with pytest.raises(TypeError):
        create_report(
            scan_type="Test Scan",
            target="example.com",
            result="invalid",
        )


def test_save_json_report(tmp_path: Path):
    report = {
        "tool": "VoidScan",
        "version": "0.1.0",
        "scan_type": "Network Scan",
        "target": "192.168.1.10",
        "timestamp": "2026-09-05T12:00:00+00:00",
        "result": {
            "success": True,
        },
    }

    output_path = save_json_report(
        report,
        tmp_path,
    )

    assert output_path.exists()
    assert output_path.is_file()
    assert output_path.suffix == ".json"

    content = output_path.read_text(
        encoding="utf-8",
    )

    assert '"tool": "VoidScan"' in content
    assert '"version": "0.1.0"' in content
    assert '"scan_type": "Network Scan"' in content
    assert '"target": "192.168.1.10"' in content
    assert '"success": true' in content


def test_create_report_with_structured_findings():
    result = MockScanResult(
        success=True,
        findings=[],
    )

    report = create_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
        findings=[make_finding()],
    )

    assert len(report["findings"]) == 1

    finding = report["findings"][0]

    assert finding["title"] == "SSH Service Detected"
    assert finding["severity"] == "INFO"
    assert finding["evidence"] == "22/tcp open ssh"


def test_create_report_deduplicates_findings_and_merges_evidence():
    result = MockScanResult(success=True, findings=[])

    report = create_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
        findings=[
            make_finding(evidence="22/tcp open ssh"),
            make_finding(evidence="2222/tcp open ssh"),
        ],
    )

    assert len(report["findings"]) == 1
    assert report["findings"][0]["evidence"] == (
        "22/tcp open ssh\n2222/tcp open ssh"
    )


def test_create_report_defaults_to_empty_findings():
    result = MockScanResult(
        success=True,
        findings=[],
    )

    report = create_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
    )

    assert report["findings"] == []


def test_create_report_accepts_already_serialized_findings():
    result = MockScanResult(success=True, findings=[])

    report = create_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
        findings=[
            {
                "title": "Custom finding",
                "severity": "HIGH",
            }
        ],
    )

    assert report["findings"][0]["severity"] == "HIGH"


def test_create_report_rejects_invalid_findings():
    result = MockScanResult(success=True, findings=[])

    with pytest.raises(TypeError):
        create_report(
            scan_type="Network Scan",
            target="192.168.1.10",
            result=result,
            findings=["not a finding"],
        )


def test_save_scan_report_persists_findings(tmp_path: Path):
    result = MockScanResult(success=True, findings=[])

    output_path = save_scan_report(
        scan_type="Network Scan",
        target="192.168.1.10",
        result=result,
        output_directory=tmp_path,
        findings=[make_finding()],
    )

    content = output_path.read_text(encoding="utf-8")

    assert '"findings"' in content
    assert "SSH Service Detected" in content
    assert '"severity": "INFO"' in content


def test_build_report_summary():
    report = {
        "tool": "VoidScan",
        "version": "0.1.0",
        "scan_type": "Network Discovery",
        "target": "192.168.1.0/24",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
            "return_code": 0,
            "hosts": [
                "192.168.1.1",
                "192.168.1.10",
                "192.168.1.20",
            ],
        },
    }

    summary = build_report_summary(report)

    assert summary["scan_type"] == "Network Discovery"
    assert summary["target"] == "192.168.1.0/24"
    assert summary["success"] is True
    assert summary["return_code"] == 0
    assert summary["hosts_found"] == 3


def test_build_report_summary_with_subdomains():
    report = {
        "scan_type": "Subdomain Enumeration",
        "target": "example.com",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
            "return_code": 0,
            "subdomains": [
                "api.example.com",
                "mail.example.com",
                "www.example.com",
            ],
        },
    }

    summary = build_report_summary(report)

    assert summary["subdomains_found"] == 3
    assert summary["success"] is True
    assert summary["return_code"] == 0


def test_build_report_summary_with_directories():
    report = {
        "scan_type": "Directory Enumeration",
        "target": "http://example.com",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
            "return_code": 0,
            "results": [
                "/admin",
                "/login",
                "/uploads",
            ],
        },
    }

    summary = build_report_summary(report)

    assert summary["results_found"] == 3
    assert summary["success"] is True
    assert summary["return_code"] == 0


def test_build_report_summary_counts_findings():
    report = {
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {"success": True, "return_code": 0},
        "findings": [
            {"title": "One", "severity": "INFO"},
            {"title": "Two", "severity": "HIGH"},
            {"title": "Three", "severity": "HIGH"},
        ],
    }

    summary = build_report_summary(report)

    assert summary["findings_count"] == 3
    assert summary["findings_by_severity"] == {
        "HIGH": 2,
        "INFO": 1,
    }


def test_build_report_summary_without_findings_reports_zero():
    report = {
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {"success": True, "return_code": 0},
    }

    summary = build_report_summary(report)

    assert summary["findings_count"] == 0
    assert "findings_by_severity" not in summary


def test_display_report_summary():
    report = {
        "tool": "VoidScan",
        "version": "0.1.0",
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-05T12:00:00+00:00",
        "result": {
            "success": True,
            "return_code": 0,
        },
    }

    with patch(
        "voidscan.reporter.Console"
    ) as mock_console:
        display_report_summary(report)

    mock_console.return_value.print.assert_called_once()


def test_display_report_summary_prints_a_single_table():
    report = {
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-05T12:00:00+00:00",
        "result": {"success": True, "return_code": 0},
        "findings": [
            {"title": "One", "severity": "INFO"},
            {"title": "Two", "severity": "HIGH"},
        ],
    }

    with patch(
        "voidscan.reporter.Console"
    ) as mock_console:
        display_report_summary(report)

    # The summary carries the counts; the detailed table is shown once by
    # display_findings(), so this must not print a second table.
    mock_console.return_value.print.assert_called_once()


def test_display_findings_prints_a_table():
    with patch("voidscan.reporter.Console") as mock_console:
        display_findings([make_finding()])

    mock_console.return_value.print.assert_called()


def test_display_findings_handles_an_empty_list():
    with patch("voidscan.reporter.Console") as mock_console:
        display_findings([])

    mock_console.return_value.print.assert_called_once()
