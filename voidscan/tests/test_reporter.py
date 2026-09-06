"""Tests for VoidScan reporting utilities."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from unittest.mock import patch

from voidscan.reporter import (
    build_report_summary,
    create_report,
    display_report_summary,
    save_json_report,
)


@dataclass
class MockScanResult:
    success: bool
    findings: list[str]


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
    assert report["version"] == "0.1.0"
    assert report["scan_type"] == "Network Scan"
    assert report["target"] == "192.168.1.10"
    assert "timestamp" in report

    assert report["result"]["success"] is True
    assert report["result"]["findings"] == ["Port 22 open"]


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