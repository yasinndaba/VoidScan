"""Tests for VoidScan reporting utilities."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from voidscan.reporter import create_report, save_json_report


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