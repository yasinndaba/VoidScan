"""Tests for VoidScan HTML reporting."""

from pathlib import Path

from voidscan.html_reporter import (
    generate_html_report,
    save_html_report,
)


def test_generate_html_report():
    report = {
        "tool": "VoidScan",
        "version": "0.1.0",
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
            "return_code": 0,
            "output": "22/tcp open ssh",
        },
    }

    html = generate_html_report(report)

    assert "<!DOCTYPE html>" in html
    assert "VoidScan Security Assessment Report" in html
    assert "Network Scan" in html
    assert "127.0.0.1" in html
    assert "Success" in html
    assert "22/tcp open ssh" in html


def test_generate_html_report_escapes_html():
    report = {
        "scan_type": "Test Scan",
        "target": "<script>alert('xss')</script>",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
        },
    }

    html = generate_html_report(report)

    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_generate_html_report_lists_findings():
    report = {
        "tool": "VoidScan",
        "version": "0.1.0",
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
            "return_code": 0,
        },
        "findings": [
            {
                "title": "SSH Service Detected",
                "severity": "HIGH",
                "description": "An SSH service was detected.",
                "evidence": "22/tcp open ssh",
                "recommendation": "Restrict SSH access.",
            }
        ],
    }

    html = generate_html_report(report)

    assert "Security Findings (1)" in html
    assert "SSH Service Detected" in html
    assert "severity-high" in html
    assert "22/tcp open ssh" in html
    assert "Restrict SSH access." in html


def test_generate_html_report_without_findings_says_so():
    report = {
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {"success": True},
    }

    html = generate_html_report(report)

    assert "Security Findings (0)" in html
    assert "No security findings were recorded" in html


def test_generate_html_report_escapes_finding_evidence():
    report = {
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {"success": True},
        "findings": [
            {
                "title": "<img src=x onerror=alert(1)>",
                "severity": "INFO",
                "description": "",
                "evidence": "<b>bold</b>",
                "recommendation": "",
            }
        ],
    }

    html = generate_html_report(report)

    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<b>bold</b>" not in html


def test_save_html_report(tmp_path: Path):
    report = {
        "tool": "VoidScan",
        "version": "0.1.0",
        "scan_type": "Network Scan",
        "target": "192.168.1.10",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {
            "success": True,
        },
    }

    output_path = save_html_report(
        report,
        tmp_path,
    )

    assert output_path.exists()
    assert output_path.is_file()
    assert output_path.suffix == ".html"

    content = output_path.read_text(
        encoding="utf-8",
    )

    assert "VoidScan Security Assessment Report" in content
    assert "192.168.1.10" in content


def test_save_html_report_uses_unique_timestamped_names(tmp_path: Path):
    report = {
        "scan_type": "Network Scan",
        "target": "127.0.0.1",
        "timestamp": "2026-09-06T10:00:00+00:00",
        "result": {"success": True},
    }

    first = save_html_report(report, tmp_path)
    second = save_html_report(report, tmp_path)

    assert first != second
    assert first.name.startswith("network_scan_")
    assert second.name.startswith("network_scan_")
    assert first.suffix == ".html"
    assert second.suffix == ".html"
