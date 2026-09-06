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