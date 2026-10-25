"""Tests for VoidScan menu workflows."""

import json
from pathlib import Path
from unittest.mock import patch

from voidscan.scanners.nmap import NmapResult


def run_network_scan(tmp_path: Path, output: str) -> None:
    """Drive network_scan() end to end with a canned nmap result."""

    mock_result = NmapResult(
        target="127.0.0.1",
        command=[
            "nmap",
            "-T4",
            "-F",
            "127.0.0.1",
        ],
        output=output,
        return_code=0,
        success=True,
    )

    with (
        patch("voidscan.menu.Config") as mock_config,
        patch("voidscan.menu.TargetManager") as mock_manager,
        patch("voidscan.menu.run_nmap", return_value=mock_result),
        patch("voidscan.menu.Prompt.ask") as mock_prompt,
        patch("voidscan.menu.Confirm.ask", return_value=True),
        patch("voidscan.menu.console.input"),
        patch("voidscan.menu.show_banner"),
    ):
        mock_config.return_value.report_dir = tmp_path
        mock_config.return_value.target_file = (
            tmp_path / "targets.txt"
        )

        mock_manager.return_value.list_targets.return_value = [
            "127.0.0.1"
        ]

        mock_prompt.side_effect = [
            "1",
            "1",
        ]

        from voidscan.menu import network_scan

        network_scan()


def test_network_scan_saves_json_report(tmp_path: Path):
    """Test that a successful network scan can save a JSON report."""

    run_network_scan(tmp_path, "22/tcp open ssh")

    reports = list(tmp_path.glob("network_scan_*.json"))

    assert len(reports) == 1

    report = reports[0].read_text(encoding="utf-8")

    assert '"tool": "VoidScan"' in report
    assert '"scan_type": "Network Scan"' in report
    assert '"target": "127.0.0.1"' in report
    assert '"success": true' in report
    assert '"return_code": 0' in report
    assert '"output": "22/tcp open ssh"' in report


def test_network_scan_report_includes_findings(tmp_path: Path):
    """Test that analyzer findings are written to the JSON report."""

    run_network_scan(
        tmp_path,
        "22/tcp open ssh\n80/tcp open http\n443/tcp closed https",
    )

    report = json.loads(
        (list(tmp_path.glob("network_scan_*.json"))[0]).read_text(
            encoding="utf-8",
        )
    )

    titles = [finding["title"] for finding in report["findings"]]

    assert titles == [
        "SSH Service Detected",
        "HTTP Service Detected",
    ]
    assert report["findings"][0]["severity"] == "INFO"


def test_network_scan_saves_empty_findings_when_clean(tmp_path: Path):
    """Test that a scan with nothing to report still records findings."""

    run_network_scan(tmp_path, "All 100 scanned ports are closed")

    report = json.loads(
        (list(tmp_path.glob("network_scan_*.json"))[0]).read_text(
            encoding="utf-8",
        )
    )

    assert report["findings"] == []


def test_network_scan_displays_findings(tmp_path: Path):
    """Test that the menu shows the findings table after a scan."""

    with patch("voidscan.menu.display_findings") as mock_display:
        run_network_scan(tmp_path, "22/tcp open ssh")

    findings = mock_display.call_args.args[0]

    assert [finding.title for finding in findings] == [
        "SSH Service Detected"
    ]


def test_network_scan_saves_html_report_with_findings(tmp_path: Path):
    """Test that the HTML report contains the findings section."""

    run_network_scan(tmp_path, "22/tcp open ssh")

    html = (
        list(tmp_path.glob("network_scan_*.html"))[0]
    ).read_text(encoding="utf-8")

    assert "Security Findings (1)" in html
    assert "SSH Service Detected" in html
