"""Tests for VoidScan menu workflows."""

from pathlib import Path
from unittest.mock import patch

from voidscan.scanners.nmap import NmapResult


def test_network_scan_saves_json_report(tmp_path: Path):
    """Test that a successful network scan can save a JSON report."""

    mock_result = NmapResult(
        target="127.0.0.1",
        command=[
            "nmap",
            "-T4",
            "-F",
            "127.0.0.1",
        ],
        output="22/tcp open ssh",
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

    reports = list(tmp_path.glob("network_scan_*.json"))

    assert len(reports) == 1

    report = reports[0].read_text(encoding="utf-8")

    assert '"tool": "VoidScan"' in report
    assert '"scan_type": "Network Scan"' in report
    assert '"target": "127.0.0.1"' in report
    assert '"success": true' in report
    assert '"return_code": 0' in report
    assert '"output": "22/tcp open ssh"' in report
