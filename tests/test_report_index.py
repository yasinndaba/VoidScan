"""Tests for the saved-report index used by the report browser."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from voidscan.html_reporter import generate_html_report
from voidscan.report_index import ReportSummary, load_report_summaries


def write_json_report(
    directory: Path,
    name: str,
    *,
    scan_type: str = "Network Scan",
    target: str = "127.0.0.1",
    timestamp: str = "2026-11-03T12:00:00+00:00",
    findings: list[dict[str, str]] | None = None,
) -> Path:
    report = {
        "tool": "VoidScan",
        "scan_type": scan_type,
        "target": target,
        "timestamp": timestamp,
        "findings": findings or [],
    }
    path = directory / name
    path.write_text(json.dumps(report), encoding="utf-8")

    return path


def write_html_report(
    directory: Path,
    name: str,
    *,
    target: str = "127.0.0.1",
    findings: list[dict[str, str]] | None = None,
) -> Path:
    report = {
        "tool": "VoidScan",
        "scan_type": "Network Scan",
        "target": target,
        "timestamp": "2026-11-03T12:00:00+00:00",
        "result": {"success": True},
        "findings": findings or [],
    }
    path = directory / name
    path.write_text(generate_html_report(report), encoding="utf-8")

    return path


def test_load_reports_from_a_missing_directory(tmp_path: Path) -> None:
    assert load_report_summaries(tmp_path / "missing") == []


def test_load_reports_from_an_empty_directory(tmp_path: Path) -> None:
    assert load_report_summaries(tmp_path) == []


def test_unreadable_directory_returns_no_reports(tmp_path: Path) -> None:
    with patch.object(Path, "iterdir", side_effect=OSError("denied")):
        assert load_report_summaries(tmp_path) == []


def test_summarizes_a_json_report(tmp_path: Path) -> None:
    path = write_json_report(
        tmp_path,
        "network_scan_20261103_120000_000000.json",
        findings=[
            {"title": "SSH Service Detected", "severity": "INFO"},
            {"title": "HTTP Service Detected", "severity": "INFO"},
        ],
    )

    reports = load_report_summaries(tmp_path)

    assert len(reports) == 1
    report = reports[0]

    assert report.path == path
    assert report.format == "json"
    assert report.scan_type == "Network Scan"
    assert report.target == "127.0.0.1"
    assert report.timestamp == datetime(
        2026, 11, 3, 12, 0, tzinfo=timezone.utc
    )
    assert report.finding_count == 2


def test_summarizes_an_html_report(tmp_path: Path) -> None:
    target = "https://example.com/?a=1&b=2"
    path = write_html_report(
        tmp_path,
        "subdomain_enumeration_20261103_120000_000000.html",
        target=target,
        findings=[{"title": "Subdomains Discovered", "severity": "INFO"}],
    )

    reports = load_report_summaries(tmp_path)

    assert len(reports) == 1
    report = reports[0]

    assert report.path == path
    assert report.format == "html"
    assert report.scan_type == "Network Scan"
    assert report.target == target
    assert report.finding_count == 1
    assert report.timestamp == datetime(
        2026, 11, 3, 12, 0, tzinfo=timezone.utc
    )


def test_html_without_metadata_falls_back_to_the_filename_and_title(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ip_information_20260101_000000_000000.html"
    path.write_text(
        "<html><head><title>VoidScan Report - 10.0.0.5</title>"
        "</head><body></body></html>",
        encoding="utf-8",
    )

    report = load_report_summaries(tmp_path)[0]

    assert report.scan_type == "IP Information"
    assert report.target == "10.0.0.5"
    assert report.timestamp is None
    assert report.finding_count == 0


def test_sorts_reports_newest_first_by_timestamp(tmp_path: Path) -> None:
    write_json_report(
        tmp_path,
        "network_scan_20260101_000000_000000.json",
        timestamp="2026-01-01T00:00:00+00:00",
        target="older",
    )
    write_json_report(
        tmp_path,
        "network_scan_20260601_000000_000000.json",
        timestamp="2026-06-01T00:00:00+00:00",
        target="newer",
    )

    reports = load_report_summaries(tmp_path)

    assert [report.target for report in reports] == ["newer", "older"]


def test_naive_timestamps_are_treated_as_utc(tmp_path: Path) -> None:
    write_json_report(
        tmp_path,
        "network_scan_20260101_000000_000000.json",
        timestamp="2026-01-01T00:00:00",
    )

    report = load_report_summaries(tmp_path)[0]

    assert report.timestamp == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_invalid_timestamps_are_ignored(tmp_path: Path) -> None:
    write_json_report(
        tmp_path,
        "network_scan_20260101_000000_000000.json",
        timestamp="not a timestamp",
    )

    report = load_report_summaries(tmp_path)[0]

    assert report.timestamp is None


def test_html_without_metadata_uses_a_placeholder_target(
    tmp_path: Path,
) -> None:
    path = tmp_path / "network_scan_20260101_000000_000000.html"
    path.write_text("<html><body>no metadata</body></html>", encoding="utf-8")

    report = load_report_summaries(tmp_path)[0]

    assert report.target == "—"
    assert report.finding_count == 0


def test_unreadable_reports_are_skipped(tmp_path: Path) -> None:
    write_json_report(
        tmp_path,
        "network_scan_20260101_000000_000000.json",
    )
    (tmp_path / "network_scan_20260101_000000_000001.html").write_text(
        "<html></html>",
        encoding="utf-8",
    )

    with patch.object(Path, "read_text", side_effect=OSError("denied")):
        reports = load_report_summaries(tmp_path)

    assert reports == []


def test_skips_malformed_and_unrelated_files(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("notes", encoding="utf-8")
    (tmp_path / "list.json").write_text("[]", encoding="utf-8")
    write_json_report(
        tmp_path,
        "network_scan_20260101_000000_000000.json",
    )

    reports = load_report_summaries(tmp_path)

    assert len(reports) == 1
    assert reports[0].path.name == "network_scan_20260101_000000_000000.json"


def test_reports_without_findings_report_no_count(tmp_path: Path) -> None:
    path = tmp_path / "network_scan_20260101_000000_000000.json"
    path.write_text(
        json.dumps({"scan_type": "Network Scan", "target": "127.0.0.1"}),
        encoding="utf-8",
    )

    report = load_report_summaries(tmp_path)[0]

    assert report.finding_count is None
    assert report.timestamp is None


def test_sort_key_falls_back_when_the_file_disappears(
    tmp_path: Path,
) -> None:
    report = ReportSummary(
        path=tmp_path / "gone.json",
        format="json",
        scan_type="Network Scan",
        target="127.0.0.1",
        timestamp=None,
        finding_count=0,
    )

    with patch.object(Path, "stat", side_effect=OSError("gone")):
        moment, name = report.sort_key

    assert moment == datetime.min.replace(tzinfo=timezone.utc)
    assert name == "gone.json"
