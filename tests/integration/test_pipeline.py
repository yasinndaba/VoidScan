"""End-to-end tests for the scan, analyzer, and report pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from voidscan.errors import ScanTimeout
from voidscan.findings_directories import analyze_directory_result
from voidscan.findings_discovery import analyze_discovery_result
from voidscan.findings_nmap import analyze_nmap_result
from voidscan.findings_subdomains import analyze_subdomain_result
from voidscan.html_reporter import save_html_report
from voidscan.reporter import create_report, save_json_report
from voidscan.scanners.directories import enumerate_directories
from voidscan.scanners.discovery import discover_hosts
from voidscan.scanners.nmap import run_nmap
from voidscan.scanners.subdomains import (
    merge_subdomain_results,
    run_amass,
    run_subfinder,
)


def test_nmap_scan_produces_findings_and_reports(
    fake_tools: Path,
    tmp_path: Path,
) -> None:
    result = run_nmap("127.0.0.1", "quick", timeout=30)

    assert result.success
    assert "22/tcp open  ssh" in result.output
    assert "80/tcp open  http" in result.output

    findings = analyze_nmap_result(result)
    titles = {finding.title for finding in findings}

    assert "SSH Service Detected" in titles
    assert "HTTP Service Detected" in titles

    report = create_report(
        scan_type="Network Scan",
        target="127.0.0.1",
        result=result,
        findings=findings,
    )

    json_path = save_json_report(report, output_directory=tmp_path)
    html_path = save_html_report(report, output_directory=tmp_path)

    saved = json.loads(json_path.read_text(encoding="utf-8"))

    assert saved["schema_version"] == 1
    assert saved["scan_type"] == "Network Scan"
    assert len(saved["findings"]) == len(findings)

    html = html_path.read_text(encoding="utf-8")

    assert "SSH Service Detected" in html
    assert "HTTP Service Detected" in html


def test_nmap_timeout_is_reported(fake_tools: Path) -> None:
    slow_nmap = fake_tools / "nmap"
    slow_nmap.write_text(
        "#!/bin/sh\nsleep 5\n",
        encoding="utf-8",
    )

    with pytest.raises(ScanTimeout, match="timed out"):
        run_nmap("127.0.0.1", "quick", timeout=0.3)


def test_host_discovery_reports_reachable_hosts(fake_tools: Path) -> None:
    progress: list[tuple[int, int]] = []

    result = discover_hosts(
        "192.168.50.0/29",
        on_progress=lambda completed, total: progress.append(
            (completed, total)
        ),
        max_workers=2,
        ping_timeout=1,
    )

    assert result.hosts == ["192.168.50.1", "192.168.50.2"]
    assert result.reachable == 2
    assert result.scanned == 6
    assert progress[-1] == (6, 6)

    findings = analyze_discovery_result(result)

    assert len(findings) == 1
    assert "2 reachable host(s)" in findings[0].description


def test_subdomain_engines_parse_and_merge(fake_tools: Path) -> None:
    subfinder = run_subfinder("example.com", timeout=30)
    amass = run_amass("example.com", timeout=30)

    assert subfinder.success
    assert subfinder.subdomains == [
        "api.example.com",
        "www.example.com",
    ]

    assert amass.success
    assert amass.subdomains == [
        "mail.example.com",
        "vpn.example.com",
    ]

    merged = merge_subdomain_results(subfinder, amass)

    assert merged.engine == "subfinder+amass"
    assert merged.subdomains == [
        "api.example.com",
        "mail.example.com",
        "vpn.example.com",
        "www.example.com",
    ]

    findings = analyze_subdomain_result(merged)

    assert len(findings) == 1
    assert "4 subdomain(s)" in findings[0].description


@pytest.mark.parametrize("engine", ["ffuf", "dirb"])
def test_directory_enumeration_uses_the_local_server(
    engine: str,
    fake_tools: Path,
    local_site: str,
    tmp_path: Path,
) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text(
        "admin\nlogin\nmissing\nproxy\n",
        encoding="utf-8",
    )

    result = enumerate_directories(
        local_site,
        engine,
        wordlist,
        timeout=30,
    )

    assert result.success
    assert result.results == [
        f"{local_site}/admin",
        f"{local_site}/login",
    ]

    findings = analyze_directory_result(result)

    assert len(findings) == 1
    assert "2 web resource(s)" in findings[0].description

    report = create_report(
        scan_type="Directory Enumeration",
        target=local_site,
        result=result,
        findings=findings,
    )

    saved = save_json_report(report, output_directory=tmp_path)
    payload = json.loads(saved.read_text(encoding="utf-8"))

    assert payload["schema_version"] == 1
    assert payload["findings"][0]["title"] == "Web Resources Discovered"
