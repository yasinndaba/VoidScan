"""Reporting utilities for VoidScan."""

import json
from collections.abc import Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from rich.console import Console
from rich.table import Table

from voidscan import __version__
from voidscan.findings import Finding, merge_evidence
from voidscan.severity import (
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
)

REPORT_SCHEMA_VERSION = 1


def _serialize_finding(
    finding: Finding | dict[str, Any],
) -> dict[str, Any]:
    """Convert a Finding into a JSON-friendly dictionary."""

    if isinstance(finding, Finding):
        return {
            "title": finding.title,
            "severity": finding.severity.value,
            "description": finding.description,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        }

    if isinstance(finding, dict):
        return dict(finding)

    raise TypeError("Findings must be Finding instances or dictionaries.")


def _deduplicate_serialized(
    findings: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse identical serialized findings and merge their evidence."""

    merged: dict[
        tuple[str, str, str, str],
        dict[str, Any],
    ] = {}
    ordered_keys: list[tuple[str, str, str, str]] = []

    for finding in findings:
        key = (
            str(finding.get("title", "")),
            str(finding.get("severity", "")).upper(),
            str(finding.get("description", "")),
            str(finding.get("recommendation", "")),
        )

        existing = merged.get(key)

        if existing is None:
            merged[key] = dict(finding)
            ordered_keys.append(key)
            continue

        existing["evidence"] = merge_evidence(
            str(existing.get("evidence", "")),
            str(finding.get("evidence", "")),
        )

    return [merged[key] for key in ordered_keys]


def _severity_counts(
    findings: Sequence[dict[str, Any]],
) -> dict[str, int]:
    """Count serialized findings per severity, most severe first."""

    counts = {severity.value: 0 for severity in SEVERITY_ORDER}

    for finding in findings:
        severity = str(finding.get("severity", "")).upper()
        if severity in counts:
            counts[severity] += 1

    return {severity: count for severity, count in counts.items() if count}


def _evidence_preview(evidence: str, limit: int = 3) -> str:
    """Keep a findings table cell short: first few lines plus a count."""

    lines = [line for line in evidence.splitlines() if line.strip()]

    if not lines:
        return "—"

    if len(lines) <= limit:
        return "\n".join(lines)

    return "\n".join([*lines[:limit], f"… (+{len(lines) - limit} more)"])


def _render_findings_table(
    findings: Sequence[dict[str, Any]],
) -> Table:
    """Render serialized findings as a severity-sorted rich table."""

    table = Table(
        title=f"Security Findings ({len(findings)})",
        border_style="cyan",
    )

    table.add_column("Severity", width=10)
    table.add_column("Finding")
    table.add_column("Evidence")

    ordered = sorted(
        findings,
        key=lambda finding: SEVERITY_RANK.get(
            str(finding.get("severity", "")).upper(),
            len(SEVERITY_RANK),
        ),
    )

    for finding in ordered:
        severity = str(finding.get("severity", "INFO")).upper()
        color = SEVERITY_COLORS.get(severity, "white")

        table.add_row(
            f"[{color}]{severity}[/{color}]",
            str(finding.get("title", "Unnamed finding")),
            _evidence_preview(str(finding.get("evidence", ""))),
        )

    return table


def create_report(
    scan_type: str,
    target: str,
    result: Any,
    findings: Sequence[Finding | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a standardized VoidScan report."""

    if is_dataclass(result):
        result_data = asdict(cast(Any, result))
    elif isinstance(result, dict):
        result_data = result
    else:
        raise TypeError(
            "Report result must be a dataclass instance or dictionary."
        )

    return {
        "tool": "VoidScan",
        "schema_version": REPORT_SCHEMA_VERSION,
        "version": __version__,
        "scan_type": scan_type,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": result_data,
        "findings": _deduplicate_serialized(
            [_serialize_finding(finding) for finding in (findings or [])]
        ),
    }


def report_filename(report: dict[str, Any], extension: str) -> str:
    """Build a unique report filename for a report and extension."""

    scan_type = (
        str(report.get("scan_type", "scan")).strip().lower().replace(" ", "_")
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

    return f"{scan_type}_{timestamp}.{extension.lstrip('.')}"


def save_json_report(
    report: dict[str, Any],
    output_directory: Path,
) -> Path:
    """Save a report as a JSON file."""

    output_directory.mkdir(parents=True, exist_ok=True)

    filename = report_filename(report, "json")
    output_path = output_directory / filename

    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return output_path


def save_scan_report(
    scan_type: str,
    target: str,
    result: Any,
    output_directory: Path,
    findings: Sequence[Finding | dict[str, Any]] | None = None,
) -> Path:
    """Create and save a scanner result as a JSON report."""

    report = create_report(
        scan_type=scan_type,
        target=target,
        result=result,
        findings=findings,
    )

    return save_json_report(
        report=report,
        output_directory=output_directory,
    )


def build_report_summary(
    report: dict[str, Any],
) -> dict[str, Any]:
    """Build a concise summary from a VoidScan report."""

    result = report.get("result", {})

    summary: dict[str, Any] = {
        "scan_type": report.get("scan_type", "Unknown"),
        "target": report.get("target", "Unknown"),
        "timestamp": report.get("timestamp", "Unknown"),
    }

    if not isinstance(result, dict):
        return summary

    if "success" in result:
        summary["success"] = result["success"]

    if "return_code" in result:
        summary["return_code"] = result["return_code"]

    if "hosts" in result:
        summary["hosts_found"] = len(result["hosts"])

    if "subdomains" in result:
        summary["subdomains_found"] = len(result["subdomains"])

    if "results" in result:
        summary["results_found"] = len(result["results"])

    findings = report.get("findings", [])

    if isinstance(findings, list):
        summary["findings_count"] = len(findings)

        counts = _severity_counts(
            [finding for finding in findings if isinstance(finding, dict)]
        )

        if counts:
            summary["findings_by_severity"] = counts

    return summary


def display_report_summary(report: dict[str, Any]) -> None:
    """Display a concise report summary in the terminal."""

    console = Console()
    summary = build_report_summary(report)

    table = Table(title="VoidScan Scan Summary")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Scan Type", str(summary["scan_type"]))
    table.add_row("Target", str(summary["target"]))
    table.add_row("Timestamp", str(summary["timestamp"]))

    if "success" in summary:
        status = (
            "[green]Success[/green]"
            if summary["success"]
            else "[red]Failed[/red]"
        )
        table.add_row("Status", status)

    if "return_code" in summary:
        table.add_row(
            "Return Code",
            str(summary["return_code"]),
        )

    if "hosts_found" in summary:
        table.add_row(
            "Hosts Found",
            str(summary["hosts_found"]),
        )

    if "subdomains_found" in summary:
        table.add_row(
            "Subdomains Found",
            str(summary["subdomains_found"]),
        )

    if "results_found" in summary:
        table.add_row(
            "Results Found",
            str(summary["results_found"]),
        )

    if "findings_count" in summary:
        table.add_row(
            "Findings",
            str(summary["findings_count"]),
        )

    if "findings_by_severity" in summary:
        breakdown = "  ".join(
            f"{severity}: {count}"
            for severity, count in summary["findings_by_severity"].items()
        )
        table.add_row("By Severity", breakdown)

    console.print(table)


def display_findings(
    findings: Sequence[Finding | dict[str, Any]],
) -> None:
    """Display structured findings in the terminal."""

    console = Console()
    serialized = _deduplicate_serialized(
        [_serialize_finding(finding) for finding in findings]
    )

    if not serialized:
        console.print("\n[dim]Security findings: none recorded.[/dim]")
        return

    console.print()
    console.print(_render_findings_table(serialized))
