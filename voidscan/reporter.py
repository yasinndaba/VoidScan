"""Reporting utilities for VoidScan."""

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from rich.console import Console
from rich.table import Table


def create_report(
    scan_type: str,
    target: str,
    result: Any,
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
        "version": "0.1.0",
        "scan_type": scan_type,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": result_data,
    }


def save_json_report(
    report: dict[str, Any],
    output_directory: Path,
) -> Path:
    """Save a report as a JSON file."""

    output_directory.mkdir(parents=True, exist_ok=True)

    scan_type = report["scan_type"].lower().replace(" ", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    filename = f"{scan_type}_{timestamp}.json"
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
) -> Path:
    """Create and save a scanner result as a JSON report."""

    report = create_report(
        scan_type=scan_type,
        target=target,
        result=result,
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

    console.print(table)