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

def display_report_summary(report: dict[str, Any]) -> None:
    """Display a concise report summary in the terminal."""

    console = Console()

    table = Table(title="VoidScan Scan Summary")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Scan Type", str(report["scan_type"]))
    table.add_row("Target", str(report["target"]))
    table.add_row("Timestamp", str(report["timestamp"]))

    result = report["result"]

    if isinstance(result, dict):
        success = result.get("success")

        if success is not None:
            status = (
                "[green]Success[/green]"
                if success
                else "[red]Failed[/red]"
            )
            table.add_row("Status", status)

        if "return_code" in result:
            table.add_row(
                "Return Code",
                str(result["return_code"]),
            )

    console.print(table)