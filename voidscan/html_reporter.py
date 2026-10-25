"""HTML reporting utilities for VoidScan."""

from html import escape
from pathlib import Path
from typing import Any

from voidscan import __version__
from voidscan.reporter import report_filename


def _render_findings_section(findings: list[Any]) -> str:
    """Render serialized findings as a list of escaped HTML blocks."""

    blocks = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = escape(str(finding.get("severity", "INFO")).upper())
        title = escape(str(finding.get("title", "Unnamed finding")))
        description = escape(str(finding.get("description", "")))
        evidence = escape(str(finding.get("evidence", "")))
        recommendation = escape(
            str(finding.get("recommendation", ""))
        )

        blocks.append(
            f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity severity-{severity.lower()}">
                    {severity}
                </span>
                <span class="finding-title">{title}</span>
            </div>
            <p>{description}</p>
            <pre class="evidence">{evidence}</pre>
            <p class="recommendation">
                <strong>Recommendation:</strong> {recommendation}
            </p>
        </div>"""
        )

    if not blocks:
        return (
            '<p class="no-findings">'
            "No security findings were recorded for this scan."
            "</p>"
        )

    return "".join(blocks)


def generate_html_report(report: dict[str, Any]) -> str:
    """Generate a self-contained HTML report from a VoidScan report."""

    result = report.get("result", {})

    scan_type = escape(str(report.get("scan_type", "Unknown")))
    target = escape(str(report.get("target", "Unknown")))
    timestamp = escape(str(report.get("timestamp", "Unknown")))

    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    findings_count = len(
        [finding for finding in findings if isinstance(finding, dict)]
    )
    findings_html = _render_findings_section(findings)

    status = "Unknown"
    status_class = "unknown"

    if isinstance(result, dict) and "success" in result:
        if result["success"]:
            status = "Success"
            status_class = "success"
        else:
            status = "Failed"
            status_class = "failed"

    result_json = escape(
        str(result)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoidScan Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #f4f4f4;
            color: #222;
            margin: 0;
            padding: 40px;
        }}

        .container {{
            max-width: 1000px;
            margin: auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
        }}

        h1 {{
            margin-top: 0;
        }}

        .metadata {{
            display: grid;
            grid-template-columns: 180px 1fr;
            gap: 10px;
            margin-bottom: 30px;
        }}

        .label {{
            font-weight: bold;
        }}

        .status {{
            font-weight: bold;
        }}

        .success {{
            color: green;
        }}

        .failed {{
            color: red;
        }}

        .unknown {{
            color: #777;
        }}

        .finding {{
            border-left: 4px solid #999;
            background: #fafafa;
            padding: 12px 16px;
            margin-bottom: 16px;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 6px;
        }}

        .finding-title {{
            font-weight: bold;
        }}

        .severity {{
            font-size: 0.8em;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            background: #777;
        }}

        .severity-critical {{
            background: #7f1d1d;
        }}

        .severity-high {{
            background: #b91c1c;
        }}

        .severity-medium {{
            background: #b45309;
        }}

        .severity-low {{
            background: #0e7490;
        }}

        .severity-info {{
            background: #4b5563;
        }}

        .evidence {{
            background: #111;
            color: #eee;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
        }}

        .recommendation {{
            color: #444;
        }}

        .no-findings {{
            color: #777;
        }}

        pre {{
            background: #111;
            color: #eee;
            padding: 20px;
            overflow-x: auto;
            border-radius: 6px;
        }}

        footer {{
            margin-top: 30px;
            color: #777;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>VoidScan Security Assessment Report</h1>

        <div class="metadata">
            <div class="label">Scan Type</div>
            <div>{scan_type}</div>

            <div class="label">Target</div>
            <div>{target}</div>

            <div class="label">Timestamp</div>
            <div>{timestamp}</div>

            <div class="label">Status</div>
            <div class="status {status_class}">{status}</div>
        </div>

        <h2>Security Findings ({findings_count})</h2>

        {findings_html}

        <h2>Scan Results</h2>

        <pre>{result_json}</pre>

        <footer>
            Generated by VoidScan v{__version__}
        </footer>
    </div>
</body>
</html>
"""


def save_html_report(
    report: dict[str, Any],
    output_directory: Path,
) -> Path:
    """Generate and save a VoidScan HTML report."""

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    filename = report_filename(report, "html")
    output_path = output_directory / filename

    output_path.write_text(
        generate_html_report(report),
        encoding="utf-8",
    )

    return output_path