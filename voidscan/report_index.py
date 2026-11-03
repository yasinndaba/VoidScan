"""Index saved VoidScan reports for the in-app report browser."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any

REPORT_EXTENSIONS = ("json", "html")

_METADATA_ROW = re.compile(
    r'<div class="label">(?P<label>[^<]+)</div>\s*'
    r"<div[^>]*>(?P<value>.*?)</div>",
    re.DOTALL,
)
_FINDING_ANCHOR = re.compile(r'id="finding-\d+"')
_PAGE_TITLE = re.compile(r"<title>VoidScan Report - (?P<target>.*?)</title>")
_FILENAME_STEM = re.compile(r"^(?P<scan_type>.+)_\d{8}_\d{6}_\d{6}$")


@dataclass(frozen=True)
class ReportSummary:
    """Describe one saved report file without loading its full contents."""

    path: Path
    format: str
    scan_type: str
    target: str
    timestamp: datetime | None
    finding_count: int | None

    @property
    def sort_key(self) -> tuple[datetime, str]:
        """Return the newest-first ordering key for the browser."""

        moment = self.timestamp

        if moment is None:
            try:
                moment = datetime.fromtimestamp(
                    self.path.stat().st_mtime,
                    tz=timezone.utc,
                )
            except OSError:
                moment = datetime.min.replace(tzinfo=timezone.utc)

        return (moment, self.path.name)


def load_report_summaries(report_dir: Path) -> list[ReportSummary]:
    """Return summaries for every readable JSON and HTML report."""

    if not report_dir.is_dir():
        return []

    try:
        paths = sorted(report_dir.iterdir())
    except OSError:
        return []

    summaries = []

    for path in paths:
        suffix = path.suffix.lower().lstrip(".")

        if suffix not in REPORT_EXTENSIONS or not path.is_file():
            continue

        summary = (
            _summarize_json(path)
            if suffix == "json"
            else _summarize_html(path)
        )

        if summary is not None:
            summaries.append(summary)

    return sorted(
        summaries,
        key=lambda summary: summary.sort_key,
        reverse=True,
    )


def _summarize_json(path: Path) -> ReportSummary | None:
    """Read report metadata from a JSON report, skipping malformed files."""

    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    findings = data.get("findings")
    finding_count = len(findings) if isinstance(findings, list) else None

    return ReportSummary(
        path=path,
        format="json",
        scan_type=str(data.get("scan_type") or _fallback_scan_type(path)),
        target=str(data.get("target") or "—"),
        timestamp=_parse_timestamp(data.get("timestamp")),
        finding_count=finding_count,
    )


def _summarize_html(path: Path) -> ReportSummary | None:
    """Read report metadata from an HTML report's metadata block."""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    metadata = _html_metadata(text)

    return ReportSummary(
        path=path,
        format="html",
        scan_type=(
            metadata.get("Scan Type", "").strip() or _fallback_scan_type(path)
        ),
        target=(
            metadata.get("Target", "").strip()
            or _html_title_target(text)
            or "—"
        ),
        timestamp=_parse_timestamp(metadata.get("Timestamp", "")),
        finding_count=len(_FINDING_ANCHOR.findall(text)),
    )


def _html_metadata(text: str) -> dict[str, str]:
    """Extract the label/value rows from an HTML report."""

    metadata: dict[str, str] = {}

    for match in _METADATA_ROW.finditer(text):
        label = unescape(match.group("label")).strip()
        value = unescape(re.sub(r"<[^>]+>", "", match.group("value"))).strip()

        metadata.setdefault(label, value)

    return metadata


def _html_title_target(text: str) -> str:
    """Extract the target from the HTML page title as a fallback."""

    match = _PAGE_TITLE.search(text)

    if not match:
        return ""

    return unescape(match.group("target")).strip()


def _fallback_scan_type(path: Path) -> str:
    """Derive a readable scan type from a report filename."""

    match = _FILENAME_STEM.match(path.stem)
    raw = match.group("scan_type") if match else path.stem
    label = raw.replace("_", " ").replace("-", " ").title()

    if label.startswith("Ip "):
        label = "IP " + label[3:]

    return label


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a report timestamp and normalize it to UTC."""

    if not isinstance(value, str) or not value.strip():
        return None

    try:
        moment = datetime.fromisoformat(value.strip())
    except ValueError:
        return None

    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)

    return moment.astimezone(timezone.utc)
