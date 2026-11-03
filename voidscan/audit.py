"""Per-scan audit metadata for VoidScan."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ScanAudit:
    """Record who ran what, when, how long it took, and how much it found."""

    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    command: str
    result_count: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly audit record."""

        return {
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "command": self.command,
            "result_count": self.result_count,
        }


class ScanTimer:
    """Measure one scan from start to finish.

    The timer uses UTC wall-clock time for the audit record and a monotonic
    clock for the duration, so system clock changes cannot skew it.
    """

    def __init__(self) -> None:
        self.started_at = datetime.now(timezone.utc)
        self._started = time.monotonic()

    def finish(self, command: str, result_count: int) -> ScanAudit:
        """Return the audit record for the completed scan."""

        return ScanAudit(
            started_at=self.started_at,
            finished_at=datetime.now(timezone.utc),
            duration_seconds=time.monotonic() - self._started,
            command=command,
            result_count=result_count,
        )


def log_scan_audit(
    logger: logging.Logger,
    audit: ScanAudit,
    *,
    scan_type: str,
    target: str,
) -> None:
    """Write one audit line for a completed scan."""

    logger.info(
        "Scan audit: type=%s target=%s started=%s finished=%s "
        "duration=%.3fs results=%s command=%s",
        scan_type,
        target,
        audit.started_at.isoformat(),
        audit.finished_at.isoformat(),
        audit.duration_seconds,
        audit.result_count,
        audit.command or "(internal)",
    )
