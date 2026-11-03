"""Tests for per-scan audit metadata."""

import logging
from datetime import datetime, timezone

from voidscan.audit import ScanAudit, ScanTimer, log_scan_audit


def make_audit(**overrides) -> ScanAudit:
    values = {
        "started_at": datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc),
        "finished_at": datetime(2026, 11, 3, 12, 0, 2, tzinfo=timezone.utc),
        "duration_seconds": 2.5,
        "command": "nmap -T4 -F 127.0.0.1",
        "result_count": 3,
    }
    values.update(overrides)
    return ScanAudit(**values)


def test_scan_timer_records_start_and_finish():
    timer = ScanTimer()

    audit = timer.finish(command="nmap 127.0.0.1", result_count=2)

    assert audit.started_at.tzinfo is not None
    assert audit.finished_at >= audit.started_at
    assert audit.duration_seconds >= 0
    assert audit.command == "nmap 127.0.0.1"
    assert audit.result_count == 2


def test_audit_to_dict_uses_iso_timestamps():
    audit = make_audit(duration_seconds=2.4567)

    data = audit.to_dict()

    assert data == {
        "started_at": "2026-11-03T12:00:00+00:00",
        "finished_at": "2026-11-03T12:00:02+00:00",
        "duration_seconds": 2.457,
        "command": "nmap -T4 -F 127.0.0.1",
        "result_count": 3,
    }


def test_log_scan_audit_writes_one_line(caplog):
    audit = make_audit()
    logger = logging.getLogger("voidscan.test.audit")

    with caplog.at_level(logging.INFO, logger="voidscan.test.audit"):
        log_scan_audit(
            logger,
            audit,
            scan_type="Network Scan",
            target="127.0.0.1",
        )

    assert len(caplog.records) == 1

    message = caplog.records[0].getMessage()

    assert "Scan audit" in message
    assert "type=Network Scan" in message
    assert "target=127.0.0.1" in message
    assert "results=3" in message
    assert "nmap -T4 -F 127.0.0.1" in message


def test_log_scan_audit_marks_internal_scans(caplog):
    audit = make_audit(command="")
    logger = logging.getLogger("voidscan.test.audit")

    with caplog.at_level(logging.INFO, logger="voidscan.test.audit"):
        log_scan_audit(
            logger,
            audit,
            scan_type="IP Information",
            target="127.0.0.1",
        )

    assert "command=(internal)" in caplog.records[0].getMessage()
