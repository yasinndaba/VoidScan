import sys
import threading
import time

import pytest
from voidscan.errors import ScanCancelled, ScanTimeout
from voidscan.process import run_command


def python_command(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_run_command_returns_output():
    result = run_command(
        python_command(
            "import sys; print('hello'); print('problem', file=sys.stderr)"
        ),
        timeout=10,
    )

    assert result.stdout.strip() == "hello"
    assert result.stderr.strip() == "problem"
    assert result.return_code == 0
    assert result.command[0] == sys.executable


def test_run_command_reports_nonzero_exit():
    result = run_command(
        python_command("raise SystemExit(3)"),
        timeout=10,
    )

    assert result.return_code == 3


def test_run_command_times_out_with_partial_output():
    started = time.monotonic()

    with pytest.raises(ScanTimeout) as exc_info:
        run_command(
            python_command(
                "import sys, time; "
                "print('partial', flush=True); "
                "time.sleep(10)"
            ),
            timeout=0.4,
            poll_interval=0.1,
        )

    elapsed = time.monotonic() - started

    assert elapsed < 4
    assert "partial" in exc_info.value.stdout
    assert exc_info.value.timeout == 0.4


def test_run_command_can_be_cancelled():
    cancel_event = threading.Event()
    timer = threading.Timer(0.3, cancel_event.set)
    timer.start()

    started = time.monotonic()

    try:
        with pytest.raises(ScanCancelled):
            run_command(
                python_command("import time; time.sleep(10)"),
                timeout=30,
                cancel_event=cancel_event,
                poll_interval=0.1,
            )
    finally:
        timer.cancel()

    assert time.monotonic() - started < 4


def test_run_command_calls_heartbeat_while_running():
    beats = []

    result = run_command(
        python_command("import time; time.sleep(0.4)"),
        timeout=10,
        poll_interval=0.1,
        on_heartbeat=beats.append,
    )

    assert result.return_code == 0
    assert beats


def test_run_command_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="greater than zero"):
        run_command(["true"], timeout=0)


def test_run_command_propagates_missing_binary():
    with pytest.raises(OSError):
        run_command(["/definitely/not/a/command"], timeout=5)
