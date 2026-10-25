import io
import threading
import time
from unittest.mock import patch

import pytest
from rich.console import Console

from voidscan.errors import ScanCancelled
from voidscan.execution import ScanContext, run_with_progress


def make_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=False)


def test_run_with_progress_returns_result_on_worker_thread():
    observed = {}

    def operation(ctx):
        observed["worker"] = (
            threading.current_thread() is not threading.main_thread()
        )
        return 42

    result = run_with_progress(
        "Testing",
        operation,
        console=make_console(),
    )

    assert result == 42
    assert observed["worker"] is True


def test_run_with_progress_propagates_errors():
    def operation(ctx):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        run_with_progress(
            "Testing",
            operation,
            console=make_console(),
        )


def test_run_with_progress_tracks_progress():
    context_seen = {}

    def operation(ctx):
        ctx.update_progress(3, 10)
        context_seen["progress"] = ctx.progress()
        return "done"

    result = run_with_progress(
        "Testing",
        operation,
        console=make_console(),
    )

    assert result == "done"
    assert context_seen["progress"] == (3, 10)


def test_ctrl_c_cancels_the_scan():
    started = threading.Event()

    def operation(ctx):
        started.set()

        while not ctx.cancel_event.is_set():
            time.sleep(0.01)

        raise ScanCancelled("cancelled by worker")

    calls = {"count": 0}

    def fake_wait(thread, timeout):
        if calls["count"] == 0:
            calls["count"] += 1
            raise KeyboardInterrupt

        thread.join(timeout)

    with (
        patch(
            "voidscan.execution._wait_for_thread",
            side_effect=fake_wait,
        ),
        patch(
            "voidscan.execution.Prompt.ask",
            return_value="cancel",
        ),
    ):
        with pytest.raises(ScanCancelled):
            run_with_progress(
                "Testing",
                operation,
                console=make_console(),
            )

    assert started.is_set()


def test_ctrl_c_can_exit_the_application():
    def operation(ctx):
        while not ctx.cancel_event.is_set():
            time.sleep(0.01)

        return "stopped"

    calls = {"count": 0}

    def fake_wait(thread, timeout):
        if calls["count"] == 0:
            calls["count"] += 1
            raise KeyboardInterrupt

        thread.join(timeout)

    with (
        patch(
            "voidscan.execution._wait_for_thread",
            side_effect=fake_wait,
        ),
        patch(
            "voidscan.execution.Prompt.ask",
            return_value="exit",
        ),
    ):
        with pytest.raises(KeyboardInterrupt):
            run_with_progress(
                "Testing",
                operation,
                console=make_console(),
            )


def test_scan_context_cancel_sets_event():
    context = ScanContext("Testing")
    context.cancel()

    assert context.cancel_event.is_set()
