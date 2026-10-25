"""Run scans on a worker thread with live progress and cancellation."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from queue import Queue
from typing import TypeVar

from rich.console import Console, Group
from rich.live import Live
from rich.prompt import Prompt
from rich.spinner import Spinner
from rich.text import Text

from voidscan.errors import ScanCancelled
from voidscan.process import terminate_active_processes

logger = logging.getLogger("voidscan.execution")

T = TypeVar("T")

JOIN_INTERVAL = 0.1
CANCEL_JOIN_TIMEOUT = 5.0


@dataclass
class ScanContext:
    """Thread-safe progress and cancellation state for one scan."""

    description: str
    started_at: float = field(default_factory=time.monotonic)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )
    _completed: int | None = None
    _total: int | None = None

    def update_progress(self, completed: int, total: int) -> None:
        """Record scanner progress for the UI thread to render."""

        with self._lock:
            self._completed = completed
            self._total = total

    def progress(self) -> tuple[int | None, int | None]:
        """Return the latest ``(completed, total)`` values."""

        with self._lock:
            return self._completed, self._total

    def elapsed(self) -> float:
        """Return seconds elapsed since the scan started."""

        return time.monotonic() - self.started_at

    def cancel(self) -> None:
        """Signal cancellation and terminate any active child process."""

        self.cancel_event.set()
        terminate_active_processes()


def _render_progress(context: ScanContext) -> Group:
    """Build the live heartbeat display for an active scan."""

    completed, total = context.progress()
    elapsed = context.elapsed()

    detail = Text()

    if completed is not None and total:
        percent = int((completed / total) * 100)
        detail.append(
            f"  {completed}/{total} hosts ({percent}%)",
            style="bold white",
        )

    detail.append(f"  {elapsed:.1f}s elapsed", style="dim")

    return Group(
        Spinner(
            "dots",
            text=Text(f"{context.description}...", style="cyan"),
        ),
        detail,
    )


def _wait_for_thread(thread: threading.Thread, timeout: float) -> None:
    """Wait briefly for a worker so the UI can refresh and catch Ctrl+C."""

    thread.join(timeout)


def _ask_cancel_action(
    description: str,
    console: Console,
) -> str:
    """Ask whether the user wants to cancel the scan or exit VoidScan."""

    console.print()
    console.print(
        f"[bold yellow]Ctrl+C pressed during:[/bold yellow] {description}"
    )

    return Prompt.ask(
        "[bold cyan]Cancel this scan or exit VoidScan?[/bold cyan]",
        choices=["cancel", "exit"],
        default="cancel",
        console=console,
    )


def run_with_progress(
    description: str,
    operation: Callable[[ScanContext], T],
    *,
    console: Console,
) -> T:
    """Run ``operation`` on a worker thread and return its result.

    The caller's thread stays free to render a live heartbeat and to handle
    Ctrl+C. Cancelling terminates active child processes and raises
    :class:`ScanCancelled`. Choosing to exit re-raises ``KeyboardInterrupt``
    so the CLI can shut down cleanly.
    """

    context = ScanContext(description)
    outcomes: Queue[tuple[T | None, BaseException | None]] = Queue(maxsize=1)

    def worker() -> None:
        try:
            outcomes.put((operation(context), None))
        except BaseException as exc:
            outcomes.put((None, exc))

    thread = threading.Thread(
        target=worker,
        name="voidscan-scan",
        daemon=True,
    )
    thread.start()

    live: Live | None = None

    try:
        if console.is_terminal:
            live = Live(
                _render_progress(context),
                console=console,
                refresh_per_second=8,
                transient=True,
            )
            live.start()

        while thread.is_alive():
            if live is not None:
                live.update(_render_progress(context))

            _wait_for_thread(thread, JOIN_INTERVAL)

    except KeyboardInterrupt:
        if live is not None:
            live.stop()
            live = None

        action = _ask_cancel_action(description, console)

        context.cancel()

        try:
            thread.join(CANCEL_JOIN_TIMEOUT)
        except KeyboardInterrupt:  # pragma: no cover - second Ctrl+C
            action = "exit"

        if thread.is_alive():  # pragma: no cover - defensive
            logger.warning(
                "Scan worker did not stop within %.0f seconds",
                CANCEL_JOIN_TIMEOUT,
            )

        if action == "exit":
            logger.info("User chose to exit during scan: %s", description)
            raise

        logger.info("User cancelled scan: %s", description)
        raise ScanCancelled("Scan cancelled by user.") from None

    finally:
        if live is not None:
            live.stop()

    result, error = outcomes.get_nowait()

    if error is not None:
        raise error

    return result  # type: ignore[return-value]
