"""Safe subprocess execution with timeout and cancellation support."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from voidscan.errors import ScanCancelled, ScanTimeout


logger = logging.getLogger("voidscan.process")

DEFAULT_POLL_INTERVAL = 0.2
TERMINATE_GRACE_SECONDS = 2.0


@dataclass
class CommandResult:
    """Represent the completed output of an external command."""

    command: list[str]
    stdout: str
    stderr: str
    return_code: int


_active_processes: set[subprocess.Popen[str]] = set()
_active_lock = threading.Lock()


def _register_process(process: subprocess.Popen[str]) -> None:
    with _active_lock:
        _active_processes.add(process)


def _unregister_process(process: subprocess.Popen[str]) -> None:
    with _active_lock:
        _active_processes.discard(process)


def _signal_process_group(
    process: subprocess.Popen[str],
    sig: signal.Signals,
) -> None:
    """Send a signal to the process group, falling back to the process."""

    try:
        os.killpg(process.pid, sig)
        return
    except (AttributeError, ProcessLookupError, PermissionError):
        pass

    try:
        if sig == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except OSError:  # pragma: no cover - process already gone
        pass


def _terminate_process(process: subprocess.Popen[str]) -> None:
    """Terminate a child process and its group within a bounded grace period."""

    if process.poll() is not None:
        return

    _signal_process_group(process, signal.SIGTERM)

    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        logger.warning(
            "Process %s ignored SIGTERM; sending SIGKILL",
            process.pid,
        )

    _signal_process_group(process, signal.SIGKILL)

    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        logger.error("Process %s could not be terminated", process.pid)


def terminate_active_processes() -> None:
    """Terminate every external process started by VoidScan."""

    with _active_lock:
        processes = list(_active_processes)

    for process in processes:
        _terminate_process(process)


def _collect_remaining_output(
    process: subprocess.Popen[str],
) -> tuple[str, str]:
    """Reap a terminated process and return whatever output remains."""

    try:
        stdout, stderr = process.communicate(
            timeout=TERMINATE_GRACE_SECONDS,
        )
    except (subprocess.TimeoutExpired, ValueError):
        return "", ""

    return stdout or "", stderr or ""


def run_command(
    command: Sequence[str],
    *,
    timeout: float,
    cancel_event: threading.Event | None = None,
    on_heartbeat: Callable[[float], None] | None = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
) -> CommandResult:
    """Run a command, enforcing a timeout and optional cancellation.

    ``on_heartbeat`` is called with the elapsed seconds while the command is
    running so callers can show that work is still progressing.
    """

    if timeout <= 0:
        raise ValueError("Command timeout must be greater than zero.")

    command = list(command)
    logger.info("Running command: %s", " ".join(command))

    popen_kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }

    if os.name == "posix":
        # A separate session lets cancellation terminate the whole process
        # group, including any helpers spawned by the external tool.
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except OSError:
        logger.exception("Failed to start command: %s", " ".join(command))
        raise

    _register_process(process)
    started_at = time.monotonic()
    stdout = ""
    stderr = ""

    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                logger.info(
                    "Cancelling command after %.1f seconds: %s",
                    time.monotonic() - started_at,
                    " ".join(command),
                )
                _terminate_process(process)
                _collect_remaining_output(process)
                raise ScanCancelled("Scan cancelled by user.")

            try:
                stdout, stderr = process.communicate(
                    timeout=poll_interval,
                )
                break
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started_at

                if on_heartbeat is not None:
                    on_heartbeat(elapsed)

                if elapsed < timeout:
                    continue

                logger.warning(
                    "Command timed out after %.1f seconds: %s",
                    elapsed,
                    " ".join(command),
                )
                _terminate_process(process)
                partial_stdout, partial_stderr = (
                    _collect_remaining_output(process)
                )

                raise ScanTimeout(
                    f"Command timed out after {timeout:g} seconds: "
                    f"{command[0]}",
                    timeout=timeout,
                    stdout=partial_stdout,
                    stderr=partial_stderr,
                    return_code=(
                        process.returncode
                        if process.returncode is not None
                        else -1
                    ),
                )

        return CommandResult(
            command=command,
            stdout=stdout or "",
            stderr=stderr or "",
            return_code=(
                process.returncode
                if process.returncode is not None
                else -1
            ),
        )
    finally:
        _unregister_process(process)
