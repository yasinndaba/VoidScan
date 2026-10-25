import pytest
from voidscan.errors import ScanTimeout
from voidscan.process import CommandResult
from voidscan.scanners.nmap import (
    NMAP_TIMEOUT,
    SCAN_PROFILES,
    build_nmap_command,
    has_root_privileges,
    nmap_installed,
    run_nmap,
)


def test_scan_profiles_exist():
    assert "quick" in SCAN_PROFILES
    assert "standard" in SCAN_PROFILES
    assert "full" in SCAN_PROFILES


def test_nmap_installed_returns_boolean():
    assert isinstance(nmap_installed(), bool)


def test_run_nmap_as_regular_user(monkeypatch):
    calls = {}

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls["timeout"] = kwargs["timeout"]

        return CommandResult(
            command=command,
            stdout="Nmap scan report",
            stderr="",
            return_code=0,
        )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.run_command",
        fake_run,
    )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: True,
    )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    result = run_nmap("127.0.0.1")

    assert calls["command"] == [
        "nmap",
        "-sT",
        "-sV",
        "-T4",
        "127.0.0.1",
    ]
    assert calls["timeout"] == NMAP_TIMEOUT
    assert result.success
    assert result.target == "127.0.0.1"
    assert "Nmap scan report" in result.output
    assert result.command[1:3] == ["-sT", "-sV"]


def test_run_nmap_uses_configured_timeout(monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed["timeout"] = kwargs["timeout"]

        return CommandResult(
            command=command,
            stdout="",
            stderr="",
            return_code=0,
        )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.run_command",
        fake_run,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: True,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    run_nmap("127.0.0.1", timeout=42)

    assert observed["timeout"] == 42


def test_run_nmap_timeout(monkeypatch):
    def fake_run(command, **kwargs):
        raise ScanTimeout(
            "Command timed out",
            timeout=kwargs["timeout"],
            stdout="partial output",
        )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.run_command",
        fake_run,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: True,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    with pytest.raises(ScanTimeout, match="timed out after 25 seconds"):
        run_nmap("127.0.0.1", timeout=25)


def test_run_nmap_as_root(monkeypatch):
    class FakeResult:
        return_code = 0
        stdout = "Nmap scan report"
        stderr = ""

    monkeypatch.setattr(
        "voidscan.scanners.nmap.run_command",
        lambda *args, **kwargs: FakeResult(),
    )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: True,
    )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: True,
    )

    run_nmap("127.0.0.1")

    command = build_nmap_command("127.0.0.1", "standard")

    assert command == ["nmap", "-sS", "-sV", "-T4", "127.0.0.1"]


def test_non_root_full_scan_avoids_os_detection(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    command = build_nmap_command("127.0.0.1", "full")

    assert "-O" not in command
    assert "-A" not in command
    assert "-sT" in command
    assert "-sC" in command


def test_build_nmap_command_rejects_unknown_profile(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    with pytest.raises(ValueError, match="Unknown scan profile"):
        build_nmap_command("127.0.0.1", "unknown")


def test_has_root_privileges_returns_boolean():
    assert isinstance(has_root_privileges(), bool)


def test_run_nmap_requires_nmap(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: False,
    )

    with pytest.raises(RuntimeError, match="not installed"):
        run_nmap("127.0.0.1", "quick")


def test_run_nmap_os_error(monkeypatch):
    def fake_run(command, **kwargs):
        raise OSError("nmap vanished")

    monkeypatch.setattr(
        "voidscan.scanners.nmap.run_command",
        fake_run,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: True,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    with pytest.raises(RuntimeError, match="Failed to execute Nmap"):
        run_nmap("127.0.0.1", "quick")


def test_run_nmap_appends_stderr(monkeypatch):
    def fake_run(command, **kwargs):
        return CommandResult(
            command=command,
            stdout="22/tcp open ssh",
            stderr="warning: host seems down",
            return_code=0,
        )

    monkeypatch.setattr(
        "voidscan.scanners.nmap.run_command",
        fake_run,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.nmap_installed",
        lambda: True,
    )
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    result = run_nmap("127.0.0.1", "quick")

    assert result.output == "22/tcp open ssh\nwarning: host seems down"
