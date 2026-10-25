import pytest

from voidscan.scanners.nmap import (
    SCAN_PROFILES,
    build_nmap_command,
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
    class FakeResult:
        returncode = 0
        stdout = "Nmap scan report"
        stderr = ""

    def fake_run(*args, **kwargs):
        assert args[0] == [
            "nmap",
            "-sT",
            "-sV",
            "-T4",
            "127.0.0.1",
        ]

        return FakeResult()

    monkeypatch.setattr(
        "voidscan.scanners.nmap.subprocess.run",
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

    assert result.success
    assert result.target == "127.0.0.1"
    assert "Nmap scan report" in result.output
    assert result.command[1:3] == ["-sT", "-sV"]


def test_run_nmap_as_root(monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = "Nmap scan report"
        stderr = ""

    monkeypatch.setattr(
        "voidscan.scanners.nmap.subprocess.run",
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
