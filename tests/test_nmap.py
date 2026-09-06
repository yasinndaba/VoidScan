from voidscan.scanners.nmap import (
    SCAN_PROFILES,
    nmap_installed,
    run_nmap,
)


def test_scan_profiles_exist():
    assert "quick" in SCAN_PROFILES
    assert "standard" in SCAN_PROFILES
    assert "full" in SCAN_PROFILES


def test_nmap_installed_returns_boolean():
    assert isinstance(nmap_installed(), bool)


def test_run_nmap(monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = "Nmap scan report"
        stderr = ""

    def fake_run(*args, **kwargs):
        assert args[0] == [
            "nmap",
            "-sS",
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

    result = run_nmap("127.0.0.1")

    assert result.success
    assert result.target == "127.0.0.1"
    assert "Nmap scan report" in result.output
