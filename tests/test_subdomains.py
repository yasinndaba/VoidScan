import pytest

from voidscan.scanners.subdomains import (
    SUPPORTED_ENGINES,
    enumerate_subdomains,
    run_amass,
    run_subfinder,
    tool_installed,
)


def test_supported_engines():
    assert "subfinder" in SUPPORTED_ENGINES
    assert "amass" in SUPPORTED_ENGINES


def test_tool_installed_returns_boolean(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.subdomains.shutil.which",
        lambda tool: "/usr/bin/" + tool,
    )

    assert tool_installed("subfinder") is True
    assert tool_installed("amass") is True


def test_unknown_engine():
    with pytest.raises(ValueError):
        tool_installed("unknown")


def test_subfinder(monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = (
            "www.example.com\n"
            "mail.example.com\n"
            "www.example.com\n"
        )
        stderr = ""

    def fake_run(*args, **kwargs):
        assert args[0] == [
            "subfinder",
            "-d",
            "example.com",
            "-silent",
        ]

        return FakeResult()

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.subprocess.run",
        fake_run,
    )

    result = run_subfinder("example.com")

    assert result.success
    assert result.domain == "example.com"
    assert result.engine == "subfinder"
    assert result.subdomains == [
        "mail.example.com",
        "www.example.com",
    ]


def test_amass(monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = (
            "api.example.com\n"
            "mail.example.com\n"
        )
        stderr = ""

    def fake_run(*args, **kwargs):
        assert args[0] == [
            "amass",
            "enum",
            "-passive",
            "-d",
            "example.com",
        ]

        return FakeResult()

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.subprocess.run",
        fake_run,
    )

    result = run_amass("example.com")

    assert result.success
    assert result.domain == "example.com"
    assert result.engine == "amass"
    assert result.subdomains == [
        "api.example.com",
        "mail.example.com",
    ]


def test_enumerate_subdomains(monkeypatch):
    expected = {
        "example.com",
        "api.example.com",
    }

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.tool_installed",
        lambda engine: True,
    )

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.run_subfinder",
        lambda domain: type(
            "FakeResult",
            (),
            {
                "domain": domain,
                "engine": "subfinder",
                "subdomains": sorted(expected),
                "return_code": 0,
                "success": True,
            },
        )(),
    )

    result = enumerate_subdomains("example.com", "subfinder")

    assert result.success
    assert result.subdomains == sorted(expected)


def test_enumerate_without_tool(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.subdomains.tool_installed",
        lambda engine: False,
    )

    with pytest.raises(RuntimeError, match="not installed"):
        enumerate_subdomains("example.com", "subfinder")