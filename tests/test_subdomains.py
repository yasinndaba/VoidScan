import pytest
from voidscan.errors import ScanTimeout
from voidscan.process import CommandResult
from voidscan.scanners.subdomains import (
    SUPPORTED_ENGINES,
    enumerate_subdomains,
    merge_subdomain_results,
    parse_subdomains,
    run_amass,
    run_subfinder,
    tool_installed,
)


def make_result(command, stdout="", return_code=0):
    return CommandResult(
        command=list(command),
        stdout=stdout,
        stderr="",
        return_code=return_code,
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
    def fake_run(command, **kwargs):
        assert command == [
            "subfinder",
            "-d",
            "example.com",
            "-silent",
        ]
        assert kwargs["timeout"] == 300

        return make_result(
            command,
            ("www.example.com\nmail.example.com\nwww.example.com\n"),
        )

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.run_command",
        fake_run,
    )

    result = run_subfinder("example.com")

    assert result.success
    assert result.domain == "example.com"
    assert result.engine == "subfinder"
    assert result.timed_out is False
    assert result.subdomains == [
        "mail.example.com",
        "www.example.com",
    ]


def test_subfinder_timeout(monkeypatch):
    def fake_run(command, **kwargs):
        raise ScanTimeout("Command timed out", timeout=kwargs["timeout"])

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.run_command",
        fake_run,
    )

    with pytest.raises(ScanTimeout, match="Subfinder enumeration timed out"):
        run_subfinder("example.com", timeout=12)


def test_amass(monkeypatch):
    def fake_run(command, **kwargs):
        assert command == [
            "amass",
            "enum",
            "-passive",
            "-timeout",
            "15",
            "-d",
            "example.com",
        ]

        return make_result(
            command,
            ("api.example.com\nmail.example.com\n"),
        )

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.run_command",
        fake_run,
    )

    result = run_amass("example.com")

    assert result.success
    assert result.domain == "example.com"
    assert result.engine == "amass"
    assert result.timed_out is False
    assert result.subdomains == [
        "api.example.com",
        "mail.example.com",
    ]


def test_amass_timeout_returns_partial_results(monkeypatch):
    def fake_run(command, **kwargs):
        assert command[4] == "2"

        raise ScanTimeout(
            "Command timed out",
            timeout=kwargs["timeout"],
            stdout=("FQDN:\napi.example.com\nmail.example.com\n"),
            stderr="[INF] still starting\n",
            return_code=-15,
        )

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.run_command",
        fake_run,
    )

    result = run_amass("example.com", timeout=90)

    assert result.success is False
    assert result.timed_out is True
    assert result.return_code == -15
    assert result.subdomains == [
        "api.example.com",
        "mail.example.com",
    ]


def test_parse_subdomains_filters_banner_lines():
    output = (
        "FQDN:\n"
        "Session Scope\n"
        "Example.COM\n"
        "api.example.com.\n"
        "not a hostname\n"
        "[INF] enumeration started\n"
    )

    assert parse_subdomains(output) == [
        "api.example.com",
        "example.com",
    ]


def test_merge_subdomain_results_combines_unique_hosts():
    from voidscan.scanners.subdomains import SubdomainResult

    primary = SubdomainResult(
        domain="example.com",
        engine="amass",
        subdomains=["api.example.com"],
        return_code=-15,
        success=False,
        timed_out=True,
    )
    secondary = SubdomainResult(
        domain="example.com",
        engine="subfinder",
        subdomains=["api.example.com", "www.example.com"],
        return_code=0,
        success=True,
    )

    merged = merge_subdomain_results(primary, secondary)

    assert merged.engine == "amass+subfinder"
    assert merged.success is True
    assert merged.timed_out is True
    assert merged.subdomains == [
        "api.example.com",
        "www.example.com",
    ]


def test_enumerate_subdomains(monkeypatch):
    expected = {
        "example.com",
        "api.example.com",
    }
    observed = {}

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.tool_installed",
        lambda engine: True,
    )

    def fake_subfinder(domain, **kwargs):
        observed.update(kwargs)

        return type(
            "FakeResult",
            (),
            {
                "domain": domain,
                "engine": "subfinder",
                "subdomains": sorted(expected),
                "return_code": 0,
                "success": True,
                "timed_out": False,
            },
        )()

    monkeypatch.setattr(
        "voidscan.scanners.subdomains.run_subfinder",
        fake_subfinder,
    )

    result = enumerate_subdomains(
        "example.com",
        "subfinder",
        timeout=30,
    )

    assert result.success
    assert result.subdomains == sorted(expected)
    assert observed["timeout"] == 30


def test_enumerate_without_tool(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.subdomains.tool_installed",
        lambda engine: False,
    )

    with pytest.raises(RuntimeError, match="not installed"):
        enumerate_subdomains("example.com", "subfinder")
