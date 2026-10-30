import pytest
from voidscan.errors import ScanTimeout
from voidscan.process import CommandResult
from voidscan.scanners.nmap import (
    NMAP_TIMEOUT,
    SCAN_PROFILES,
    NmapPort,
    build_nmap_command,
    format_nmap_ports,
    has_root_privileges,
    nmap_installed,
    parse_nmap_xml,
    run_nmap,
)

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"
                 extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="not-a-port">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


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
        "-oX",
        "-",
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

    assert command == [
        "nmap",
        "-sS",
        "-sV",
        "-T4",
        "-oX",
        "-",
        "127.0.0.1",
    ]


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


def test_build_nmap_command_adds_the_ipv6_flag(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    command = build_nmap_command("2001:db8::1", "quick")

    assert command[-2:] == ["-6", "2001:db8::1"]
    assert command.count("-6") == 1


def test_build_nmap_command_omits_the_ipv6_flag_for_ipv4(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.nmap.has_root_privileges",
        lambda: False,
    )

    command = build_nmap_command("192.0.2.10", "quick")

    assert "-6" not in command
    assert command[-1] == "192.0.2.10"


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


def test_parse_nmap_xml_extracts_ports():
    ports = parse_nmap_xml(NMAP_XML)

    assert ports == [
        NmapPort(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            version="OpenSSH 8.9p1 Ubuntu",
        ),
        NmapPort(
            port=443,
            protocol="tcp",
            state="filtered",
            service="https",
        ),
    ]


def test_parse_nmap_xml_returns_none_for_text():
    assert parse_nmap_xml("Nmap scan report") is None


def test_format_nmap_ports_handles_no_ports():
    assert format_nmap_ports("127.0.0.1", []) == (
        "Nmap scan report for 127.0.0.1\nNo open ports found."
    )


def test_run_nmap_uses_structured_xml_output(monkeypatch):
    def fake_run(command, **kwargs):
        return CommandResult(
            command=command,
            stdout=NMAP_XML,
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

    assert [entry.port for entry in result.ports] == [22, 443]
    assert "22/tcp open ssh OpenSSH 8.9p1 Ubuntu" in result.output
    assert "<nmaprun>" not in result.output
