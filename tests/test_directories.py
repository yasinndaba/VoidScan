from unittest.mock import patch

import pytest
from voidscan.errors import ScanTimeout
from voidscan.process import CommandResult
from voidscan.scanners.directories import (
    DEFAULT_WORDLIST,
    enumerate_directories,
    parse_dirb_results,
    run_dirb,
    run_ffuf,
    tool_installed,
    validate_wordlist,
)


def make_result(command, stdout="", return_code=0):
    return CommandResult(
        command=list(command),
        stdout=stdout,
        stderr="",
        return_code=return_code,
    )


def test_default_wordlist_exists():
    assert DEFAULT_WORDLIST.is_file()


def test_validate_wordlist():
    path = validate_wordlist(DEFAULT_WORDLIST)
    assert path == DEFAULT_WORDLIST


def test_validate_missing_wordlist():
    with pytest.raises(ValueError, match="Wordlist not found"):
        validate_wordlist("/tmp/does-not-exist.txt")


def test_validate_custom_wordlist(tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\nlogin\n")

    result = validate_wordlist(wordlist)

    assert result == wordlist


@patch("voidscan.scanners.directories.shutil.which")
def test_tool_installed(mock_which):
    mock_which.return_value = "/usr/bin/ffuf"

    assert tool_installed("ffuf") is True


@patch("voidscan.scanners.directories.shutil.which")
def test_tool_not_installed(mock_which):
    mock_which.return_value = None

    assert tool_installed("ffuf") is False


def test_tool_installed_invalid_engine():
    with pytest.raises(ValueError, match="Unsupported enumeration engine"):
        tool_installed("invalid")


@patch("voidscan.scanners.directories.run_command")
def test_run_ffuf(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\nlogin\n")

    mock_run.side_effect = lambda command, **kwargs: make_result(
        command,
        "admin\nlogin\n",
    )

    result = run_ffuf("http://127.0.0.1", wordlist, timeout=45)

    command = mock_run.call_args.args[0]

    assert command[0] == "ffuf"
    assert "-u" in command
    assert "http://127.0.0.1/FUZZ" in command
    assert "-w" in command
    assert str(wordlist) in command
    assert mock_run.call_args.kwargs["timeout"] == 45

    assert result.engine == "ffuf"
    assert result.target == "http://127.0.0.1"
    assert result.wordlist == str(wordlist)
    assert result.results == [
        "http://127.0.0.1/admin",
        "http://127.0.0.1/login",
    ]
    assert result.success is True


@patch("voidscan.scanners.directories.run_command")
def test_run_dirb(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\nlogin\n")

    mock_run.return_value = make_result(
        ["dirb"],
        (
            "-----------------\n"
            "DIRB v2.22\n"
            "By The Dark Raver\n"
            "-----------------\n"
            "---- Scanning URL: http://127.0.0.1/ ----\n"
            "+ http://127.0.0.1/admin (CODE:301|SIZE:0)\n"
            "+ http://127.0.0.1/login (CODE:200|SIZE:42)\n"
            "\n"
            "-----------------\n"
            "END_TIME: Sun Oct 25 13:43:56 2026\n"
            "DOWNLOADED: 2 - FOUND: 2\n"
        ),
    )

    result = run_dirb("http://127.0.0.1", wordlist)

    command = mock_run.call_args.args[0]

    assert command[0] == "dirb"
    assert "http://127.0.0.1" in command
    assert str(wordlist) in command
    assert "-S" in command

    assert result.engine == "dirb"
    assert result.results == [
        "http://127.0.0.1/admin",
        "http://127.0.0.1/login",
    ]
    assert result.success is True


def test_parse_dirb_results_ignores_banner_lines():
    output = (
        "-----------------\n"
        "DIRB v2.22\n"
        "By The Dark Raver\n"
        "-----------------\n"
        "---- Scanning URL: http://example.com/ ----\n"
        "+ http://example.com/admin (CODE:301|SIZE:0)\n"
        "+ http://example.com/robots.txt (CODE:200|SIZE:7)\n"
        "DOWNLOADED: 2 - FOUND: 2\n"
    )

    assert parse_dirb_results(output) == [
        "http://example.com/admin",
        "http://example.com/robots.txt",
    ]


def test_enumerate_directories_invalid_engine():
    with pytest.raises(ValueError, match="Unsupported enumeration engine"):
        enumerate_directories(
            "http://127.0.0.1",
            engine="invalid",
        )


@patch("voidscan.scanners.directories.tool_installed")
def test_enumerate_directories_missing_tool(mock_installed):
    mock_installed.return_value = False

    with pytest.raises(RuntimeError, match="not installed"):
        enumerate_directories("http://127.0.0.1")


@patch("voidscan.scanners.directories.run_command")
def test_run_ffuf_timeout(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    mock_run.side_effect = ScanTimeout(
        "Command timed out",
        timeout=17,
    )

    with pytest.raises(ScanTimeout, match="timed out after 17 seconds"):
        run_ffuf("http://127.0.0.1", wordlist, timeout=17)


def test_validate_wordlist_reports_unreadable_file(tmp_path):
    wordlist = tmp_path / "unreadable.txt"
    wordlist.write_text("admin\n")

    with (
        patch("pathlib.Path.open", side_effect=OSError("denied")),
        pytest.raises(ValueError, match="not readable"),
    ):
        validate_wordlist(wordlist)


@patch("voidscan.scanners.directories.run_command")
def test_run_ffuf_os_error(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    mock_run.side_effect = OSError("ffuf vanished")

    with pytest.raises(RuntimeError, match="Failed to execute FFUF"):
        run_ffuf("http://127.0.0.1", wordlist)


@patch("voidscan.scanners.directories.run_command")
def test_run_dirb_timeout(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    mock_run.side_effect = ScanTimeout(
        "Command timed out",
        timeout=21,
        stdout="http://127.0.0.1/admin",
    )

    with pytest.raises(ScanTimeout, match="timed out after 21 seconds"):
        run_dirb("http://127.0.0.1", wordlist, timeout=21)


@patch("voidscan.scanners.directories.run_command")
def test_run_dirb_os_error(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    mock_run.side_effect = OSError("dirb vanished")

    with pytest.raises(RuntimeError, match="Failed to execute DIRB"):
        run_dirb("http://127.0.0.1", wordlist)


def test_enumerate_directories_uses_ffuf(monkeypatch, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    sentinel = object()
    observed = {}

    def fake_run_ffuf(target, wordlist_path, **kwargs):
        observed["target"] = target
        observed["wordlist"] = wordlist_path
        observed["timeout"] = kwargs["timeout"]
        return sentinel

    monkeypatch.setattr(
        "voidscan.scanners.directories.tool_installed",
        lambda engine: True,
    )
    monkeypatch.setattr(
        "voidscan.scanners.directories.run_ffuf",
        fake_run_ffuf,
    )

    result = enumerate_directories(
        "http://127.0.0.1",
        "ffuf",
        wordlist,
        timeout=11,
    )

    assert result is sentinel
    assert observed == {
        "target": "http://127.0.0.1",
        "wordlist": wordlist,
        "timeout": 11,
    }


def test_enumerate_directories_uses_dirb(monkeypatch, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    sentinel = object()

    monkeypatch.setattr(
        "voidscan.scanners.directories.tool_installed",
        lambda engine: True,
    )
    monkeypatch.setattr(
        "voidscan.scanners.directories.run_dirb",
        lambda *args, **kwargs: sentinel,
    )

    assert (
        enumerate_directories("http://127.0.0.1", "dirb", wordlist) is sentinel
    )


@patch("voidscan.scanners.directories.run_command")
def test_run_ffuf_accepts_full_urls(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\nlogin\n")

    mock_run.side_effect = lambda command, **kwargs: make_result(
        command,
        "http://127.0.0.1/admin\nhttp://127.0.0.1/login\n",
    )

    result = run_ffuf("http://127.0.0.1", wordlist)

    assert result.results == [
        "http://127.0.0.1/admin",
        "http://127.0.0.1/login",
    ]
