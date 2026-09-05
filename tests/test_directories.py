from pathlib import Path
from unittest.mock import patch

import pytest

from voidscan.scanners.directories import (
    DEFAULT_WORDLIST,
    enumerate_directories,
    run_dirb,
    run_ffuf,
    tool_installed,
    validate_wordlist,
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


@patch("voidscan.scanners.directories.subprocess.run")
def test_run_ffuf(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\nlogin\n")

    mock_run.return_value.stdout = "admin\nlogin\n"
    mock_run.return_value.stderr = ""
    mock_run.return_value.returncode = 0

    result = run_ffuf("http://127.0.0.1", wordlist)

    command = mock_run.call_args.args[0]

    assert command[0] == "ffuf"
    assert "-u" in command
    assert "http://127.0.0.1/FUZZ" in command
    assert "-w" in command
    assert str(wordlist) in command

    assert result.engine == "ffuf"
    assert result.target == "http://127.0.0.1"
    assert result.wordlist == str(wordlist)
    assert result.results == ["admin", "login"]
    assert result.success is True


@patch("voidscan.scanners.directories.subprocess.run")
def test_run_dirb(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\nlogin\n")

    mock_run.return_value.stdout = "FOUND: /admin\nFOUND: /login\n"
    mock_run.return_value.stderr = ""
    mock_run.return_value.returncode = 0

    result = run_dirb("http://127.0.0.1", wordlist)

    command = mock_run.call_args.args[0]

    assert command[0] == "dirb"
    assert "http://127.0.0.1" in command
    assert str(wordlist) in command
    assert "-S" in command

    assert result.engine == "dirb"
    assert result.success is True


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


@patch("voidscan.scanners.directories.subprocess.run")
def test_run_ffuf_timeout(mock_run, tmp_path):
    wordlist = tmp_path / "custom.txt"
    wordlist.write_text("admin\n")

    import subprocess

    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["ffuf"],
        timeout=300,
    )

    with pytest.raises(RuntimeError, match="timed out"):
        run_ffuf("http://127.0.0.1", wordlist)
