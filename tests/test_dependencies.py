"""Tests for VoidScan dependency checks."""

from unittest.mock import patch

from voidscan.dependencies import (
    REQUIRED_TOOLS,
    get_missing_tools,
    is_tool_installed,
)


def test_required_tools_are_defined():
    assert "nmap" in REQUIRED_TOOLS
    assert "ffuf" in REQUIRED_TOOLS
    assert "dirb" in REQUIRED_TOOLS
    assert "subfinder" in REQUIRED_TOOLS
    assert "amass" in REQUIRED_TOOLS


@patch("voidscan.dependencies.shutil.which")
def test_is_tool_installed(mock_which):
    mock_which.return_value = "/usr/bin/nmap"

    assert is_tool_installed("nmap") is True
    mock_which.assert_called_once_with("nmap")


@patch("voidscan.dependencies.shutil.which")
def test_is_tool_not_installed(mock_which):
    mock_which.return_value = None

    assert is_tool_installed("nmap") is False


@patch("voidscan.dependencies.shutil.which")
def test_get_missing_tools(mock_which):
    def fake_which(tool):
        if tool in {"nmap", "ffuf"}:
            return f"/usr/bin/{tool}"
        return None

    mock_which.side_effect = fake_which

    missing = get_missing_tools()

    assert missing == ["dirb", "subfinder", "amass"]
