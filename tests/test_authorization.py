"""Tests for first-scan authorization confirmation."""

from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from voidscan import menu
from voidscan.authorization import (
    is_authorized,
    mark_authorized,
    reset_authorization,
)
from voidscan.config import Config
from voidscan.execution import ScanContext
from voidscan.scanners.nmap import NmapResult


@pytest.fixture(autouse=True)
def clear_authorization():
    """Keep authorization state isolated between tests."""

    reset_authorization()

    yield

    reset_authorization()


def make_config(
    tmp_path: Path | None = None, *, assume_yes: bool = False
) -> Config:
    """Build a configuration, optionally rooted in a temporary directory."""

    if tmp_path is None:
        return replace(Config(), assume_yes=assume_yes)

    return Config(
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        target_file=tmp_path / "targets.txt",
        assume_yes=assume_yes,
    )


def test_confirmation_is_remembered_for_the_session():
    config = make_config()
    prompt = "Confirm you are authorized to scan example.com?"

    with patch("voidscan.menu.Confirm.ask", return_value=True) as confirm:
        assert menu.require_authorization("example.com", config) is True
        assert menu.require_authorization("example.com", config) is True

    confirm.assert_called_once_with(prompt)
    assert is_authorized()


def test_declining_does_not_authorize_the_session():
    with patch("voidscan.menu.Confirm.ask", return_value=False):
        assert (
            menu.require_authorization("example.com", make_config()) is False
        )

    assert not is_authorized()


def test_assume_yes_skips_the_confirmation():
    with patch("voidscan.menu.Confirm.ask") as confirm:
        authorized = menu.require_authorization(
            "example.com",
            make_config(assume_yes=True),
        )

    assert authorized is True
    confirm.assert_not_called()


def test_existing_authorization_skips_the_confirmation():
    mark_authorized()

    with patch("voidscan.menu.Confirm.ask") as confirm:
        authorized = menu.require_authorization("example.com", make_config())

    assert authorized is True
    confirm.assert_not_called()


def test_declining_prevents_the_network_scan(tmp_path):
    manager = MagicMock()
    manager.list_targets.return_value = ["example.com"]

    with (
        patch(
            "voidscan.menu.get_config",
            return_value=make_config(tmp_path),
        ),
        patch("voidscan.menu.TargetManager", return_value=manager),
        patch("voidscan.menu.Prompt.ask", side_effect=["1", "1"]),
        patch("voidscan.menu.Confirm.ask", return_value=False),
        patch("voidscan.menu.console.input"),
        patch("voidscan.menu.show_banner"),
        patch("voidscan.menu.run_nmap") as run_nmap,
    ):
        menu.network_scan()

    run_nmap.assert_not_called()
    assert not is_authorized()


def test_confirmation_allows_the_network_scan(tmp_path):
    manager = MagicMock()
    manager.list_targets.return_value = ["example.com"]

    result = NmapResult(
        target="example.com",
        command=["nmap", "example.com"],
        output="",
        return_code=1,
        success=False,
    )

    with (
        patch(
            "voidscan.menu.get_config",
            return_value=make_config(tmp_path),
        ),
        patch("voidscan.menu.TargetManager", return_value=manager),
        patch("voidscan.menu.Prompt.ask", side_effect=["1", "1"]),
        patch("voidscan.menu.Confirm.ask", return_value=True),
        patch("voidscan.menu.console.input"),
        patch("voidscan.menu.show_banner"),
        patch(
            "voidscan.menu.run_with_progress",
            side_effect=lambda description, operation, console=None: operation(
                ScanContext(description=description)
            ),
        ),
        patch("voidscan.menu.run_nmap", return_value=result) as run_nmap,
    ):
        menu.network_scan()

    run_nmap.assert_called_once()
    assert is_authorized()
