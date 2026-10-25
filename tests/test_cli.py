from pathlib import Path
from unittest.mock import MagicMock

import pytest

from voidscan.cli import main


def isolate_cli(monkeypatch, tmp_path: Path) -> MagicMock:
    """Keep CLI tests away from the real ~/.voidscan directory."""

    config = MagicMock()
    config.log_dir = tmp_path
    config.create_directories = MagicMock()

    monkeypatch.setattr(
        "voidscan.cli.Config",
        lambda: config,
    )
    monkeypatch.setattr(
        "voidscan.cli.setup_logger",
        lambda directory: MagicMock(),
    )
    monkeypatch.setattr(
        "voidscan.cli.get_missing_tools",
        lambda: [],
    )

    return config


def test_main_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "voidscan 0.1.0" in captured.out


def test_main_starts_menu(monkeypatch, tmp_path):
    isolate_cli(monkeypatch, tmp_path)

    called = False

    def fake_run_menu():
        nonlocal called
        called = True

    monkeypatch.setattr("voidscan.cli.run_menu", fake_run_menu)

    main([])

    assert called


def test_main_handles_eof(monkeypatch, tmp_path, capsys):
    isolate_cli(monkeypatch, tmp_path)

    def fake_run_menu():
        raise EOFError

    monkeypatch.setattr("voidscan.cli.run_menu", fake_run_menu)

    main([])

    captured = capsys.readouterr()

    assert "VoidScan Session Ended." in captured.out


def test_main_warns_about_missing_tools(monkeypatch, tmp_path, capsys):
    isolate_cli(monkeypatch, tmp_path)

    monkeypatch.setattr(
        "voidscan.cli.get_missing_tools",
        lambda: ["nmap", "ffuf"],
    )
    monkeypatch.setattr("voidscan.cli.run_menu", lambda: None)

    main([])

    captured = capsys.readouterr()

    assert "Dependency Warning" in captured.out
    assert "nmap" in captured.out
    assert "ffuf" in captured.out
