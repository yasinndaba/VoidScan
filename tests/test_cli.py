from pathlib import Path
from unittest.mock import MagicMock

import pytest

from voidscan.cli import main


def isolate_cli(monkeypatch, tmp_path: Path) -> MagicMock:
    """Keep CLI tests away from the real ~/.voidscan directory."""

    config = MagicMock()
    config.log_dir = tmp_path
    config.report_dir = tmp_path
    config.config_file = tmp_path / "config.toml"
    config.create_directories = MagicMock()

    monkeypatch.setattr(
        "voidscan.cli.load_config",
        lambda path=None: (config, []),
    )
    monkeypatch.setattr(
        "voidscan.cli.apply_env_overrides",
        lambda cfg, warnings=None: cfg,
    )
    monkeypatch.setattr(
        "voidscan.cli.set_config",
        lambda cfg: None,
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
    assert "voidscan 0.2.0" in captured.out


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


def test_main_warns_about_invalid_config(monkeypatch, tmp_path, capsys):
    isolate_cli(monkeypatch, tmp_path)

    config = MagicMock()
    config.log_dir = tmp_path
    config.create_directories = MagicMock()

    monkeypatch.setattr(
        "voidscan.cli.load_config",
        lambda path=None: (config, ["bad setting"]),
    )
    monkeypatch.setattr("voidscan.cli.run_menu", lambda: None)

    main([])

    captured = capsys.readouterr()

    assert "Configuration Warning" in captured.out
    assert "bad setting" in captured.out


def test_main_uses_config_path_from_environment(
    monkeypatch,
    tmp_path,
):
    isolate_cli(monkeypatch, tmp_path)

    observed = {}
    config_path = tmp_path / "custom.toml"

    def fake_load_config(path=None):
        observed["path"] = path
        config = MagicMock()
        config.log_dir = tmp_path
        config.create_directories = MagicMock()
        return config, []

    monkeypatch.setattr("voidscan.cli.load_config", fake_load_config)
    monkeypatch.setenv("VOIDSCAN_CONFIG", str(config_path))
    monkeypatch.setattr("voidscan.cli.run_menu", lambda: None)

    main([])

    assert observed["path"] == str(config_path)


def test_main_applies_cli_path_overrides(
    monkeypatch,
    tmp_path,
):
    isolate_cli(monkeypatch, tmp_path)

    applied = {}

    def fake_apply(cfg, args):
        applied["log_dir"] = args.log_dir
        applied["report_dir"] = args.report_dir
        applied["data_dir"] = args.data_dir
        return cfg

    monkeypatch.setattr(
        "voidscan.cli._apply_cli_overrides",
        fake_apply,
    )
    monkeypatch.setattr("voidscan.cli.run_menu", lambda: None)

    main(
        [
            "--data-dir",
            str(tmp_path / "data"),
            "--log-dir",
            str(tmp_path / "logs"),
            "--report-dir",
            str(tmp_path / "reports"),
        ]
    )

    assert applied["data_dir"] == tmp_path / "data"
    assert applied["log_dir"] == tmp_path / "logs"
    assert applied["report_dir"] == tmp_path / "reports"
