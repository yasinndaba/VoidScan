import pytest

from voidscan.cli import main


def test_main_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "voidscan 0.1.0" in captured.out


def test_main_starts_menu(monkeypatch):
    called = False

    def fake_run_menu():
        nonlocal called
        called = True

    monkeypatch.setattr("voidscan.cli.run_menu", fake_run_menu)

    main([])

    assert called