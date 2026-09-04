from voidscan.cli import main


def test_main(capsys):
    main()

    captured = capsys.readouterr()

    assert "VoidScan" in captured.out
    assert "Authorized Reconnaissance" in captured.out
    assert "Version 0.1.0" in captured.out
