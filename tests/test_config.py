from voidscan.config import Config


def test_config_creates_directories(tmp_path):
    config = Config(
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
    )

    config.create_directories()

    assert config.data_dir.is_dir()
    assert config.log_dir.is_dir()
    assert config.report_dir.is_dir()
