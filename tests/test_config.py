from pathlib import Path

from voidscan import config as config_module
from voidscan.config import (
    Config,
    apply_env_overrides,
    get_config,
    load_config,
    reset_config,
    set_config,
    with_data_dir,
)


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


def test_defaults_are_used_without_a_config_file(tmp_path):
    config, warnings = load_config(tmp_path / "missing.toml")

    assert warnings
    assert config.nmap_timeout == 300
    assert config.amass_timeout == 900
    assert config.max_hosts == 4096
    assert config.discovery_workers == 32


def test_loads_toml_settings(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[paths]
data_dir = "~/custom-voidscan"
log_dir = "~/custom-voidscan/logs"
report_dir = "~/custom-voidscan/reports"
target_file = "~/custom-voidscan/targets.txt"

[timeouts]
nmap = 120
ffuf = 90
dirb = 60
subfinder = 45
amass = 180

[discovery]
max_hosts = 512
workers = 8
ping_timeout = 2
""",
        encoding="utf-8",
    )

    config, warnings = load_config(config_path)

    assert warnings == []
    assert config.config_file == config_path
    assert config.data_dir == Path("~/custom-voidscan").expanduser()
    assert config.log_dir == Path("~/custom-voidscan/logs").expanduser()
    assert config.nmap_timeout == 120
    assert config.ffuf_timeout == 90
    assert config.dirb_timeout == 60
    assert config.subfinder_timeout == 45
    assert config.amass_timeout == 180
    assert config.max_hosts == 512
    assert config.discovery_workers == 8
    assert config.ping_timeout == 2


def test_data_dir_derives_other_default_paths(tmp_path):
    data_dir = tmp_path / "voidscan-data"
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[paths]\ndata_dir = "{data_dir}"\n',
        encoding="utf-8",
    )

    config, warnings = load_config(config_path)

    assert warnings == []
    assert config.data_dir == data_dir
    assert config.log_dir == data_dir / "logs"
    assert config.report_dir == data_dir / "reports"
    assert config.target_file == data_dir / "targets.txt"


def test_invalid_toml_warns_and_falls_back(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text("[timeouts\nnmap = 1", encoding="utf-8")

    config, warnings = load_config(config_path)

    assert any("Could not parse" in warning for warning in warnings)
    assert config.nmap_timeout == 300


def test_invalid_values_warn_and_keep_valid_settings(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[timeouts]
nmap = "soon"
ffuf = -1
dirb = 75

[discovery]
max_hosts = 0
workers = "many"
""",
        encoding="utf-8",
    )

    config, warnings = load_config(config_path)

    assert config.nmap_timeout == 300
    assert config.ffuf_timeout == 300
    assert config.dirb_timeout == 75
    assert config.max_hosts == 4096
    assert config.discovery_workers == 32
    assert len(warnings) == 4


def test_environment_overrides_config(tmp_path):
    config = Config(data_dir=tmp_path / "data")

    overridden = apply_env_overrides(
        config,
        environ={
            "VOIDSCAN_DATA_DIR": str(tmp_path / "env-data"),
            "VOIDSCAN_NMAP_TIMEOUT": "42",
            "VOIDSCAN_MAX_HOSTS": "128",
            "VOIDSCAN_DISCOVERY_WORKERS": "4",
        },
    )

    assert overridden.data_dir == tmp_path / "env-data"
    assert overridden.log_dir == tmp_path / "env-data" / "logs"
    assert overridden.report_dir == tmp_path / "env-data" / "reports"
    assert overridden.nmap_timeout == 42
    assert overridden.max_hosts == 128
    assert overridden.discovery_workers == 4


def test_invalid_environment_value_warns(tmp_path):
    warnings = []

    overridden = apply_env_overrides(
        Config(data_dir=tmp_path),
        warnings,
        environ={"VOIDSCAN_NMAP_TIMEOUT": "later"},
    )

    assert overridden.nmap_timeout == 300
    assert warnings


def test_with_data_dir_moves_all_storage_paths(tmp_path):
    data_dir = tmp_path / "moved"

    config = with_data_dir(Config(), data_dir)

    assert config.data_dir == data_dir
    assert config.log_dir == data_dir / "logs"
    assert config.report_dir == data_dir / "reports"
    assert config.target_file == data_dir / "targets.txt"


def test_get_config_caches_and_can_be_replaced(tmp_path):
    reset_config()

    first = Config(data_dir=tmp_path / "first")
    set_config(first)

    assert get_config() is first

    second = Config(data_dir=tmp_path / "second")
    set_config(second)

    assert get_config() is second

    reset_config()


def test_get_config_loads_defaults_once(monkeypatch, tmp_path):
    reset_config()

    loaded = Config(data_dir=tmp_path / "loaded")
    calls = []

    def fake_load_config(path=None):
        calls.append(path)
        return loaded, []

    monkeypatch.setattr(
        config_module,
        "load_config",
        fake_load_config,
    )

    assert get_config() is loaded
    assert get_config() is loaded
    assert calls == [None]

    reset_config()
