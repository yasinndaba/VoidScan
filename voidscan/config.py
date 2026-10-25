"""Application configuration and user config-file loading for VoidScan."""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


logger = logging.getLogger("voidscan.config")

CONFIG_FILENAME = "config.toml"

DEFAULT_NMAP_TIMEOUT = 300
DEFAULT_FFUF_TIMEOUT = 300
DEFAULT_DIRB_TIMEOUT = 300
DEFAULT_SUBFINDER_TIMEOUT = 300
DEFAULT_AMASS_TIMEOUT = 900
DEFAULT_MAX_HOSTS = 4096
DEFAULT_DISCOVERY_WORKERS = 32
DEFAULT_PING_TIMEOUT = 1


def _default_data_dir() -> Path:
    return Path.home() / ".voidscan"


def _default_log_dir() -> Path:
    return _default_data_dir() / "logs"


def _default_report_dir() -> Path:
    return _default_data_dir() / "reports"


def _default_target_file() -> Path:
    return _default_data_dir() / "targets.txt"


def _default_config_file() -> Path:
    return _default_data_dir() / CONFIG_FILENAME


@dataclass(frozen=True)
class Config:
    """Global VoidScan configuration."""

    data_dir: Path = field(default_factory=_default_data_dir)
    log_dir: Path = field(default_factory=_default_log_dir)
    report_dir: Path = field(default_factory=_default_report_dir)
    target_file: Path = field(default_factory=_default_target_file)
    config_file: Path = field(default_factory=_default_config_file)

    nmap_timeout: int = DEFAULT_NMAP_TIMEOUT
    ffuf_timeout: int = DEFAULT_FFUF_TIMEOUT
    dirb_timeout: int = DEFAULT_DIRB_TIMEOUT
    subfinder_timeout: int = DEFAULT_SUBFINDER_TIMEOUT
    amass_timeout: int = DEFAULT_AMASS_TIMEOUT

    max_hosts: int = DEFAULT_MAX_HOSTS
    discovery_workers: int = DEFAULT_DISCOVERY_WORKERS
    ping_timeout: int = DEFAULT_PING_TIMEOUT
    assume_yes: bool = False

    def create_directories(self) -> None:
        """Create required VoidScan directories."""

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)


def _read_toml(
    path: Path,
    warnings: list[str],
) -> dict[str, Any]:
    """Read a TOML file, returning an empty mapping on any failure."""

    if not path.exists():
        return {}

    try:
        with path.open("rb") as config_file:
            return tomllib.load(config_file)
    except tomllib.TOMLDecodeError as exc:
        warnings.append(
            f"Could not parse {path}: {exc}. Using default settings."
        )
    except OSError as exc:
        warnings.append(
            f"Could not read {path}: {exc}. Using default settings."
        )

    return {}


def _section(
    raw: Mapping[str, Any],
    name: str,
    warnings: list[str],
) -> Mapping[str, Any]:
    """Return a TOML table, warning when the section has the wrong type."""

    value = raw.get(name, {})

    if not isinstance(value, dict):
        warnings.append(
            f"Config section [{name}] must be a table. Ignoring it."
        )
        return {}

    return value


def _path_setting(
    values: Mapping[str, Any],
    key: str,
    default: Path,
    warnings: list[str],
) -> Path:
    """Read and validate a path setting."""

    value = values.get(key)

    if value is None:
        return default

    if not isinstance(value, str) or not value.strip():
        warnings.append(
            f"Config setting paths.{key} must be a non-empty string. "
            f"Using {default}."
        )
        return default

    return Path(value).expanduser()


def _int_setting(
    values: Mapping[str, Any],
    key: str,
    default: int,
    warnings: list[str],
    *,
    minimum: int = 1,
) -> int:
    """Read and validate an integer setting."""

    value = values.get(key)

    if value is None:
        return default

    if isinstance(value, bool) or not isinstance(value, int):
        warnings.append(
            f"Config setting {key} must be an integer. Using {default}."
        )
        return default

    if value < minimum:
        warnings.append(
            f"Config setting {key} must be at least {minimum}. "
            f"Using {default}."
        )
        return default

    return value


def load_config(
    path: str | Path | None = None,
) -> tuple[Config, list[str]]:
    """Load configuration from TOML and return it with any warnings.

    Missing settings use the built-in defaults. Invalid values are reported
    and replaced individually so one typo cannot break the whole application.
    """

    warnings: list[str] = []
    default_data_dir = _default_data_dir()
    config_path = (
        Path(path).expanduser()
        if path is not None
        else default_data_dir / CONFIG_FILENAME
    )

    if path is not None and not config_path.exists():
        warnings.append(
            f"Config file not found: {config_path}. Using default settings."
        )

    raw = _read_toml(config_path, warnings)
    paths = _section(raw, "paths", warnings)
    timeouts = _section(raw, "timeouts", warnings)
    discovery = _section(raw, "discovery", warnings)

    data_dir = _path_setting(
        paths,
        "data_dir",
        default_data_dir,
        warnings,
    )
    log_dir = _path_setting(
        paths,
        "log_dir",
        data_dir / "logs",
        warnings,
    )
    report_dir = _path_setting(
        paths,
        "report_dir",
        data_dir / "reports",
        warnings,
    )
    target_file = _path_setting(
        paths,
        "target_file",
        data_dir / "targets.txt",
        warnings,
    )

    config = Config(
        data_dir=data_dir,
        log_dir=log_dir,
        report_dir=report_dir,
        target_file=target_file,
        config_file=config_path,
        nmap_timeout=_int_setting(
            timeouts,
            "nmap",
            DEFAULT_NMAP_TIMEOUT,
            warnings,
        ),
        ffuf_timeout=_int_setting(
            timeouts,
            "ffuf",
            DEFAULT_FFUF_TIMEOUT,
            warnings,
        ),
        dirb_timeout=_int_setting(
            timeouts,
            "dirb",
            DEFAULT_DIRB_TIMEOUT,
            warnings,
        ),
        subfinder_timeout=_int_setting(
            timeouts,
            "subfinder",
            DEFAULT_SUBFINDER_TIMEOUT,
            warnings,
        ),
        amass_timeout=_int_setting(
            timeouts,
            "amass",
            DEFAULT_AMASS_TIMEOUT,
            warnings,
        ),
        max_hosts=_int_setting(
            discovery,
            "max_hosts",
            DEFAULT_MAX_HOSTS,
            warnings,
        ),
        discovery_workers=_int_setting(
            discovery,
            "workers",
            DEFAULT_DISCOVERY_WORKERS,
            warnings,
        ),
        ping_timeout=_int_setting(
            discovery,
            "ping_timeout",
            DEFAULT_PING_TIMEOUT,
            warnings,
        ),
    )

    return config, warnings


def with_data_dir(config: Config, data_dir: Path) -> Config:
    """Point every storage path at a new data directory."""

    data_dir = Path(data_dir).expanduser()

    return replace(
        config,
        data_dir=data_dir,
        log_dir=data_dir / "logs",
        report_dir=data_dir / "reports",
        target_file=data_dir / "targets.txt",
    )


def _env_path(
    environ: Mapping[str, str],
    variable: str,
) -> Path | None:
    """Return a path from an environment variable, if it is set."""

    value = environ.get(variable)

    if not value:
        return None

    return Path(value).expanduser()


def _env_int(
    environ: Mapping[str, str],
    variable: str,
    warnings: list[str],
) -> int | None:
    """Return a positive integer from the environment, if valid."""

    value = environ.get(variable)

    if value is None or value == "":
        return None

    try:
        parsed = int(value)
    except ValueError:
        warnings.append(
            f"Environment variable {variable} must be an integer. Ignoring it."
        )
        return None

    if parsed < 1:
        warnings.append(
            f"Environment variable {variable} must be at least 1. Ignoring it."
        )
        return None

    return parsed


def apply_env_overrides(
    config: Config,
    warnings: list[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Config:
    """Apply ``VOIDSCAN_*`` environment variable overrides."""

    warnings = warnings if warnings is not None else []
    environ = environ if environ is not None else os.environ

    data_dir = _env_path(environ, "VOIDSCAN_DATA_DIR")

    if data_dir is not None:
        config = with_data_dir(config, data_dir)

    log_dir = _env_path(environ, "VOIDSCAN_LOG_DIR")

    if log_dir is not None:
        config = replace(config, log_dir=log_dir)

    report_dir = _env_path(environ, "VOIDSCAN_REPORT_DIR")

    if report_dir is not None:
        config = replace(config, report_dir=report_dir)

    target_file = _env_path(environ, "VOIDSCAN_TARGET_FILE")

    if target_file is not None:
        config = replace(config, target_file=target_file)

    nmap_timeout = _env_int(environ, "VOIDSCAN_NMAP_TIMEOUT", warnings)

    if nmap_timeout is not None:
        config = replace(config, nmap_timeout=nmap_timeout)

    ffuf_timeout = _env_int(environ, "VOIDSCAN_FFUF_TIMEOUT", warnings)

    if ffuf_timeout is not None:
        config = replace(config, ffuf_timeout=ffuf_timeout)

    dirb_timeout = _env_int(environ, "VOIDSCAN_DIRB_TIMEOUT", warnings)

    if dirb_timeout is not None:
        config = replace(config, dirb_timeout=dirb_timeout)

    subfinder_timeout = _env_int(
        environ,
        "VOIDSCAN_SUBFINDER_TIMEOUT",
        warnings,
    )

    if subfinder_timeout is not None:
        config = replace(config, subfinder_timeout=subfinder_timeout)

    amass_timeout = _env_int(environ, "VOIDSCAN_AMASS_TIMEOUT", warnings)

    if amass_timeout is not None:
        config = replace(config, amass_timeout=amass_timeout)

    max_hosts = _env_int(environ, "VOIDSCAN_MAX_HOSTS", warnings)

    if max_hosts is not None:
        config = replace(config, max_hosts=max_hosts)

    discovery_workers = _env_int(
        environ,
        "VOIDSCAN_DISCOVERY_WORKERS",
        warnings,
    )

    if discovery_workers is not None:
        config = replace(config, discovery_workers=discovery_workers)

    ping_timeout = _env_int(environ, "VOIDSCAN_PING_TIMEOUT", warnings)

    if ping_timeout is not None:
        config = replace(config, ping_timeout=ping_timeout)

    return config


_config_lock = threading.Lock()
_cached_config: Config | None = None


def get_config() -> Config:
    """Return the process-wide configuration, loading it once."""

    global _cached_config

    with _config_lock:
        if _cached_config is None:
            _cached_config, warnings = load_config()

            for warning in warnings:
                logger.warning("%s", warning)

        return _cached_config


def set_config(config: Config) -> None:
    """Replace the process-wide configuration."""

    global _cached_config

    with _config_lock:
        _cached_config = config


def reset_config() -> None:
    """Clear the cached configuration. Intended for tests."""

    global _cached_config

    with _config_lock:
        _cached_config = None
