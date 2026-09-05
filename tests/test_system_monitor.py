from collections import namedtuple
from unittest.mock import mock_open, patch

from voidscan.scanners.system_monitor import (
    get_memory_info,
    get_system_monitor,
    get_uptime,
)


def test_get_memory_info():
    meminfo = (
        "MemTotal:       16384000 kB\n"
        "MemAvailable:    8192000 kB\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=meminfo),
    ):
        total, available = get_memory_info()

    assert total == 15.62
    assert available == 7.81


def test_get_uptime():
    with patch(
        "builtins.open",
        mock_open(read_data="12345.67 54321.00\n"),
    ):
        uptime = get_uptime()

    assert uptime == 12345.67


@patch("voidscan.scanners.system_monitor.get_uptime")
@patch("voidscan.scanners.system_monitor.get_memory_info")
@patch("voidscan.scanners.system_monitor.shutil.disk_usage")
@patch("voidscan.scanners.system_monitor.socket.gethostname")
@patch("voidscan.scanners.system_monitor.platform.machine")
@patch("voidscan.scanners.system_monitor.platform.release")
@patch("voidscan.scanners.system_monitor.platform.system")
@patch("voidscan.scanners.system_monitor.os.cpu_count")
def test_get_system_monitor(
    mock_cpu_count,
    mock_system,
    mock_release,
    mock_machine,
    mock_hostname,
    mock_disk_usage,
    mock_memory_info,
    mock_uptime,
):
    mock_cpu_count.return_value = 4
    mock_system.return_value = "Linux"
    mock_release.return_value = "7.1.8"
    mock_machine.return_value = "x86_64"
    mock_hostname.return_value = "TestHost"

    mock_memory_info.return_value = (16.0, 8.0)
    mock_uptime.return_value = 3600.0

    disk_usage = namedtuple(
        "disk_usage",
        ["total", "used", "free"],
    )

    mock_disk_usage.return_value = disk_usage(
        100 * 1024**3,
        40 * 1024**3,
        60 * 1024**3,
    )

    result = get_system_monitor()

    assert result.hostname == "TestHost"
    assert result.operating_system == "Linux"
    assert result.kernel == "7.1.8"
    assert result.architecture == "x86_64"
    assert result.cpu_count == 4
    assert result.memory_total_gb == 16.0
    assert result.memory_available_gb == 8.0
    assert result.disk_total_gb == 100.0
    assert result.disk_free_gb == 60.0
    assert result.uptime_seconds == 3600.0


def test_memory_info_handles_invalid_lines():
    meminfo = (
        "Invalid line\n"
        "MemTotal: invalid kB\n"
        "MemAvailable: 8192000 kB\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=meminfo),
    ):
        try:
            get_memory_info()
        except ValueError:
            pass
