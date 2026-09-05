"""Local system monitoring engine for VoidScan."""

import os
import platform
import shutil
import socket
import time
from dataclasses import dataclass


@dataclass
class SystemMonitorResult:
    """Represent local system information."""

    hostname: str
    operating_system: str
    kernel: str
    architecture: str
    cpu_count: int
    memory_total_gb: float
    memory_available_gb: float
    disk_total_gb: float
    disk_free_gb: float
    uptime_seconds: float


def get_memory_info() -> tuple[float, float]:
    """Return total and available memory in GB."""

    total = 0
    available = 0

    try:
        with open("/proc/meminfo", "r") as file:
            for line in file:
                parts = line.split()

                if len(parts) < 2:
                    continue

                if parts[0] == "MemTotal:":
                    total = int(parts[1]) * 1024

                elif parts[0] == "MemAvailable:":
                    available = int(parts[1]) * 1024

    except OSError as exc:
        raise RuntimeError("Unable to read system memory information.") from exc

    return (
        round(total / (1024 ** 3), 2),
        round(available / (1024 ** 3), 2),
    )


def get_uptime() -> float:
    """Return system uptime in seconds."""

    try:
        with open("/proc/uptime", "r") as file:
            return float(file.readline().split()[0])
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeError("Unable to read system uptime.") from exc


def get_system_monitor() -> SystemMonitorResult:
    """Collect local system information."""

    memory_total, memory_available = get_memory_info()

    disk = shutil.disk_usage("/")

    return SystemMonitorResult(
        hostname=socket.gethostname(),
        operating_system=platform.system(),
        kernel=platform.release(),
        architecture=platform.machine(),
        cpu_count=os.cpu_count() or 1,
        memory_total_gb=memory_total,
        memory_available_gb=memory_available,
        disk_total_gb=round(disk.total / (1024 ** 3), 2),
        disk_free_gb=round(disk.free / (1024 ** 3), 2),
        uptime_seconds=get_uptime(),
    )
