"""Live host discovery engine for VoidScan."""

import ipaddress
import logging
import subprocess
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from voidscan.errors import ScanCancelled

logger = logging.getLogger("voidscan.scanners.discovery")

# Guard rails so a typo such as 10.0.0.0/8 cannot freeze the application.
MAX_HOSTS = 4096
MAX_WORKERS = 32
PING_TIMEOUT = 1


@dataclass
class HostDiscoveryResult:
    """Represent a host discovery result."""

    network: str
    hosts: list[str]
    scanned: int
    reachable: int
    command: list[str] = field(default_factory=list)


def validate_network(
    network: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate and return a network in explicit CIDR notation."""

    network = network.strip()

    if "/" not in network:
        raise ValueError(
            "Invalid network. Use CIDR notation such as 192.168.1.0/24."
        )

    try:
        return ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise ValueError(
            "Invalid network. Use CIDR notation such as 192.168.1.0/24."
        ) from exc


def network_host_count(network: str) -> int:
    """Return the number of hosts that would be scanned in a network."""

    validated = validate_network(network)

    return _host_count(validated.version, validated.prefixlen)


def _host_count(version: int, prefixlen: int) -> int:
    """Return the scannable host count for a family and prefix length."""

    if version == 4:
        addresses = 1 << (32 - prefixlen)
        return addresses if prefixlen >= 31 else addresses - 2

    addresses = 1 << (128 - prefixlen)
    return addresses if prefixlen >= 127 else addresses - 1


def _example_prefix(version: int, max_hosts: int) -> int:
    """Return the broadest prefix length whose host count fits the cap."""

    bits = 32 if version == 4 else 128

    for prefixlen in range(bits + 1):
        if _host_count(version, prefixlen) <= max_hosts:
            return prefixlen

    return bits  # pragma: no cover - a /32 or /128 always fits


def validate_discovery_scope(
    network: str,
    max_hosts: int = MAX_HOSTS,
) -> int:
    """Validate a network and return its host count.

    Oversized networks are rejected before any address is enumerated, with
    a message that names the address family and a supported example prefix.
    """

    validated = validate_network(network)
    total_hosts = _host_count(validated.version, validated.prefixlen)

    if max_hosts < 1:
        raise ValueError("Discovery host limit must be at least 1.")

    if total_hosts <= max_hosts:
        return total_hosts

    example = _example_prefix(validated.version, max_hosts)
    unit = "hosts" if validated.version == 4 else "addresses"
    family = "IPv4" if validated.version == 4 else "IPv6"

    raise ValueError(
        f"{family} network is too large ({total_hosts:,} {unit}). "
        f"Scan {max_hosts:,} {unit} or fewer, such as a /{example} "
        "network or smaller."
    )


def host_is_up(
    host: str,
    timeout: int = PING_TIMEOUT,
    cancel_event: threading.Event | None = None,
) -> bool:
    """Check whether a host responds to an ICMP ping."""

    if cancel_event is not None and cancel_event.is_set():
        return False

    command = ["ping"]

    try:
        if ipaddress.ip_address(host).version == 6:
            command.append("-6")
    except ValueError:
        pass

    command.extend(["-c", "1", "-W", str(timeout), host])

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout + 1,
        )

        return result.returncode == 0

    except (OSError, subprocess.TimeoutExpired):
        return False


def discover_hosts(
    network: str,
    on_progress: Callable[[int, int], None] | None = None,
    *,
    max_hosts: int = MAX_HOSTS,
    max_workers: int = MAX_WORKERS,
    ping_timeout: int = PING_TIMEOUT,
    cancel_event: threading.Event | None = None,
) -> HostDiscoveryResult:
    """Discover reachable hosts in a network.

    ``on_progress`` is called with ``(completed, total)`` after each host
    finishes so the menu can display progress.
    """

    validate_discovery_scope(network, max_hosts)
    validated_network = validate_network(network)

    hosts = [str(host) for host in validated_network.hosts()]

    worker_count = max(1, min(max_workers, len(hosts)))

    logger.info(
        "Starting host discovery for %s (%s hosts, %s workers)",
        validated_network,
        len(hosts),
        worker_count,
    )

    reachable: set[str] = set()
    completed = 0

    if hosts:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    host_is_up,
                    host,
                    ping_timeout,
                    cancel_event,
                ): host
                for host in hosts
            }

            for future in as_completed(futures):
                if cancel_event is not None and cancel_event.is_set():
                    for pending in futures:
                        pending.cancel()

                    logger.info(
                        "Host discovery cancelled for %s",
                        validated_network,
                    )
                    raise ScanCancelled("Host discovery cancelled by user.")

                completed += 1

                try:
                    if future.result():
                        reachable.add(futures[future])
                except Exception:  # pragma: no cover - defensive
                    logger.debug(
                        "Host check failed for %s",
                        futures[future],
                        exc_info=True,
                    )

                if on_progress is not None:
                    on_progress(completed, len(hosts))

    ordered_hosts = [host for host in hosts if host in reachable]

    logger.info(
        "Host discovery finished for %s: %s/%s reachable",
        validated_network,
        len(ordered_hosts),
        len(hosts),
    )

    return HostDiscoveryResult(
        network=str(validated_network),
        hosts=ordered_hosts,
        scanned=len(hosts),
        reachable=len(ordered_hosts),
        command=["ping", "-c", "1", "-W", str(ping_timeout), "<host>"],
    )
