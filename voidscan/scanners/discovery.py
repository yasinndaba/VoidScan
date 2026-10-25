"""Live host discovery engine for VoidScan."""

import ipaddress
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable


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

    if validated.version == 4:
        if validated.prefixlen >= 31:
            return validated.num_addresses
        return validated.num_addresses - 2

    if validated.prefixlen >= 127:
        return validated.num_addresses

    return validated.num_addresses - 1


def host_is_up(host: str, timeout: int = PING_TIMEOUT) -> bool:
    """Check whether a host responds to an ICMP ping."""

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
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
) -> HostDiscoveryResult:
    """Discover reachable hosts in a network.

    ``on_progress`` is called with ``(completed, total)`` after each host
    finishes so the menu can display progress.
    """

    validated_network = validate_network(network)
    total_hosts = network_host_count(network)

    if total_hosts > MAX_HOSTS:
        raise ValueError(
            f"Network is too large ({total_hosts} hosts). "
            f"Scan {MAX_HOSTS} hosts or fewer, such as a /20 network."
        )

    hosts = [str(host) for host in validated_network.hosts()]

    logger.info(
        "Starting host discovery for %s (%s hosts, %s workers)",
        validated_network,
        len(hosts),
        min(MAX_WORKERS, max(1, len(hosts))),
    )

    reachable: set[str] = set()
    completed = 0

    if hosts:
        with ThreadPoolExecutor(
            max_workers=min(MAX_WORKERS, len(hosts))
        ) as executor:
            futures = {
                executor.submit(host_is_up, host): host
                for host in hosts
            }

            for future in as_completed(futures):
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
    )
