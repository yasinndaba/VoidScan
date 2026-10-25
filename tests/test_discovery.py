import threading

import pytest

from voidscan.errors import ScanCancelled
from voidscan.scanners.discovery import (
    MAX_HOSTS,
    discover_hosts,
    host_is_up,
    network_host_count,
    validate_network,
)


@pytest.mark.parametrize(
    "network",
    [
        "192.168.1.0/24",
        "10.0.0.0/24",
        "172.16.0.0/16",
    ],
)
def test_validate_network(network):
    result = validate_network(network)

    assert result


def test_validate_network_accepts_host_address():
    result = validate_network("192.168.1.25/24")

    assert str(result) == "192.168.1.0/24"


@pytest.mark.parametrize(
    "network",
    [
        "",
        "192.168.1.1",
        "not-a-network",
        "192.168.1.0/99",
    ],
)
def test_invalid_network(network):
    with pytest.raises(ValueError):
        validate_network(network)


def test_host_is_up_returns_boolean(monkeypatch):
    class FakeResult:
        returncode = 0

    monkeypatch.setattr(
        "voidscan.scanners.discovery.subprocess.run",
        lambda *args, **kwargs: FakeResult(),
    )

    assert host_is_up("127.0.0.1") is True


def test_host_is_up_accepts_cancel_event(monkeypatch):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True

        class FakeResult:
            returncode = 0

        return FakeResult()

    monkeypatch.setattr(
        "voidscan.scanners.discovery.subprocess.run",
        fake_run,
    )

    event = threading.Event()
    event.set()

    assert host_is_up("127.0.0.1", cancel_event=event) is False
    assert called is False


def test_discover_hosts(monkeypatch):
    def fake_host_is_up(host, timeout=1, cancel_event=None):
        return host == "192.168.1.1"

    monkeypatch.setattr(
        "voidscan.scanners.discovery.host_is_up",
        fake_host_is_up,
    )

    result = discover_hosts("192.168.1.0/30")

    assert result.network == "192.168.1.0/30"
    assert result.scanned == 2
    assert result.reachable == 1
    assert result.hosts == ["192.168.1.1"]


def test_network_host_count():
    assert network_host_count("192.168.1.0/24") == 254
    assert network_host_count("192.168.1.0/30") == 2
    assert network_host_count("192.168.1.1/32") == 1


def test_discover_hosts_rejects_large_ipv4_networks(monkeypatch):
    called = False

    def fake_host_is_up(host, timeout=1, cancel_event=None):
        nonlocal called
        called = True
        return False

    monkeypatch.setattr(
        "voidscan.scanners.discovery.host_is_up",
        fake_host_is_up,
    )

    with pytest.raises(ValueError, match="too large"):
        discover_hosts("10.0.0.0/8")

    assert called is False
    assert MAX_HOSTS == 4096


def test_discover_hosts_rejects_large_ipv6_networks(monkeypatch):
    with pytest.raises(ValueError, match="too large"):
        discover_hosts("2001:db8::/64")


def test_discover_hosts_uses_configured_limits(monkeypatch):
    observed = {}

    def fake_host_is_up(host, timeout=1, cancel_event=None):
        observed["timeout"] = timeout
        return False

    monkeypatch.setattr(
        "voidscan.scanners.discovery.host_is_up",
        fake_host_is_up,
    )

    with pytest.raises(ValueError, match="32 hosts"):
        discover_hosts(
            "192.168.1.0/24",
            max_hosts=32,
        )

    result = discover_hosts(
        "192.168.1.0/30",
        max_hosts=32,
        max_workers=1,
        ping_timeout=3,
    )

    assert result.scanned == 2
    assert observed["timeout"] == 3


def test_discover_hosts_reports_progress(monkeypatch):
    monkeypatch.setattr(
        "voidscan.scanners.discovery.host_is_up",
        lambda host, timeout=1, cancel_event=None: host.endswith(".1"),
    )

    events = []

    result = discover_hosts(
        "192.168.1.0/30",
        on_progress=lambda completed, total: events.append(
            (completed, total)
        ),
    )

    assert events == [(1, 2), (2, 2)]
    assert result.reachable == 1


def test_discover_hosts_can_be_cancelled(monkeypatch):
    event = threading.Event()
    event.set()

    def fake_host_is_up(host, timeout=1, cancel_event=None):
        return False

    monkeypatch.setattr(
        "voidscan.scanners.discovery.host_is_up",
        fake_host_is_up,
    )

    with pytest.raises(ScanCancelled):
        discover_hosts(
            "192.168.1.0/29",
            cancel_event=event,
        )
