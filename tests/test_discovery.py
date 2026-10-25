import pytest

from voidscan.scanners.discovery import (
    discover_hosts,
    host_is_up,
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


def test_discover_hosts(monkeypatch):
    def fake_host_is_up(host):
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