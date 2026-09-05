import socket
from unittest.mock import patch

import pytest

from voidscan.scanners.ip_info import (
    get_ip_info,
    get_reverse_dns,
    resolve_target,
)


def test_resolve_ip():
    assert resolve_target("127.0.0.1") == "127.0.0.1"


@patch("voidscan.scanners.ip_info.socket.gethostbyname")
def test_resolve_hostname(mock_gethostbyname):
    mock_gethostbyname.return_value = "93.184.216.34"

    result = resolve_target("example.com")

    assert result == "93.184.216.34"
    mock_gethostbyname.assert_called_once_with("example.com")


@patch("voidscan.scanners.ip_info.socket.gethostbyname")
def test_resolve_invalid_hostname(mock_gethostbyname):
    mock_gethostbyname.side_effect = socket.gaierror

    with pytest.raises(ValueError, match="Could not resolve target"):
        resolve_target("invalid.example")


@patch("voidscan.scanners.ip_info.socket.gethostbyaddr")
def test_reverse_dns(mock_gethostbyaddr):
    mock_gethostbyaddr.return_value = (
        "localhost",
        [],
        ["127.0.0.1"],
    )

    result = get_reverse_dns("127.0.0.1")

    assert result == "localhost"


@patch("voidscan.scanners.ip_info.socket.gethostbyaddr")
def test_reverse_dns_failure(mock_gethostbyaddr):
    mock_gethostbyaddr.side_effect = socket.herror

    result = get_reverse_dns("192.0.2.1")

    assert result is None


def test_get_ip_info_loopback():
    result = get_ip_info("127.0.0.1")

    assert result.address == "127.0.0.1"
    assert result.version == "IPv4"
    assert result.is_private is True
    assert result.is_loopback is True
    assert result.is_multicast is False


def test_get_ip_info_private_address():
    result = get_ip_info("192.168.1.1")

    assert result.address == "192.168.1.1"
    assert result.version == "IPv4"
    assert result.is_private is True
    assert result.is_loopback is False


def test_get_ip_info_multicast():
    result = get_ip_info("224.0.0.1")

    assert result.address == "224.0.0.1"
    assert result.version == "IPv4"
    assert result.is_multicast is True


def test_get_ip_info_ipv6():
    result = get_ip_info("::1")

    assert result.address == "::1"
    assert result.version == "IPv6"
    assert result.is_loopback is True


@patch("voidscan.scanners.ip_info.socket.gethostbyname")
def test_get_ip_info_hostname(mock_gethostbyname):
    mock_gethostbyname.return_value = "93.184.216.34"

    result = get_ip_info("example.com")

    assert result.address == "93.184.216.34"
    assert result.version == "IPv4"


def test_get_ip_info_invalid():
    with pytest.raises(ValueError, match="Could not resolve target"):
        get_ip_info("not-a-valid-target")
