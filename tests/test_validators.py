import pytest

from voidscan.validators import (
    is_valid_hostname,
    is_valid_ip,
    is_valid_target,
)


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.1",
        "10.0.0.1",
        "8.8.8.8",
        "2001:4860:4860::8888",
    ],
)
def test_valid_ips(target):
    assert is_valid_ip(target)


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "scan.example.com",
        "subdomain.example.org",
    ],
)
def test_valid_hostnames(target):
    assert is_valid_hostname(target)


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        "not a target",
        "999.999.999.999",
        "http://example.com",
        "example",
    ],
)
def test_invalid_targets(target):
    assert not is_valid_target(target)
