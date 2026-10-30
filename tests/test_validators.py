import pytest
from voidscan.validators import (
    is_ipv6,
    is_valid_hostname,
    is_valid_ip,
    is_valid_target,
    is_valid_web_url,
    target_host,
    to_web_url,
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
        "localhost",
        "my-lab-host",
        "example.com.",
        "xn--bcher-kva.example",
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
        "exa mple.com",
        "-example.com",
    ],
)
def test_invalid_hostnames(target):
    assert not is_valid_hostname(target)


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://example.com",
        "http://127.0.0.1:8765",
        "https://localhost:8443/app?q=1",
        "https://sub.example.co.uk/path",
    ],
)
def test_valid_web_urls(target):
    assert is_valid_web_url(target)


@pytest.mark.parametrize(
    "target",
    [
        "",
        "example.com",
        "ftp://example.com",
        "http://",
        "http:///path",
        "http://exa mple.com",
        "http://example.com:99999",
        "http://user:pass@example.com",
    ],
)
def test_invalid_web_urls(target):
    assert not is_valid_web_url(target)


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.1",
        "example.com",
        "localhost",
        "http://example.com",
        "https://127.0.0.1:8765/path",
    ],
)
def test_valid_targets(target):
    assert is_valid_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        "not a target",
        "999.999.999.999",
        "ftp://example.com",
        "192.168.0.0/24",
    ],
)
def test_invalid_targets(target):
    assert not is_valid_target(target)


def test_target_host_strips_url():
    assert target_host("https://example.com:8443/path?q=1") == "example.com"
    assert target_host("example.com") == "example.com"
    assert target_host("http://[2001:db8::1]:8443/app") == "2001:db8::1"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("::1", True),
        ("2001:db8::1", True),
        ("::ffff:192.0.2.1", True),
        ("127.0.0.1", False),
        ("example.com", False),
        ("[::1]", False),
    ],
)
def test_is_ipv6(target, expected):
    assert is_ipv6(target) is expected


def test_to_web_url_keeps_urls_and_promotes_hosts():
    assert to_web_url("https://example.com/app") == "https://example.com/app"
    assert to_web_url("127.0.0.1") == "http://127.0.0.1"
    assert to_web_url("localhost") == "http://localhost"


def test_to_web_url_brackets_ipv6_literals():
    assert to_web_url("2001:db8::1") == "http://[2001:db8::1]"
    assert to_web_url("::1") == "http://[::1]"

    url = "https://[2001:db8::2]:8443/app"
    assert to_web_url(url) == url


def test_to_web_url_rejects_invalid_targets():
    with pytest.raises(ValueError, match="Invalid web target"):
        to_web_url("not a target")
