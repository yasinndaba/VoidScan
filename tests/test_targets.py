import pytest

from voidscan.targets import Target


def test_valid_target():
    target = Target("192.168.1.10")

    assert target.value == "192.168.1.10"


def test_valid_domain():
    target = Target("example.com")

    assert target.value == "example.com"


def test_valid_web_url():
    target = Target("http://127.0.0.1:8765")

    assert target.value == "http://127.0.0.1:8765"


def test_valid_localhost():
    target = Target("localhost")

    assert target.value == "localhost"


def test_invalid_target():
    with pytest.raises(ValueError):
        Target("not a valid target")
