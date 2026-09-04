import pytest

from voidscan.targets import Target


def test_valid_target():
    target = Target("192.168.1.10")

    assert target.value == "192.168.1.10"


def test_valid_domain():
    target = Target("example.com")

    assert target.value == "example.com"


def test_invalid_target():
    with pytest.raises(ValueError):
        Target("not a valid target")
