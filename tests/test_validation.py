import pytest
from backend.ip2location import validate_ip

def test_ipv4():
    assert validate_ip("8.8.8.8") == "8.8.8.8"

def test_ipv6():
    assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

def test_invalid():
    with pytest.raises(ValueError):
        validate_ip("not-an-ip")

def test_empty():
    with pytest.raises(ValueError):
        validate_ip("")
