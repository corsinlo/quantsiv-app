"""SSRF guard (A17): the address list from audit section 7, plus internal names."""

import socket

import pytest

from app.services.ssrf import is_public_ip, resolve_scan_target


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a9fe:a9fe",
        "192.168.1.1",
        "172.16.0.1",
        "224.0.0.1",
        "fe80::1%eth0",
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_blocked(address):
    assert is_public_ip(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_pass(address):
    assert is_public_ip(address) is True


def _resolves_to(monkeypatch, *ips):
    def fake_getaddrinfo(host, port, type=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "redis.railway.internal",
        "db.internal",
        "printer.local",
        "box.lan",
        "x.localhost.",
    ],
)
def test_internal_names_are_refused_before_resolving(monkeypatch, host):
    def explode(*args, **kwargs):
        raise AssertionError("must not resolve internal names")

    monkeypatch.setattr(socket, "getaddrinfo", explode)
    with pytest.raises(ValueError, match="internal name"):
        resolve_scan_target(host)


def test_a_name_resolving_to_metadata_is_refused(monkeypatch):
    _resolves_to(monkeypatch, "93.184.216.34", "169.254.169.254")  # one bad record is enough
    with pytest.raises(ValueError, match="non-public"):
        resolve_scan_target("rebind.example")


def test_public_name_returns_a_vetted_ip(monkeypatch):
    _resolves_to(monkeypatch, "93.184.216.34")
    assert resolve_scan_target("example.org") == "93.184.216.34"


def test_only_port_443(monkeypatch):
    with pytest.raises(ValueError, match="443"):
        resolve_scan_target("example.org", port=8443)
