"""SSRF guard for TLS scanning (A17) [tested in the audit].

Blocks loopback, RFC 1918, link-local (including 169.254.169.254), CGNAT, ULA, multicast and the
IPv4-in-IPv6 forms, including NAT64 `64:ff9b::a9fe:a9fe`. Public addresses pass.

Call it via `asyncio.to_thread(resolve_scan_target, host)`, then connect to the returned IP with
SNI set to `host` (e.g. `sslyze.ServerNetworkLocation(hostname=host, port=443,
ip_address=vetted_ip)`), so DNS cannot be rebound between the check and the connection.
TLS scanning is not built yet; when it is, it must scan only DNS-TXT-verified domains through
this guard, and unverified hosts get at most one lightweight handshake.
"""

import ipaddress
import socket

_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    if any(ip in net for net in _NAT64):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:  # e.g. scoped "fe80::1%eth0"
        return False
    if ip.version == 6:
        v4 = _embedded_ipv4(ip)
        if v4 is not None and not (v4.is_global and not v4.is_multicast):
            return False
    return ip.is_global and not ip.is_multicast


_BLOCKED_SUFFIXES = (".internal", ".railway.internal", ".local", ".localhost", ".lan")


def resolve_scan_target(host: str, port: int = 443) -> str:
    """Return a vetted public IP; connect to it with SNI=host so DNS cannot be rebound."""
    if port != 443:
        raise ValueError("only port 443 is scanned")
    name = host.lower().rstrip(".")
    if name == "localhost" or name.endswith(_BLOCKED_SUFFIXES):
        raise ValueError(f"{host} is an internal name")
    ips = sorted({info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not ips or not all(is_public_ip(ip) for ip in ips):
        raise ValueError(f"{host} resolves to a non-public address")
    return ips[0]
