"""Shared utility helpers."""
import re
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address

# Matches the ::ffff:a.b.c.d or ::ffff:hex form produced by the kernel
_IPV4_MAPPED_RE = re.compile(
    r'^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', re.IGNORECASE
)

# All RFC-defined private / reserved / special-use ranges that should never
# leave the host or be sent to an external lookup service.
# Sources: RFC 1918, 5735, 6598, 3927, 6890, 4193, 4291
RFC_PRIVATE_RANGES = [
    # IPv4
    ("0.0.0.0/8",        "This network (RFC 1122)"),
    ("10.0.0.0/8",       "Private-use (RFC 1918)"),
    ("100.64.0.0/10",    "Shared address space (RFC 6598)"),
    ("127.0.0.0/8",      "Loopback (RFC 1122)"),
    ("169.254.0.0/16",   "Link-local (RFC 3927)"),
    ("172.16.0.0/12",    "Private-use (RFC 1918)"),
    ("192.0.0.0/24",     "IETF protocol assignments (RFC 6890)"),
    ("192.0.2.0/24",     "TEST-NET-1 (RFC 5737)"),
    ("192.168.0.0/16",   "Private-use (RFC 1918)"),
    ("198.18.0.0/15",    "Benchmarking (RFC 2544)"),
    ("198.51.100.0/24",  "TEST-NET-2 (RFC 5737)"),
    ("203.0.113.0/24",   "TEST-NET-3 (RFC 5737)"),
    ("240.0.0.0/4",      "Reserved (RFC 1112)"),
    ("255.255.255.255/32","Limited broadcast (RFC 919)"),
    # IPv6
    ("::1/128",          "IPv6 loopback (RFC 4291)"),
    ("fc00::/7",         "IPv6 unique local (RFC 4193)"),
    ("fe80::/10",        "IPv6 link-local (RFC 4291)"),
    ("::/128",           "IPv6 unspecified (RFC 4291)"),
]

# Pre-parsed network objects for fast membership tests
_PRIVATE_NETS = [ip_network(cidr, strict=False) for cidr, _ in RFC_PRIVATE_RANGES]


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* falls within any RFC-reserved range."""
    try:
        addr = ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def unmap_ipv4(ip_str: str) -> str:
    """Return plain IPv4 string if *ip_str* is an IPv4-mapped IPv6 address.

    Examples
    --------
    ``::ffff:1.2.3.4``  →  ``1.2.3.4``
    ``::ffff:c0a8:101`` →  ``192.168.1.1``  (hex-encoded mapped form)
    ``2001:db8::1``     →  ``2001:db8::1``  (unchanged)
    ``1.2.3.4``         →  ``1.2.3.4``      (unchanged)
    """
    if not ip_str:
        return ip_str
    # Fast path for the decimal form ::ffff:a.b.c.d
    m = _IPV4_MAPPED_RE.match(ip_str)
    if m:
        return m.group(1)
    # General path: parse with stdlib and check
    try:
        addr = ip_address(ip_str)
        if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
    except ValueError:
        pass
    return ip_str
