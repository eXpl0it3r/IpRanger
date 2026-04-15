"""Shared utility helpers."""
import re
from ipaddress import ip_address, IPv4Address, IPv6Address

# Matches the ::ffff:a.b.c.d or ::ffff:hex form produced by the kernel
_IPV4_MAPPED_RE = re.compile(
    r'^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', re.IGNORECASE
)


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
