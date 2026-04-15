import logging
import time

from .utils import unmap_ipv4, is_private_ip

logger = logging.getLogger(__name__)


def lookup_ip(ip):
    """Perform RDAP lookup for a single IP. Returns dict or None.

    Returns a synthetic local record (no network call) for RFC-private IPs.
    """
    ip = unmap_ipv4(ip)
    if is_private_ip(ip):
        logger.debug(f"Skipping RDAP for private/reserved IP {ip}")
        return {'org': 'Local / Reserved', 'network': '', 'asn': '', 'country': ''}
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        network = result.get('network') or {}
        return {
            'org': network.get('name', '') or '',
            'network': network.get('cidr', '') or '',
            'asn': str(result.get('asn', '') or ''),
            'country': network.get('country', '') or '',
        }
    except Exception as e:
        logger.warning(f"RDAP lookup failed for {ip}: {e}")
        return None


def enrich_pending_ips(limit=10):
    """Look up RDAP data for IPs that haven't been looked up yet."""
    from .db import get_ips_needing_rdap, update_rdap
    from .config import config

    ips = get_ips_needing_rdap(limit)
    delay = config.get('rdap', 'lookup_delay_seconds', default=1)
    enriched = 0
    for ip in ips:
        data = lookup_ip(ip)
        if data:
            update_rdap(ip, **data)
            enriched += 1
        else:
            # Mark as looked up even on failure to avoid retrying bad IPs constantly
            update_rdap(ip, org='', network='', asn='', country='')
        # No delay needed for private IPs — only throttle real network calls
        if not is_private_ip(unmap_ipv4(ip)):
            time.sleep(delay)
    if enriched:
        logger.info(f"Enriched {enriched} IPs with RDAP data")
    return enriched
