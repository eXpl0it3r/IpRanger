"""RDAP / ASN enrichment with range-cache-first lookup."""
import logging
import time

from .utils import is_private_ip, unmap_ipv4

logger = logging.getLogger(__name__)


def lookup_ip(ip: str):
    """Resolve ASN info for a single IP via ipwhois RDAP.

    Returns a dict with keys: cidr, asn, network_name, country_code, info_url
    or None on failure.
    """
    ip = unmap_ipv4(ip)
    if is_private_ip(ip):
        return None
    try:
        from ipwhois import IPWhois
        result = IPWhois(ip).lookup_rdap(depth=1)
        net = result.get('network') or {}
        cidr = net.get('cidr', '') or ''
        asn = str(result.get('asn', '') or '')
        network_name = net.get('name', '') or ''
        country_code = net.get('country', '') or ''
        if asn:
            info_url = f"https://search.arin.net/rdap/?query=AS{asn}"
        elif net.get('handle'):
            info_url = f"https://search.arin.net/rdap/#/entity/{net.get('handle')}"
        else:
            info_url = ''
        if not cidr:
            return None
        return {
            'cidr': cidr,
            'asn': asn,
            'network_name': network_name,
            'country_code': country_code,
            'info_url': info_url,
        }
    except Exception as exc:
        logger.warning(f"RDAP lookup failed for {ip}: {exc}")
        return None


def enrich_pending_ips(limit: int = 10):
    """Look up ASN data for IPs that have no entry in ip_asn_map yet."""
    from .db import get_ips_missing_asn, find_cached_range_for_ip, upsert_asn_range, record_ip_asn
    from .config import config

    ips = get_ips_missing_asn(limit)
    delay = config.get('rdap', 'lookup_delay_seconds', default=1)
    enriched = 0

    for ip in ips:
        ip = unmap_ipv4(ip)
        if is_private_ip(ip):
            record_ip_asn(ip, None)
            continue

        # Cache-first: check if IP falls inside an already-known CIDR
        cached = find_cached_range_for_ip(ip)
        if cached:
            record_ip_asn(ip, cached['id'])
            enriched += 1
            continue

        # External lookup
        data = lookup_ip(ip)
        if data:
            range_id = upsert_asn_range(
                cidr=data['cidr'],
                asn=data['asn'],
                network_name=data['network_name'],
                country_code=data['country_code'],
                info_url=data['info_url'],
            )
            record_ip_asn(ip, range_id)
            enriched += 1
        else:
            record_ip_asn(ip, None)

        time.sleep(delay)

    if enriched:
        logger.info(f"Enriched {enriched} IPs with ASN data")
    return enriched


def refresh_group_asn(network_name: str, asn: str) -> int:
    """Drop an ASN group's cached data and re-resolve all of its IPs.

    Cache-first per IP, so only one external RDAP call is made per new CIDR.
    Returns the number of re-resolved IPs.
    """
    from .db import (
        get_ips_for_group, clear_asn_group,
        find_cached_range_for_ip, upsert_asn_range, record_ip_asn,
    )
    from .config import config

    ips = get_ips_for_group(network_name, asn)
    clear_asn_group(network_name, asn)
    delay = config.get('rdap', 'lookup_delay_seconds', default=1)
    refreshed = 0

    for ip in ips:
        ip = unmap_ipv4(ip)
        if is_private_ip(ip):
            record_ip_asn(ip, None)
            continue

        cached = find_cached_range_for_ip(ip)
        if cached:
            record_ip_asn(ip, cached['id'])
            refreshed += 1
            continue

        data = lookup_ip(ip)
        if data:
            range_id = upsert_asn_range(
                cidr=data['cidr'],
                asn=data['asn'],
                network_name=data['network_name'],
                country_code=data['country_code'],
                info_url=data['info_url'],
            )
            record_ip_asn(ip, range_id)
            refreshed += 1
        else:
            record_ip_asn(ip, None)
        time.sleep(delay)

    logger.info(f"Refreshed ASN info for group {network_name}/AS{asn}: {refreshed} IPs")
    return refreshed
