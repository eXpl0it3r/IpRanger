"""Blocklist feed fetching and storage for IpRanger V2."""
import logging
import requests
from ipaddress import ip_network, ip_address, AddressValueError

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'IpRanger/2.0'}


def _parse_feed(content: str, entry_type: str) -> list:
    """Parse a blocklist text file into a list of (entry, resolved_type) tuples."""
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')):
            continue
        token = line.split()[0].rstrip(';,')
        try:
            if '/' in token:
                net = ip_network(token, strict=False)
                entries.append((str(net), 'cidr'))
            else:
                ip_address(token)
                entries.append((token, 'ip'))
        except (AddressValueError, ValueError):
            continue
    return entries


def fetch_blocklist(url: str, entry_type: str) -> list:
    try:
        resp = requests.get(url, timeout=30, headers=HEADERS)
        resp.raise_for_status()
        return _parse_feed(resp.text, entry_type)
    except requests.RequestException as exc:
        logger.error(f"Failed to fetch {url}: {exc}")
        return []


def refresh_all_blocklists() -> int:
    """Fetch, store, and push to ipset all enabled blocklist sources."""
    from .config import config
    from .db import seed_blocklist_source, replace_blocklist_entries
    from .ipset import bulk_add_to_blacklist, ensure_ipsets

    sources = config.get('blocklists', 'sources', default=[])
    ensure_ipsets()
    updated = 0
    for src in sources:
        if not src.get('enabled', True):
            seed_blocklist_source(src['name'], src['url'], src['type'], enabled=0)
            continue
        seed_blocklist_source(src['name'], src['url'], src['type'], enabled=1)
        entries = fetch_blocklist(src['url'], src['type'])
        if entries:
            replace_blocklist_entries(src['name'], entries)
            bulk_add_to_blacklist(entries)
            updated += 1
            logger.info(f"Updated {src['name']}: {len(entries)} entries")
        else:
            logger.warning(f"Blocklist {src['name']} returned no entries")
    return updated


def refresh_one_blocklist(name: str) -> int:
    """Refresh a single blocklist source by name. Returns entry count."""
    from .config import config
    from .db import replace_blocklist_entries
    from .ipset import bulk_add_to_blacklist, ensure_ipsets

    sources = config.get('blocklists', 'sources', default=[])
    for src in sources:
        if src['name'] != name:
            continue
        ensure_ipsets()
        entries = fetch_blocklist(src['url'], src['type'])
        if entries:
            replace_blocklist_entries(name, entries)
            bulk_add_to_blacklist(entries)
            logger.info(f"Refreshed {name}: {len(entries)} entries")
        return len(entries)
    logger.warning(f"Blocklist source not found: {name}")
    return 0
