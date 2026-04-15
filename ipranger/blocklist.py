import requests
import logging
from ipaddress import ip_network, ip_address, AddressValueError

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'IpRanger/1.0'}


def fetch_blocklist(url, entry_type):
    """Fetch a block list URL. Returns list of (entry, entry_type) tuples."""
    try:
        resp = requests.get(url, timeout=30, headers=HEADERS)
        resp.raise_for_status()
        return parse_blocklist_content(resp.text, entry_type)
    except requests.RequestException as e:
        logger.error(f"Failed to fetch blocklist {url}: {e}")
        return []


def parse_blocklist_content(content, entry_type):
    """Parse block list text content. Returns list of (entry, resolved_type) tuples."""
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';') or line.startswith('//'):
            continue
        # Extract first token (handle inline comments)
        token = line.split()[0]
        # Strip any trailing semicolons or commas
        token = token.rstrip(';,')
        try:
            if '/' in token:
                net = ip_network(token, strict=False)
                entries.append((str(net), 'cidr'))
            elif token.upper().startswith('AS') and token[2:].isdigit():
                entries.append((token.upper(), 'asn'))
            elif token.isdigit():
                entries.append((f"AS{token}", 'asn'))
            else:
                ip_address(token)
                entries.append((token, 'ip'))
        except (AddressValueError, ValueError):
            continue
    return entries


def _push_to_ipset(entries):
    """Push IP/CIDR entries to ipset. Silently skips if ipset is unavailable."""
    try:
        from .ipset import bulk_add_to_ipset
        added = bulk_add_to_ipset(entries)
        logger.info(f"Pushed {added} entries to ipset")
    except Exception as e:
        logger.warning(f"Could not push entries to ipset: {e}")


def refresh_all_blocklists():
    """Fetch, store, and push to ipset all enabled block lists from config."""
    from .config import config
    from .db import upsert_blocklist_source, update_blocklist_entries

    sources = config.get('blocklists', 'sources', default=[])
    updated = 0
    for source in sources:
        if not source.get('enabled', True):
            continue
        name = source['name']
        url = source['url']
        entry_type = source['type']
        upsert_blocklist_source(name, url, entry_type, enabled=1)
        entries = fetch_blocklist(url, entry_type)
        if entries:
            update_blocklist_entries(name, entries)
            _push_to_ipset(entries)
            updated += 1
            logger.info(f"Updated blocklist {name}: {len(entries)} entries")
        else:
            logger.warning(f"Blocklist {name} returned no entries")
    return updated


def refresh_blocklist_source(source_name):
    """Refresh a single blocklist source by name. Returns entry count or 0."""
    from .config import config
    from .db import update_blocklist_entries

    sources = config.get('blocklists', 'sources', default=[])
    for source in sources:
        if source['name'] == source_name:
            entries = fetch_blocklist(source['url'], source['type'])
            if entries:
                update_blocklist_entries(source['name'], entries)
                _push_to_ipset(entries)
                logger.info(f"Refreshed blocklist {source_name}: {len(entries)} entries")
            return len(entries)
    logger.warning(f"Blocklist source not found: {source_name}")
    return 0
