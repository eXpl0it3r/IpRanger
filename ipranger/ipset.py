"""ipset / iptables management for IpRanger V2.

Two ipsets:
  ipranger_blacklist  - populated from threat-feed blocklists
  ipranger_manual     - populated from manually-added blocks
"""
import subprocess
import logging

from .config import config

logger = logging.getLogger(__name__)

SET_BLACKLIST = 'ipranger_blacklist'
SET_MANUAL = 'ipranger_manual'


def _run(cmd: list, check: bool = True):
    """Run a command; return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if check and r.returncode != 0:
            logger.error(f"Command failed {' '.join(cmd)}: {r.stderr.strip()}")
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        logger.warning(f"Command not found: {cmd[0]}")
        return 127, '', f"not found: {cmd[0]}"
    except Exception as exc:
        logger.error(f"Command error: {exc}")
        return 1, '', str(exc)


def _ensure_set(name: str):
    rc, _, _ = _run(['ipset', 'list', name], check=False)
    if rc != 0:
        _run(['ipset', 'create', name, 'hash:net', 'maxelem', '1000000'])
        logger.info(f"Created ipset {name}")


def _save():
    if not config.get('ipset', 'persist', default=True):
        return
    rc, out, _ = _run(['ipset', 'save'])
    if rc == 0:
        try:
            with open('/etc/ipset.conf', 'w') as f:
                f.write(out)
        except PermissionError:
            logger.warning("Cannot write /etc/ipset.conf (no root?)")


def ensure_ipsets():
    """Create both ipsets if they don't exist."""
    _ensure_set(SET_BLACKLIST)
    _ensure_set(SET_MANUAL)


# ── Blacklist set (threat feeds) ──────────────────────────────────────────────

def sync_blacklist_from_db():
    """Flush and rebuild ipranger_blacklist from all enabled blocklist entries."""
    from .db import get_all_blocklist_entries_for_ipset
    ensure_ipsets()
    _run(['ipset', 'flush', SET_BLACKLIST])
    entries = get_all_blocklist_entries_for_ipset()
    added = 0
    for entry, _ in entries:
        rc, _, _ = _run(['ipset', 'add', '-exist', SET_BLACKLIST, entry], check=False)
        if rc == 0:
            added += 1
    _save()
    logger.info(f"Blacklist ipset synced: {added} entries")
    return added


def bulk_add_to_blacklist(entries: list):
    """Add a list of (entry, type) tuples to the blacklist ipset."""
    ensure_ipsets()
    added = 0
    for item in entries:
        entry = item[0] if isinstance(item, (list, tuple)) else item
        if isinstance(entry, str) and entry.upper().startswith('AS'):
            continue
        rc, _, _ = _run(['ipset', 'add', '-exist', SET_BLACKLIST, entry], check=False)
        if rc == 0:
            added += 1
    if added:
        _save()
    return added


# ── Manual set (user-defined blocks) ─────────────────────────────────────────

def sync_manual_from_db():
    """Flush and rebuild ipranger_manual from manual_blocks table."""
    from .db import get_manual_blocks
    ensure_ipsets()
    _run(['ipset', 'flush', SET_MANUAL])
    blocks = get_manual_blocks()
    added = 0
    for block in blocks:
        entry = block['entry']
        rc, _, _ = _run(['ipset', 'add', '-exist', SET_MANUAL, entry], check=False)
        if rc == 0:
            added += 1
    _save()
    logger.info(f"Manual ipset synced: {added} entries")
    return added


def add_to_manual(entry: str) -> bool:
    ensure_ipsets()
    rc, _, _ = _run(['ipset', 'add', '-exist', SET_MANUAL, entry], check=False)
    if rc == 0:
        _save()
    return rc == 0


def remove_from_manual(entry: str) -> bool:
    rc, _, _ = _run(['ipset', 'del', '-exist', SET_MANUAL, entry], check=False)
    if rc == 0:
        _save()
    return rc == 0


# ── iptables rule management ──────────────────────────────────────────────────

def _has_rule(set_name: str, chain: str = 'INPUT') -> bool:
    rc, _, _ = _run(
        ['iptables', '-C', chain, '-m', 'set', '--match-set', set_name, 'src', '-j', 'DROP'],
        check=False)
    return rc == 0


def ensure_iptables_rules():
    """Ensure DROP rules exist for both ipsets."""
    results = {}
    for name in (SET_BLACKLIST, SET_MANUAL):
        if not _has_rule(name):
            rc, _, err = _run(
                ['iptables', '-I', 'INPUT', '-m', 'set', '--match-set', name, 'src', '-j', 'DROP'])
            results[name] = rc == 0
            if rc == 0:
                logger.info(f"Added iptables DROP rule for {name}")
            else:
                logger.error(f"Failed to add iptables rule for {name}: {err}")
        else:
            results[name] = True
    return results


def remove_iptables_rules():
    for name in (SET_BLACKLIST, SET_MANUAL):
        if _has_rule(name):
            _run(['iptables', '-D', 'INPUT', '-m', 'set', '--match-set', name, 'src', '-j', 'DROP'],
                 check=False)


def get_active_block_sets() -> list:
    """Names of IpRanger ipsets that currently have an active iptables DROP rule."""
    return [name for name in (SET_BLACKLIST, SET_MANUAL) if _has_rule(name)]


def test_entry_enforced(entry: str, active_sets=None) -> bool:
    """True if *entry* (IP or CIDR) matches an ipset with an active DROP rule."""
    if active_sets is None:
        active_sets = get_active_block_sets()
    for name in active_sets:
        rc, _, _ = _run(['ipset', 'test', name, entry], check=False)
        if rc == 0:
            return True
    return False


def get_iptables_rules() -> list:
    """Return all active iptables rules across all chains (iptables -S output)."""
    rc, out, _ = _run(['iptables', '-S'], check=False)
    if rc != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


# ── Status ────────────────────────────────────────────────────────────────────

def get_ipset_status() -> dict:
    status = {'available': False, 'sets': {}, 'iptables_rules': [],
              'ipranger_rules_active': False}
    rc, out, _ = _run(['ipset', 'list', '-t'], check=False)
    if rc != 0:
        return status
    status['available'] = True
    current_name = None
    for line in out.splitlines():
        if line.startswith('Name:'):
            current_name = line.split(':', 1)[1].strip()
            status['sets'][current_name] = {'name': current_name, 'entry_count': 0}
        elif line.startswith('Number of entries:') and current_name:
            try:
                status['sets'][current_name]['entry_count'] = int(line.split(':')[1].strip())
            except (ValueError, IndexError):
                pass
    status['iptables_rules'] = get_iptables_rules()
    status['ipranger_rules_active'] = all(
        _has_rule(name) for name in (SET_BLACKLIST, SET_MANUAL))
    return status
