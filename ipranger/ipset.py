import subprocess
import logging

from .config import config

logger = logging.getLogger(__name__)


def run_cmd(cmd, check=True):
    """Run a shell command. Returns (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if check and result.returncode != 0:
            logger.error(f"Command failed: {' '.join(cmd)}: {result.stderr.strip()}")
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        logger.warning(f"Command not found: {cmd[0]}")
        return 127, '', f"Command not found: {cmd[0]}"
    except Exception as e:
        logger.error(f"Command error {' '.join(cmd)}: {e}")
        return 1, '', str(e)


def get_set_name():
    return config.get('ipset', 'set_name', default='ipranger_blocked')


def create_ipset():
    """Create the ipset if it doesn't exist."""
    name = get_set_name()
    rc, _, _ = run_cmd(['ipset', 'list', name], check=False)
    if rc != 0:
        rc2, _, err = run_cmd(['ipset', 'create', name, 'hash:net', 'maxelem', '1000000'])
        if rc2 == 0:
            logger.info(f"Created ipset {name}")
        else:
            logger.error(f"Failed to create ipset {name}: {err}")
    return rc == 0 or True


def add_to_ipset(entry):
    """Add an IP or CIDR to the ipset."""
    rc, _, err = run_cmd(['ipset', 'add', '-exist', get_set_name(), entry])
    if rc == 0 and config.get('ipset', 'persist', default=True):
        save_ipset()
    return rc == 0


def remove_from_ipset(entry):
    """Remove an IP or CIDR from the ipset."""
    rc, _, _ = run_cmd(['ipset', 'del', '-exist', get_set_name(), entry], check=False)
    if rc == 0 and config.get('ipset', 'persist', default=True):
        save_ipset()
    return rc == 0


def flush_ipset():
    """Remove all entries from the ipset."""
    rc, _, _ = run_cmd(['ipset', 'flush', get_set_name()])
    if rc == 0 and config.get('ipset', 'persist', default=True):
        save_ipset()
    return rc == 0


def save_ipset():
    """Save ipset to /etc/ipset.conf."""
    rc, stdout, err = run_cmd(['ipset', 'save'])
    if rc == 0:
        try:
            with open('/etc/ipset.conf', 'w') as f:
                f.write(stdout)
        except PermissionError:
            logger.warning("Cannot write /etc/ipset.conf: permission denied")
    return rc == 0


def restore_ipset():
    """Restore ipset from /etc/ipset.conf."""
    rc, _, err = run_cmd(['ipset', 'restore', '-exist', '-f', '/etc/ipset.conf'])
    return rc == 0


def ensure_iptables_rule():
    """Add iptables DROP rule for the ipset if not present."""
    name = get_set_name()
    rc, _, _ = run_cmd(
        ['iptables', '-C', 'INPUT', '-m', 'set', '--match-set', name, 'src', '-j', 'DROP'],
        check=False
    )
    if rc != 0:
        rc2, _, err = run_cmd(
            ['iptables', '-I', 'INPUT', '-m', 'set', '--match-set', name, 'src', '-j', 'DROP']
        )
        if rc2 == 0:
            logger.info("Added iptables DROP rule for ipset")
            return True
        logger.error(f"Failed to add iptables rule: {err}")
        return False
    return True  # rule already exists


def remove_iptables_rule():
    """Remove iptables DROP rule for the ipset."""
    name = get_set_name()
    rc, _, _ = run_cmd(
        ['iptables', '-D', 'INPUT', '-m', 'set', '--match-set', name, 'src', '-j', 'DROP'],
        check=False
    )
    return rc == 0


def sync_ipset_from_db():
    """Rebuild ipset from blocked_entries in DB."""
    from .db import get_blocked_entries
    create_ipset()
    flush_ipset()
    entries, total = get_blocked_entries(page=1, per_page=100000)
    added = 0
    for entry in entries:
        if add_to_ipset(entry['entry']):
            added += 1
    logger.info(f"Synced ipset: {added}/{total} entries")
    return added


def get_ipset_status():
    """Return dict with ipset info."""
    name = get_set_name()
    rc, stdout, _ = run_cmd(['ipset', 'list', '-t', name], check=False)
    if rc != 0:
        return {'available': False, 'entry_count': 0, 'set_name': name, 'error': 'ipset not available or set does not exist'}
    lines = stdout.strip().split('\n')
    members_line = next((l for l in lines if l.startswith('Number of entries')), '')
    count = 0
    if members_line:
        try:
            count = int(members_line.split(':')[1].strip())
        except (IndexError, ValueError):
            pass
    return {'available': True, 'entry_count': count, 'set_name': name}
