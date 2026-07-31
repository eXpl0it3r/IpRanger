"""Monitor TCP connections via ss and push snapshots to the database."""
import subprocess
import re
import logging

from .utils import unmap_ipv4
from .db import record_snapshot

logger = logging.getLogger(__name__)

_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')
_IPV6_ADDR_RE = re.compile(r'^\[(.+)\]:(\d+)$')
_IPV4_ADDR_RE = re.compile(r'^([\d.]+):(\d+)$')


def _parse_addr(addr: str) -> tuple:
    m = _IPV6_ADDR_RE.match(addr)
    if m:
        return unmap_ipv4(m.group(1)), m.group(2)
    m = _IPV4_ADDR_RE.match(addr)
    if m:
        return m.group(1), m.group(2)
    if ':' in addr:
        parts = addr.rsplit(':', 1)
        return unmap_ipv4(parts[0]), parts[1]
    return addr, ''


def _extract_process(s: str) -> str:
    if not s:
        return ''
    m = _PROCESS_RE.search(s)
    return m.group(1) if m else s


def parse_ss_output(output: str) -> list:
    connections = []
    for line in output.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        local_ip, local_port = _parse_addr(parts[3])
        peer_ip, peer_port = _parse_addr(parts[4])
        if not peer_ip or peer_ip in ('*', '0.0.0.0', '::', ''):
            continue
        connections.append({
            'state':      parts[0],
            'local_ip':   local_ip,
            'local_port': local_port,
            'peer_ip':    peer_ip,
            'peer_port':  peer_port,
            'process':    _extract_process(parts[5] if len(parts) > 5 else ''),
        })
    return connections


def get_connections() -> list:
    try:
        result = subprocess.run(
            ['ss', '-tnp'], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            logger.warning(f"ss returned {result.returncode}: {result.stderr.strip()}")
        return parse_ss_output(result.stdout)
    except FileNotFoundError:
        logger.error("ss not found - install iproute2")
        return []
    except subprocess.TimeoutExpired:
        logger.error("ss timed out")
        return []
    except Exception as exc:
        logger.error(f"ss failed: {exc}")
        return []


def record_connections() -> int:
    """Poll connections and push snapshot to DB. Called by the scheduler."""
    return record_snapshot(get_connections())
