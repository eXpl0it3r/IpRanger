import subprocess
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')
_IPV6_ADDR_RE = re.compile(r'^\[(.+)\]:(\d+)$')
_IPV4_ADDR_RE = re.compile(r'^([\d.]+):(\d+)$')


def parse_addr(addr):
    """Parse IP:port or [IPv6]:port into (ip, port) tuple."""
    m = _IPV6_ADDR_RE.match(addr)
    if m:
        return m.group(1), m.group(2)
    m = _IPV4_ADDR_RE.match(addr)
    if m:
        return m.group(1), m.group(2)
    # fallback: split on last colon
    if ':' in addr:
        parts = addr.rsplit(':', 1)
        return parts[0], parts[1]
    return addr, ''


def extract_process_name(process_str):
    """Extract process name from ss process string like users:(("nginx",pid=1234,fd=5))"""
    if not process_str:
        return ''
    m = _PROCESS_RE.search(process_str)
    return m.group(1) if m else process_str


def parse_ss_output(output):
    """Parse ss -tnp output into list of connection dicts."""
    connections = []
    lines = output.strip().split('\n')
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        local = parts[3]
        peer = parts[4]
        process = parts[5] if len(parts) > 5 else ''

        local_ip, local_port = parse_addr(local)
        peer_ip, peer_port = parse_addr(peer)

        if peer_ip and peer_ip not in ('*', '0.0.0.0', '::', ''):
            connections.append({
                'state': state,
                'local_ip': local_ip,
                'local_port': local_port,
                'peer_ip': peer_ip,
                'peer_port': peer_port,
                'process': extract_process_name(process),
            })
    return connections


def get_connections():
    """Run ss -tnp and parse output. Returns list of connection dicts."""
    try:
        result = subprocess.run(
            ['ss', '-tnp'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logger.warning(f"ss returned non-zero exit code: {result.stderr}")
        return parse_ss_output(result.stdout)
    except FileNotFoundError:
        logger.error("ss command not found. Is iproute2 installed?")
        return []
    except subprocess.TimeoutExpired:
        logger.error("ss command timed out")
        return []
    except Exception as e:
        logger.error(f"Failed to run ss: {e}")
        return []


def record_connections():
    """Called by scheduler. Get connections and record to DB."""
    from .db import upsert_ip_connection
    from .config import config

    connections = get_connections()
    flag_threshold = config.get('monitoring', 'flag_threshold', default=500)
    for conn in connections:
        upsert_ip_connection(
            ip=conn['peer_ip'],
            local_port=conn['local_port'],
            remote_port=conn['peer_port'],
            state=conn['state'],
            process=conn['process'],
            flag_threshold=flag_threshold,
        )
    logger.debug(f"Recorded {len(connections)} connections")
    return len(connections)
