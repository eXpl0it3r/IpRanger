"""Database layer for IpRanger V2."""
import sqlite3
import logging
from datetime import datetime
from ipaddress import ip_address, ip_network, AddressValueError

from flask import g

from .config import config

logger = logging.getLogger(__name__)


def _utc() -> str:
    return datetime.utcnow().isoformat()


# ── Connection management ─────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(config.get_db_path())
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def _get_direct_db():
    conn = sqlite3.connect(config.get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _db():
    """Return (connection, owned). Background jobs get an owned direct connection."""
    try:
        return get_db(), False
    except RuntimeError:
        return _get_direct_db(), True


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(config.get_db_path())
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        -- Every unique peer IP ever seen (historic backlog)
        CREATE TABLE IF NOT EXISTS seen_ips (
            ip         TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL,
            hit_count  INTEGER NOT NULL DEFAULT 0
        );

        -- Live snapshot - replaced every monitor poll
        CREATE TABLE IF NOT EXISTS live_connections (
            conn_key    TEXT PRIMARY KEY,
            ip          TEXT NOT NULL,
            local_ip    TEXT,
            local_port  TEXT,
            remote_port TEXT,
            state       TEXT,
            process     TEXT,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_live_ip ON live_connections(ip);

        -- Cached CIDR/ASN ranges resolved via RDAP
        CREATE TABLE IF NOT EXISTS asn_ranges (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr         TEXT UNIQUE NOT NULL,
            asn          TEXT,
            network_name TEXT,
            country_code TEXT,
            info_url     TEXT,
            looked_up_at TEXT NOT NULL
        );

        -- Per-IP mapping to its resolved ASN range
        CREATE TABLE IF NOT EXISTS ip_asn_map (
            ip           TEXT PRIMARY KEY,
            asn_range_id INTEGER,
            looked_up_at TEXT NOT NULL,
            FOREIGN KEY(asn_range_id) REFERENCES asn_ranges(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ip_asn_range ON ip_asn_map(asn_range_id);

        -- Manual blocks -> pushed to ipranger_manual ipset
        CREATE TABLE IF NOT EXISTS manual_blocks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            entry      TEXT UNIQUE NOT NULL,
            entry_type TEXT NOT NULL,
            reason     TEXT,
            created_at TEXT NOT NULL
        );

        -- Whitelist (IPs/CIDRs that must never be auto-blocked)
        CREATE TABLE IF NOT EXISTS whitelist_entries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            entry      TEXT UNIQUE NOT NULL,
            entry_type TEXT NOT NULL,
            label      TEXT,
            created_at TEXT NOT NULL
        );

        -- External blocklist feed sources
        CREATE TABLE IF NOT EXISTS blocklist_sources (
            name        TEXT PRIMARY KEY,
            url         TEXT NOT NULL,
            entry_type  TEXT NOT NULL,
            enabled     INTEGER NOT NULL DEFAULT 1,
            last_updated TEXT,
            entry_count INTEGER NOT NULL DEFAULT 0
        );

        -- Blocklist feed entries -> pushed to ipranger_blacklist ipset
        CREATE TABLE IF NOT EXISTS blocklist_entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            entry       TEXT NOT NULL,
            entry_type  TEXT NOT NULL,
            UNIQUE(source_name, entry),
            FOREIGN KEY(source_name) REFERENCES blocklist_sources(name) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_bl_entry ON blocklist_entries(entry);
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized")


# ── Live connection snapshot ──────────────────────────────────────────────────

def record_snapshot(connections: list) -> int:
    """Replace live_connections with current snapshot; update seen_ips for new peers."""
    conn, owned = _db()
    try:
        now = _utc()
        cur = conn.cursor()
        current_keys: set = set()
        new_count = 0

        for item in connections:
            key = (
                f"{item['local_ip']}:{item['local_port']}"
                f"->{item['peer_ip']}:{item['peer_port']}"
            )
            current_keys.add(key)

            cur.execute("SELECT 1 FROM live_connections WHERE conn_key=?", (key,))
            is_new = cur.fetchone() is None

            if is_new:
                new_count += 1
                cur.execute("""
                    INSERT INTO seen_ips (ip, first_seen, last_seen, hit_count)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(ip) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        hit_count = hit_count + 1
                """, (item['peer_ip'], now, now))
                cur.execute("""
                    INSERT INTO live_connections
                        (conn_key, ip, local_ip, local_port, remote_port,
                         state, process, first_seen, last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (key, item['peer_ip'], item['local_ip'], item['local_port'],
                      item['peer_port'], item['state'], item['process'], now, now))
            else:
                cur.execute(
                    "UPDATE live_connections SET state=?,process=?,last_seen=? WHERE conn_key=?",
                    (item['state'], item['process'], now, key))
                cur.execute(
                    "UPDATE seen_ips SET last_seen=? WHERE ip=?",
                    (now, item['peer_ip']))

        if current_keys:
            placeholders = ",".join("?" * len(current_keys))
            cur.execute(
                f"DELETE FROM live_connections WHERE conn_key NOT IN ({placeholders})",
                tuple(current_keys))
        else:
            cur.execute("DELETE FROM live_connections")

        conn.commit()
        logger.debug(f"Snapshot: {len(connections)} open, {new_count} new")
        return new_count
    except Exception as exc:
        conn.rollback()
        logger.error(f"record_snapshot failed: {exc}")
        return 0
    finally:
        if owned:
            conn.close()


def get_live_connection_count() -> int:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM live_connections")
        return cur.fetchone()[0]
    finally:
        if owned:
            conn.close()


def get_historic_ip_count() -> int:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM seen_ips")
        return cur.fetchone()[0]
    finally:
        if owned:
            conn.close()


# ── Live view queries ─────────────────────────────────────────────────────────

def get_live_ips_with_asn() -> list:
    """Currently connected unique IPs enriched with ASN, sorted by IP."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                l.ip,
                COUNT(l.conn_key)       AS active_connections,
                MAX(l.last_seen)        AS last_seen,
                r.asn,
                r.network_name,
                r.country_code,
                r.info_url,
                r.cidr,
                CASE WHEN m.ip IS NOT NULL THEN 1 ELSE 0 END AS asn_resolved
            FROM live_connections l
            LEFT JOIN ip_asn_map  m ON m.ip = l.ip
            LEFT JOIN asn_ranges  r ON r.id = m.asn_range_id
            GROUP BY l.ip
            ORDER BY l.ip
        """)
        return [dict(row) for row in cur.fetchall()]
    finally:
        if owned:
            conn.close()


# ── ASN / CIDR range cache ────────────────────────────────────────────────────

def get_ips_missing_asn(limit: int = 50) -> list:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT s.ip FROM seen_ips s
            LEFT JOIN ip_asn_map m ON m.ip = s.ip
            WHERE m.ip IS NULL
            ORDER BY s.last_seen DESC
            LIMIT ?
        """, (limit,))
        return [row[0] for row in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_all_asn_ranges() -> list:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM asn_ranges ORDER BY network_name, cidr")
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def find_cached_range_for_ip(ip: str):
    """Check if ip falls inside any already-cached CIDR; return that range dict or None."""
    try:
        ip_obj = ip_address(ip)
    except ValueError:
        return None
    for row in get_all_asn_ranges():
        try:
            if ip_obj in ip_network(row['cidr'], strict=False):
                return row
        except ValueError:
            continue
    return None


def upsert_asn_range(cidr: str, asn: str, network_name: str,
                     country_code: str, info_url: str) -> int:
    """Insert or refresh an ASN range; return its id."""
    conn, owned = _db()
    try:
        now = _utc()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO asn_ranges (cidr, asn, network_name, country_code, info_url, looked_up_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(cidr) DO UPDATE SET
                asn          = excluded.asn,
                network_name = excluded.network_name,
                country_code = excluded.country_code,
                info_url     = excluded.info_url,
                looked_up_at = excluded.looked_up_at
        """, (cidr, asn, network_name, country_code, info_url, now))
        cur.execute("SELECT id FROM asn_ranges WHERE cidr=?", (cidr,))
        range_id = cur.fetchone()[0]
        conn.commit()
        return range_id
    finally:
        if owned:
            conn.close()


def record_ip_asn(ip: str, asn_range_id):
    """Link an IP to its resolved ASN range (None = looked up but no range found)."""
    conn, owned = _db()
    try:
        conn.execute("""
            INSERT INTO ip_asn_map (ip, asn_range_id, looked_up_at)
            VALUES (?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                asn_range_id = excluded.asn_range_id,
                looked_up_at = excluded.looked_up_at
        """, (ip, asn_range_id, _utc()))
        conn.commit()
    finally:
        if owned:
            conn.close()


# ── Network group view ────────────────────────────────────────────────────────

def get_network_groups() -> list:
    """ASN groups ordered by live IP count descending."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                COALESCE(r.network_name, 'Unknown') AS network_name,
                COALESCE(r.asn, '')                 AS asn,
                COALESCE(r.country_code, '')        AS country_code,
                MIN(r.info_url)                     AS info_url,
                COUNT(DISTINCT r.cidr)              AS range_count,
                COUNT(DISTINCT m.ip)                AS historic_ip_count,
                COUNT(DISTINCT l.ip)                AS live_ip_count
            FROM ip_asn_map m
            JOIN  asn_ranges r      ON r.id = m.asn_range_id
            LEFT JOIN seen_ips s    ON s.ip  = m.ip
            LEFT JOIN live_connections l ON l.ip = m.ip
            GROUP BY COALESCE(r.network_name,'Unknown'),
                     COALESCE(r.asn,''),
                     COALESCE(r.country_code,'')
            ORDER BY live_ip_count DESC, historic_ip_count DESC, network_name
        """)
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_live_ips_for_group(network_name: str, asn: str) -> list:
    """Currently connected IPs for a specific ASN group, sorted by IP."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT l.ip, r.cidr, MAX(l.last_seen) AS last_seen
            FROM live_connections l
            JOIN  ip_asn_map m  ON m.ip = l.ip
            JOIN  asn_ranges r  ON r.id = m.asn_range_id
            WHERE COALESCE(r.network_name,'Unknown') = ?
              AND COALESCE(r.asn,'') = ?
            GROUP BY l.ip, r.cidr
            ORDER BY l.ip
        """, (network_name, asn))
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_cidrs_for_group(network_name: str, asn: str) -> list:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT r.cidr FROM asn_ranges r
            WHERE COALESCE(r.network_name,'Unknown')=?
              AND COALESCE(r.asn,'')=?
            ORDER BY r.cidr
        """, (network_name, asn))
        return [row[0] for row in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_ips_for_group(network_name: str, asn: str) -> list:
    """All IPs (historic) mapped to any range of an ASN group."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT m.ip FROM ip_asn_map m
            JOIN asn_ranges r ON r.id = m.asn_range_id
            WHERE COALESCE(r.network_name,'Unknown')=?
              AND COALESCE(r.asn,'')=?
            ORDER BY m.ip
        """, (network_name, asn))
        return [row[0] for row in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def rename_network_group(network_name: str, asn: str, new_name: str) -> int:
    """Rename all ranges of an ASN group; return number of updated ranges."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE asn_ranges SET network_name=?
            WHERE COALESCE(network_name,'Unknown')=?
              AND COALESCE(asn,'')=?
        """, (new_name, network_name, asn))
        conn.commit()
        return cur.rowcount
    finally:
        if owned:
            conn.close()


def clear_asn_group(network_name: str, asn: str):
    """Drop an ASN group's cached ranges and IP mappings so they can be re-resolved."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM ip_asn_map WHERE asn_range_id IN (
                SELECT id FROM asn_ranges
                WHERE COALESCE(network_name,'Unknown')=?
                  AND COALESCE(asn,'')=?
            )
        """, (network_name, asn))
        cur.execute("""
            DELETE FROM asn_ranges
            WHERE COALESCE(network_name,'Unknown')=?
              AND COALESCE(asn,'')=?
        """, (network_name, asn))
        conn.commit()
    finally:
        if owned:
            conn.close()


# ── Manual blocks ─────────────────────────────────────────────────────────────

def get_manual_blocks() -> list:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM manual_blocks ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def add_manual_block(entry: str, reason: str = ""):
    entry_type = "cidr" if "/" in entry else "ip"
    conn, owned = _db()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO manual_blocks (entry, entry_type, reason, created_at)
            VALUES (?,?,?,?)
        """, (entry, entry_type, reason, _utc()))
        conn.commit()
    finally:
        if owned:
            conn.close()


def remove_manual_block(entry: str):
    conn, owned = _db()
    try:
        conn.execute("DELETE FROM manual_blocks WHERE entry=?", (entry,))
        conn.commit()
    finally:
        if owned:
            conn.close()


# ── Whitelist ─────────────────────────────────────────────────────────────────

def get_whitelist_entries() -> list:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM whitelist_entries ORDER BY entry")
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def add_whitelist_entry(entry: str, label: str = ""):
    entry_type = "cidr" if "/" in entry else "ip"
    conn, owned = _db()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO whitelist_entries (entry, entry_type, label, created_at)
            VALUES (?,?,?,?)
        """, (entry, entry_type, label, _utc()))
        conn.commit()
    finally:
        if owned:
            conn.close()


def remove_whitelist_entry(entry: str):
    conn, owned = _db()
    try:
        conn.execute("DELETE FROM whitelist_entries WHERE entry=?", (entry,))
        conn.commit()
    finally:
        if owned:
            conn.close()


def is_whitelisted(entry: str) -> bool:
    """True if *entry* (IP or CIDR) is covered by the whitelist."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM whitelist_entries WHERE entry=?", (entry,))
        if cur.fetchone():
            return True
        try:
            ip_obj = ip_address(entry)
        except (AddressValueError, ValueError):
            return False
        cur.execute("SELECT entry FROM whitelist_entries WHERE entry_type='cidr'")
        for row in cur.fetchall():
            try:
                if ip_obj in ip_network(row[0], strict=False):
                    return True
            except ValueError:
                continue
        return False
    finally:
        if owned:
            conn.close()


def get_whitelist_checker():
    """Return an ip -> bool callable backed by a single whitelist snapshot.

    Use this to annotate lists of IPs without one DB round-trip per IP.
    """
    entries = get_whitelist_entries()
    exact = {e['entry'] for e in entries}
    networks = []
    for e in entries:
        if e['entry_type'] == 'cidr':
            try:
                networks.append(ip_network(e['entry'], strict=False))
            except ValueError:
                continue

    def check(ip: str) -> bool:
        if ip in exact:
            return True
        try:
            ip_obj = ip_address(ip)
        except (AddressValueError, ValueError):
            return False
        return any(ip_obj in net for net in networks)

    return check


# ── Blocklist sources / entries ───────────────────────────────────────────────

def get_blocklist_sources() -> list:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM blocklist_sources ORDER BY name")
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def seed_blocklist_source(name: str, url: str, entry_type: str, enabled: int = 1):
    conn, owned = _db()
    try:
        conn.execute("""
            INSERT INTO blocklist_sources (name, url, entry_type, enabled)
            VALUES (?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                url=excluded.url, entry_type=excluded.entry_type
        """, (name, url, entry_type, enabled))
        conn.commit()
    finally:
        if owned:
            conn.close()


def replace_blocklist_entries(source_name: str, entries: list):
    """Replace all entries for a source atomically. entries = list of (entry, type) tuples."""
    conn, owned = _db()
    try:
        conn.execute("DELETE FROM blocklist_entries WHERE source_name=?", (source_name,))
        conn.executemany(
            "INSERT OR IGNORE INTO blocklist_entries (source_name, entry, entry_type)"
            " VALUES (?,?,?)",
            [(source_name, e, t) for e, t in entries],
        )
        conn.execute(
            "UPDATE blocklist_sources SET last_updated=?, entry_count=? WHERE name=?",
            (_utc(), len(entries), source_name))
        conn.commit()
        logger.info(f"Blocklist {source_name}: {len(entries)} entries stored")
    except Exception as exc:
        conn.rollback()
        logger.error(f"replace_blocklist_entries failed for {source_name}: {exc}")
    finally:
        if owned:
            conn.close()


def get_all_blocklist_entries_for_ipset() -> list:
    """All (entry, entry_type) pairs from enabled sources suitable for ipset."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT e.entry, e.entry_type
            FROM blocklist_entries e
            JOIN  blocklist_sources s ON s.name = e.source_name
            WHERE s.enabled=1 AND e.entry_type IN ('ip','cidr')
        """)
        return [(row[0], row[1]) for row in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_blocklist_entries_page(source_name=None, page: int = 1, per_page: int = 50):
    conn, owned = _db()
    try:
        cur = conn.cursor()
        where = "WHERE e.source_name=?" if source_name else ""
        params = [source_name] if source_name else []
        cur.execute(f"SELECT COUNT(*) FROM blocklist_entries e {where}", params)
        total = cur.fetchone()[0]
        offset = (page - 1) * per_page
        cur.execute(
            f"SELECT e.* FROM blocklist_entries e {where}"
            f" ORDER BY e.entry LIMIT ? OFFSET ?",
            params + [per_page, offset])
        return [dict(r) for r in cur.fetchall()], total
    finally:
        if owned:
            conn.close()


# ── Overview stats ────────────────────────────────────────────────────────────

def get_overview_stats() -> dict:
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM seen_ips"); historic_ips = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT ip) FROM live_connections"); live_ips = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM live_connections"); live_conns = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM manual_blocks"); manual_blocks = cur.fetchone()[0]
        cur.execute("SELECT COALESCE(SUM(entry_count),0) FROM blocklist_sources WHERE enabled=1")
        bl_entries = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM whitelist_entries"); whitelist = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM asn_ranges"); asn_ranges = cur.fetchone()[0]
        return {
            'historic_ips': historic_ips,
            'live_ips': live_ips,
            'live_conns': live_conns,
            'manual_blocks': manual_blocks,
            'bl_entries': bl_entries,
            'whitelist': whitelist,
            'asn_ranges': asn_ranges,
        }
    finally:
        if owned:
            conn.close()
