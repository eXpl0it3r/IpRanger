import sqlite3
import logging
from datetime import datetime
from ipaddress import ip_address, ip_network, AddressValueError
from flask import g

from .config import config

logger = logging.getLogger(__name__)


def get_db():
    """Get the database connection for the current application context."""
    if 'db' not in g:
        db_path = config.get_db_path()
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(e=None):
    """Close the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def _get_direct_db():
    """Get a direct (non-Flask-context) DB connection for use in background jobs."""
    db_path = config.get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _db():
    """Return DB connection from Flask context if available, else a direct connection."""
    try:
        return get_db(), False
    except RuntimeError:
        return _get_direct_db(), True


def init_db():
    """Create all tables."""
    db_path = config.get_db_path()
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS ip_stats (
            ip TEXT PRIMARY KEY,
            connection_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            is_blocked INTEGER DEFAULT 0,
            is_friendly INTEGER DEFAULT 0,
            is_flagged INTEGER DEFAULT 0,
            rdap_org TEXT,
            rdap_network TEXT,
            rdap_asn TEXT,
            rdap_country TEXT,
            rdap_looked_up INTEGER DEFAULT 0,
            rdap_looked_up_at TEXT
        );

        CREATE TABLE IF NOT EXISTS blocklist_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            last_updated TEXT,
            entry_count INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS blocklist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            source_name TEXT NOT NULL,
            UNIQUE(entry, source_name)
        );

        CREATE TABLE IF NOT EXISTS friendly_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry TEXT UNIQUE NOT NULL,
            entry_type TEXT NOT NULL,
            label TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS blocked_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry TEXT UNIQUE NOT NULL,
            entry_type TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized")


def upsert_ip_connection(ip, local_port, remote_port, state, process, flag_threshold=500, increment=True):
    """Insert or update ip_stats for a seen connection.

    When *increment* is True (default) the connection_count is incremented —
    use this only for connections that are new since the last poll.
    When False, only last_seen and is_friendly are updated, leaving the count
    unchanged so long-lived connections aren't double-counted.
    """
    conn, owned = _db()
    try:
        now = datetime.utcnow().isoformat()
        cur = conn.cursor()

        # Check if IP is friendly
        cur.execute("SELECT 1 FROM friendly_entries WHERE entry = ?", (ip,))
        is_friendly = 1 if cur.fetchone() else 0

        # Check if IP is in a friendly CIDR
        if not is_friendly:
            try:
                ip_obj = ip_address(ip)
                cur.execute("SELECT entry FROM friendly_entries WHERE entry_type = 'cidr'")
                for row in cur.fetchall():
                    try:
                        if ip_obj in ip_network(row[0], strict=False):
                            is_friendly = 1
                            break
                    except ValueError:
                        pass
            except (AddressValueError, ValueError):
                pass

        if increment:
            cur.execute("""
                INSERT INTO ip_stats (ip, connection_count, first_seen, last_seen, is_friendly)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    connection_count = connection_count + 1,
                    last_seen = excluded.last_seen,
                    is_friendly = CASE WHEN excluded.is_friendly = 1 THEN 1 ELSE is_friendly END
            """, (ip, now, now, is_friendly))
        else:
            # Ongoing connection: just refresh last_seen and is_friendly
            cur.execute("""
                INSERT INTO ip_stats (ip, connection_count, first_seen, last_seen, is_friendly)
                VALUES (?, 0, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    is_friendly = CASE WHEN excluded.is_friendly = 1 THEN 1 ELSE is_friendly END
            """, (ip, now, now, is_friendly))

        # Check flag threshold (only relevant when incrementing)
        if increment:
            cur.execute("SELECT connection_count FROM ip_stats WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if row and row[0] >= flag_threshold and not is_friendly:
                cur.execute("UPDATE ip_stats SET is_flagged = 1 WHERE ip = ?", (ip,))

        conn.commit()
    except Exception as e:
        logger.error(f"upsert_ip_connection failed for {ip}: {e}")
        conn.rollback()
    finally:
        if owned:
            conn.close()


def get_ip_stats(page=1, per_page=50, sort='connection_count', search=None):
    """Return paginated IP statistics."""
    allowed_sorts = {
        'connection_count', 'ip', 'first_seen', 'last_seen',
        'rdap_org', 'rdap_country', 'rdap_asn',
    }
    if sort not in allowed_sorts:
        sort = 'connection_count'

    conn, owned = _db()
    try:
        cur = conn.cursor()
        params = []
        where = ""
        if search:
            where = "WHERE ip LIKE ? OR rdap_org LIKE ? OR rdap_country LIKE ? OR rdap_asn LIKE ?"
            like = f"%{search}%"
            params = [like, like, like, like]

        count_sql = f"SELECT COUNT(*) FROM ip_stats {where}"
        cur.execute(count_sql, params)
        total = cur.fetchone()[0]

        offset = (page - 1) * per_page
        sql = f"""
            SELECT * FROM ip_stats {where}
            ORDER BY {sort} DESC
            LIMIT ? OFFSET ?
        """
        cur.execute(sql, params + [per_page, offset])
        rows = [dict(r) for r in cur.fetchall()]
        return rows, total
    finally:
        if owned:
            conn.close()


def get_ip_detail(ip):
    """Return single IP detail dict or None."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ip_stats WHERE ip = ?", (ip,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        if owned:
            conn.close()


def get_overview_stats():
    """Return dict with aggregate stats."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ip_stats")
        total_ips = cur.fetchone()[0]

        cur.execute("SELECT COALESCE(SUM(connection_count), 0) FROM ip_stats")
        total_connections = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ip_stats WHERE is_blocked = 1")
        blocked_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ip_stats WHERE is_flagged = 1 AND is_blocked = 0")
        flagged_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM blocklist_entries")
        blocklist_entries_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM friendly_entries")
        friendly_count = cur.fetchone()[0]

        return {
            'total_ips': total_ips,
            'total_connections': total_connections,
            'blocked_count': blocked_count,
            'flagged_count': flagged_count,
            'blocklist_entries_count': blocklist_entries_count,
            'friendly_count': friendly_count,
        }
    finally:
        if owned:
            conn.close()


def update_rdap(ip, org, network, asn, country):
    """Update RDAP fields for an IP."""
    conn, owned = _db()
    try:
        now = datetime.utcnow().isoformat()
        conn.execute("""
            UPDATE ip_stats
            SET rdap_org=?, rdap_network=?, rdap_asn=?, rdap_country=?,
                rdap_looked_up=1, rdap_looked_up_at=?
            WHERE ip=?
        """, (org, network, asn, country, now, ip))
        conn.commit()
    finally:
        if owned:
            conn.close()


def get_ips_needing_rdap(limit=10):
    """Return list of IPs that have not had RDAP lookup yet."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT ip FROM ip_stats
            WHERE rdap_looked_up = 0
            ORDER BY connection_count DESC
            LIMIT ?
        """, (limit,))
        return [row[0] for row in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_blocklist_sources():
    """Return list of all blocklist sources."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM blocklist_sources ORDER BY name")
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def upsert_blocklist_source(name, url, entry_type, enabled=1):
    """Add or update a blocklist source record.

    When *enabled* is None the existing enabled value in the DB is preserved
    (used during restart seeding so UI toggles are not overwritten).
    """
    conn, owned = _db()
    try:
        if enabled is None:
            # Update url and type only; leave enabled untouched
            conn.execute("""
                INSERT INTO blocklist_sources (name, url, entry_type, enabled)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    entry_type=excluded.entry_type
            """, (name, url, entry_type))
        else:
            conn.execute("""
                INSERT INTO blocklist_sources (name, url, entry_type, enabled)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    entry_type=excluded.entry_type,
                    enabled=excluded.enabled
            """, (name, url, entry_type, int(enabled)))
        conn.commit()
    finally:
        if owned:
            conn.close()


def update_blocklist_entries(source_name, entries):
    """Replace all entries for a source with the new list."""
    conn, owned = _db()
    try:
        now = datetime.utcnow().isoformat()
        conn.execute("DELETE FROM blocklist_entries WHERE source_name = ?", (source_name,))
        conn.executemany(
            "INSERT OR IGNORE INTO blocklist_entries (entry, entry_type, source_name) VALUES (?, ?, ?)",
            [(e, t, source_name) for e, t in entries]
        )
        conn.execute("""
            UPDATE blocklist_sources
            SET last_updated=?, entry_count=?
            WHERE name=?
        """, (now, len(entries), source_name))
        conn.commit()
    except Exception as e:
        logger.error(f"update_blocklist_entries failed for {source_name}: {e}")
        conn.rollback()
    finally:
        if owned:
            conn.close()


def get_blocklist_entries(source_name=None, page=1, per_page=50):
    """Return paginated blocklist entries."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        params = []
        where = ""
        if source_name:
            where = "WHERE source_name = ?"
            params = [source_name]

        cur.execute(f"SELECT COUNT(*) FROM blocklist_entries {where}", params)
        total = cur.fetchone()[0]

        offset = (page - 1) * per_page
        cur.execute(
            f"SELECT * FROM blocklist_entries {where} ORDER BY entry LIMIT ? OFFSET ?",
            params + [per_page, offset]
        )
        rows = [dict(r) for r in cur.fetchall()]
        return rows, total
    finally:
        if owned:
            conn.close()


def is_ip_in_blocklist(ip):
    """Check if an IP or any of its CIDR ranges is in the blocklist."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        # Direct IP match
        cur.execute("SELECT 1 FROM blocklist_entries WHERE entry = ? AND entry_type = 'ip'", (ip,))
        if cur.fetchone():
            return True

        # CIDR match
        try:
            ip_obj = ip_address(ip)
            cur.execute("SELECT entry FROM blocklist_entries WHERE entry_type = 'cidr'")
            for row in cur.fetchall():
                try:
                    if ip_obj in ip_network(row[0], strict=False):
                        return True
                except ValueError:
                    pass
        except (AddressValueError, ValueError):
            pass
        return False
    finally:
        if owned:
            conn.close()


def block_ip(ip, reason=''):
    """Add IP to blocked_entries and mark ip_stats."""
    conn, owned = _db()
    try:
        entry_type = 'cidr' if '/' in ip else 'ip'
        conn.execute("""
            INSERT OR IGNORE INTO blocked_entries (entry, entry_type, reason)
            VALUES (?, ?, ?)
        """, (ip, entry_type, reason))
        conn.execute("UPDATE ip_stats SET is_blocked = 1 WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        if owned:
            conn.close()


def unblock_ip(ip):
    """Remove IP from blocked_entries and clear ip_stats flag."""
    conn, owned = _db()
    try:
        conn.execute("DELETE FROM blocked_entries WHERE entry = ?", (ip,))
        conn.execute("UPDATE ip_stats SET is_blocked = 0 WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        if owned:
            conn.close()


def add_friendly(entry, label='', entry_type=None):
    """Add an IP or CIDR to friendly_entries."""
    conn, owned = _db()
    try:
        if entry_type is None:
            entry_type = 'cidr' if '/' in entry else 'ip'
        conn.execute("""
            INSERT OR IGNORE INTO friendly_entries (entry, entry_type, label)
            VALUES (?, ?, ?)
        """, (entry, entry_type, label))
        # Mark in ip_stats if it's a plain IP
        if entry_type == 'ip':
            conn.execute("UPDATE ip_stats SET is_friendly = 1 WHERE ip = ?", (entry,))
        conn.commit()
    finally:
        if owned:
            conn.close()


def remove_friendly(entry):
    """Remove from friendly_entries."""
    conn, owned = _db()
    try:
        conn.execute("DELETE FROM friendly_entries WHERE entry = ?", (entry,))
        conn.execute("UPDATE ip_stats SET is_friendly = 0 WHERE ip = ?", (entry,))
        conn.commit()
    finally:
        if owned:
            conn.close()


def get_friendly_entries():
    """Return list of all friendly entries."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM friendly_entries ORDER BY entry")
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_blocked_entries(page=1, per_page=50):
    """Return paginated blocked entries."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM blocked_entries")
        total = cur.fetchone()[0]

        offset = (page - 1) * per_page
        cur.execute(
            "SELECT * FROM blocked_entries ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        )
        rows = [dict(r) for r in cur.fetchall()]
        return rows, total
    finally:
        if owned:
            conn.close()


def mark_flagged(ip):
    """Set is_flagged=1 for an IP."""
    conn, owned = _db()
    try:
        conn.execute("UPDATE ip_stats SET is_flagged = 1 WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        if owned:
            conn.close()


def get_top_ips(limit=10):
    """Return top IPs by connection count."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM ip_stats
            ORDER BY connection_count DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def get_network_stats(page=1, per_page=50, search=None):
    """Return paginated discovered networks grouped by rdap_network.

    Each row contains aggregate data for all IPs belonging to that network.
    IPs whose RDAP has not been resolved yet are excluded.
    """
    conn, owned = _db()
    try:
        cur = conn.cursor()

        where_parts = ["rdap_looked_up = 1", "rdap_network IS NOT NULL", "rdap_network != ''"]
        params: list = []
        if search:
            like = f"%{search}%"
            where_parts.append(
                "(rdap_network LIKE ? OR rdap_org LIKE ? OR rdap_asn LIKE ? OR rdap_country LIKE ?)"
            )
            params.extend([like, like, like, like])

        where = "WHERE " + " AND ".join(where_parts)

        cur.execute(
            f"SELECT COUNT(DISTINCT rdap_network) FROM ip_stats {where}", params
        )
        total = cur.fetchone()[0]

        offset = (page - 1) * per_page
        cur.execute(f"""
            SELECT
                rdap_network                        AS network,
                rdap_org                            AS org,
                rdap_asn                            AS asn,
                rdap_country                        AS country,
                COUNT(ip)                           AS ip_count,
                SUM(connection_count)               AS total_connections,
                SUM(is_blocked)                     AS blocked_count,
                SUM(CASE WHEN is_flagged=1 AND is_blocked=0 THEN 1 ELSE 0 END) AS flagged_count,
                SUM(is_friendly)                    AS friendly_count,
                MAX(last_seen)                      AS last_seen,
                EXISTS(
                    SELECT 1 FROM blocked_entries
                    WHERE entry = rdap_network AND entry_type = 'cidr'
                )                                   AS network_blocked
            FROM ip_stats
            {where}
            GROUP BY rdap_network
            ORDER BY total_connections DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])
        rows = [dict(r) for r in cur.fetchall()]
        return rows, total
    finally:
        if owned:
            conn.close()


def get_ips_for_network(network):
    """Return all IPs that belong to the given rdap_network."""
    conn, owned = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT ip, connection_count, first_seen, last_seen,
                   is_blocked, is_flagged, is_friendly,
                   rdap_org, rdap_asn, rdap_country
            FROM ip_stats
            WHERE rdap_network = ?
            ORDER BY connection_count DESC
        """, (network,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        if owned:
            conn.close()


def block_network(network, reason=''):
    """Block a network CIDR range.

    Inserts the CIDR into blocked_entries and marks all known IPs that belong
    to this rdap_network as blocked in ip_stats.
    """
    conn, owned = _db()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO blocked_entries (entry, entry_type, reason)
            VALUES (?, 'cidr', ?)
        """, (network, reason))
        conn.execute("""
            UPDATE ip_stats SET is_blocked = 1
            WHERE rdap_network = ?
        """, (network,))
        conn.commit()
        logger.info(f"Blocked network {network}")
    except Exception as e:
        logger.error(f"block_network failed for {network}: {e}")
        conn.rollback()
    finally:
        if owned:
            conn.close()


def unblock_network(network):
    """Unblock a network CIDR range.

    Removes the CIDR from blocked_entries and clears the blocked flag on all
    IPs that belong to this rdap_network (unless they were individually blocked
    by another entry too).
    """
    conn, owned = _db()
    try:
        conn.execute("DELETE FROM blocked_entries WHERE entry = ?", (network,))
        # Only clear is_blocked on IPs that have no individual block entry
        conn.execute("""
            UPDATE ip_stats SET is_blocked = 0
            WHERE rdap_network = ?
              AND ip NOT IN (SELECT entry FROM blocked_entries WHERE entry_type = 'ip')
        """, (network,))
        conn.commit()
        logger.info(f"Unblocked network {network}")
    except Exception as e:
        logger.error(f"unblock_network failed for {network}: {e}")
        conn.rollback()
    finally:
        if owned:
            conn.close()
