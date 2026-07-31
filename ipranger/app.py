"""Flask application for IpRanger V2."""
import logging
import math
from ipaddress import ip_network

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, flash, Response,
)

from .config import config
from .db import (
    init_db, close_db,
    get_overview_stats,
    get_live_ips_with_asn,
    get_network_groups,
    get_live_ips_for_group,
    get_cidrs_for_group,
    get_manual_blocks, add_manual_block, remove_manual_block,
    get_whitelist_entries, add_whitelist_entry, remove_whitelist_entry,
    is_whitelisted, get_whitelist_checker,
    rename_network_group,
    get_blocklist_sources, seed_blocklist_source,
    get_blocklist_entries_page,
    get_ips_missing_asn,
)
from . import logbuffer

logger = logging.getLogger(__name__)


# ── Block-state helpers ───────────────────────────────────────────────────────

def _blocking_context():
    """Snapshot of manual blocks (as parsed networks) and active enforcement sets."""
    manual_nets = []
    for block in get_manual_blocks():
        try:
            manual_nets.append(ip_network(block['entry'], strict=False))
        except ValueError:
            continue
    try:
        from .ipset import get_active_block_sets
        active_sets = get_active_block_sets()
    except Exception:
        active_sets = []
    return manual_nets, active_sets


def _cidr_block_states(cidrs, manual_nets, active_sets):
    """Per-CIDR block state: covered by a manual block (DB) and/or enforced in kernel."""
    from .ipset import test_entry_enforced
    states = []
    for cidr in cidrs:
        db_blocked = False
        try:
            net = ip_network(cidr, strict=False)
            db_blocked = any(
                net.version == b.version and net.subnet_of(b) for b in manual_nets)
        except ValueError:
            pass
        enforced = bool(active_sets) and test_entry_enforced(cidr, active_sets)
        states.append({'cidr': cidr, 'db_blocked': db_blocked, 'enforced': enforced,
                       'blocked': db_blocked or enforced})
    return states


def _annotated_network_groups():
    """Network groups annotated with block status: 'full', 'partial' or 'none'."""
    groups = get_network_groups()
    manual_nets, active_sets = _blocking_context()
    for g in groups:
        states = _cidr_block_states(
            get_cidrs_for_group(g['network_name'], g['asn']),
            manual_nets, active_sets)
        g['total_cidrs'] = len(states)
        g['blocked_count'] = sum(1 for s in states if s['blocked'])
        g['enforced_count'] = sum(1 for s in states if s['enforced'])
        if states and g['blocked_count'] == len(states):
            g['block_status'] = 'full'
        elif g['blocked_count']:
            g['block_status'] = 'partial'
        else:
            g['block_status'] = 'none'
    return groups


def create_app():
    logbuffer.install()

    app = Flask(__name__)
    app.secret_key = config.get('server', 'secret_key', default='change-me')

    # ── Basic auth ────────────────────────────────────────────────────────────
    _auth_enabled  = config.get('server', 'auth', 'enabled',  default=True)
    _auth_username = config.get('server', 'auth', 'username', default='admin')
    _auth_password = config.get('server', 'auth', 'password', default='change-me')

    @app.before_request
    def _require_auth():
        if not _auth_enabled:
            return None
        creds = request.authorization
        if creds and creds.username == _auth_username and creds.password == _auth_password:
            return None
        return Response(
            'Unauthorized',
            401,
            {'WWW-Authenticate': 'Basic realm="IpRanger"'},
        )

    # ── Init ──────────────────────────────────────────────────────────────────
    with app.app_context():
        init_db()
        _seed_blocklist_sources()
        _seed_whitelist_defaults()

    app.teardown_appcontext(close_db)

    try:
        from .scheduler import init_scheduler
        init_scheduler(app)
    except Exception as exc:
        logger.warning(f"Scheduler could not start: {exc}")

    def _annotate_whitelisted(rows):
        """Mark each row (dict with 'ip') as whitelisted or not."""
        check = get_whitelist_checker()
        for row in rows:
            row['whitelisted'] = check(row['ip'])
        return rows

    # ── Dashboard (live connections) ──────────────────────────────────────────
    @app.route('/')
    def index():
        stats = get_overview_stats()
        live_ips = _annotate_whitelisted(get_live_ips_with_asn())
        return render_template('index.html', stats=stats, live_ips=live_ips)

    @app.route('/partials/live-ips')
    def partial_live_ips():
        live_ips = _annotate_whitelisted(get_live_ips_with_asn())
        return render_template('partials/live_ips_table.html', live_ips=live_ips)

    @app.route('/partials/stats-cards')
    def partial_stats_cards():
        stats = get_overview_stats()
        return render_template('partials/stats_cards.html', stats=stats)

    # ── Networks (ASN groups) ─────────────────────────────────────────────────
    @app.route('/networks')
    def networks():
        groups = _annotated_network_groups()
        return render_template('networks.html', groups=groups)

    @app.route('/partials/group-live-ips')
    def partial_group_live_ips():
        network_name = request.args.get('network_name', '')
        asn = request.args.get('asn', '')
        ips = _annotate_whitelisted(get_live_ips_for_group(network_name, asn))
        manual_nets, active_sets = _blocking_context()
        cidr_states = _cidr_block_states(
            get_cidrs_for_group(network_name, asn), manual_nets, active_sets)
        return render_template('partials/group_live_ips.html', ips=ips,
                               cidr_states=cidr_states,
                               network_name=network_name, asn=asn)

    @app.route('/api/networks/rename', methods=['POST'])
    def api_network_rename():
        network_name = request.form.get('network_name', '').strip()
        asn = request.form.get('asn', '').strip()
        new_name = (request.headers.get('HX-Prompt')
                    or request.form.get('new_name', '')).strip()
        if not network_name or not new_name:
            return jsonify({'error': 'network_name and new_name required'}), 400
        rename_network_group(network_name, asn, new_name)
        if request.headers.get('HX-Request'):
            return render_template('partials/network_groups_table.html',
                                   groups=_annotated_network_groups())
        flash(f'Renamed {network_name} to {new_name}', 'success')
        return redirect(url_for('networks'))

    @app.route('/api/networks/refresh-asn', methods=['POST'])
    def api_network_refresh_asn():
        network_name = request.form.get('network_name', '').strip()
        asn = request.form.get('asn', '').strip()
        if not network_name:
            return jsonify({'error': 'network_name required'}), 400
        from .rdap import refresh_group_asn
        try:
            count = refresh_group_asn(network_name, asn)
        except Exception as exc:
            logger.error(f"ASN refresh failed for {network_name}: {exc}")
            if request.headers.get('HX-Request'):
                return Response(f'ASN refresh failed: {exc}', 500)
            flash(f'ASN refresh failed: {exc}', 'error')
            return redirect(url_for('networks'))
        if request.headers.get('HX-Request'):
            return render_template('partials/network_groups_table.html',
                                   groups=_annotated_network_groups())
        flash(f'Refreshed ASN info for {count} IP(s)', 'success')
        return redirect(url_for('networks'))

    # ── Blocking ──────────────────────────────────────────────────────────────
    @app.route('/blocking')
    def blocking():
        manual_blocks = get_manual_blocks()
        sources = get_blocklist_sources()
        source_filter = request.args.get('source', '').strip()
        page = int(request.args.get('page', 1))
        bl_entries, bl_total = get_blocklist_entries_page(
            source_name=source_filter or None, page=page, per_page=50)
        bl_total_pages = max(1, math.ceil(bl_total / 50))
        try:
            from .ipset import get_ipset_status
            ipset_status = get_ipset_status()
        except Exception:
            ipset_status = {'available': False, 'sets': {}, 'iptables_rules': []}
        return render_template(
            'blocking.html',
            manual_blocks=manual_blocks,
            sources=sources,
            source_filter=source_filter,
            bl_entries=bl_entries,
            bl_total=bl_total,
            bl_page=page,
            bl_total_pages=bl_total_pages,
            ipset_status=ipset_status,
        )

    @app.route('/api/block', methods=['POST'])
    def api_block():
        entry = request.form.get('entry', '').strip()
        reason = request.form.get('reason', '').strip()
        if not entry:
            return jsonify({'error': 'entry required'}), 400
        if is_whitelisted(entry):
            msg = f'{entry} is whitelisted and cannot be blocked'
            if request.headers.get('HX-Request'):
                return Response(msg, 400)
            flash(msg, 'error')
            return redirect(url_for('blocking'))
        add_manual_block(entry, reason)
        try:
            from .ipset import add_to_manual, ensure_ipsets
            ensure_ipsets()
            add_to_manual(entry)
        except Exception as exc:
            logger.warning(f"ipset add failed: {exc}")
        if request.headers.get('HX-Request'):
            return render_template('partials/manual_blocks_table.html',
                                   manual_blocks=get_manual_blocks())
        flash(f'Blocked {entry}', 'success')
        return redirect(url_for('blocking'))

    @app.route('/api/unblock', methods=['POST'])
    def api_unblock():
        entry = request.form.get('entry', '').strip()
        if not entry:
            return jsonify({'error': 'entry required'}), 400
        remove_manual_block(entry)
        try:
            from .ipset import remove_from_manual
            remove_from_manual(entry)
        except Exception as exc:
            logger.warning(f"ipset remove failed: {exc}")
        if request.headers.get('HX-Request'):
            return render_template('partials/manual_blocks_table.html',
                                   manual_blocks=get_manual_blocks())
        flash(f'Unblocked {entry}', 'success')
        return redirect(url_for('blocking'))

    @app.route('/api/block-group', methods=['POST'])
    def api_block_group():
        """Block all CIDRs belonging to an ASN group."""
        network_name = request.form.get('network_name', '').strip()
        asn = request.form.get('asn', '').strip()
        reason = request.form.get('reason', f'ASN block: {network_name}').strip()
        if not network_name:
            return jsonify({'error': 'network_name required'}), 400
        cidrs = [c for c in get_cidrs_for_group(network_name, asn)
                 if not is_whitelisted(c)]
        for cidr in cidrs:
            add_manual_block(cidr, reason)
            try:
                from .ipset import add_to_manual, ensure_ipsets
                ensure_ipsets()
                add_to_manual(cidr)
            except Exception as exc:
                logger.warning(f"ipset add failed for {cidr}: {exc}")
        if request.headers.get('HX-Request'):
            return render_template('partials/network_groups_table.html',
                                   groups=_annotated_network_groups())
        flash(f'Blocked {len(cidrs)} CIDR(s) for {network_name}', 'success')
        return redirect(url_for('networks'))

    @app.route('/api/blocklists/refresh', methods=['POST'])
    def api_blocklists_refresh():
        from .blocklist import refresh_all_blocklists
        try:
            count = refresh_all_blocklists()
            if request.headers.get('HX-Request'):
                return render_template('partials/sources_table.html',
                                       sources=get_blocklist_sources())
            flash(f'Refreshed {count} block lists', 'success')
        except Exception as exc:
            flash(f'Error: {exc}', 'error')
        return redirect(url_for('blocking'))

    @app.route('/api/blocklists/refresh/<name>', methods=['POST'])
    def api_blocklist_refresh_one(name):
        from .blocklist import refresh_one_blocklist
        try:
            count = refresh_one_blocklist(name)
            if request.headers.get('HX-Request'):
                return render_template('partials/sources_table.html',
                                       sources=get_blocklist_sources())
            flash(f'Refreshed {name}: {count} entries', 'success')
        except Exception as exc:
            flash(f'Error: {exc}', 'error')
        return redirect(url_for('blocking'))

    @app.route('/api/ipset/sync-blacklist', methods=['POST'])
    def api_ipset_sync_blacklist():
        from .ipset import sync_blacklist_from_db, get_ipset_status
        try:
            count = sync_blacklist_from_db()
            if request.headers.get('HX-Request'):
                return render_template('partials/ipset_status.html',
                                       ipset_status=get_ipset_status())
            flash(f'Blacklist ipset synced: {count} entries', 'success')
        except Exception as exc:
            flash(f'ipset sync failed: {exc}', 'error')
        return redirect(url_for('blocking'))

    @app.route('/api/ipset/sync-manual', methods=['POST'])
    def api_ipset_sync_manual():
        from .ipset import sync_manual_from_db, get_ipset_status
        try:
            count = sync_manual_from_db()
            if request.headers.get('HX-Request'):
                return render_template('partials/ipset_status.html',
                                       ipset_status=get_ipset_status())
            flash(f'Manual ipset synced: {count} entries', 'success')
        except Exception as exc:
            flash(f'ipset sync failed: {exc}', 'error')
        return redirect(url_for('blocking'))

    @app.route('/api/ipset/ensure-rules', methods=['POST'])
    def api_ipset_ensure_rules():
        from .ipset import ensure_iptables_rules, get_ipset_status
        try:
            ensure_iptables_rules()
            if request.headers.get('HX-Request'):
                return render_template('partials/ipset_status.html',
                                       ipset_status=get_ipset_status())
            flash('iptables rules added/verified', 'success')
        except Exception as exc:
            flash(f'Error: {exc}', 'error')
        return redirect(url_for('blocking'))

    @app.route('/partials/ipset-status')
    def partial_ipset_status():
        from .ipset import get_ipset_status
        return render_template('partials/ipset_status.html',
                               ipset_status=get_ipset_status())

    # ── Whitelist ─────────────────────────────────────────────────────────────
    @app.route('/whitelist')
    def whitelist():
        entries = get_whitelist_entries()
        return render_template('whitelist.html', entries=entries)

    @app.route('/api/whitelist/add', methods=['POST'])
    def api_whitelist_add():
        entry = request.form.get('entry', '').strip()
        label = request.form.get('label', '').strip()
        if not entry:
            return jsonify({'error': 'entry required'}), 400
        add_whitelist_entry(entry, label)
        if request.headers.get('HX-Request'):
            return render_template('partials/whitelist_table.html',
                                   entries=get_whitelist_entries())
        flash(f'Added {entry} to whitelist', 'success')
        return redirect(url_for('whitelist'))

    @app.route('/api/whitelist/remove', methods=['POST'])
    def api_whitelist_remove():
        entry = request.form.get('entry', '').strip()
        if not entry:
            return jsonify({'error': 'entry required'}), 400
        remove_whitelist_entry(entry)
        if request.headers.get('HX-Request'):
            return render_template('partials/whitelist_table.html',
                                   entries=get_whitelist_entries())
        flash(f'Removed {entry} from whitelist', 'success')
        return redirect(url_for('whitelist'))

    # ── Logs ──────────────────────────────────────────────────────────────────
    @app.route('/logs')
    def logs():
        level_filter = request.args.get('level', '').strip()
        search = request.args.get('search', '').strip()
        records = logbuffer.get_records(level_filter=level_filter, name_filter=search)
        return render_template('logs.html', records=records,
                               levels=['DEBUG','INFO','WARNING','ERROR','CRITICAL'],
                               level_filter=level_filter, search=search)

    @app.route('/partials/logs')
    def partial_logs():
        level_filter = request.args.get('level', '').strip()
        search = request.args.get('search', '').strip()
        records = logbuffer.get_records(level_filter=level_filter, name_filter=search)
        return render_template('partials/log_lines.html', records=records)

    @app.route('/api/logs/clear', methods=['POST'])
    def api_logs_clear():
        logbuffer.clear()
        if request.headers.get('HX-Request'):
            return render_template('partials/log_lines.html', records=[])
        flash('Log buffer cleared', 'success')
        return redirect(url_for('logs'))

    # ── Template globals ──────────────────────────────────────────────────────
    @app.template_global()
    def page_range(current, total):
        pages = set([1, total])
        for i in range(max(1, current-2), min(total+1, current+3)):
            pages.add(i)
        return sorted(pages)

    return app


def _seed_blocklist_sources():
    from .config import config
    sources = config.get('blocklists', 'sources', default=[])
    existing = {s['name'] for s in get_blocklist_sources()}
    for src in sources:
        enabled = int(src.get('enabled', True))
        if src['name'] not in existing:
            seed_blocklist_source(src['name'], src['url'], src['type'], enabled)
        else:
            # Update url/type only, preserve enabled state from DB
            seed_blocklist_source(src['name'], src['url'], src['type'],
                                  enabled=enabled)


def _seed_whitelist_defaults():
    """Add RFC-private / reserved ranges to whitelist (idempotent)."""
    from .utils import RFC_PRIVATE_RANGES
    existing = {e['entry'] for e in get_whitelist_entries()}
    seeded = 0
    for cidr, label in RFC_PRIVATE_RANGES:
        if cidr not in existing:
            add_whitelist_entry(cidr, label)
            seeded += 1
    if seeded:
        logger.info(f"Seeded {seeded} RFC-private ranges into whitelist")
