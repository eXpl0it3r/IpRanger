import logging
import math
import functools

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response

from .config import config
from .db import (
    init_db, close_db, get_ip_stats, get_ip_detail, get_overview_stats,
    get_blocklist_sources, get_blocklist_entries, get_friendly_entries,
    get_blocked_entries, block_ip, unblock_ip, add_friendly, remove_friendly,
    update_rdap, get_top_ips, upsert_blocklist_source,
    get_network_stats, get_ips_for_network, block_network, unblock_network,
)
from .rdap import lookup_ip
from . import logbuffer

logger = logging.getLogger(__name__)


def create_app():
    # Install log buffer before anything else so all startup messages are captured
    logbuffer.install()

    app = Flask(__name__)
    app.secret_key = config.get('server', 'secret_key', default='change-me')

    # ── Basic Auth ────────────────────────────────────────────────────────────
    _auth_enabled  = config.get('server', 'auth', 'enabled',  default=True)
    _auth_username = config.get('server', 'auth', 'username', default='admin')
    _auth_password = config.get('server', 'auth', 'password', default='change-me')

    def _require_auth():
        if not _auth_enabled:
            return None
        creds = request.authorization
        if creds and creds.username == _auth_username and creds.password == _auth_password:
            return None
        return Response(
            'Unauthorized – please log in.',
            401,
            {'WWW-Authenticate': 'Basic realm="IpRanger"'},
        )

    app.before_request(_require_auth)

    # Initialize DB
    with app.app_context():
        init_db()
        _seed_blocklist_sources(app)
        _seed_private_friendly()

    app.teardown_appcontext(close_db)

    # Start scheduler
    try:
        from .scheduler import init_scheduler
        init_scheduler(app)
    except Exception as e:
        logger.warning(f"Scheduler could not start: {e}")

    # ── Page routes ──────────────────────────────────────────────────────────

    @app.route('/')
    def index():
        stats = get_overview_stats()
        top_ips = get_top_ips(10)
        return render_template('index.html', stats=stats, top_ips=top_ips)

    @app.route('/stats')
    def stats():
        page = int(request.args.get('page', 1))
        search = request.args.get('search', '').strip()
        sort = request.args.get('sort', 'connection_count')
        per_page = 50
        rows, total = get_ip_stats(page=page, per_page=per_page, sort=sort, search=search or None)
        total_pages = max(1, math.ceil(total / per_page))
        return render_template(
            'stats.html',
            rows=rows, page=page, total=total,
            total_pages=total_pages, search=search, sort=sort,
        )

    @app.route('/networks')
    def networks():
        page = int(request.args.get('page', 1))
        search = request.args.get('search', '').strip()
        per_page = 50
        rows, total = get_network_stats(page=page, per_page=per_page, search=search or None)
        total_pages = max(1, math.ceil(total / per_page))
        return render_template(
            'networks.html',
            rows=rows, page=page, total=total,
            total_pages=total_pages, search=search,
        )

    @app.route('/partials/network-ips')
    def partial_network_ips():
        network = request.args.get('network', '').strip()
        if not network:
            return '', 400
        ips = get_ips_for_network(network)
        return render_template('partials/network_ips.html', ips=ips, network=network)

    @app.route('/api/network/block', methods=['POST'])
    def api_network_block():
        network = request.form.get('network', '').strip()
        reason  = request.form.get('reason', 'Blocked via Networks page').strip()
        if not network:
            return jsonify({'error': 'network required'}), 400
        block_network(network, reason)
        try:
            from .ipset import add_to_ipset, create_ipset
            create_ipset()
            add_to_ipset(network)
        except Exception as e:
            logger.warning(f"ipset add failed for network {network}: {e}")
        if request.headers.get('HX-Request'):
            # Return just the updated action cell for this row
            return render_template('partials/network_action.html',
                                   network=network, network_blocked=True)
        flash(f'Blocked network {network}', 'success')
        return redirect(url_for('networks'))

    @app.route('/api/network/unblock', methods=['POST'])
    def api_network_unblock():
        network = request.form.get('network', '').strip()
        if not network:
            return jsonify({'error': 'network required'}), 400
        unblock_network(network)
        try:
            from .ipset import remove_from_ipset
            remove_from_ipset(network)
        except Exception as e:
            logger.warning(f"ipset remove failed for network {network}: {e}")
        if request.headers.get('HX-Request'):
            return render_template('partials/network_action.html',
                                   network=network, network_blocked=False)
        flash(f'Unblocked network {network}', 'success')
        return redirect(url_for('networks'))

    @app.route('/blocked')
    def blocked():
        page = int(request.args.get('page', 1))
        per_page = 50
        entries, total = get_blocked_entries(page=page, per_page=per_page)
        total_pages = max(1, math.ceil(total / per_page))
        return render_template('blocked.html', entries=entries, page=page,
                               total=total, total_pages=total_pages)

    @app.route('/bad-ips')
    def bad_ips():
        source_filter = request.args.get('source', '').strip()
        page = int(request.args.get('page', 1))
        per_page = 50
        entries, total = get_blocklist_entries(
            source_name=source_filter or None, page=page, per_page=per_page
        )
        total_pages = max(1, math.ceil(total / per_page))
        sources = get_blocklist_sources()
        return render_template(
            'bad_ips.html',
            entries=entries, sources=sources,
            source_filter=source_filter,
            page=page, total=total, total_pages=total_pages,
        )

    @app.route('/settings')
    def settings():
        sources = get_blocklist_sources()
        friendly = get_friendly_entries()
        from .ipset import get_ipset_status
        ipset_status = get_ipset_status()
        cfg_sources = config.get('blocklists', 'sources', default=[])
        return render_template(
            'settings.html',
            sources=sources,
            friendly=friendly,
            ipset_status=ipset_status,
            cfg_sources=cfg_sources,
        )

    # ── HTMX partials ────────────────────────────────────────────────────────

    @app.route('/partials/overview')
    def partial_overview():
        stats = get_overview_stats()
        return render_template('partials/overview_cards.html', stats=stats)

    @app.route('/partials/stats')
    def partial_stats():
        page = int(request.args.get('page', 1))
        search = request.args.get('search', '').strip()
        sort = request.args.get('sort', 'connection_count')
        per_page = 50
        rows, total = get_ip_stats(page=page, per_page=per_page, sort=sort, search=search or None)
        total_pages = max(1, math.ceil(total / per_page))
        return render_template(
            'partials/stats_table.html',
            rows=rows, page=page, total=total,
            total_pages=total_pages, search=search, sort=sort,
        )

    @app.route('/partials/blocked')
    def partial_blocked():
        page = int(request.args.get('page', 1))
        per_page = 50
        entries, total = get_blocked_entries(page=page, per_page=per_page)
        total_pages = max(1, math.ceil(total / per_page))
        return render_template('partials/blocked_table.html', entries=entries,
                               page=page, total=total, total_pages=total_pages)

    @app.route('/partials/bad-ips')
    def partial_bad_ips():
        source_filter = request.args.get('source', '').strip()
        page = int(request.args.get('page', 1))
        per_page = 50
        entries, total = get_blocklist_entries(
            source_name=source_filter or None, page=page, per_page=per_page
        )
        total_pages = max(1, math.ceil(total / per_page))
        return render_template('partials/bad_ips_table.html',
                               entries=entries, source_filter=source_filter,
                               page=page, total=total, total_pages=total_pages)

    # ── API endpoints ────────────────────────────────────────────────────────

    @app.route('/api/block', methods=['POST'])
    def api_block():
        ip = request.form.get('ip', '').strip()
        reason = request.form.get('reason', '').strip()
        if not ip:
            return jsonify({'error': 'IP required'}), 400
        block_ip(ip, reason)
        # Optionally add to ipset
        if config.get('ipset', 'auto_block', default=False):
            try:
                from .ipset import add_to_ipset, create_ipset
                create_ipset()
                add_to_ipset(ip)
            except Exception as e:
                logger.warning(f"ipset add failed: {e}")
        if request.headers.get('HX-Request'):
            entries, total = get_blocked_entries(page=1, per_page=50)
            total_pages = max(1, math.ceil(total / 50))
            return render_template('partials/blocked_table.html', entries=entries,
                                   page=1, total=total, total_pages=total_pages)
        flash(f'Blocked {ip}', 'success')
        return redirect(url_for('blocked'))

    @app.route('/api/unblock', methods=['POST'])
    def api_unblock():
        ip = request.form.get('ip', '').strip()
        if not ip:
            return jsonify({'error': 'IP required'}), 400
        unblock_ip(ip)
        try:
            from .ipset import remove_from_ipset
            remove_from_ipset(ip)
        except Exception as e:
            logger.warning(f"ipset remove failed: {e}")
        if request.headers.get('HX-Request'):
            entries, total = get_blocked_entries(page=1, per_page=50)
            total_pages = max(1, math.ceil(total / 50))
            return render_template('partials/blocked_table.html', entries=entries,
                                   page=1, total=total, total_pages=total_pages)
        flash(f'Unblocked {ip}', 'success')
        return redirect(url_for('blocked'))

    @app.route('/api/friendly/add', methods=['POST'])
    def api_friendly_add():
        entry = request.form.get('ip', '').strip()
        label = request.form.get('label', '').strip()
        if not entry:
            return jsonify({'error': 'IP/CIDR required'}), 400
        add_friendly(entry, label)
        if request.headers.get('HX-Request'):
            friendly = get_friendly_entries()
            return render_template('partials/friendly_table.html', friendly=friendly)
        flash(f'Added {entry} to friendly list', 'success')
        return redirect(url_for('settings'))

    @app.route('/api/friendly/remove', methods=['POST'])
    def api_friendly_remove():
        entry = request.form.get('entry', '').strip()
        if not entry:
            return jsonify({'error': 'entry required'}), 400
        remove_friendly(entry)
        if request.headers.get('HX-Request'):
            friendly = get_friendly_entries()
            return render_template('partials/friendly_table.html', friendly=friendly)
        flash(f'Removed {entry} from friendly list', 'success')
        return redirect(url_for('settings'))

    @app.route('/api/rdap-lookup', methods=['POST'])
    def api_rdap_lookup():
        ip = request.form.get('ip', '').strip()
        if not ip:
            return jsonify({'error': 'IP required'}), 400
        data = lookup_ip(ip)
        if data:
            update_rdap(ip, **data)
            return jsonify({'success': True, 'data': data})
        return jsonify({'success': False, 'error': 'RDAP lookup failed'}), 500

    @app.route('/api/blocklists/refresh', methods=['POST'])
    def api_blocklists_refresh():
        from .blocklist import refresh_all_blocklists
        try:
            count = refresh_all_blocklists()
            if request.headers.get('HX-Request'):
                sources = get_blocklist_sources()
                return render_template('partials/sources_table.html', sources=sources)
            flash(f'Refreshed {count} block lists', 'success')
        except Exception as e:
            flash(f'Error refreshing block lists: {e}', 'error')
        return redirect(url_for('settings'))

    @app.route('/api/blocklists/refresh/<name>', methods=['POST'])
    def api_blocklist_refresh_one(name):
        from .blocklist import refresh_blocklist_source
        try:
            count = refresh_blocklist_source(name)
            if request.headers.get('HX-Request'):
                sources = get_blocklist_sources()
                return render_template('partials/sources_table.html', sources=sources)
            flash(f'Refreshed {name}: {count} entries', 'success')
        except Exception as e:
            flash(f'Error: {e}', 'error')
        return redirect(url_for('settings'))

    @app.route('/api/ipset/status')
    def api_ipset_status():
        from .ipset import get_ipset_status
        return jsonify(get_ipset_status())

    @app.route('/api/ipset/sync', methods=['POST'])
    def api_ipset_sync():
        from .ipset import sync_ipset_from_db, create_ipset
        try:
            create_ipset()
            count = sync_ipset_from_db()
            if request.headers.get('HX-Request'):
                from .ipset import get_ipset_status
                status = get_ipset_status()
                return render_template('partials/ipset_status.html', ipset_status=status)
            flash(f'ipset synced: {count} entries', 'success')
        except Exception as e:
            flash(f'ipset sync failed: {e}', 'error')
        return redirect(url_for('settings'))

    @app.route('/api/ipset/ensure-rule', methods=['POST'])
    def api_ipset_ensure_rule():
        from .ipset import ensure_iptables_rule, create_ipset
        try:
            create_ipset()
            ok = ensure_iptables_rule()
            if request.headers.get('HX-Request'):
                from .ipset import get_ipset_status
                status = get_ipset_status()
                return render_template('partials/ipset_status.html', ipset_status=status)
            if ok:
                flash('iptables rule added/verified', 'success')
            else:
                flash('Failed to add iptables rule (run as root?)', 'error')
        except Exception as e:
            flash(f'Error: {e}', 'error')
        return redirect(url_for('settings'))

    # ── Logs ─────────────────────────────────────────────────────────────────

    @app.route('/logs')
    def logs():
        level_filter = request.args.get('level', '').strip()
        name_filter  = request.args.get('search', '').strip()
        records = logbuffer.get_records(level_filter=level_filter, name_filter=name_filter)
        levels  = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        return render_template('logs.html', records=records, levels=levels,
                               level_filter=level_filter, name_filter=name_filter)

    @app.route('/partials/logs')
    def partial_logs():
        level_filter = request.args.get('level', '').strip()
        name_filter  = request.args.get('search', '').strip()
        records = logbuffer.get_records(level_filter=level_filter, name_filter=name_filter)
        return render_template('partials/log_lines.html', records=records)

    @app.route('/api/logs/clear', methods=['POST'])
    def api_logs_clear():
        logbuffer.clear()
        if request.headers.get('HX-Request'):
            return render_template('partials/log_lines.html', records=[])
        flash('Log buffer cleared', 'success')
        return redirect(url_for('logs'))

    # ── Template helpers ─────────────────────────────────────────────────────

    @app.template_filter('status_badge')
    def status_badge(row):
        badges = []
        if row.get('is_blocked'):
            badges.append('<span class="px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">Blocked</span>')
        if row.get('is_flagged') and not row.get('is_blocked'):
            badges.append('<span class="px-2 py-0.5 rounded text-xs font-semibold bg-yellow-100 text-yellow-700">Flagged</span>')
        if row.get('is_friendly'):
            badges.append('<span class="px-2 py-0.5 rounded text-xs font-semibold bg-green-100 text-green-700">Friendly</span>')
        return ' '.join(badges) if badges else '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-500">-</span>'

    @app.template_global()
    def page_range(current, total):
        """Generate page numbers for pagination."""
        pages = set()
        pages.add(1)
        pages.add(total)
        for i in range(max(1, current - 2), min(total + 1, current + 3)):
            pages.add(i)
        return sorted(pages)

    return app


def _seed_blocklist_sources(app):
    """Sync blocklist sources from config into the DB.

    New sources are inserted with the enabled flag from config.yaml.
    Existing sources have their URL and type updated (in case config changed)
    but their enabled flag is left untouched — so UI toggles survive restarts.
    """
    from .db import upsert_blocklist_source, get_blocklist_sources
    existing = {s['name'] for s in get_blocklist_sources()}
    sources = config.get('blocklists', 'sources', default=[])
    for s in sources:
        if s['name'] in existing:
            # Already in DB — only update url/type, preserve enabled state
            upsert_blocklist_source(s['name'], s['url'], s['type'], enabled=None)
        else:
            # First time — seed with enabled value from config
            upsert_blocklist_source(s['name'], s['url'], s['type'],
                                    enabled=int(s.get('enabled', True)))


def _seed_private_friendly():
    """Add all RFC-private/reserved ranges to the friendly list (idempotent)."""
    from .db import add_friendly
    from .utils import RFC_PRIVATE_RANGES
    import logging
    log = logging.getLogger(__name__)
    seeded = 0
    for cidr, label in RFC_PRIVATE_RANGES:
        try:
            add_friendly(cidr, label=label, entry_type='cidr')
            seeded += 1
        except Exception as e:
            log.debug(f"Could not seed friendly entry {cidr}: {e}")
    if seeded:
        log.info(f"Seeded {seeded} RFC-private ranges into the friendly list")
