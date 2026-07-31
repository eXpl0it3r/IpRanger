"""Background scheduler for IpRanger V2."""
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler(daemon=True)


def init_scheduler(app):
    from .config import config
    from .monitor import record_connections
    from .rdap import enrich_pending_ips
    from .blocklist import refresh_all_blocklists

    monitor_interval = config.get('monitoring', 'interval_seconds', default=10)
    blocklist_hours = config.get('blocklists', 'update_interval_hours', default=24)

    scheduler.add_job(
        func=record_connections,
        trigger=IntervalTrigger(seconds=monitor_interval),
        id='monitor', name='Monitor TCP connections',
        replace_existing=True, max_instances=1, coalesce=True,
    )
    scheduler.add_job(
        func=enrich_pending_ips,
        trigger=IntervalTrigger(seconds=60),
        id='rdap_enrich', name='ASN enrichment',
        replace_existing=True, max_instances=1, coalesce=True,
    )
    scheduler.add_job(
        func=refresh_all_blocklists,
        trigger=IntervalTrigger(hours=blocklist_hours),
        id='blocklist_refresh', name='Blocklist refresh',
        replace_existing=True, max_instances=1, coalesce=True,
    )

    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler started")
    return scheduler
