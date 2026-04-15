"""In-memory log ring-buffer exposed to the web UI."""
import logging
import collections
import threading

_MAX_RECORDS = 500

_lock = threading.Lock()
_records: collections.deque = collections.deque(maxlen=_MAX_RECORDS)

LEVEL_COLOURS = {
    'DEBUG':    'text-gray-400',
    'INFO':     'text-blue-600',
    'WARNING':  'text-yellow-600',
    'ERROR':    'text-red-600',
    'CRITICAL': 'text-red-800',
}


class _RingBufferHandler(logging.Handler):
    """Logging handler that appends formatted records to the shared deque."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                'time':    self.formatTime(record, '%H:%M:%S'),
                'level':   record.levelname,
                'name':    record.name,
                'message': self.format(record),
                'colour':  LEVEL_COLOURS.get(record.levelname, 'text-gray-600'),
            }
            with _lock:
                _records.append(entry)
        except Exception:
            self.handleError(record)


_handler: _RingBufferHandler | None = None


def install(level: int = logging.DEBUG) -> None:
    """Attach the ring-buffer handler to the root logger (idempotent)."""
    global _handler
    if _handler is not None:
        return
    fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(name)s – %(message)s',
                            datefmt='%H:%M:%S')
    _handler = _RingBufferHandler()
    _handler.setFormatter(fmt)
    _handler.setLevel(level)
    root = logging.getLogger()
    if root.level == logging.NOTSET or root.level > level:
        root.setLevel(level)
    root.addHandler(_handler)

    # Also ensure a StreamHandler exists so logs still appear in the console
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, _RingBufferHandler)
               for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)


def get_records(level_filter: str = '', name_filter: str = '', limit: int = 200) -> list[dict]:
    """Return recent log records, newest last, optionally filtered."""
    with _lock:
        records = list(_records)
    if level_filter:
        records = [r for r in records if r['level'] == level_filter.upper()]
    if name_filter:
        nf = name_filter.lower()
        records = [r for r in records if nf in r['name'].lower() or nf in r['message'].lower()]
    return records[-limit:]


def clear() -> None:
    """Discard all buffered records."""
    with _lock:
        _records.clear()
