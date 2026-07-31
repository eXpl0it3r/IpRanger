import yaml
import os
import copy

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_PACKAGE_DIR)
_DEFAULT_CONFIG_PATH = os.path.join(_PROJECT_ROOT, 'config.yaml')

DEFAULT_CONFIG = {
    'server': {
        'host': '0.0.0.0',
        'port': 5000,
        'debug': False,
        'secret_key': 'change-me-in-production',
        'auth': {
            'enabled': True,
            'username': 'admin',
            'password': 'change-me',
        },
    },
    'database': {
        'path': 'ipranger.db',
    },
    'monitoring': {
        'interval_seconds': 10,
    },
    'blocklists': {
        'update_interval_hours': 24,
        'sources': [
            {
                'name': 'emerging_threats',
                'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'type': 'ip',
                'enabled': True,
            },
            {
                'name': 'spamhaus_drop',
                'url': 'https://www.spamhaus.org/drop/drop.txt',
                'type': 'cidr',
                'enabled': True,
            },
            {
                'name': 'cinsscore',
                'url': 'https://cinsscore.com/list/ci-badguys.txt',
                'type': 'ip',
                'enabled': True,
            },
        ],
    },
    'rdap': {
        'lookup_delay_seconds': 1,
    },
    'ipset': {
        'persist': True,
    },
}


def _deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    def __init__(self, path=None):
        if path is None:
            path = _DEFAULT_CONFIG_PATH
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        self._path = path
        self._load(path)

    def _load(self, path):
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r') as f:
                loaded = yaml.safe_load(f) or {}
            self._data = _deep_merge(self._data, loaded)
        except Exception as exc:
            import logging
            logging.warning(f"Failed to load config from {path}: {exc}. Using defaults.")

    def get(self, *keys, default=None):
        node = self._data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def get_db_path(self):
        path = self.get('database', 'path', default='ipranger.db')
        if not os.path.isabs(path):
            path = os.path.join(_PROJECT_ROOT, path)
        return path


config = Config()
