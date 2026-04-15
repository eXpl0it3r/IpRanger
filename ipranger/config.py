import yaml
import os
import copy

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
        'flag_threshold': 500,
    },
    'blocklists': {
        'update_interval_hours': 24,
        'sources': [
            {
                'name': 'firehol_level1',
                'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'type': 'cidr',
                'enabled': False,
            },
            {
                'name': 'firehol_level2',
                'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset',
                'type': 'cidr',
                'enabled': False,
            },
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
                'name': 'tor_exit_nodes',
                'url': 'https://check.torproject.org/torbulkexitlist',
                'type': 'ip',
                'enabled': False,
            },
            {
                'name': 'cinsscore',
                'url': 'https://cinsscore.com/list/ci-badguys.txt',
                'type': 'ip',
                'enabled': True,
            }

        ],
    },
    'rdap': {
        'cache_ttl_hours': 168,
        'lookup_delay_seconds': 1,
    },
    'ipset': {
        'set_name': 'ipranger_blocked',
        'auto_block': False,
        'auto_block_threshold': 1000,
        'persist': True,
    },
    'friendly': {
        'ips': [],
        'ranges': [],
    },
    'countries': {
        'blocking_enabled': False,
        'blocked_countries': [],
    },
}


def _deep_merge(base, override):
    """Recursively merge override dict into base dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    def __init__(self, path='config.yaml'):
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
        except Exception as e:
            import logging
            logging.warning(f"Failed to load config from {path}: {e}. Using defaults.")

    def get(self, *keys, default=None):
        """Access nested config values by key path. E.g. config.get('server', 'port')."""
        node = self._data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def get_db_path(self):
        return self.get('database', 'path', default='ipranger.db')


config = Config()
