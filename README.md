# IpRanger

TCP traffic monitoring and blocking tool for Debian/Ubuntu servers. Monitor incoming connections, enrich IP data via RDAP, pull threat intelligence from block lists, and manage iptables/ipset rules - all from a modern web UI.

## Features

- **Live monitoring** - polls `ss -tnp` every 10 s and tracks connection counts per IP
- **RDAP enrichment** - auto-resolves org, network, ASN, and country for each IP
- **Block lists** - fetches FireHOL, Spamhaus DROP, Emerging Threats, and Tor exit nodes on a 24 h schedule
- **ipset / iptables** - create/flush/sync sets and install DROP rules without hand-editing
- **Friendly IPs** - whitelist IPs or CIDR ranges that should never be flagged
- **Country blocking** - optional per-country blocking based on RDAP country codes
- **Web UI** - dashboard, statistics, **network explorer**, blocked IPs, bad-IP explorer, and settings via Flask + HTMX + Tailwind CSS

## Requirements

- Debian / Ubuntu server
- Python 3.10+
- `ipset` and `iptables` installed
- Root privileges (needed for ipset/iptables)

## Installation

```bash
git clone https://github.com/you/ipranger.git
cd ipranger
pip install -r requirements.txt
```

Edit `config.yaml` - at minimum change `server.secret_key`.

## Usage

```bash
sudo python run.py
```

Open `http://<server-ip>:5000` in your browser.

## Configuration

All settings live in `config.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `server.host` | `0.0.0.0` | Bind address |
| `server.port` | `5000` | HTTP port |
| `monitoring.interval_seconds` | `10` | How often to poll connections |
| `monitoring.flag_threshold` | `500` | Connection count that flags an IP |
| `blocklists.update_interval_hours` | `24` | Block list refresh interval |
| `ipset.auto_block` | `false` | Automatically block flagged IPs |
| `ipset.auto_block_threshold` | `1000` | Connection count for auto-block |
| `rdap.cache_ttl_hours` | `168` | How long RDAP results are cached (7 days) |
| `countries.blocking_enabled` | `false` | Enable country-level blocking |
| `countries.blocked_countries` | `[]` | ISO 3166-1 alpha-2 codes to block |

### Block list sources

Five sources are pre-configured. Enable or disable them in `config.yaml` under `blocklists.sources`, or manage them live from the **Settings** page.

| Name | Type | Enabled by default |
|------|------|--------------------|
| `firehol_level1` | CIDR | ✅ |
| `spamhaus_drop` | CIDR | ✅ |
| `emerging_threats` | IP | ✅ |
| `firehol_level2` | CIDR | ❌ |
| `tor_exit_nodes` | IP | ❌ |

## Web UI pages

| Page | Description |
|------|-------------|
| **Dashboard** | Live overview cards (auto-refresh every 10 s) and top-10 connections |
| **Statistics** | Searchable, sortable per-IP table with RDAP data and block/friendly actions |
| **Networks** | RDAP-resolved networks/prefixes grouped by CIDR, with expandable IP drilldown |
| **Blocked** | Manually and automatically blocked entries; add/remove from here |
| **Bad IPs** | Browser for block list entries, filterable by source |
| **Settings** | Block list management, friendly IPs, ipset status and sync |

## Project layout

```
ipranger/
├── app.py          # Flask application and routes
├── db.py           # SQLite data layer
├── config.py       # Config loader
├── monitor.py      # TCP connection monitoring (ss -tnp)
├── rdap.py         # RDAP IP enrichment
├── blocklist.py    # Block list fetching and parsing
├── ipset.py        # ipset / iptables management
├── scheduler.py    # Background jobs (APScheduler)
└── templates/      # Jinja2 templates (Tailwind + HTMX)
```

## License

MIT
