# IpRanger

ASN-aware TCP traffic monitoring and blocking tool for Debian/Ubuntu servers.
Collects connected IPs over time, resolves them to ASN/network ranges, and helps
you detect and block scrapers that rotate IPs across the same ASN.

## Features

- **Live dashboard** - currently connected IPs sorted by address (makes IP-range clustering obvious), auto-refreshes every 10 s
- **ASN/Network view** - groups by network name (one org can own multiple CIDRs), shows historic + live IP counts, collapsible per-group live IP list
- **Two ipsets** - `ipranger_blacklist` (threat feeds) and `ipranger_manual` (user blocks), both with separate sync controls and iptables DROP rules
- **Threat feeds** - emerging_threats, spamhaus_drop, cinsscore - refreshed on a 24 h schedule, triggerable manually
- **Whitelist** - IPs/CIDRs that will never be blocked; all RFC-private ranges are pre-seeded
- **RDAP cache** - resolves CIDR/ASN once, re-uses for all IPs in that range; runs at most once per second to avoid rate-limiting
- **Basic auth** - configurable username/password to protect the web UI
- **Log viewer** - live ring-buffer with level and module filters

## Disclaimer

> [!NOTE]
> This project was built with the assistance of an LLM.

## Screenshots

<img width="2268" height="1435" alt="image" src="https://github.com/user-attachments/assets/4f336cf6-a8a6-49f2-9399-881687bc1528" />
<img width="2276" height="977" alt="image" src="https://github.com/user-attachments/assets/550db3bb-f118-4a87-af30-7b889a8de5f1" />

## Requirements

- Debian / Ubuntu server
- Python 3.10+
- `ipset` and `iptables` installed
- Root privileges (needed for ipset/iptables)

## Installation

```bash
git clone https://github.com/eXpl0it3r/ipranger.git
cd ipranger
pip install -r requirements.txt
```

Edit `config.yaml` before starting:

```yaml
server:
  secret_key: "generate-a-random-string"
  auth:
    username: "admin"
    password: "your-secure-password"
```

## Usage

```bash
sudo python run.py
```

Open `http://<server-ip>:5000` in your browser.

## Configuration

| Key                                | Default                   | Description                         |
|------------------------------------|---------------------------|-------------------------------------|
| `server.host`                      | `0.0.0.0`                 | Bind address                        |
| `server.port`                      | `5000`                    | HTTP port                           |
| `server.secret_key`                | `change-me-in-production` | Session signing key                 |
| `server.auth.enabled`              | `true`                    | Enable HTTP basic auth              |
| `server.auth.username`             | `admin`                   | Basic auth username                 |
| `server.auth.password`             | `change-me`               | Basic auth password                 |
| `database.path`                    | `ipranger.db`             | SQLite database path                |
| `monitoring.interval_seconds`      | `10`                      | Connection poll interval            |
| `blocklists.update_interval_hours` | `24`                      | Feed refresh interval               |
| `rdap.lookup_delay_seconds`        | `1`                       | Delay between RDAP requests         |
| `ipset.persist`                    | `true`                    | Save ipset rules to /etc/ipset.conf |

## Web UI pages

| Page          | Description                                                                                                     |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Dashboard** | Live connected IPs sorted by address - auto-refreshes every 10 s                                                |
| **Networks**  | ASN/network groups with historic + live IP counts; expandable live-IP list per group; one-click block all CIDRs |
| **Blocking**  | Manage manual blocks, sync both ipsets, manage iptables rules, refresh / browse threat-feed blocklists          |
| **Whitelist** | Add/remove IPs and CIDRs from the whitelist; RFC-private ranges pre-seeded                                      |
| **Logs**      | Live ring-buffer log viewer with level and module filters                                                       |

## License

IpRanger is distributed under the MIT license, see [LICENSE](LICENSE).
