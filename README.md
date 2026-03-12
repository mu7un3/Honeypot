# ML-Enhanced Honeypot Alert System v2.1

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

A production-grade security alert system with multi-port honeypot capabilities, real-time machine learning attack classification, enhanced threat intelligence, and automated incident response.

Delivers comprehensive email alerts with attacker geolocation, network intelligence, security flagging, and behavioral profiling. Runs as a system service on Windows, Linux, and macOS.

---

## Dashboard Overview

```
+===============================================================================+
|  HONEYPOT ANALYTICS                                    [Online]  14:32:45    |
|  ML-Enhanced - Live - Last updated 2026-03-12T14:32:40                       |
+===============================================================================+
|                                                                               |
|  +-------------+ +-------------+ +-------------+ +-------------+              |
|  | Total       | | Unique      | | Blocked     | | Avg         |              |
|  | Attacks     | | Attackers   | | IPs         | | Threat      |              |
|  |    847      | |    142      | |     23      | |   6.8/10    |              |
|  +-------------+ +-------------+ +-------------+ +-------------+              |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  |  Attack Timeline (last 24h)                                             |  |
|  |  _--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--^^--_   |  |
|  |  00  04  08  12  16  20  00  04  08  12  16  20  00                     |  |
|  +-------------------------------------------------------------------------+  |
|                                                                               |
|  +------------------+ +------------------+ +------------------+               |
|  | Severity         | | ML Attack        | | Attacker         |               |
|  | Distribution     | | Classification   | | Profiles         |               |
|  | [====] CRITICAL  | | [====] SSH       | | [====] Scanner   |               |
|  | [===]  HIGH      | | [===]  HTTP      | | [===]  Bot       |               |
|  | [==]   MEDIUM    | | [==]   RDP       | | [==]   APT       |               |
|  | [=]    LOW       | | [=]    SMB       | | [=]    Manual    |               |
|  +------------------+ +------------------+ +------------------+               |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  |  World Attack Map                                                       |  |
|  |                      [Interactive Leaflet Map]                          |  |
|  |         * *    ***    *        Attack markers by country                |  |
|  |              **     *****                                               |  |
|  |    ***          ***           Top: CN(234), US(156), RU(89)             |  |
|  +-------------------------------------------------------------------------+  |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  |  Live Attack Feed                                    [Show all 847]     |  |
|  +-------------------------------------------------------------------------+  |
|  |  Time     Attacker        Service    Severity   Threat   Type           |  |
|  |  14:32:40 185.220.101.42  SSH        CRITICAL   9.2/10   BruteForce     |  |
|  |  14:32:38 45.155.205.99   RDP        HIGH       7.8/10   Scan           |  |
|  |  14:32:35 103.75.201.2     HTTP       MEDIUM     5.4/10   SQLi          |  |
|  |  14:32:31 194.26.192.77    SMB        CRITICAL   8.9/10   Exploit       |  |
|  |  14:32:28 89.248.167.90    MySQL      HIGH       6.7/10   BruteForce    |  |
|  +-------------------------------------------------------------------------+  |
|                                                                               |
+===============================================================================+
```

---

## Capabilities

### Honeypot Engine
- **TCP Services**: SSH, Telnet, FTP, SMTP, HTTP, HTTPS, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB, VNC, MSSQL, LDAP, and 35+ more
- **UDP Services**: DNS (53), SNMP (161/162), TFTP (69)
- Realistic service banners per port
- Payload capture with hex/text decode
- IP watchlist and repeat-offender tracking
- Automatic blocked-IP list on startup

### Threat Intelligence
- **Multi-API Geolocation** — ipapi.co, ip-api.com, ipinfo.io with automatic fallback
- **Location Data** — City, country, continent, coordinates, timezone, postal code
- **Network Intelligence** — ISP, ASN, organization, connection type, reverse DNS
- **Security Detection** — Proxy, VPN, Tor exit node, hosting/datacenter identification
- **Attacker History** — Return visitor tracking, total attacks, persistence scoring

### Machine Learning Analysis
| Model | Algorithm | Metric |
|-------|-----------|--------|
| Attack Classification | Random Forest | 100% accuracy |
| Anomaly Detection | Isolation Forest | Contamination: 0.1 |
| Threat Scoring | Gradient Boosting Regressor | MAE 0.013 |
| Attacker Profiling | K-Means Clustering | 5 profiles |

### Automated Response
| Tier | Trigger | Actions |
|------|---------|---------|
| 1 | Any detection | Log + desktop notification + email alert |
| 2 | Score >= 6 OR 5+ hits | iptables block + AbuseIPDB report + IOC export |
| 3 | Score >= 8 OR anomaly + score >= 6 | fail2ban integration + critical email + geo-block analysis |

### Email Alert System
- **Dual Format** — Professional HTML and plain text versions
- **Attacker Intelligence** — Full geolocation, network, and ISP details
- **Security Indicators** — Tor/VPN/Proxy/Hosting flags with risk scores
- **Behavioral Analysis** — Repeat offender detection with persistence metrics
- **ML Results** — Attack type classification, threat score, severity level
- **Evidence** — Captured payload and commands included

### Web Dashboard
- **Real-time Monitoring** — Live attack feed with auto-refresh (5s)
- **Geographic Visualization** — Leaflet world map with attack markers
- **Analytics** — Timeline charts, severity distribution, attack classification
- **Attacker Profiles** — ML-generated behavioral clusters
- **Export Capabilities** — IOC download in JSON format
- **Status Indicators** — Online/offline status, notifications, system health

---

## Requirements

| Component | Version |
|-----------|---------|
| Python | 3.10+ |
| Node.js | 18+ LTS |

Dependencies auto-install via `winget` (Windows), `apt`/`brew` (Linux/macOS).

---

## Installation

### Linux (Ubuntu/Debian)

```bash
git clone https://github.com/your-username/honeypot.git
cd honeypot
sudo bash install.sh
```

**Installer performs:**
1. Python 3 and Node.js 20 installation (if missing)
2. Python packages: `scikit-learn numpy requests python-dotenv`
3. File deployment to `/opt/honeypot/`
4. Environment configuration via `/opt/honeypot/.env`
5. ML model training
6. systemd service registration:
   - `honeypot` — Core detection service (auto-start on boot)
   - `honeypot-dashboard` — Web interface on port 3000

**Service Management:**
```bash
sudo systemctl status honeypot
sudo systemctl restart honeypot
sudo journalctl -u honeypot -f
```

### macOS

```bash
cd honeypot-package
bash install.sh
```

Registers launchd agents for automatic startup. Note: Ports below 1024 require elevated privileges.

### Windows

```powershell
# Run PowerShell as Administrator
cd honeypot-package
.\install.ps1
```

Registers Windows Services via NSSM. Manage via `services.msc` or PowerShell:
```powershell
Get-Service honeypot, honeypot-dashboard
Restart-Service honeypot
```

### Manual Start (All Platforms)

```bash
# Terminal 1 - Honeypot
pip3 install scikit-learn numpy requests python-dotenv
PYTHONPATH=./honeypot python3 honeypot/honeypot.py

# Terminal 2 - Dashboard
cd honeypot-analytics && npm install && npm run dev
# Access: http://localhost:3000
```

---

## Configuration

Edit `.env` in the honeypot directory:

```env
# Email Alerts (Required)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your_email@gmail.com
SENDER_PASSWORD=your_app_password
RECIPIENT_EMAIL=your_email@gmail.com

# Optional: AbuseIPDB Reporting
ABUSEIPDB_API_KEY=your_api_key

# Alert Throttling
EMAIL_THROTTLE_SECONDS=300
EMAIL_MAX_PER_HOUR=20

# System
MAX_HANDLER_THREADS=50
HONEYPOT_LOG_FILE=./honeypot.log
```

**Gmail App Password:** https://support.google.com/accounts/answer/185833

---

## Uninstall

**Linux/macOS:**
```bash
sudo bash uninstall.sh
```

**Windows:**
```powershell
.\uninstall.ps1
# Remove services only, keep files:
.\uninstall.ps1 -KeepFiles
```

---

## Output Files

| File | Purpose |
|------|---------|
| `honeypot.log` | JSONL-formatted attack events |
| `ioc_export.json` | Threat intelligence indicators |
| `blocked_ips.txt` | Firewall-blocked IP addresses |
| `fail2ban_manual.log` | Critical attacker records |
| `attacker_history.json` | Behavioral profiles and history |

---

## Operational Notes

- **Privileged Ports**: Binding ports below 1024 requires root/Administrator
- **Port Conflicts**: In-use ports are automatically skipped
- **ML Models**: Pre-trained; retrain with `python ml/ml_pipeline.py train data/honeypot_synthetic.json`
- **AbuseIPDB**: Optional; leave `ABUSEIPDB_API_KEY` empty to disable
- **Firewall Integration**: iptables (Tier 2) Linux-only; Windows/macOS log only

---

## Support

For issues, configuration assistance, or feature requests, please open an issue on the project repository.

**License:** MIT
