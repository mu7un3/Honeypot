# ML-Enhanced Honeypot System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

A production-grade, multi-port honeypot with real-time machine learning attack classification,
threat scoring, anomaly detection, attacker profiling, automated tiered response actions,
and a live Next.js analytics dashboard.

Runs as a **system service** on Windows, Linux, and macOS — auto-starts on boot.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      honeypot.py (v2.0)                     │
│  50+ TCP ports  +  UDP (DNS/SNMP/TFTP)                      │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │ Payload      │→  │  ML Pipeline │→  │ Tiered Response│  │
│  │ Capture      │   │  (real-time) │   │  Tier 1/2/3    │  │
│  └──────────────┘   └──────────────┘   └────────────────┘  │
│         ↓                   ↓                    ↓          │
│   honeypot.log        ioc_export.json      iptables / fail2ban
└─────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────┐
│             Next.js Dashboard (port 3000)                   │
│  Timeline · Severity · ML Charts · Map · Live Feed · IOC   │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### Honeypot (50+ ports)
- TCP: SSH, Telnet, FTP, SMTP, HTTP, HTTPS, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB, VNC, MSSQL, LDAP, and 35+ more
- UDP: DNS (53), SNMP (161/162), TFTP (69)
- Realistic fake banners per service
- Payload capture with hex/text decode
- IP watchlist + repeat-offender tracking
- Blocked-IP list loaded on startup (silently drops known-bad IPs)

### Machine Learning (real-time)
| Model | Algorithm | Metric |
|-------|-----------|--------|
| Attack Classification | Random Forest | 100% accuracy |
| Anomaly Detection | Isolation Forest | — |
| Threat Scoring | Gradient Boosting Regressor | MAE 0.013 |
| Attacker Profiling | K-Means Clustering | 5 profiles |

### Tiered Response
| Tier | Trigger | Actions |
|------|---------|---------|
| 1 | Any hit | Log + desktop notification + email alert |
| 2 | Score ≥ 6 OR 5+ hits | iptables block + AbuseIPDB report + IOC file write |
| 3 | Score ≥ 8 OR (anomaly + score ≥ 6) | fail2ban log + enriched critical email + geo-block recommendation |

### Analytics Dashboard
- 6 stat cards: Total Attacks, Unique Attackers, Blocked IPs, Avg Threat Score, Critical Hits, Anomalies
- Area chart timeline (last 24 h, 10-min buckets)
- Severity breakdown, ML Attack Classification, Attacker Profiles donut
- Leaflet world attack map
- Live feed table with click-to-expand detail panel
- Export IOC button → downloads `ioc_export_YYYY-MM-DD.json`

---

## Requirements

| Tool | Version |
|------|---------|
| Python | 3.10+ |
| Node.js | 18+ LTS |

The installers auto-download these via `winget` (Windows), `apt`/`brew` (Linux/macOS).

---

## Installation

### Linux (Ubuntu / Debian) — systemd service

```bash
# Clone or extract the package
git clone https://github.com/your-username/honeypot.git
cd honeypot

# Run the installer as root
sudo bash install.sh
```

The installer:
1. Installs Python 3 and Node.js 20 (via `apt` + NodeSource) if missing
2. Installs Python packages: `scikit-learn numpy requests python-dotenv`
3. Copies files to `/opt/honeypot/`
4. Creates `/opt/honeypot/.env` from template (edit it — see Configuration)
5. Trains ML models
6. Registers and starts two **systemd** services:
   - `honeypot` — the multi-port trap (auto-starts on boot)
   - `honeypot-dashboard` — the Next.js web dashboard on port 3000

**Service management:**
```bash
sudo systemctl status  honeypot
sudo systemctl restart honeypot
sudo systemctl stop    honeypot
sudo journalctl -u honeypot -f          # live logs

sudo systemctl status  honeypot-dashboard
sudo journalctl -u honeypot-dashboard -f
```

**Skip service registration (manual start):**
```bash
sudo bash install.sh --no-service

# Then start manually:
sudo PYTHONPATH=/opt/honeypot python3 /opt/honeypot/honeypot.py &
cd /opt/honeypot/honeypot-analytics && npm run start
```

---

### macOS — launchd agent

```bash
# Homebrew and Xcode CLI tools must be installed, or the script installs them
cd honeypot-package
bash install.sh
```

The installer:
1. Installs Python 3.11 and Node.js 20 via Homebrew if missing
2. Copies files to `~/honeypot/`
3. Creates `~/honeypot/.env` from template
4. Trains ML models
5. Registers two **launchd** agents (auto-start on login):
   - `com.honeypot` — honeypot daemon
   - `com.honeypot.dashboard` — Next.js dashboard on port 3000

> **Note:** macOS requires root (`sudo`) to bind ports below 1024 (SSH:22, HTTP:80, etc.).
> The launchd agent runs under your user by default. For privileged ports, move the plists
> to `/Library/LaunchDaemons/` and run the installer as root.

**Service management:**
```bash
launchctl stop  com.honeypot
launchctl start com.honeypot
tail -f ~/honeypot/honeypot-stdout.log    # live log

launchctl stop  com.honeypot.dashboard
launchctl start com.honeypot.dashboard
tail -f ~/honeypot/dashboard-stdout.log
```

---

### Windows — Windows Service (NSSM)

Open **PowerShell as Administrator** and run:

```powershell
cd honeypot-package
.\install.ps1
```

The installer:
1. Auto-installs Python 3.11 and Node.js LTS via `winget` if missing
2. Installs Python packages
3. Copies files to `C:\honeypot\`
4. Opens `C:\honeypot\.env` in Notepad for you to fill in credentials
5. Trains ML models
6. Downloads **NSSM** and registers two Windows services:
   - `honeypot` — starts automatically at boot
   - `honeypot-dashboard` — Next.js dashboard on port 3000

**Custom install path or port:**
```powershell
.\install.ps1 -InstallDir "D:\security\honeypot" -DashboardPort 8080
```

**Skip service registration:**
```powershell
.\install.ps1 -NoService
```

**Service management:**
```powershell
Get-Service honeypot, honeypot-dashboard
Restart-Service honeypot
Stop-Service honeypot
Get-Content C:\honeypot\honeypot-stdout.log -Wait   # live log
```
Or open `services.msc` and look for **honeypot** / **honeypot-dashboard**.

---

### Desktop / Developer (any OS — no service)

```bash
# Linux / macOS — manual start
cd honeypot-package
pip3 install scikit-learn numpy requests python-dotenv
PYTHONPATH=$(pwd)/honeypot python3 honeypot/ml/ml_pipeline.py train honeypot/data/honeypot_synthetic.json
sudo PYTHONPATH=$(pwd)/honeypot python3 honeypot/honeypot.py

# Dashboard (separate terminal)
cd honeypot-analytics && npm install && npm run dev
# Open http://localhost:3000
```

```batch
:: Windows CMD (run as Administrator)
cd honeypot-package
SETUP.bat
honeypot\start_honeypot.bat
start_dashboard.bat
```

---

## Uninstall

**Linux / macOS:**
```bash
sudo bash uninstall.sh
```

**Windows (PowerShell as Administrator):**
```powershell
.\uninstall.ps1
# Keep files but remove services only:
.\uninstall.ps1 -KeepFiles
```

---

## Configuration (`honeypot/.env` or `C:\honeypot\.env` or `/opt/honeypot/.env`)

```env
# Email alerts
SENDER_EMAIL=you@gmail.com
RECIPIENT_EMAIL=you@gmail.com
SENDER_PASSWORD=xxxx-xxxx-xxxx-xxxx   # Gmail App Password

# Optional — AbuseIPDB auto-reporting (Tier 2)
ABUSEIPDB_API_KEY=your_key_here

# Dashboard log path override (set automatically by installer)
# HONEYPOT_LOG_FILE=/opt/honeypot/honeypot.log

# Throttle / concurrency
EMAIL_THROTTLE_SECONDS=300
EMAIL_MAX_PER_HOUR=20
MAX_HANDLER_THREADS=50
```

Get a Gmail App Password: https://support.google.com/accounts/answer/185833

---

## File Structure

```
honeypot-package/
├── install.sh                       ← Linux + macOS installer (systemd / launchd)
├── install.ps1                      ← Windows installer (NSSM service)
├── uninstall.sh                     ← Linux + macOS uninstaller
├── uninstall.ps1                    ← Windows uninstaller
├── SETUP.bat                        ← Windows quick-setup (no service)
├── start_dashboard.bat              ← Start web dashboard (Windows)
├── README.md
│
├── honeypot/
│   ├── honeypot.py                  ← Main honeypot v2.0 (ML + tiers)
│   ├── config.py                    ← Shared paths / settings
│   ├── analytics.py                 ← Terminal dashboard
│   ├── .env.example                 ← Config template
│   ├── start_honeypot.bat
│   ├── train_ml.bat
│   ├── analytics_dashboard.bat
│   ├── ml/
│   │   ├── ml_pipeline.py           ← HoneypotML (train + infer)
│   │   └── synthetic_data_generator.py
│   ├── data/
│   │   └── honeypot_synthetic.json  ← 5 000 training samples
│   └── models/                      ← Trained .pkl model files
│
└── honeypot-analytics/              ← Next.js web dashboard
    └── src/app/
        ├── page.tsx                 ← Full ML dashboard UI
        └── api/analytics/route.ts  ← Log parser + ML aggregations
```

---

## Runtime Files

| File | Description |
|------|-------------|
| `honeypot.log` | JSONL attack log (one event per line) |
| `ioc_export.json` | IOC list — exported by dashboard or Tier 2 |
| `blocked_ips.txt` | IPs blocked by iptables (Tier 2, Linux) |
| `fail2ban_manual.log` | Critical attacker log for fail2ban (Tier 3) |
| `geo_block_recommendations.txt` | Countries flagged for geo-blocking |

---

## Notes

- Binding ports below 1024 (SSH:22, HTTP:80, etc.) requires **root / Administrator**
- Ports already in use on the host are skipped automatically
- ML models are pre-trained. Re-train anytime: `python ml/ml_pipeline.py train data/honeypot_synthetic.json`
- AbuseIPDB reporting is optional — leave `ABUSEIPDB_API_KEY` blank to skip
- iptables blocking (Tier 2) only works on Linux; Windows/macOS log the block intent without applying firewall rules
