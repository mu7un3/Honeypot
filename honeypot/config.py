#!/usr/bin/env python3
"""
Honeypot Shared Configuration
All settings loaded from environment variables or .env file.

"""

import os
from pathlib import Path

_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ.setdefault(_key.strip(), _val.strip())

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(os.getenv("HONEYPOT_BASE_DIR", Path(__file__).parent))
LOG_FILE   = Path(os.getenv("HONEYPOT_LOG_FILE", BASE_DIR / "honeypot.log"))
MODELS_DIR = Path(os.getenv("HONEYPOT_MODELS_DIR", BASE_DIR / "models"))

# ── Email ─────────────────────────────────────────────────────────────────────
EMAIL_CONFIG = {
    "smtp_server":      os.getenv("SMTP_SERVER",   "smtp.gmail.com"),
    "smtp_port":        int(os.getenv("SMTP_PORT", "587")),
    "sender_email":     os.getenv("SENDER_EMAIL",  ""),
    "sender_password":  os.getenv("SENDER_PASSWORD", ""),   # Set in .env — never hardcode
    "recipient_email":  os.getenv("RECIPIENT_EMAIL", ""),
}

# ── Alert throttling ─────────────────────────────────────────────────────────
# Minimum seconds between email alerts for the same source IP
EMAIL_THROTTLE_SECONDS = int(os.getenv("EMAIL_THROTTLE_SECONDS", "300"))
# Max emails per hour across all events
EMAIL_MAX_PER_HOUR = int(os.getenv("EMAIL_MAX_PER_HOUR", "20"))

# ── Thread pool ───────────────────────────────────────────────────────────────
MAX_HANDLER_THREADS = int(os.getenv("MAX_HANDLER_THREADS", "50"))

# ── Honeypot ports ────────────────────────────────────────────────────────────
HONEYPOT_PORTS: dict[int, str] = {
    # File Transfer
    20: "FTP-DATA", 21: "FTP", 69: "TFTP", 115: "SFTP",
    # Remote Access
    22: "SSH", 23: "TELNET", 2222: "SSH-ALT",
    # Email
    25: "SMTP", 110: "POP3", 143: "IMAP",
    465: "SMTPS", 587: "SMTP-SUB", 993: "IMAPS", 995: "POP3S",
    # Web
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-PROXY",
    8443: "HTTPS-ALT", 8888: "HTTP-ALT", 8000: "HTTP-DEV",
    5000: "HTTP-FLASK", 3000: "HTTP-NODE", 4000: "HTTP-DEV2",
    # Database
    1433: "MSSQL", 3306: "MYSQL", 5432: "POSTGRES",
    6379: "REDIS", 27017: "MONGODB", 9042: "CASSANDRA",
    # Messaging
    1883: "MQTT", 5672: "AMQP", 61613: "STOMP",
    # Remote Desktop
    3389: "RDP", 5900: "VNC", 5901: "VNC-1",
    # File/Printer sharing
    139: "NETBIOS-SSN", 445: "SMB", 515: "LPD", 631: "IPP",
    # DNS / Network
    53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT", 123: "NTP",
    # Directory
    389: "LDAP", 636: "LDAPS",
    # Management
    161: "SNMP", 162: "SNMP-TRAP",
    # IoT / Streaming
    554: "RTSP", 8554: "RTSP-ALT",
    9000: "HTTP-ALT2", 8081: "HTTP-ALT3",
    # VPN
    1723: "PPTP", 4500: "IPSEC",
    # Dev
    10000: "WEB-DEV", 20000: "WEB-DEV2",
}

# ── Attack signature map (port → description) ─────────────────────────────────
ATTACK_SIGNATURES: dict[int, str] = {
    21:    "FTP Attack — possible anonymous login or credential stuffing",
    22:    "SSH Attack — brute force or automated exploitation attempt",
    23:    "Telnet Attack — legacy service probe, possible default credential attack",
    25:    "SMTP Attack — email server probe, possible spam relay attempt",
    110:   "POP3 Attack — email credential brute force",
    143:   "IMAP Attack — email server attack",
    445:   "SMB Attack — Windows share enumeration, possible exploit (e.g. EternalBlue)",
    1433:  "MSSQL Attack — database brute force or exploitation",
    3306:  "MySQL Attack — database brute force or SQL injection probe",
    3389:  "RDP Attack — Windows remote desktop brute force or BlueKeep probe",
    5432:  "PostgreSQL Attack — database attack",
    6379:  "Redis Attack — unauthenticated access or data exfiltration attempt",
    8080:  "HTTP Proxy Attack — web proxy scan or CGI-proxy abuse",
    8443:  "HTTPS-Alt Attack — SSL service enumeration",
    27017: "MongoDB Attack — unauthenticated access or injection attempt",
}

# ── ML settings ───────────────────────────────────────────────────────────────
ML_N_CLUSTERS        = int(os.getenv("ML_N_CLUSTERS",   "5"))
ML_CONTAMINATION     = float(os.getenv("ML_CONTAMINATION", "0.1"))
ML_N_ESTIMATORS      = int(os.getenv("ML_N_ESTIMATORS", "100"))
ML_TEST_SIZE         = float(os.getenv("ML_TEST_SIZE",  "0.2"))
ML_THREAT_RULE_WEIGHT = float(os.getenv("ML_THREAT_RULE_WEIGHT", "0.6"))
ML_THREAT_ML_WEIGHT  = 1.0 - ML_THREAT_RULE_WEIGHT

# ── Validate required email settings ─────────────────────────────────────────
def validate_email_config() -> list[str]:
    """Return list of missing required email settings."""
    missing = []
    for key in ("sender_email", "sender_password", "recipient_email"):
        if not EMAIL_CONFIG[key]:
            missing.append(key.upper())
    return missing
