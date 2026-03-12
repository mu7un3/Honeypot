#!/usr/bin/env python3
"""
HoneyPot Alert System — v2.0
Upgrades over v1:
  - Real-time ML scoring on every connection (attack type, threat score, anomaly, cluster)
  - Payload capture — reads what the attacker actually sends
  - UDP listener support (DNS:53, SNMP:161, TFTP:69)
  - IP watchlist + repeat-offender tracking
  - Automated attacker response:
      Tier 1 (any)        → log + desktop + email alert
      Tier 2 (score ≥ 6)  → iptables block + AbuseIPDB report + IOC file
      Tier 3 (score ≥ 8)  → enriched alert + fail2ban rule + country geo-block if 3+ hits
  - Attack rate timeline logging
  - IOC export (JSON)
"""

import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import smtplib

# ── Add honeypot root to path so ml_pipeline can import config ────────────────
sys.path.insert(0, str(Path(__file__).parent))

from config import (
    ATTACK_SIGNATURES,
    EMAIL_CONFIG,
    EMAIL_MAX_PER_HOUR,
    EMAIL_THROTTLE_SECONDS,
    HONEYPOT_PORTS,
    LOG_FILE,
    MAX_HANDLER_THREADS,
    MODELS_DIR,
    BASE_DIR,
    validate_email_config,
)

# ── Enhanced Attacker Intelligence ─────────────────────────────────────────────
from intelligence.attacker_info import get_attacker_info_singleton

# ── Optional AbuseIPDB reporting ───────────────────────────────────────────────
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED   = bool(ABUSEIPDB_API_KEY)
ABUSEIPDB_MIN_SCORE = float(os.getenv("ABUSEIPDB_MIN_SCORE", "6"))

# ── IOC / block files ──────────────────────────────────────────────────────────
IOC_FILE         = BASE_DIR / "ioc_export.json"
BLOCKED_IPS_FILE = BASE_DIR / "blocked_ips.txt"

# ── UDP ports (subset of HONEYPOT_PORTS that should use UDP) ──────────────────
UDP_PORTS = {53: "DNS", 69: "TFTP", 161: "SNMP", 162: "SNMP-TRAP"}

# ── Logging ────────────────────────────────────────────────────────────────────

def setup_logging() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(),
        ],
    )


# ── ML — lazy-loaded singleton ─────────────────────────────────────────────────

_ml_instance = None
_ml_lock     = threading.Lock()

def get_ml():
    global _ml_instance
    if _ml_instance is not None:
        return _ml_instance
    with _ml_lock:
        if _ml_instance is not None:
            return _ml_instance
        try:
            from ml.ml_pipeline import HoneypotML
            ml = HoneypotML()
            ml.load_models(MODELS_DIR)
            _ml_instance = ml
            if ml.is_trained:
                logging.info("ML models loaded successfully.")
            else:
                logging.warning("ML models not trained — rule-based mode active.")
        except Exception as exc:
            logging.warning(f"ML unavailable: {exc}")
            _ml_instance = None
    return _ml_instance


# ── In-memory state ────────────────────────────────────────────────────────────

attack_db:    dict = defaultdict(list)   # ip → [event, ...]
watchlist:    dict = defaultdict(int)    # ip → hit count
country_hits: dict = defaultdict(set)   # country → {ip, ...}
blocked_ips:  set  = set()
state_lock         = threading.Lock()

# Alert throttling
_last_email_time:       dict[str, float] = {}
_email_count_this_hour: list[float]      = []
_throttle_lock = threading.Lock()


# ── Load previously blocked IPs on startup ────────────────────────────────────

def _load_blocked_ips() -> None:
    if BLOCKED_IPS_FILE.exists():
        with open(BLOCKED_IPS_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip:
                    blocked_ips.add(ip)
        logging.info(f"Loaded {len(blocked_ips)} previously blocked IPs.")


# ── Email alerting ─────────────────────────────────────────────────────────────

def _can_send_email(attacker_ip: str) -> bool:
    now = time.time()
    with _throttle_lock:
        if now - _last_email_time.get(attacker_ip, 0) < EMAIL_THROTTLE_SECONDS:
            return False
        _email_count_this_hour[:] = [t for t in _email_count_this_hour if now - t < 3600]
        if len(_email_count_this_hour) >= EMAIL_MAX_PER_HOUR:
            return False
        _last_email_time[attacker_ip] = now
        _email_count_this_hour.append(now)
        return True


def _format_email_body(
    attacker_ip: str,
    port: int,
    service: str,
    info: dict,
    threat_score: float,
    severity: str,
    attack_type: str,
    hit_count: int,
    payload_decoded: str = "",
) -> str:
    """Format enhanced email alert body with comprehensive attacker information."""
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    
    # Build security flags section
    security_flags = []
    if info.get("is_tor"):
        security_flags.append("Tor Exit Node")
    if info.get("is_vpn"):
        security_flags.append("VPN Provider")
    if info.get("is_proxy"):
        security_flags.append("Proxy Detected")
    if info.get("is_hosting"):
        security_flags.append("Hosting/Datacenter")
    if info.get("attacker_profile", {}).get("is_returning"):
        security_flags.append("Repeat Offender")
    
    security_section = ""
    if security_flags:
        security_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  SECURITY FLAGS                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  {'  |  '.join(security_flags):<68} │
│  Risk Score: {info.get('proxy_risk_score', 0)}/100{' ' * 55} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build attacker profile section
    profile = info.get("attacker_profile", {})
    profile_section = ""
    if profile.get("is_returning"):
        profile_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  ATTACKER HISTORY                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  First Seen:     {profile.get('first_seen', 'N/A'):<52} │
│  Last Seen:      {profile.get('last_seen', 'N/A'):<52} │
│  Total Attacks:  {str(profile.get('total_attacks', 0)):<52} │
│  Attacks/Day:    {str(profile.get('attacks_per_day', 0)):<52} │
│  Persistence:    {f"{profile.get('persistence_score', 0):.1f}/10":<52} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build location section
    location_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  LOCATION INFORMATION                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  City:           {f"{info.get('city', 'Unknown')}, {info.get('region', '')}".strip():<52} │
│  Country:        {f"{info.get('country', 'Unknown')} ({info.get('country_code', '')})".strip():<52} │
│  Continent:      {info.get('continent', 'Unknown'):<52} │
│  Coordinates:    {f"{info.get('lat', 0):.4f}, {info.get('lon', 0):.4f}":<52} │
│  Postal:         {info.get('postal', 'Unknown'):<52} │
│  Timezone:       {info.get('timezone', 'Unknown'):<52} │
│  UTC Offset:     {info.get('utc_offset', 'Unknown'):<52} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build network section
    network_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  NETWORK INFORMATION                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ISP:            {info.get('isp', 'Unknown'):<52} │
│  ASN:            {info.get('asn', 'Unknown'):<52} │
│  Organization:   {info.get('org', 'Unknown'):<52} │
│  Connection:     {info.get('connection_type', 'Unknown'):<52} │
│  Reverse DNS:    {info.get('reverse_dns', 'Unknown'):<52} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build supplemental section
    supplemental_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  SUPPLEMENTAL DATA                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Currency:       {info.get('currency', 'Unknown'):<52} │
│  Languages:      {info.get('languages', 'Unknown'):<52} │
│  Calling Code:   {info.get('calling_code', 'Unknown'):<52} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build threat indicators section
    indicators = info.get("threat_indicators", [])
    indicators_section = ""
    if indicators:
        indicators_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  THREAT INDICATORS                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  {'  |  '.join(indicators):<68} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build payload section
    payload_section = ""
    if payload_decoded and payload_decoded.strip():
        payload_preview = payload_decoded[:400].replace("\n", "\\n")
        if len(payload_decoded) > 400:
            payload_preview += "... (truncated)"
        payload_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  CAPTURED PAYLOAD                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  {payload_preview:<68} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Build ML analysis section
    ml_section = f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  ML ANALYSIS                                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Attack Type:    {attack_type:<52} │
│  Threat Score:   {f"{threat_score:.1f}/10":<52} │
│  Severity:       {severity:<52} │
└─────────────────────────────────────────────────────────────────────────────┘

"""
    
    # Combine all sections
    body = f"""
╔═════════════════════════════════════════════════════════════════════════════╗
║                                                                             ║
║     HONEYPOT SECURITY ALERT                                                 ║
║                                                                             ║
╚═════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│  ALERT SUMMARY                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Attacker IP:    {attacker_ip:<52} │
│  Target Service: {service:<52} │
│  Target Port:    {str(port):<52} │
│  Hit Count:      {str(hit_count):<52} │
│  Timestamp:      {now:<52} │
└─────────────────────────────────────────────────────────────────────────────┘

{security_section}{profile_section}{location_section}{network_section}{supplemental_section}{indicators_section}{ml_section}{payload_section}
═══════════════════════════════════════════════════════════════════════════════

  This is an automated alert from Honeypot v2.1
  View dashboard: http://localhost:3000
  Log file: {LOG_FILE}

═══════════════════════════════════════════════════════════════════════════════
"""
    
    return body


def _format_email_html(
    attacker_ip: str,
    port: int,
    service: str,
    info: dict,
    threat_score: float,
    severity: str,
    attack_type: str,
    hit_count: int,
    payload_decoded: str = "",
) -> str:
    """Format HTML email alert with comprehensive attacker information."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")

    # Severity color
    severity_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "INFO": "#6b7280",
    }
    severity_color = severity_colors.get(severity, "#6b7280")

    # Security flags HTML
    security_flags_html = ""
    if info.get("is_tor"):
        security_flags_html += '<span style="background:#fee2e2;color:#dc2626;padding:4px 8px;border-radius:4px;margin:2px;display:inline-block;">Tor Exit Node</span>'
    if info.get("is_vpn"):
        security_flags_html += '<span style="background:#ffedd5;color:#ea580c;padding:4px 8px;border-radius:4px;margin:2px;display:inline-block;">VPN Provider</span>'
    if info.get("is_proxy"):
        security_flags_html += '<span style="background:#fef3c7;color:#ca8a04;padding:4px 8px;border-radius:4px;margin:2px;display:inline-block;">Proxy Detected</span>'
    if info.get("is_hosting"):
        security_flags_html += '<span style="background:#dbeafe;color:#2563eb;padding:4px 8px;border-radius:4px;margin:2px;display:inline-block;">Hosting/Datacenter</span>'
    if info.get("attacker_profile", {}).get("is_returning"):
        security_flags_html += '<span style="background:#f3e8ff;color:#9333ea;padding:4px 8px;border-radius:4px;margin:2px;display:inline-block;">Repeat Offender</span>'

    security_section_html = ""
    if security_flags_html:
        security_section_html = f"""
        <tr>
            <td colspan="2" style="padding:16px;background:#fef2f2;border:1px solid #fecaca;">
                <strong style="color:#dc2626;">Security Flags:</strong><br>
                <div style="margin-top:8px;">{security_flags_html}</div>
                <div style="margin-top:8px;color:#6b7280;font-size:12px;">Risk Score: {info.get('proxy_risk_score', 0)}/100</div>
            </td>
        </tr>
"""

    # Attacker profile HTML
    profile = info.get("attacker_profile", {})
    profile_section_html = ""
    if profile.get("is_returning"):
        profile_section_html = f"""
        <tr>
            <td colspan="2" style="padding:16px;background:#f5f3ff;border:1px solid #e9d5ff;">
                <strong style="color:#9333ea;">Attacker History:</strong>
                <table style="width:100%;margin-top:8px;font-size:13px;">
                    <tr><td style="padding:4px 0;color:#6b7280;">First Seen:</td><td style="padding:4px 0;">{profile.get('first_seen', 'N/A')}</td></tr>
                    <tr><td style="padding:4px 0;color:#6b7280;">Last Seen:</td><td style="padding:4px 0;">{profile.get('last_seen', 'N/A')}</td></tr>
                    <tr><td style="padding:4px 0;color:#6b7280;">Total Attacks:</td><td style="padding:4px 0;">{profile.get('total_attacks', 0)}</td></tr>
                    <tr><td style="padding:4px 0;color:#6b7280;">Attacks/Day:</td><td style="padding:4px 0;">{profile.get('attacks_per_day', 0):.2f}</td></tr>
                    <tr><td style="padding:4px 0;color:#6b7280;">Persistence:</td><td style="padding:4px 0;">{profile.get('persistence_score', 0):.1f}/10</td></tr>
                </table>
            </td>
        </tr>
"""

    # Payload HTML
    payload_html = ""
    if payload_decoded and payload_decoded.strip():
        payload_preview = payload_decoded[:500]
        if len(payload_decoded) > 500:
            payload_preview += "... (truncated)"
        payload_html = f"""
        <tr>
            <td colspan="2" style="padding:16px;background:#f0fdf4;border:1px solid #bbf7d0;">
                <strong style="color:#16a34a;">Captured Payload:</strong>
                <pre style="background:#1f2937;color:#4ade80;padding:12px;border-radius:4px;overflow-x:auto;font-size:11px;margin-top:8px;">{payload_preview}</pre>
            </td>
        </tr>
"""

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; margin:0; padding:20px; background:#f9fafb; }}
        .container {{ max-width:800px; margin:0 auto; background:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ background:linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color:#ffffff; padding:24px; text-align:center; }}
        .header h1 {{ margin:0; font-size:24px; }}
        .content {{ padding:24px; }}
        .section {{ margin-bottom:24px; }}
        .section-title {{ color:#1f2937; font-size:16px; font-weight:600; margin-bottom:12px; border-bottom:2px solid #e5e7eb; padding-bottom:8px; }}
        .info-grid {{ display:grid; grid-template-columns:140px 1fr; gap:8px; font-size:14px; }}
        .info-label {{ color:#6b7280; font-weight:500; }}
        .info-value {{ color:#1f2937; font-family:monospace; }}
        .footer {{ background:#f3f4f6; padding:16px; text-align:center; font-size:12px; color:#6b7280; }}
        .severity-badge {{ display:inline-block; padding:4px 12px; border-radius:4px; color:#ffffff; font-weight:600; font-size:12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Honeypot Security Alert</h1>
            <p style="margin:8px 0 0 0; opacity:0.9;">{now}</p>
        </div>

        <div class="content">
            <!-- Alert Summary -->
            <div class="section">
                <div class="section-title">Alert Summary</div>
                <div class="info-grid">
                    <span class="info-label">Attacker IP:</span>
                    <span class="info-value" style="font-size:16px;font-weight:600;">{attacker_ip}</span>

                    <span class="info-label">Target Service:</span>
                    <span class="info-value">{service}</span>

                    <span class="info-label">Target Port:</span>
                    <span class="info-value">{port}</span>

                    <span class="info-label">Hit Count:</span>
                    <span class="info-value">{hit_count}</span>

                    <span class="info-label">Severity:</span>
                    <span class="severity-badge" style="background:{severity_color};">{severity}</span>
                </div>
            </div>

            {security_section_html}
            {profile_section_html}

            <!-- Location -->
            <div class="section">
                <div class="section-title">Location Information</div>
                <div class="info-grid">
                    <span class="info-label">City:</span>
                    <span class="info-value">{info.get('city', 'Unknown')}, {info.get('region', '')}</span>

                    <span class="info-label">Country:</span>
                    <span class="info-value">{info.get('country', 'Unknown')} ({info.get('country_code', '')})</span>

                    <span class="info-label">Continent:</span>
                    <span class="info-value">{info.get('continent', 'Unknown')}</span>
                    
                    <span class="info-label">Coordinates:</span>
                    <span class="info-value">{info.get('lat', 0):.4f}, {info.get('lon', 0):.4f}</span>
                    
                    <span class="info-label">Timezone:</span>
                    <span class="info-value">{info.get('timezone', 'Unknown')}</span>
                </div>
            </div>

            <!-- Network -->
            <div class="section">
                <div class="section-title">Network Information</div>
                <div class="info-grid">
                    <span class="info-label">ISP:</span>
                    <span class="info-value">{info.get('isp', 'Unknown')}</span>

                    <span class="info-label">ASN:</span>
                    <span class="info-value">{info.get('asn', 'Unknown')}</span>

                    <span class="info-label">Organization:</span>
                    <span class="info-value">{info.get('org', 'Unknown')}</span>

                    <span class="info-label">Connection Type:</span>
                    <span class="info-value">{info.get('connection_type', 'Unknown')}</span>

                    <span class="info-label">Reverse DNS:</span>
                    <span class="info-value">{info.get('reverse_dns', 'Unknown')}</span>
                </div>
            </div>

            <!-- Supplemental -->
            <div class="section">
                <div class="section-title">Supplemental Data</div>
                <div class="info-grid">
                    <span class="info-label">Currency:</span>
                    <span class="info-value">{info.get('currency', 'Unknown')}</span>

                    <span class="info-label">Languages:</span>
                    <span class="info-value">{info.get('languages', 'Unknown')}</span>

                    <span class="info-label">Calling Code:</span>
                    <span class="info-value">{info.get('calling_code', 'Unknown')}</span>
                </div>
            </div>

            <!-- ML Analysis -->
            <div class="section">
                <div class="section-title">ML Analysis</div>
                <div class="info-grid">
                    <span class="info-label">Attack Type:</span>
                    <span class="info-value">{attack_type}</span>

                    <span class="info-label">Threat Score:</span>
                    <span class="info-value">{threat_score:.1f}/10</span>
                </div>
            </div>

            <!-- Threat Indicators -->
            {f'<div class="section"><div class="section-title">Threat Indicators</div><div style="color:#dc2626;">' + ', '.join(info.get('threat_indicators', [])) + '</div></div>' if info.get('threat_indicators') else ''}

            {payload_html}

        </div>

        <div class="footer">
            <p>Automated alert from <strong>Honeypot v2.1</strong></p>
            <p>View dashboard: <a href="http://localhost:3000" style="color:#2563eb;">http://localhost:3000</a></p>
            <p style="margin-top:12px;font-size:11px;color:#9ca3af;">This is an automated security alert. Please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


def send_email_alert(
    attacker_ip: str,
    port: int,
    service: str,
    info: dict,
    threat_score: float,
    severity: str,
    attack_type: str,
    hit_count: int,
    payload_decoded: str = "",
) -> None:
    """
    Send comprehensive email alert with enhanced attacker information.
    
    Args:
        attacker_ip: Source IP address
        port: Target port number
        service: Target service name
        info: Enhanced attacker info dict (from get_attacker_info)
        threat_score: ML threat score (0-10)
        severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        attack_type: ML-predicted attack type
        hit_count: Number of hits from this IP
        payload_decoded: Captured payload text
    """
    if not _can_send_email(attacker_ip):
        logging.debug(f"Email suppressed for {attacker_ip} (throttled)")
        return
    if validate_email_config():
        logging.warning("Email configuration incomplete - cannot send alert")
        return
    
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = EMAIL_CONFIG["sender_email"]
        msg["To"] = EMAIL_CONFIG["recipient_email"]
        msg["Subject"] = f"[{severity}] HONEYPOT ALERT: {service} Attack from {attacker_ip} ({info.get('city', 'Unknown')}, {info.get('country', 'Unknown')})"
        
        # Create plain text and HTML versions
        plain_body = _format_email_body(
            attacker_ip, port, service, info, threat_score, severity, attack_type, hit_count, payload_decoded
        )
        html_body = _format_email_html(
            attacker_ip, port, service, info, threat_score, severity, attack_type, hit_count, payload_decoded
        )
        
        # Attach both versions
        msg.attach(MIMEText(plain_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        
        # Attach log file (optional - comment out if too large)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size < 5 * 1024 * 1024:  # Max 5MB
            try:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(LOG_FILE.read_bytes())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", "attachment; filename=honeypot.log")
                msg.attach(part)
            except Exception as e:
                logging.debug(f"Failed to attach log file: {e}")
        
        # Send email
        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as srv:
            srv.starttls()
            srv.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
            srv.sendmail(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["recipient_email"], msg.as_string())
        
        logging.info(f"Email alert sent for {attacker_ip}:{port} [{severity}]")
    
    except Exception as exc:
        logging.error(f"Failed to send email alert: {exc}")


def send_desktop_notification(
    attacker_ip: str, service: str, port: int, info: dict, severity: str = "MEDIUM"
) -> None:
    urgency = "critical" if severity in ("CRITICAL", "HIGH") else "normal"
    icons   = {"CRITICAL": "security-high", "HIGH": "security-high",
               "MEDIUM": "security-medium", "LOW": "security-low", "INFO": "dialog-information"}
    title = f"[{severity}] {service} Attack — {attacker_ip}"
    body  = (
        f"Port: {port}  |  {info.get('city','?')}, {info.get('country','?')}\n"
        f"ISP: {info.get('isp','?')}  |  Hits: {watchlist.get(attacker_ip, 1)}"
    )
    try:
        subprocess.Popen(
            ["notify-send", "-u", urgency, "-i", icons.get(severity, "security-high"), title, body],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass
    except Exception as exc:
        logging.debug(f"Desktop notification failed: {exc}")


# ── Attacker intelligence ──────────────────────────────────────────────────────

def get_attacker_info(ip: str, port: int = 0, service: str = "Unknown") -> dict:
    """
    Get comprehensive attacker information using enhanced intelligence module.
    
    Returns dict with:
    - Location: city, country, lat, lon, timezone, postal, continent
    - Network: ISP, ASN, org, connection type, reverse DNS
    - Security: proxy/VPN/Tor detection, risk score
    - Supplemental: currency, languages, calling code
    - History: attacker profile (returning visitor, total attacks, etc.)
    """
    # Use enhanced intelligence module
    intel = get_attacker_info_singleton()
    info = intel.get_info(ip, port, service)
    
    # Add attack signature
    info["attack_signature"] = ATTACK_SIGNATURES.get(port, "Unknown attack vector")
    info["threat_indicators"] = []
    
    # Add risk indicators
    if info.get("is_tor"):
        info["threat_indicators"].append("Tor exit node")
    if info.get("is_vpn"):
        info["threat_indicators"].append("VPN provider")
    if info.get("is_proxy"):
        info["threat_indicators"].append("Proxy detected")
    if info.get("is_hosting"):
        info["threat_indicators"].append("Hosting/datacenter IP")
    if info["attacker_profile"].get("is_returning"):
        info["threat_indicators"].append("Repeat offender")
    
    return info


# ── Payload capture ────────────────────────────────────────────────────────────

def capture_payload(client_socket: socket.socket, timeout: float = 2.0) -> bytes:
    """Read up to 4096 bytes from the attacker with a short timeout."""
    client_socket.settimeout(timeout)
    try:
        return client_socket.recv(4096)
    except (socket.timeout, OSError):
        return b""


def decode_payload(raw: bytes) -> str:
    """Decode payload as UTF-8; fall back to hex."""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8", errors="replace").strip()[:500]
    except Exception:
        return raw.hex()[:200]


def extract_ml_features(payload: bytes, port: int, attacker_ip: str) -> dict:
    """Build ml_features dict from live connection data."""
    now         = datetime.now()
    hit_count   = watchlist.get(attacker_ip, 1)
    pl          = payload.lower() if payload else b""

    indicators = []
    if b"select" in pl or b"union" in pl:         indicators.append("sql_injection")
    if b"<script" in pl or b"javascript:" in pl:  indicators.append("xss")
    if b"/etc/passwd" in pl or b"../../" in pl:    indicators.append("path_traversal")
    if b"cmd.exe" in pl or b"/bin/sh" in pl:       indicators.append("command_injection")
    if b"root" in pl or b"admin" in pl or b"password" in pl:
        indicators.append("credential_stuffing")
    if b"metasploit" in pl or b"msfvenom" in pl:  indicators.append("metasploit")
    if b"nmap" in pl or b"masscan" in pl:          indicators.append("scanner_signature")

    return {
        "port_commonality":    1.0 if port in (22, 80, 443, 3306, 3389) else 0.3,
        "requests_per_second": min(float(hit_count), 10.0),
        "unique_payloads":     1,
        "duration_seconds":    1,
        "is_scanning":         int(hit_count > 3),
        "is_exploit":          int(bool(indicators)),
        "is_bruteforce":       int(port in (22, 3389, 21, 23) and hit_count > 2),
        "time_of_day":         now.hour,
        "day_of_week":         now.weekday(),
        "threat_indicators":   indicators,
    }


# ── Attacker response actions ──────────────────────────────────────────────────

def block_ip_firewall(ip: str) -> bool:
    """Add iptables DROP rule. Linux only — silently skips on other platforms."""
    if platform.system() != "Linux" or ip in ("127.0.0.1", "::1"):
        return False
    try:
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
        if check.returncode == 0:
            return True  # already blocked
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(ip + "\n")
        blocked_ips.add(ip)
        logging.warning(f"[BLOCK] {ip} added to iptables DROP.")
        return True
    except (PermissionError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logging.debug(f"iptables block failed for {ip}: {exc}")
        return False


def report_to_abuseipdb(ip: str, port: int, categories: str = "14,18") -> None:
    """Report attacker to AbuseIPDB. Requires ABUSEIPDB_API_KEY in .env"""
    if not ABUSEIPDB_ENABLED or ip in ("127.0.0.1", "::1"):
        return
    try:
        data = urllib.parse.urlencode({
            "ip":         ip,
            "categories": categories,
            "comment":    f"Honeypot hit on port {port} at {datetime.now().isoformat()}",
        }).encode()
        req = urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/report",
            data=data,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
        score = result.get("data", {}).get("abuseConfidenceScore", "?")
        logging.info(f"[ABUSEIPDB] Reported {ip} — confidence score now: {score}%")
    except Exception as exc:
        logging.debug(f"AbuseIPDB report failed for {ip}: {exc}")


def write_ioc(event: dict, ml_result: dict) -> None:
    """Append attacker IOC to ioc_export.json."""
    ioc = {
        "timestamp":    event.get("timestamp"),
        "ip":           event.get("attacker_ip"),
        "port":         event.get("honeypot_port"),
        "service":      event.get("service"),
        "country":      event.get("info", {}).get("country"),
        "city":         event.get("info", {}).get("city"),
        "isp":          event.get("info", {}).get("isp"),
        "asn":          event.get("info", {}).get("asn"),
        "lat":          event.get("info", {}).get("lat"),
        "lon":          event.get("info", {}).get("lon"),
        "reverse_dns":  event.get("info", {}).get("reverse_dns"),
        "attack_type":  ml_result.get("attack_type", {}).get("predicted_type"),
        "threat_score": ml_result.get("threat", {}).get("threat_score"),
        "severity":     ml_result.get("threat", {}).get("severity"),
        "is_anomaly":   ml_result.get("anomaly", {}).get("is_anomaly"),
        "profile":      ml_result.get("cluster", {}).get("profile"),
        "payload_hex":  event.get("payload_hex", ""),
        "indicators":   event.get("info", {}).get("threat_indicators", []),
    }
    try:
        iocs: list = []
        if IOC_FILE.exists():
            try:
                iocs = json.loads(IOC_FILE.read_text())
            except Exception:
                iocs = []
        iocs.append(ioc)
        IOC_FILE.write_text(json.dumps(iocs, indent=2))
    except Exception as exc:
        logging.debug(f"IOC write failed: {exc}")


def add_fail2ban_rule(ip: str) -> None:
    """Write to manual fail2ban-style log for critical attackers."""
    fail2ban_log = BASE_DIR / "fail2ban_manual.log"
    try:
        with open(fail2ban_log, "a") as f:
            f.write(f"{datetime.now().isoformat()} BAN {ip} HONEYPOT-CRITICAL\n")
        logging.info(f"[FAIL2BAN] Logged {ip} to fail2ban_manual.log")
    except Exception:
        pass


def geo_block_country(country: str, ips_from_country: set) -> None:
    """Log geo-block recommendation when 3+ attackers from same country."""
    if len(ips_from_country) < 3:
        return
    block_log = BASE_DIR / "geo_block_recommendations.txt"
    try:
        entry = (
            f"{datetime.now().isoformat()} RECOMMEND-GEO-BLOCK "
            f"country={country} attackers={len(ips_from_country)} "
            f"ips={','.join(list(ips_from_country)[:10])}\n"
        )
        with open(block_log, "a") as f:
            f.write(entry)
        logging.warning(f"[GEO-BLOCK] Recommend blocking {country} ({len(ips_from_country)} attackers)")
    except Exception:
        pass


def take_action(event: dict, ml_result: dict, attacker_ip: str) -> None:
    """
    Tiered response based on ML threat score and repeat-offender count.

    Tier 1 (score < 6):  log + desktop + email
    Tier 2 (score >= 6): + iptables block + AbuseIPDB report + IOC
    Tier 3 (score >= 8): + enriched email + fail2ban + geo-block check
    """
    threat      = ml_result.get("threat", {})
    score       = threat.get("threat_score", 0)
    severity    = threat.get("severity", "INFO")
    recs        = threat.get("recommendations", [])
    attack_type = ml_result.get("attack_type", {}).get("predicted_type", "Unknown")
    anomaly     = ml_result.get("anomaly", {}).get("is_anomaly", False)
    profile     = ml_result.get("cluster", {}).get("profile", "Unknown")
    hit_count   = watchlist.get(attacker_ip, 1)
    info        = event.get("info", {})
    port        = event.get("honeypot_port", 0)
    service     = event.get("service", "Unknown")
    payload     = event.get("payload_decoded", "")

    # Always write IOC
    write_ioc(event, ml_result)

    # Always send desktop notification
    send_desktop_notification(attacker_ip, service, port, info, severity)

    # Send email alert with enhanced information
    send_email_alert(
        attacker_ip=attacker_ip,
        port=port,
        service=service,
        info=info,
        threat_score=score,
        severity=severity,
        attack_type=attack_type,
        hit_count=hit_count,
        payload_decoded=payload,
    )

    # Tier 2: score >= 6 OR repeat offender (5+ hits)
    if score >= 6 or hit_count >= 5:
        logging.warning(
            f"[TIER-2] {attacker_ip} score={score} hits={hit_count} — blocking + reporting"
        )
        block_ip_firewall(attacker_ip)
        cats = "14" if "scan" in attack_type.lower() else "18,15"
        report_to_abuseipdb(attacker_ip, port, categories=cats)

    # Tier 3: score >= 8 or (anomaly + score >= 6)
    if score >= 8 or (anomaly and score >= 6):
        logging.critical(
            f"[TIER-3] CRITICAL attacker {attacker_ip} — fail2ban + geo-block check"
        )
        add_fail2ban_rule(attacker_ip)
        country = info.get("country", "Unknown")
        if country not in ("Unknown", "Localhost", "Local"):
            with state_lock:
                country_hits[country].add(attacker_ip)
                geo_block_country(country, country_hits[country])


# ── Fake service banners ───────────────────────────────────────────────────────

def _send_fake_response(client_socket: socket.socket, service: str) -> None:
    """Send a realistic fake banner to buy time and capture attacker payload."""
    banners: dict[str, bytes] = {
        "FTP":      b"220 FTP server ready\r\n",
        "SSH":      b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
        "TELNET":   b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f\r\nlogin: ",
        "SMTP":     b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
        "HTTP":     (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\n"
                     b"Content-Type: text/html\r\n\r\n"
                     b"<html><body><h1>It works!</h1></body></html>"),
        "HTTPS":    b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n",
        "MYSQL":    b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00",
        "SMB":      b"\x00\x00\x00\x7c\xffSMBr\x00\x00\x00\x00",
        "REDIS":    b"+OK\r\n",
        "POSTGRES": b"N",
        "RDP":      b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00",
        "MONGODB":  b"\x16\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xee\x03\x00\x00\x00",
        "MSSQL":    b"\x04\x01\x00\x25\x00\x00\x01\x00",
        "VNC":      b"RFB 003.008\n",
    }
    svc = service.split("-")[0]
    try:
        resp = banners.get(svc, b"")
        if resp:
            client_socket.send(resp)
    except Exception:
        pass


# ── TCP connection handler ─────────────────────────────────────────────────────

def handle_connection(
    client_socket: socket.socket, addr: tuple, port: int, service: str
) -> None:
    attacker_ip, attacker_port = addr

    # Silently drop already-blocked IPs
    if attacker_ip in blocked_ips:
        try:
            client_socket.close()
        except Exception:
            pass
        return

    with state_lock:
        watchlist[attacker_ip] += 1
        hit_count = watchlist[attacker_ip]

    logging.warning(
        f"[TRAP] {attacker_ip}:{attacker_port} → {service} (port {port}) | hit #{hit_count}"
    )

    # Send fake banner first, then capture attacker response
    _send_fake_response(client_socket, service)
    raw_payload     = capture_payload(client_socket)
    payload_decoded = decode_payload(raw_payload)

    # Geo + WHOIS
    attacker_info = get_attacker_info(attacker_ip, port)

    # ML features + indicator extraction
    ml_features = extract_ml_features(raw_payload, port, attacker_ip)
    attacker_info["threat_indicators"] = ml_features.get("threat_indicators", [])

    event = {
        "attacker_ip":     attacker_ip,
        "attacker_port":   attacker_port,
        "honeypot_port":   port,
        "service":         service,
        "timestamp":       datetime.now().isoformat(),
        "hit_count":       hit_count,
        "payload_hex":     raw_payload.hex() if raw_payload else "",
        "payload_decoded": payload_decoded,
        "ml_features":     ml_features,
        "info":            attacker_info,
    }

    # Real-time ML analysis
    ml_result: dict = {}
    threat_score = 0
    attack_type = "Unknown"
    ml = get_ml()
    if ml:
        try:
            ml_result          = ml.analyze_attack(event)
            event["ml_analysis"] = ml_result
            threat_score    = ml_result.get("threat", {}).get("threat_score", 0)
            severity = ml_result.get("threat", {}).get("severity", "INFO")
            attack_type    = ml_result.get("attack_type", {}).get("predicted_type", "Unknown")
            logging.info(
                f"[ML] {attacker_ip} → {attack_type} | score={threat_score}/10 [{severity}]"
                f" | anomaly={ml_result.get('anomaly',{}).get('is_anomaly', False)}"
                f" | profile={ml_result.get('cluster',{}).get('profile','?')}"
            )
        except Exception as exc:
            logging.warning(f"ML analysis failed for {attacker_ip}: {exc}")
    
    # Record to attacker history (for tracking repeat offenders)
    session_id = f"{attacker_ip}-{port}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    try:
        intel = get_attacker_info_singleton()
        intel.record_attack(attacker_ip, port, service, threat_score, attack_type, session_id)
    except Exception as exc:
        logging.debug(f"Failed to record attacker history: {exc}")

    # Persist to log
    with state_lock:
        attack_db[attacker_ip].append(event)
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as exc:
            logging.error(f"Failed to write log entry: {exc}")

    # Tiered response
    take_action(event, ml_result, attacker_ip)

    try:
        client_socket.close()
    except Exception:
        pass


# ── UDP listener ───────────────────────────────────────────────────────────────

def start_udp_honeypot(port: int, service: str) -> None:
    """Listen on a UDP port and process packets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(1)
        logging.info(f"  Listening on port {port:5d} ({service}) [UDP]")
    except Exception as exc:
        logging.error(f"Failed to bind UDP port {port} ({service}): {exc}")
        return

    while True:
        try:
            data, addr  = sock.recvfrom(4096)
            attacker_ip = addr[0]

            if attacker_ip in blocked_ips:
                continue

            with state_lock:
                watchlist[attacker_ip] += 1

            logging.warning(f"[UDP TRAP] {attacker_ip} → {service} (port {port})")

            ml_features   = extract_ml_features(data, port, attacker_ip)
            attacker_info = get_attacker_info(attacker_ip, port)
            attacker_info["threat_indicators"] = ml_features.get("threat_indicators", [])

            event = {
                "attacker_ip":     attacker_ip,
                "attacker_port":   addr[1],
                "honeypot_port":   port,
                "service":         f"{service}-UDP",
                "timestamp":       datetime.now().isoformat(),
                "hit_count":       watchlist[attacker_ip],
                "payload_hex":     data.hex(),
                "payload_decoded": decode_payload(data),
                "ml_features":     ml_features,
                "info":            attacker_info,
            }

            ml_result: dict = {}
            ml = get_ml()
            if ml:
                try:
                    ml_result          = ml.analyze_attack(event)
                    event["ml_analysis"] = ml_result
                except Exception:
                    pass

            with state_lock:
                attack_db[attacker_ip].append(event)
                try:
                    with open(LOG_FILE, "a") as f:
                        f.write(json.dumps(event) + "\n")
                except Exception:
                    pass

            take_action(event, ml_result, attacker_ip)

        except socket.timeout:
            continue
        except Exception as exc:
            logging.error(f"UDP listener error on port {port}: {exc}")


# ── TCP port listener ──────────────────────────────────────────────────────────

def start_honeypot(port: int, service: str, executor: ThreadPoolExecutor) -> None:
    """Listen on a single TCP port and dispatch connections to the thread pool."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        sock.settimeout(1)
        logging.info(f"  Listening on port {port:5d} ({service}) [TCP]")
    except Exception as exc:
        logging.error(f"Failed to bind port {port} ({service}): {exc}")
        return

    while True:
        try:
            client_socket, addr = sock.accept()
            executor.submit(handle_connection, client_socket, addr, port, service)
        except socket.timeout:
            continue
        except Exception as exc:
            logging.error(f"Listener error on port {port}: {exc}")
            break


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    setup_logging()
    _load_blocked_ips()

    missing = validate_email_config()
    if missing:
        logging.warning(f"Email alerts disabled — set {', '.join(missing)} in .env")

    logging.info("=" * 60)
    logging.info("  HONEYPOT v2.0 — ML-ENHANCED MULTI-PORT TRAP")
    logging.info("=" * 60)
    logging.info(f"  AbuseIPDB: {'ENABLED' if ABUSEIPDB_ENABLED else 'disabled (set ABUSEIPDB_API_KEY)'}")

    # Pre-load ML models in background
    threading.Thread(target=get_ml, daemon=True, name="ml-loader").start()

    executor = ThreadPoolExecutor(max_workers=MAX_HANDLER_THREADS)
    threads  = []

    for port, service in HONEYPOT_PORTS.items():
        if port in UDP_PORTS:
            t = threading.Thread(
                target=start_udp_honeypot,
                args=(port, service),
                daemon=True,
                name=f"udp-{port}",
            )
        else:
            t = threading.Thread(
                target=start_honeypot,
                args=(port, service, executor),
                daemon=True,
                name=f"tcp-{port}",
            )
        t.start()
        threads.append(t)

    tcp_count = len(HONEYPOT_PORTS) - len([p for p in UDP_PORTS if p in HONEYPOT_PORTS])
    udp_count = len([p for p in UDP_PORTS if p in HONEYPOT_PORTS])
    logging.info(f"  Started {len(HONEYPOT_PORTS)} services ({tcp_count} TCP, {udp_count} UDP)")
    logging.info("  Press Ctrl+C to stop")
    logging.info("=" * 60)

    try:
        while True:
            threading.Event().wait(60)
            with state_lock:
                total  = sum(len(v) for v in attack_db.values())
                unique = len(attack_db)
            logging.info(
                f"[STATUS] Unique attackers: {unique} | Total events: {total} | "
                f"Blocked IPs: {len(blocked_ips)}"
            )
    except KeyboardInterrupt:
        logging.info("Shutting down — waiting for active handlers...")
        executor.shutdown(wait=True, cancel_futures=False)
        logging.info("Shutdown complete.")


if __name__ == "__main__":
    main()
