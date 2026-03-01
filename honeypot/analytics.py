#!/usr/bin/env python3
"""
HoneyPot Analytics Dashboard
Shows attack statistics from the shared log file.

Fixes vs original:
  - Log path from shared config (not hardcoded)
  - Bare except replaced with explicit exception logging
  - Command injection in open_logs() removed — uses shlex + allowlist
  - Timestamp slice guarded against short strings
"""

import json
import logging
import os
import shlex
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from config import LOG_FILE


# ── Log loading ────────────────────────────────────────────────────────────────

def load_logs() -> list[dict]:
    """Load and parse JSONL honeypot log. Returns list of attack dicts."""
    attacks: list[dict] = []

    if not LOG_FILE.exists():
        return attacks

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                attacks.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logging.debug(f"Skipping malformed log line {lineno}: {exc}")

    return attacks


# ── Summary stats ──────────────────────────────────────────────────────────────

def get_attack_summary(attacks: list[dict]) -> dict | None:
    if not attacks:
        return None

    services      = Counter(a.get("service", "Unknown") for a in attacks)
    countries     = Counter(
        a.get("info", {}).get("country", "Unknown")
        for a in attacks
        if a.get("info", {}).get("country") not in (None, "Unknown", "")
    )
    attack_types  = Counter(
        a.get("info", {}).get("attack_signature", "")
        for a in attacks
        if a.get("info", {}).get("attack_signature")
    )
    unique_ips    = len({a.get("attacker_ip") for a in attacks if a.get("attacker_ip")})
    timestamps    = [a.get("timestamp", "") for a in attacks if a.get("timestamp")]
    first         = min(timestamps, default="N/A")
    last          = max(timestamps, default="N/A")

    return {
        "total_attacks":   len(attacks),
        "unique_attackers": unique_ips,
        "services":        dict(services.most_common(10)),
        "countries":       dict(countries.most_common(10)),
        "attack_types":    dict(attack_types.most_common(10)),
        "first_attack":    first,
        "last_attack":     last,
    }


def _fmt_ts(ts: str) -> str:
    """Safely trim timestamp to 19 chars (YYYY-MM-DDTHH:MM:SS)."""
    return ts[:19] if len(ts) >= 19 else ts


# ── Dashboard rendering ────────────────────────────────────────────────────────

def print_dashboard() -> None:
    attacks = load_logs()
    summary = get_attack_summary(attacks)

    width = 70
    print("\n" + "=" * width)
    print("  HONEYPOT ANALYTICS DASHBOARD".center(width))
    print("=" * width)

    if not summary:
        print("\n  No attacks recorded yet.")
        print(f"\n  Log file: {LOG_FILE}")
        print("=" * width)
        return

    first_ts = _fmt_ts(summary["first_attack"]) if summary["first_attack"] != "N/A" else "N/A"
    last_ts  = _fmt_ts(summary["last_attack"])  if summary["last_attack"]  != "N/A" else "N/A"

    print(f"""
  OVERVIEW
  {'─' * 65}
  Total Attacks:     {summary['total_attacks']}
  Unique Attackers:  {summary['unique_attackers']}
  Time Range:        {first_ts}
                     to {last_ts}
""")

    _print_section("TOP ATTACKED SERVICES", summary["services"], bar_max=30)
    _print_section("TOP ATTACK SOURCES (Countries)", summary["countries"], bar_max=30)

    print("  ATTACK TYPES")
    print(f"  {'─' * 65}")
    for attack_type, count in summary["attack_types"].items():
        label = attack_type.split(" - ")[0][:40] if " - " in attack_type else attack_type[:40]
        bar   = "█" * min(count, 20)
        print(f"  {label:40}  {count:4}  {bar}")

    print("""
  RECENT ATTACKS (Last 5)
  ─────────────────────────────────────────────────────────────────""")
    for attack in attacks[-5:]:
        ip      = attack.get("attacker_ip",   "Unknown")
        service = attack.get("service",       "Unknown")
        port    = attack.get("honeypot_port", "?")
        ts      = _fmt_ts(attack.get("timestamp", ""))
        country = attack.get("info", {}).get("country", "N/A")
        print(f"  [{ts}] {ip:15} → {service:12} (port {port!s:5}) [{country}]")

    print(f"""
  {'─' * 65}
  Log File:    {LOG_FILE}
  Total Lines: {len(attacks)}
  {'=' * 65}""")


def _print_section(title: str, data: dict, bar_max: int = 30) -> None:
    print(f"  {title}")
    print(f"  {'─' * 65}")
    for label, count in data.items():
        bar = "█" * min(count, bar_max)
        print(f"  {label:15}  {count:4}  {bar}")
    print()


# ── Log viewer ─────────────────────────────────────────────────────────────────

def open_logs() -> None:
    """Open the log file in a safe, allowlisted text editor."""
    editors = ["mousepad", "gedit", "kate", "nano", "less"]
    for editor in editors:
        if shutil.which(editor):
            print(f"Opening log with: {editor}")
            # Use list form — never shell=True with user-influenced paths
            os.execvp(editor, [editor, str(LOG_FILE)])
            return  # execvp replaces process, this is unreachable on success
    print(f"No GUI editor found. Log file is at:\n  {LOG_FILE}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--open-logs":
        open_logs()
    elif arg == "--help":
        print("Usage: python3 analytics.py [--open-logs | --help]")
        print("  (no args)    Print the analytics dashboard")
        print("  --open-logs  Open the log file in a text editor")
        print("  --help       Show this help message")
    else:
        print_dashboard()


if __name__ == "__main__":
    main()
