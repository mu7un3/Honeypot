#!/usr/bin/env python3
"""
Enhanced Attacker Intelligence Module

Provides:
- Multi-API geolocation with fallback chain
- Network intelligence (ISP, ASN, proxy/VPN/tor detection)
- Detailed location data (timezone, currency, languages, etc.)
- Attacker history tracking

Usage:
    from intelligence.attacker_info import EnhancedAttackerInfo
    
    info = EnhancedAttackerInfo()
    result = info.get_info("185.220.101.42")
    print(result)
"""

import json
import logging
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────

# Geolocation APIs in priority order (free tiers)
GEO_APIS = [
    {
        "name": "ipapi.co",
        "url": "https://ipapi.co/{ip}/json/",
        "timeout": 5,
        "fields": {
            "ip": "ip",
            "city": "city",
            "region": "region",
            "country": "country_name",
            "country_code": "country_code",
            "postal": "postal",
            "lat": "latitude",
            "lon": "longitude",
            "timezone": "timezone",
            "utc_offset": "utc_offset",
            "country_calling_code": "country_calling_code",
            "currency": "currency",
            "languages": "languages",
            "asn": "asn",
            "org": "org",
        },
        "rate_limit": 1000,  # requests per day
    },
    {
        "name": "ip-api.com",
        "url": "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
        "timeout": 5,
        "fields": {
            "ip": "query",
            "city": "city",
            "region": "regionName",
            "country": "country",
            "country_code": "countryCode",
            "postal": "zip",
            "lat": "lat",
            "lon": "lon",
            "timezone": "timezone",
            "utc_offset": "",
            "country_calling_code": "",
            "currency": "",
            "languages": "",
            "asn": "as",
            "org": "org",
            "isp": "isp",
            "reverse_dns": "reverse",
            "mobile": "mobile",
            "proxy": "proxy",
            "hosting": "hosting",
        },
        "rate_limit": 45,  # requests per minute
    },
    {
        "name": "ipinfo.io",
        "url": "https://ipinfo.io/{ip}/json",
        "timeout": 5,
        "fields": {
            "ip": "ip",
            "city": "city",
            "region": "region",
            "country": "country",
            "postal": "postal",
            "lat": "loc",  # split "lat,lon"
            "lon": "loc",
            "timezone": "timezone",
            "asn": "org",
            "org": "org",
        },
        "rate_limit": 50000,  # requests per month
    },
]

# ── Data Files ─────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent
ATTACKER_HISTORY_FILE = BASE_DIR / "attacker_history.json"
COUNTRY_DATA_FILE = BASE_DIR / "country_data.json"

# ── Country Supplemental Data ─────────────────────────────────────────────────

COUNTRY_INFO = {
    "US": {"currency": "USD", "languages": "en-US,es-US", "calling_code": "+1"},
    "CN": {"currency": "CNY", "languages": "zh-CN", "calling_code": "+86"},
    "RU": {"currency": "RUB", "languages": "ru", "calling_code": "+7"},
    "DE": {"currency": "EUR", "languages": "de", "calling_code": "+49"},
    "GB": {"currency": "GBP", "languages": "en-GB", "calling_code": "+44"},
    "FR": {"currency": "EUR", "languages": "fr", "calling_code": "+33"},
    "IN": {"currency": "INR", "languages": "en-IN,hi", "calling_code": "+91"},
    "BR": {"currency": "BRL", "languages": "pt-BR", "calling_code": "+55"},
    "JP": {"currency": "JPY", "languages": "ja", "calling_code": "+81"},
    "KR": {"currency": "KRW", "languages": "ko", "calling_code": "+82"},
    "UA": {"currency": "UAH", "languages": "uk", "calling_code": "+380"},
    "VN": {"currency": "VND", "languages": "vi", "calling_code": "+84"},
    "NL": {"currency": "EUR", "languages": "nl", "calling_code": "+31"},
    "CA": {"currency": "CAD", "languages": "en-CA,fr-CA", "calling_code": "+1"},
    "AU": {"currency": "AUD", "languages": "en-AU", "calling_code": "+61"},
}

# ── Attacker History Tracking ─────────────────────────────────────────────────

class AttackerHistory:
    """Track attacker behavior over time"""
    
    def __init__(self):
        self.history: dict = defaultdict(lambda: {
            "first_seen": None,
            "last_seen": None,
            "total_attacks": 0,
            "ports_targeted": set(),
            "services_targeted": set(),
            "countries_reported": set(),
            "threat_scores": [],
            "attack_types": set(),
            "sessions": [],
        })
        self._lock = threading.Lock()
        self._load()
    
    def _load(self):
        """Load history from file"""
        if ATTACKER_HISTORY_FILE.exists():
            try:
                with open(ATTACKER_HISTORY_FILE) as f:
                    data = json.load(f)
                for ip, info in data.items():
                    self.history[ip]["first_seen"] = info.get("first_seen")
                    self.history[ip]["last_seen"] = info.get("last_seen")
                    self.history[ip]["total_attacks"] = info.get("total_attacks", 0)
                    self.history[ip]["ports_targeted"] = set(info.get("ports_targeted", []))
                    self.history[ip]["services_targeted"] = set(info.get("services_targeted", []))
                    self.history[ip]["threat_scores"] = info.get("threat_scores", [])
                    self.history[ip]["attack_types"] = set(info.get("attack_types", []))
                logging.info(f"Loaded attacker history for {len(self.history)} IPs")
            except Exception as e:
                logging.error(f"Failed to load attacker history: {e}")
    
    def _save(self):
        """Save history to file"""
        try:
            data = {}
            for ip, info in self.history.items():
                data[ip] = {
                    "first_seen": info["first_seen"],
                    "last_seen": info["last_seen"],
                    "total_attacks": info["total_attacks"],
                    "ports_targeted": list(info["ports_targeted"]),
                    "services_targeted": list(info["services_targeted"]),
                    "threat_scores": info["threat_scores"],
                    "attack_types": list(info["attack_types"]),
                }
            with open(ATTACKER_HISTORY_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save attacker history: {e}")
    
    def record_attack(self, ip: str, port: int, service: str, threat_score: float, 
                      attack_type: str, session_id: str = None):
        """Record an attack event"""
        now = datetime.now().isoformat()
        with self._lock:
            h = self.history[ip]
            if h["first_seen"] is None:
                h["first_seen"] = now
            h["last_seen"] = now
            h["total_attacks"] += 1
            h["ports_targeted"].add(port)
            h["services_targeted"].add(service)
            h["threat_scores"].append(threat_score)
            h["attack_types"].add(attack_type)
            if session_id:
                h["sessions"].append({
                    "session_id": session_id,
                    "timestamp": now,
                    "port": port,
                    "service": service,
                })
            # Keep only last 100 sessions
            h["sessions"] = h["sessions"][-100:]
            # Keep only last 50 threat scores
            h["threat_scores"] = h["threat_scores"][-50:]
            self._save()
    
    def get_profile(self, ip: str) -> dict:
        """Get attacker profile"""
        h = self.history.get(ip, {})
        if not h.get("first_seen"):
            return {"is_returning": False, "is_new": True}
        
        first = datetime.fromisoformat(h["first_seen"])
        last = datetime.fromisoformat(h["last_seen"])
        days_active = max(1, (last - first).days)
        
        return {
            "is_returning": True,
            "is_new": False,
            "first_seen": h["first_seen"],
            "last_seen": h["last_seen"],
            "total_attacks": h["total_attacks"],
            "unique_ports": len(h["ports_targeted"]),
            "unique_services": len(h["services_targeted"]),
            "avg_threat_score": sum(h["threat_scores"]) / len(h["threat_scores"]) if h["threat_scores"] else 0,
            "attacks_per_day": round(h["total_attacks"] / days_active, 2),
            "attack_types": list(h["attack_types"]),
            "persistence_score": min(10, h["total_attacks"] / 10 + len(h["ports_targeted"])),
            "sessions": h.get("sessions", [])[-10:],
        }


# ── Enhanced Attacker Info ─────────────────────────────────────────────────────

class EnhancedAttackerInfo:
    """Get comprehensive attacker information"""
    
    def __init__(self):
        self.history = AttackerHistory()
        self._api_usage = defaultdict(int)
        self._last_api_reset = datetime.now()
    
    def _reset_api_counters(self):
        """Reset API usage counters daily"""
        now = datetime.now()
        if (now - self._last_api_reset).days > 0:
            self._api_usage.clear()
            self._last_api_reset = now
    
    def _fetch_geo(self, ip: str) -> Optional[dict]:
        """Fetch geolocation from APIs with fallback chain"""
        self._reset_api_counters()
        
        for api in GEO_APIS:
            # Check rate limit
            if self._api_usage[api["name"]] >= api["rate_limit"]:
                logging.debug(f"Skipping {api['name']} - rate limit reached")
                continue
            
            try:
                url = api["url"].format(ip=ip)
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "HoneypotMonitor/2.1"}
                )
                with urllib.request.urlopen(req, timeout=api["timeout"]) as resp:
                    data = json.loads(resp.read().decode())
                
                self._api_usage[api["name"]] += 1
                
                # Parse response
                result = {}
                for key, field in api["fields"].items():
                    if field:
                        if field == "loc" and key in ("lat", "lon"):
                            # Handle "lat,lon" format
                            parts = data.get(field, "0,0").split(",")
                            idx = 0 if key == "lat" else 1
                            result[key] = float(parts[idx]) if len(parts) > idx else 0
                        else:
                            result[key] = data.get(field, "")
                    else:
                        result[key] = ""
                
                result["source"] = api["name"]
                result["success"] = True
                return result
                
            except Exception as e:
                logging.debug(f"Geo API {api['name']} failed: {e}")
                continue
        
        return None
    
    def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "No reverse DNS"
    
    def _get_whois(self, ip: str) -> dict:
        """Get WHOIS information"""
        result = {
            "asn": "Unknown",
            "org": "Unknown",
            "country": "Unknown",
            "city": "Unknown",
            "raw": "WHOIS lookup failed",
        }
        
        try:
            cmd_result = subprocess.run(
                ["whois", ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            whois_data = cmd_result.stdout or ""
            result["raw"] = whois_data[:5000]
            
            for line in whois_data.splitlines():
                line_lower = line.lower()
                if "originas:" in line_lower or "asn:" in line_lower:
                    result["asn"] = line.split(":", 1)[1].strip()
                elif "orgname:" in line_lower or "org:" in line_lower:
                    result["org"] = line.split(":", 1)[1].strip()
                elif "country:" in line_lower:
                    result["country"] = line.split(":", 1)[1].strip()
                elif "city:" in line_lower:
                    result["city"] = line.split(":", 1)[1].strip()
                    
        except Exception as e:
            logging.debug(f"WHOIS lookup failed: {e}")
        
        return result
    
    def _supplement_country_data(self, country_code: str) -> dict:
        """Get supplemental country data"""
        base = COUNTRY_INFO.get(country_code, {})
        return {
            "currency": base.get("currency", "Unknown"),
            "languages": base.get("languages", "Unknown"),
            "calling_code": base.get("calling_code", "Unknown"),
        }
    
    def _detect_connection_type(self, isp: str, org: str, asn: str) -> str:
        """Detect connection type based on ISP/org"""
        isp_lower = (isp + " " + org + " " + asn).lower()
        
        if any(x in isp_lower for x in ["hosting", "cloud", "aws", "azure", "google", "digitalocean", "ovh", "hetzner"]):
            return "hosting/datacenter"
        elif any(x in isp_lower for x in ["mobile", "cellular", "wireless", "lte", "5g"]):
            return "mobile"
        elif any(x in isp_lower for x in ["broadband", "cable", "fiber", "dsl", "telecom"]):
            return "broadband"
        elif any(x in isp_lower for x in ["university", "college", "edu"]):
            return "education"
        elif any(x in isp_lower for x in ["bank", "finance", "corp", "enterprise"]):
            return "corporate"
        
        return "unknown"
    
    def _detect_proxy_vpn(self, geo_data: dict) -> dict:
        """Detect proxy/VPN/Tor usage"""
        result = {
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_hosting": False,
            "risk_score": 0,
        }
        
        # Check API flags
        if geo_data.get("proxy"):
            result["is_proxy"] = True
            result["risk_score"] += 30
        if geo_data.get("hosting"):
            result["is_hosting"] = True
            result["risk_score"] += 20
        
        # Check for Tor exit nodes (common patterns)
        org = (geo_data.get("org", "") + " " + geo_data.get("asn", "")).lower()
        if any(x in org for x in ["tor", "tor2web", "torservers"]):
            result["is_tor"] = True
            result["risk_score"] += 50
        
        # Check for known VPN providers
        vpn_providers = ["nordvpn", "expressvpn", "cyberghost", "surfshark", "protonvpn", 
                        "private internet access", "mullvad", "windscribe"]
        if any(x in org for x in vpn_providers):
            result["is_vpn"] = True
            result["risk_score"] += 25
        
        return result
    
    def get_info(self, ip: str, port: int = 0, service: str = "Unknown") -> dict:
        """Get comprehensive attacker information"""
        
        # Initialize base info
        info = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "port": port,
            "service": service,
            # Location
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "country_code": "Unknown",
            "postal": "Unknown",
            "continent": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "timezone": "Unknown",
            "utc_offset": "Unknown",
            # Network
            "isp": "Unknown",
            "asn": "Unknown",
            "org": "Unknown",
            "connection_type": "Unknown",
            "reverse_dns": "Unknown",
            # Supplemental
            "currency": "Unknown",
            "languages": "Unknown",
            "calling_code": "Unknown",
            # Security
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_hosting": False,
            "proxy_risk_score": 0,
            # History
            "attacker_profile": {},
            # Source
            "geo_source": "None",
        }
        
        # Localhost check
        if ip in ("127.0.0.1", "::1", "localhost"):
            info.update({
                "country": "Localhost",
                "city": "Local",
                "isp": "Local",
                "timezone": "UTC",
            })
            return info
        
        # 1. Reverse DNS
        info["reverse_dns"] = self._get_reverse_dns(ip)
        
        # 2. WHOIS
        whois = self._get_whois(ip)
        info.update({
            "asn": whois.get("asn", info["asn"]),
            "org": whois.get("org", info["org"]),
        })
        
        # 3. Geolocation APIs
        geo = self._fetch_geo(ip)
        if geo and geo.get("success"):
            info.update({
                "city": geo.get("city", info["city"]),
                "region": geo.get("region", info["region"]),
                "country": geo.get("country", info["country"]),
                "country_code": geo.get("country_code", info["country_code"]),
                "postal": geo.get("postal", info["postal"]),
                "lat": float(geo.get("lat", 0)) if geo.get("lat") else 0.0,
                "lon": float(geo.get("lon", 0)) if geo.get("lon") else 0.0,
                "timezone": geo.get("timezone", info["timezone"]),
                "utc_offset": geo.get("utc_offset", info["utc_offset"]),
                "isp": geo.get("isp", info["isp"]),
                "asn": geo.get("asn", info["asn"]),
                "org": geo.get("org", info["org"]),
                "geo_source": geo.get("source", "Unknown"),
            })
            
            # Proxy/VPN detection from API
            if geo.get("proxy"):
                info["is_proxy"] = True
            if geo.get("hosting"):
                info["is_hosting"] = True
            if geo.get("mobile"):
                info["connection_type"] = "mobile"
        
        # 4. Supplemental country data
        if info["country_code"] != "Unknown":
            country_data = self._supplement_country_data(info["country_code"])
            info.update(country_data)
        
        # 5. Connection type detection
        info["connection_type"] = self._detect_connection_type(
            info["isp"], info["org"], info["asn"]
        )
        
        # 6. Proxy/VPN/Tor detection
        proxy_info = self._detect_proxy_vpn(info)
        info.update(proxy_info)
        
        # 7. Attacker history
        info["attacker_profile"] = self.history.get_profile(ip)
        
        # 8. Determine continent
        info["continent"] = self._get_continent(info["country_code"])
        
        return info
    
    def _get_continent(self, country_code: str) -> str:
        """Get continent from country code"""
        continent_map = {
            "US": "North America", "CA": "North America", "MX": "North America",
            "CN": "Asia", "IN": "Asia", "JP": "Asia", "KR": "Asia", "VN": "Asia",
            "RU": "Europe/Asia", "UA": "Europe", "DE": "Europe", "GB": "Europe",
            "FR": "Europe", "NL": "Europe",
            "BR": "South America", "AR": "South America",
            "AU": "Oceania", "NZ": "Oceania",
            "ZA": "Africa", "EG": "Africa", "NG": "Africa",
        }
        return continent_map.get(country_code, "Unknown")
    
    def record_attack(self, ip: str, port: int, service: str, 
                      threat_score: float, attack_type: str, session_id: str = None):
        """Record attack to history"""
        self.history.record_attack(ip, port, service, threat_score, attack_type, session_id)


# ── Singleton Instance ─────────────────────────────────────────────────────────

_attacker_info_instance: Optional[EnhancedAttackerInfo] = None
_info_lock = threading.Lock()


def get_attacker_info_singleton() -> EnhancedAttackerInfo:
    """Get singleton instance of EnhancedAttackerInfo"""
    global _attacker_info_instance
    if _attacker_info_instance is None:
        with _info_lock:
            if _attacker_info_instance is None:
                _attacker_info_instance = EnhancedAttackerInfo()
    return _attacker_info_instance


# ── CLI Test ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    
    info = EnhancedAttackerInfo()
    
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = "185.220.101.42"  # Example Tor exit node
    
    print(f"\n{'='*60}")
    print(f"  Enhanced Attacker Intelligence Report")
    print(f"  IP: {ip}")
    print(f"{'='*60}\n")
    
    result = info.get_info(ip)
    
    print("📍 LOCATION")
    print(f"   City:         {result['city']}, {result['region']}")
    print(f"   Country:      {result['country']} ({result['country_code']})")
    print(f"   Continent:    {result['continent']}")
    print(f"   Postal:       {result['postal']}")
    print(f"   Coordinates:  {result['lat']}, {result['lon']}")
    print(f"   Timezone:     {result['timezone']} ({result['utc_offset']})")
    
    print(f"\n🌐 NETWORK")
    print(f"   ISP:          {result['isp']}")
    print(f"   ASN:          {result['asn']}")
    print(f"   Org:          {result['org']}")
    print(f"   Type:         {result['connection_type']}")
    print(f"   Reverse DNS:  {result['reverse_dns']}")
    
    print(f"\n📋 SUPPLEMENTAL")
    print(f"   Currency:     {result['currency']}")
    print(f"   Languages:    {result['languages']}")
    print(f"   Calling Code: {result['calling_code']}")
    
    print(f"\n🔒 SECURITY")
    print(f"   Proxy:        {'⚠️ YES' if result['is_proxy'] else 'No'}")
    print(f"   VPN:          {'⚠️ YES' if result['is_vpn'] else 'No'}")
    print(f"   Tor:          {'⚠️ YES' if result['is_tor'] else 'No'}")
    print(f"   Hosting:      {'⚠️ YES' if result['is_hosting'] else 'No'}")
    print(f"   Risk Score:   {result['proxy_risk_score']}/100")
    
    print(f"\n📊 HISTORY")
    profile = result['attacker_profile']
    if profile.get('is_returning'):
        print(f"   Returning:    Yes")
        print(f"   First Seen:   {profile['first_seen'][:10]}")
        print(f"   Last Seen:    {profile['last_seen'][:10]}")
        print(f"   Total Attacks: {profile['total_attacks']}")
        print(f"   Attacks/Day:  {profile['attacks_per_day']}")
        print(f"   Avg Threat:   {profile['avg_threat_score']:.1f}")
        print(f"   Persistence:  {profile['persistence_score']:.1f}/10")
    else:
        print(f"   First time attacker")
    
    print(f"\n📡 Geo Source: {result['geo_source']}")
    print(f"{'='*60}\n")
