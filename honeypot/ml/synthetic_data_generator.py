#!/usr/bin/env python3
"""
Synthetic Attack Data Generator for Honeypot ML Training
Generates realistic attack patterns for training ML models
"""

import random
import json
import datetime
from collections import defaultdict

# Realistic attack patterns based on honeypot research
ATTACK_PATTERNS = {
    "SSH Brute Force": {
        "ports": [22],
        "typical_duration": (60, 3600),
        "requests_per_minute": (10, 100),
        "payloads": ["root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle"],
        "countries": ["CN", "RU", "US", "IN", "KR", "BR", "UA", "VN"],
    },
    "FTP Attack": {
        "ports": [21],
        "typical_duration": (30, 1800),
        "requests_per_minute": (5, 50),
        "payloads": ["anonymous", "ftp", "user", "admin"],
        "countries": ["CN", "US", "RU", "IN", "BR"],
    },
    "Telnet Brute Force": {
        "ports": [23],
        "typical_duration": (120, 3600),
        "requests_per_minute": (5, 30),
        "payloads": ["root", "admin", "user", "guest"],
        "countries": ["CN", "RU", "US", "IN", "KR"],
    },
    "SMB Exploit": {
        "ports": [445, 139],
        "typical_duration": (10, 300),
        "requests_per_minute": (1, 20),
        "payloads": ["\\IPC$", "\\ADMIN$", "smb", " EternalBlue", " WannaCry"],
        "countries": ["US", "RU", "CN", "UA", "GB"],
    },
    "HTTP Web Scan": {
        "ports": [80, 443, 8080, 8443],
        "typical_duration": (60, 3600),
        "requests_per_minute": (20, 200),
        "payloads": ["/admin", "/phpinfo", "/.env", "/wp-admin", "/login", "/shell"],
        "countries": ["US", "CN", "RU", "DE", "NL", "FR"],
    },
    "MySQL Attack": {
        "ports": [3306],
        "typical_duration": (30, 600),
        "requests_per_minute": (5, 30),
        "payloads": ["root", "admin", "mysql", "test"],
        "countries": ["US", "CN", "RU", "IN", "DE"],
    },
    "PostgreSQL Attack": {
        "ports": [5432],
        "typical_duration": (30, 600),
        "requests_per_minute": (5, 30),
        "payloads": ["postgres", "admin", "root"],
        "countries": ["US", "CN", "RU", "DE"],
    },
    "Redis Attack": {
        "ports": [6379],
        "typical_duration": (10, 300),
        "requests_per_minute": (3, 20),
        "payloads": ["CONFIG", "SET", "GET", "FLUSHALL"],
        "countries": ["US", "CN", "RU", "DE", "NL"],
    },
    "MongoDB Attack": {
        "ports": [27017],
        "typical_duration": (20, 300),
        "requests_per_minute": (3, 15),
        "payloads": ["admin", "root", "user"],
        "countries": ["US", "CN", "RU", "DE"],
    },
    "RDP Brute Force": {
        "ports": [3389],
        "typical_duration": (300, 7200),
        "requests_per_minute": (5, 50),
        "payloads": ["administrator", "admin", "user"],
        "countries": ["US", "RU", "CN", "IN", "BR"],
    },
    "Port Scan": {
        "ports": list(range(1, 1024)),
        "typical_duration": (5, 300),
        "requests_per_minute": (100, 1000),
        "payloads": [],
        "countries": ["US", "CN", "RU", "KR", "IN"],
    },
    "DNS Amplification": {
        "ports": [53],
        "typical_duration": (1, 60),
        "requests_per_minute": (1000, 10000),
        "payloads": ["ANY", "TXT"],
        "countries": ["US", "RU", "CN", "UA"],
    },
    "IoT Exploit": {
        "ports": [554, 8554, 8080, 9000],
        "typical_duration": (10, 180),
        "requests_per_minute": (1, 10),
        "payloads": ["Hikvision", "DVR", "NVR", "RTSP", "ONVIF"],
        "countries": ["CN", "US", "RU", "KR", "TW"],
    },
}

# Country code to name mapping
COUNTRY_NAMES = {
    "CN": "China", "RU": "Russia", "US": "United States", "IN": "India",
    "KR": "South Korea", "BR": "Brazil", "UA": "Ukraine", "VN": "Vietnam",
    "DE": "Germany", "NL": "Netherlands", "FR": "France", "GB": "United Kingdom",
    "JP": "Japan", "TW": "Taiwan", "TR": "Turkey", "IT": "Italy",
    "ES": "Spain", "PL": "Poland", "CA": "Canada", "AU": "Australia",
}

# ISP patterns by country
ISP_PATTERNS = {
    "CN": ["China Telecom", "China Unicom", "China Mobile", "Aliyun", "Tencent Cloud"],
    "US": ["Amazon", "Google", "Cloudflare", "DigitalOcean", "Linode"],
    "RU": ["Rostelecom", "MTS", "Beeline", "Yandex"],
    "IN": ["Airtel", "Jio", "Vodafone", "BSNL"],
    "DE": ["Deutsche Telekom", "OVH", "Hetzner", "Telekom"],
}

def generate_ip():
    """Generate realistic attack IP"""
    # More likely to be from certain ranges (malware-infected networks)
    if random.random() < 0.3:
        # Private/VPN ranges (simulating NAT)
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    elif random.random() < 0.5:
        # Cloud providers
        return f"{random.choice([52, 54, 34, 35, 18])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        # Random public IP
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_attack_timestamp(base_time, duration_hours=7):
    """Generate attack timestamp within a time window"""
    offset = random.randint(0, duration_hours * 3600)
    return base_time - datetime.timedelta(seconds=offset)

def generate_attack(attack_type, base_time):
    """Generate a single attack record"""
    pattern = ATTACK_PATTERNS[attack_type]
    
    # Generate basic info
    ip = generate_ip()
    country = random.choice(pattern["countries"])
    country_name = COUNTRY_NAMES.get(country, country)
    
    # Generate location (rough coordinates)
    lat, lon = get_country_coordinates(country)
    
    # Generate timestamp
    timestamp = generate_attack_timestamp(base_time)
    
    # Generate port and service
    port = random.choice(pattern["ports"])
    service = get_service_name(port)
    
    # Generate payload (if any)
    payload = random.choice(pattern["payloads"]) if pattern["payloads"] else None
    
    # Generate additional metadata
    requests_count = random.randint(*pattern["requests_per_minute"]) * random.randint(1, 10)
    duration = random.randint(*pattern["typical_duration"])
    
    # Generate attacker info
    isp = random.choice(ISP_PATTERNS.get(country, ["Unknown ISP"]))
    asn = f"AS{random.randint(1000, 65000)}"
    
    # Generate threat indicators
    threat_indicators = generate_threat_indicators(attack_type, port)
    
    return {
        "attacker_ip": ip,
        "attacker_port": random.randint(1024, 65535),
        "honeypot_port": port,
        "service": service,
        "timestamp": timestamp.isoformat(),
        "attack_type": attack_type,
        "payload": payload,
        "requests_count": requests_count,
        "duration_seconds": duration,
        "info": {
            "ip": ip,
            "country": country_name,
            "country_code": country,
            "city": generate_city(country),
            "isp": isp,
            "asn": asn,
            "lat": round(lat, 6),
            "lon": round(lon, 6),
            "reverse_dns": generate_reverse_dns(ip, isp),
            "attack_signature": generate_signature(attack_type, port),
            "threat_indicators": threat_indicators,
            "malware_family": random.choice([None, "Mirai", "Botena", "Mozi", "Gafgyt", "Emotet"]) if random.random() < 0.1 else None,
        },
        "ml_features": {
            "requests_per_second": round(requests_count / max(duration, 1), 2),
            "unique_payloads": len(set(pattern["payloads"])) if pattern["payloads"] else 0,
            "port_commonality": 1.0 if port in [21, 22, 23, 80, 443, 3306, 3389, 5432, 6379] else 0.3,
            "is_scanning": 1 if attack_type == "Port Scan" else 0,
            "is_exploit": 1 if "Exploit" in attack_type else 0,
            "is_bruteforce": 1 if "Brute Force" in attack_type else 0,
            "time_of_day": timestamp.hour,
            "day_of_week": timestamp.weekday(),
        }
    }

def generate_threat_indicators(attack_type, port):
    """Generate threat indicators based on attack type"""
    indicators = []
    
    if "Brute Force" in attack_type:
        indicators.append("multiple_auth_attempts")
        indicators.append("credential_stuffing")
    if "Exploit" in attack_type:
        indicators.append("known_cve_poc")
        indicators.append("buffer_overflow_attempt")
    if attack_type == "Port Scan":
        indicators.append("network_reconnaissance")
        indicators.append("port_probing")
    if port in [21, 23]:
        indicators.append("legacy_protocol")
    if "SMB" in attack_type:
        indicators.append("smb_exploit_kit")
        indicators.append("eternalblue_indicator")
    if "HTTP" in attack_type:
        indicators.append("web_scan")
        indicators.append("vulnerability_probe")
    
    return indicators

def get_service_name(port):
    """Map port to service name"""
    services = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 445: "SMB", 443: "HTTPS",
        3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES", 6379: "REDIS",
        8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 27017: "MONGODB",
        554: "RTSP", 8554: "RTSP-ALT", 9000: "HTTP-ALT",
    }
    return services.get(port, f"PORT-{port}")

def get_country_coordinates(country_code):
    """Get approximate coordinates for a country"""
    coords = {
        "CN": (35.8617, 104.1954), "US": (37.0902, -95.7129), "RU": (61.5240, 105.3188),
        "IN": (20.5937, 78.9629), "KR": (35.9078, 127.7669), "BR": (-14.2350, -51.9253),
        "UA": (48.3794, 31.1656), "DE": (51.1657, 10.4515), "NL": (52.1326, 5.2913),
        "FR": (46.2276, 2.2137), "GB": (55.3781, -3.4360), "JP": (36.2048, 138.2529),
    }
    base = coords.get(country_code, (0, 0))
    # Add some randomness
    return base[0] + random.uniform(-5, 5), base[1] + random.uniform(-10, 10)

def generate_city(country):
    """Generate city name"""
    cities = {
        "CN": ["Beijing", "Shanghai", "Shenzhen", "Guangzhou", "Hangzhou"],
        "US": ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"],
        "RU": ["Moscow", "St. Petersburg", "Novosibirsk", "Yekaterinburg"],
        "IN": ["Mumbai", "Delhi", "Bangalore", "Hyderabad", "Chennai"],
        "DE": ["Berlin", "Munich", "Frankfurt", "Hamburg"],
    }
    return random.choice(cities.get(country, ["Unknown City"]))

def generate_reverse_dns(ip, isp):
    """Generate realistic reverse DNS"""
    if random.random() < 0.3:
        return None
    domains = ["static", "dynamic", "broadband", "host", "server"]
    return f"host-{random.randint(1,255)}.{random.choice(domains)}.net"

def generate_signature(attack_type, port):
    """Generate attack signature description"""
    signatures = {
        "SSH Brute Force": "SSH authentication brute force - automated credential stuffing",
        "FTP Attack": "FTP anonymous login probe or brute force attempt",
        "Telnet Brute Force": "Telnet credential brute force - legacy service attack",
        "SMB Exploit": "SMB/Windows share enumeration or EternalBlue exploit attempt",
        "HTTP Web Scan": "Web application reconnaissance - directory/file probe",
        "MySQL Attack": "MySQL database authentication attack",
        "PostgreSQL Attack": "PostgreSQL database brute force attempt",
        "Redis Attack": "Redis NoSQL injection or unauthorized access",
        "MongoDB Attack": "MongoDB unauthenticated access attempt",
        "RDP Brute Force": "Windows Remote Desktop brute force attack",
        "Port Scan": "Network reconnaissance - port sweeping",
        "DNS Amplification": "DNS amplification DDoS reflection attack",
        "IoT Exploit": "Internet of Things vulnerability exploitation",
    }
    return signatures.get(attack_type, f"{attack_type} attack detected")

def generate_dataset(num_attacks=10000, output_file="honeypot_synthetic.json"):
    """Generate synthetic honeypot dataset"""
    print(f"Generating {num_attacks} synthetic attack records...")
    
    # Base time (7 days ago)
    base_time = datetime.datetime.now() - datetime.timedelta(days=7)
    
    attacks = []
    attack_types = list(ATTACK_PATTERNS.keys())
    
    # Weighted attack type distribution
    weights = [15, 10, 8, 12, 20, 8, 6, 8, 5, 10, 15, 3, 4]
    
    for i in range(num_attacks):
        # Choose attack type based on weights
        attack_type = random.choices(attack_types, weights=weights)[0]
        
        attack = generate_attack(attack_type, base_time)
        attacks.append(attack)
        
        if (i + 1) % 1000 == 0:
            print(f"  Generated {i + 1}/{num_attacks} attacks...")
    
    # Sort by timestamp
    attacks.sort(key=lambda x: x["timestamp"])
    
    # Save to file
    with open(output_file, "w") as f:
        for attack in attacks:
            f.write(json.dumps(attack) + "\n")
    
    print(f"\nDataset saved to: {output_file}")
    print(f"Total attacks: {len(attacks)}")
    
    # Print statistics
    attack_counts = defaultdict(int)
    country_counts = defaultdict(int)
    for attack in attacks:
        attack_counts[attack["attack_type"]] += 1
        country_counts[attack["info"]["country"]] += 1
    
    print("\nAttack type distribution:")
    for attack_type, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        print(f"  {attack_type}: {count} ({100*count/len(attacks):.1f}%)")
    
    print("\nTop countries:")
    for country, count in sorted(country_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {country}: {count}")
    
    return attacks

def generate_training_data(attacks):
    """Generate training-ready CSV from attack data"""
    import csv
    
    output_file = "honeypot_training_data.csv"
    
    # Define features and label
    features = [
        "port", "requests_per_second", "unique_payloads", "port_commonality",
        "is_scanning", "is_exploit", "is_bruteforce", "time_of_day", "day_of_week"
    ]
    
    # Attack type labels (encoded as numbers)
    attack_labels = {t: i for i, t in enumerate(ATTACK_PATTERNS.keys())}
    
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(features + ["attack_type", "threat_level"])
        
        for attack in attacks:
            ml = attack["ml_features"]
            row = [
                attack["honeypot_port"],
                ml["requests_per_second"],
                ml["unique_payloads"],
                ml["port_commonality"],
                ml["is_scanning"],
                ml["is_exploit"],
                ml["is_bruteforce"],
                ml["time_of_day"],
                ml["day_of_week"],
                attack["attack_type"],
                calculate_threat_level(attack),
            ]
            writer.writerow(row)
    
    print(f"\nTraining data saved to: {output_file}")
    return output_file

def calculate_threat_level(attack):
    """Calculate threat level (0-10)"""
    level = 3.0  # Base level
    
    # Increase based on attack type
    if "Brute Force" in attack["attack_type"]:
        level += 3
    if "Exploit" in attack["attack_type"]:
        level += 4
    if "Scan" in attack["attack_type"]:
        level += 1
    if attack["info"].get("malware_family"):
        level += 3
    
    # Increase based on indicators
    indicators = attack["info"].get("threat_indicators", [])
    level += min(len(indicators), 3)
    
    return min(10.0, level)

if __name__ == "__main__":
    import sys
    
    num_attacks = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    output_file = sys.argv[2] if len(sys.argv) > 2 else "honeypot_synthetic.json"
    
    attacks = generate_dataset(num_attacks, output_file)
    generate_training_data(attacks)
