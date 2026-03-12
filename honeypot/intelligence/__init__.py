"""
Attacker Intelligence Module

Provides enhanced attacker information gathering:
- Multi-API geolocation with fallback
- Network intelligence (ISP, ASN, proxy/VPN detection)
- Detailed location data
- Attacker history tracking
"""

from .attacker_info import (
    EnhancedAttackerInfo,
    AttackerHistory,
    get_attacker_info_singleton,
)

__all__ = [
    "EnhancedAttackerInfo",
    "AttackerHistory",
    "get_attacker_info_singleton",
]
