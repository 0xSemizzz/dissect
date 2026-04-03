"""
IPInfo.io IP geolocation + ASN lookups.
"""
import hashlib
import logging
from typing import Dict, Any, List, Optional
import aiohttp
from db.models import Database
from db import queries
from config import IPINFO_API_KEY, IPINFO_CACHE_TTL_HOURS

logger = logging.getLogger(__name__)

IPINFO_BASE_URL = "https://ipinfo.io"

# Known suspicious hosting indicators
SUSPICIOUS_ASN_KEYWORDS = [
    "bulletproof",
    "offshore",
    "anonymous",
    "vpn",
    "proxy",
    "tor",
]


class IPInfoClient:
    def __init__(self, api_key: Optional[str] = None, db: Optional[Database] = None):
        self.api_key = api_key or IPINFO_API_KEY
        self.db = db

    async def lookup_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """
        Look up IP geolocation + ASN info.
        Returns list of dicts with IPInfo data per IP.
        """
        if not ips:
            return []

        results = []
        for ip in ips:
            try:
                result = await self._lookup_single_ip(ip)
                results.append({"ip": ip, "ipinfo": result or {}})
            except Exception as e:
                logger.warning("IPInfo lookup failed for %s: %s", ip, e)
                results.append({"ip": ip, "ipinfo": {}})

        return results

    async def _lookup_single_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up a single IP on IPInfo."""
        cache_key = f"ipinfo_{hashlib.sha256(ip.encode()).hexdigest()}"

        if self.db:
            cached = await queries.get_enrichment_cache(self.db, cache_key)
            if cached:
                return cached

        async def fetch():
            params = {}
            if self.api_key:
                params["token"] = self.api_key

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{IPINFO_BASE_URL}/{ip}/json",
                    params=params,
                ) as response:
                    if response.status != 200:
                        logger.warning("IPInfo API error: %d", response.status)
                        return None

                    data = await response.json()
                    if "bogon" in data:
                        return {"status": "bogon", "note": "Private/reserved IP range"}

                    return self._parse_response(data)

        result = await fetch()

        if result and self.db:
            await queries.set_enrichment_cache(self.db, cache_key, result, IPINFO_CACHE_TTL_HOURS)

        return result

    def _parse_response(self, data: dict) -> Dict[str, Any]:
        """Parse IPInfo response into simplified format."""
        org = data.get("org", "unknown")
        country = data.get("country", "unknown")
        city = data.get("city", "unknown")
        region = data.get("region", "unknown")

        # Extract ASN from org field (format: "AS12345 Organization Name")
        asn = "unknown"
        org_name = org
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            asn = parts[0]
            org_name = parts[1] if len(parts) > 1 else org

        # Check for suspicious indicators
        is_suspicious = self._is_suspicious_hosting(org, asn)

        # Check for known Tor exit nodes (simplified — would use a dedicated list in production)
        is_tor = "tor" in org.lower() or "tor" in data.get("hostname", "").lower()

        return {
            "country": country,
            "region": region,
            "city": city,
            "org": org_name,
            "asn": asn,
            "hostname": data.get("hostname", "unknown"),
            "is_tor": is_tor,
            "is_suspicious_hosting": is_suspicious,
            "suspicion_reason": self._get_suspicion_reason(org, asn) if is_suspicious else None,
        }

    def _is_suspicious_hosting(self, org: str, asn: str) -> bool:
        """Check if the hosting org/ASN matches known suspicious patterns."""
        combined = f"{org} {asn}".lower()
        return any(keyword in combined for keyword in SUSPICIOUS_ASN_KEYWORDS)

    def _get_suspicion_reason(self, org: str, asn: str) -> Optional[str]:
        """Get reason for suspicion."""
        combined = f"{org} {asn}".lower()
        for keyword in SUSPICIOUS_ASN_KEYWORDS:
            if keyword in combined:
                return f"Hosting provider matches known {keyword} service"
        return None
