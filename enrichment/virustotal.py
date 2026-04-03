"""
VirusTotal URL and hash reputation lookups.
"""
import asyncio
import hashlib
import logging
from typing import Dict, Any, List, Optional
import aiohttp
from db.models import Database
from db import queries
from config import VIRUSTOTAL_API_KEY, VT_CACHE_TTL_HOURS

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
# Rate limit: 4 requests per minute
VT_RATE_LIMIT_DELAY = 15  # seconds between requests


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None, db: Optional[Database] = None):
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.db = db
        self._last_request_time = 0

    async def _wait_for_rate_limit(self):
        """Enforce rate limiting (4 req/min)."""
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request_time
        if elapsed < VT_RATE_LIMIT_DELAY:
            await asyncio.sleep(VT_RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = asyncio.get_event_loop().time()

    async def _get_cached_or_fetch(self, cache_key: str, fetch_fn) -> Optional[Dict[str, Any]]:
        """Check cache first, then fetch if needed."""
        if self.db:
            cached = await queries.get_enrichment_cache(self.db, cache_key)
            if cached:
                return cached

        await self._wait_for_rate_limit()
        result = await fetch_fn()

        if result and self.db:
            await queries.set_enrichment_cache(self.db, cache_key, result, VT_CACHE_TTL_HOURS)

        return result

    async def lookup_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Look up URL reputation on VirusTotal.
        Returns list of dicts with VT data per URL.
        """
        if not self.api_key or not urls:
            return [{"url": url, "virustotal": {}} for url in urls]

        results = []
        for url in urls:
            try:
                result = await self._lookup_single_url(url)
                results.append({"url": url, "virustotal": result or {}})
            except Exception as e:
                logger.warning("VirusTotal URL lookup failed for %s: %s", url, e)
                results.append({"url": url, "virustotal": {}})

        return results

    async def _lookup_single_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Look up a single URL on VirusTotal."""
        # VT v3 requires base64url encoding of the URL for the API path
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        cache_key = f"vt_url_{hashlib.sha256(url.encode()).hexdigest()}"

        async def fetch():
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{VT_BASE_URL}/urls/{url_id}",
                    headers={"x-apikey": self.api_key},
                ) as response:
                    if response.status == 404:
                        return {"status": "not_found"}
                    if response.status == 429:
                        logger.warning("VirusTotal rate limit hit")
                        return None
                    if response.status != 200:
                        logger.warning("VirusTotal API error: %d", response.status)
                        return None

                    data = await response.json()
                    return self._parse_url_report(data.get("data", {}))

        return await self._get_cached_or_fetch(cache_key, fetch)

    async def lookup_hashes(self, hashes: List[str]) -> List[Dict[str, Any]]:
        """
        Look up hash reputation on VirusTotal.
        Returns list of dicts with VT data per hash.
        """
        if not self.api_key or not hashes:
            return [{"hash": h, "virustotal": {}} for h in hashes]

        results = []
        for h in hashes:
            try:
                result = await self._lookup_single_hash(h)
                results.append({"hash": h, "virustotal": result or {}})
            except Exception as e:
                logger.warning("VirusTotal hash lookup failed for %s: %s", h, e)
                results.append({"hash": h, "virustotal": {}})

        return results

    async def _lookup_single_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Look up a single file hash on VirusTotal."""
        cache_key = f"vt_hash_{hashlib.sha256(file_hash.encode()).hexdigest()}"

        async def fetch():
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{VT_BASE_URL}/files/{file_hash}",
                    headers={"x-apikey": self.api_key},
                ) as response:
                    if response.status == 404:
                        return {"status": "not_found"}
                    if response.status == 429:
                        logger.warning("VirusTotal rate limit hit")
                        return None
                    if response.status != 200:
                        logger.warning("VirusTotal API error: %d", response.status)
                        return None

                    data = await response.json()
                    return self._parse_file_report(data.get("data", {}))

        return await self._get_cached_or_fetch(cache_key, fetch)

    def _parse_url_report(self, report: dict) -> Dict[str, Any]:
        """Parse VT URL report into simplified format."""
        attributes = report.get("attributes", {})
        last_analysis = attributes.get("last_analysis_results", {})

        malicious = 0
        total = 0
        for engine, result in last_analysis.items():
            total += 1
            if result.get("category") == "malicious":
                malicious += 1

        return {
            "malicious": malicious,
            "total_engines": total,
            "reputation": attributes.get("reputation", "unknown"),
            "last_submission": attributes.get("last_submission_date", "unknown"),
        }

    def _parse_file_report(self, report: dict) -> Dict[str, Any]:
        """Parse VT file report into simplified format."""
        attributes = report.get("attributes", {})
        last_analysis = attributes.get("last_analysis_results", {})

        malicious = 0
        total = 0
        for engine, result in last_analysis.items():
            total += 1
            if result.get("category") == "malicious":
                malicious += 1

        return {
            "malicious": malicious,
            "total_engines": total,
            "reputation": attributes.get("reputation", "unknown"),
            "meaningful_name": attributes.get("meaningful_name", "unknown"),
            "type_description": attributes.get("type_description", "unknown"),
        }
