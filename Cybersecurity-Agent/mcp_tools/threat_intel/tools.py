from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from shared.config import settings

logger = logging.getLogger("threat-intel-mcp")


def _success(data: Any) -> dict:
    return {"status": "success", "data": data, "error": None}


def _failure(message: str) -> dict:
    return {"status": "error", "data": None, "error": message}


async def get_epss(cve: str) -> dict:
    """
    Fetch EPSS score and percentile for a CVE using the public FIRST API.
    """
    cve = (cve or "").strip().upper()
    if not cve.startswith("CVE-"):
        return _failure("Invalid CVE format.")

    url = "https://api.first.org/data/v1/epss"
    params = {"cve": cve}

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.get(url, params=params, headers={"User-Agent": "cybersecurity-agent/phase1"})
            resp.raise_for_status()
            payload = resp.json()

        items = payload.get("data") or []
        if not items:
            return _failure(f"No EPSS data found for {cve}.")

        item = items[0] or {}
        epss = float(item.get("epss"))
        percentile = float(item.get("percentile"))
        return _success({"cve": cve, "epss": epss, "percentile": percentile})
    except Exception as e:
        logger.exception("EPSS lookup failed")
        return _failure(str(e))


async def check_exploit_available(cve: str) -> dict:
    """
    Detect exploit availability via GitHub Search API.

    If GitHub API is unavailable (rate limit/network), returns a deterministic fallback:
    exploit_available=false, source="unavailable".
    """
    cve = (cve or "").strip().upper()
    if not cve.startswith("CVE-"):
        return _failure("Invalid CVE format.")

    token = (settings.GITHUB_TOKEN or "").strip()
    headers = {"User-Agent": "cybersecurity-agent/phase1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Repos search is broadly available (unlike code search in some environments).
    url = "https://api.github.com/search/repositories"
    params = {"q": f'{cve} exploit'}

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0)) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            payload = resp.json()

        total = int(payload.get("total_count") or 0)
        return _success({"cve": cve, "exploit_available": total > 0, "source": "github"})
    except Exception as e:
        logger.warning("GitHub exploit search unavailable: %s", str(e))
        return _success({"cve": cve, "exploit_available": False, "source": "unavailable"})


KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class _KevCache:
    fetched_at: float = 0.0
    cves: set[str] | None = None


_kev_cache = _KevCache()
_kev_lock = asyncio.Lock()


async def _load_kev_cves() -> set[str]:
    ttl_seconds = int(getattr(settings, "CISA_KEV_CACHE_TTL_SECONDS", 6 * 60 * 60))
    now = time.time()

    async with _kev_lock:
        if _kev_cache.cves is not None and (now - _kev_cache.fetched_at) < ttl_seconds:
            return _kev_cache.cves

        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            resp = await client.get(KEV_FEED_URL, headers={"User-Agent": "cybersecurity-agent/phase1"})
            resp.raise_for_status()
            payload = resp.json()

        vulns = payload.get("vulnerabilities") or []
        cves = {str(v.get("cveID") or "").strip().upper() for v in vulns}
        cves.discard("")
        _kev_cache.cves = cves
        _kev_cache.fetched_at = now
        logger.info("Loaded CISA KEV feed: %d CVEs", len(cves))
        return cves


async def check_cisa_kev(cve: str) -> dict:
    """
    Check whether a CVE is present in the CISA Known Exploited Vulnerabilities catalog.
    """
    cve = (cve or "").strip().upper()
    if not cve.startswith("CVE-"):
        return _failure("Invalid CVE format.")

    try:
        cves = await _load_kev_cves()
        return _success({"cve": cve, "in_kev": cve in cves})
    except Exception as e:
        logger.exception("CISA KEV check failed")
        return _failure(str(e))

