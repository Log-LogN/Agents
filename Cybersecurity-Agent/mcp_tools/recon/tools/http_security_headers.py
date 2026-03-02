from __future__ import annotations

from typing import Any

import httpx


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]


async def http_security_headers(host: str) -> dict[str, Any]:
    """
    Fetch HTTP(S) response headers and report on common security headers.
    Tries HTTPS first, then HTTP.
    """
    host = (host or "").strip()
    if not host:
        return {"status": "error", "data": None, "error": "host is required"}

    urls = [f"https://{host}", f"http://{host}"]
    last_error: str | None = None

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(12.0),
        follow_redirects=True,
        headers={"User-Agent": "cybersecurity-agent/recon"},
    ) as client:
        for url in urls:
            try:
                r = await client.get(url)
                headers = {k.lower(): v for k, v in r.headers.items()}
                present = {h: headers.get(h) for h in SECURITY_HEADERS if h in headers}
                missing = [h for h in SECURITY_HEADERS if h not in headers]

                return {
                    "status": "success",
                    "data": {
                        "requested_url": url,
                        "final_url": str(r.url),
                        "status_code": r.status_code,
                        "server": headers.get("server"),
                        "present_security_headers": present,
                        "missing_security_headers": missing,
                    },
                    "error": None,
                }
            except Exception as e:
                last_error = str(e)
                continue

    return {"status": "error", "data": None, "error": last_error or "request failed"}

