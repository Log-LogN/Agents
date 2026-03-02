from __future__ import annotations

from typing import Any

import httpx


class ThreatIntelClient:
    """
    Simple HTTP client for the Threat Intel MCP service.

    Note: The Supervisor typically uses MCP adapters directly. This client is
    provided for service-to-service use and local testing.
    """

    def __init__(self, base_url: str = "http://localhost:8004"):
        self.base_url = base_url.rstrip("/")

    async def health(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{self.base_url}/health")
            r.raise_for_status()
            return r.json()

