import logging
import random
import time
from typing import Any

import requests

from shared.config import settings
from shared.telemetry import incr

logger = logging.getLogger("github-client")


class GitHubAPIError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.token = token or settings.GITHUB_TOKEN
        self.base_url = "https://api.github.com"
        self.session = requests.Session()

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def request(self, method: str, path: str, params: dict | None = None, json_body: dict | None = None) -> dict | list:
        url = f"{self.base_url}{path}"
        max_attempts = 4

        for attempt in range(1, max_attempts + 1):
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    headers=self._headers(),
                    params=params,
                    json=json_body,
                    timeout=30,
                )
            except requests.RequestException as exc:
                if attempt == max_attempts:
                    raise GitHubAPIError(f"network error: {exc}") from exc
                sleep_s = (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                time.sleep(sleep_s)
                continue

            if resp.status_code == 429:
                incr("github_rate_limited")
                retry_after = resp.headers.get("Retry-After")
                if attempt == max_attempts:
                    raise GitHubAPIError("github rate limit exceeded")
                sleep_s = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt)
                time.sleep(sleep_s)
                continue

            if 500 <= resp.status_code < 600:
                if attempt == max_attempts:
                    raise GitHubAPIError(f"github server error ({resp.status_code})")
                sleep_s = (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                time.sleep(sleep_s)
                continue

            if resp.status_code in (401, 403):
                raise GitHubAPIError("github authorization failed (401/403)")

            if resp.status_code == 404:
                raise GitHubAPIError("github resource not found (404)")

            if resp.status_code >= 400:
                raise GitHubAPIError(f"github error ({resp.status_code}): {resp.text[:200]}")

            return resp.json()

        raise GitHubAPIError("request failed unexpectedly")


def standard_tool_output(data: Any, duration_ms: float, cache_hit: bool = False) -> dict[str, Any]:
    return {
        "data": data,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "github",
        "duration_ms": round(duration_ms, 2),
        "cache": {"hit": cache_hit},
    }
