import time
from collections.abc import Callable
from typing import Any

from shared.cache import get_cache
from shared.cache_keys import build_tool_cache_key
from shared.config import settings
from shared.github_client import standard_tool_output
from shared.telemetry import incr


def cached_tool_call(
    server: str,
    tool_name: str,
    args: dict[str, Any],
    ttl: int,
    fetcher: Callable[[], Any],
) -> dict[str, Any]:
    incr("tool_calls_total")
    incr(f"tool_call_{tool_name}")
    cache = get_cache()
    key = build_tool_cache_key(server=server, tool=tool_name, args=args, tool_version=settings.TOOL_VERSION)
    start = time.perf_counter()
    cached = cache.get(key)
    if cached is not None:
        incr("cache_hit")
        duration_ms = (time.perf_counter() - start) * 1000
        return standard_tool_output(cached, duration_ms=duration_ms, cache_hit=True)

    incr("cache_miss")
    data = fetcher()
    cache.set(key, data, ttl=ttl)
    duration_ms = (time.perf_counter() - start) * 1000
    return standard_tool_output(data, duration_ms=duration_ms, cache_hit=False)


def uncached_tool_call(fetcher: Callable[[], Any]) -> dict[str, Any]:
    incr("tool_calls_total")
    start = time.perf_counter()
    data = fetcher()
    duration_ms = (time.perf_counter() - start) * 1000
    return standard_tool_output(data, duration_ms=duration_ms, cache_hit=False)
