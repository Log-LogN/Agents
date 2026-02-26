import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from shared.config import settings


class CacheAdapter:
    def get(self, key: str) -> Any:
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int) -> None:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError


@dataclass
class CacheItem:
    value: Any
    expires_at: float


class InMemoryLRUCache(CacheAdapter):
    def __init__(self, max_size: int = 256):
        self.max_size = max_size
        self._store: OrderedDict[str, CacheItem] = OrderedDict()

    def _evict_if_needed(self) -> None:
        while len(self._store) > self.max_size:
            self._store.popitem(last=False)

    def get(self, key: str) -> Any:
        item = self._store.get(key)
        if not item:
            return None

        if item.expires_at < time.time():
            self._store.pop(key, None)
            return None

        self._store.move_to_end(key)
        return item.value

    def set(self, key: str, value: Any, ttl: int) -> None:
        expires_at = time.time() + max(1, ttl)
        self._store[key] = CacheItem(value=value, expires_at=expires_at)
        self._store.move_to_end(key)
        self._evict_if_needed()

    def delete(self, key: str) -> None:
        self._store.pop(key, None)


class RedisCache(CacheAdapter):
    def __init__(self, redis_url: str):
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError(
                "redis package is required for CACHE_BACKEND=redis"
            ) from exc

        self._client = redis.Redis.from_url(redis_url, decode_responses=True)

    def get(self, key: str) -> Any:
        raw = self._client.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    def set(self, key: str, value: Any, ttl: int) -> None:
        self._client.setex(key, max(1, ttl), json.dumps(value))

    def delete(self, key: str) -> None:
        self._client.delete(key)


_cache_instance: CacheAdapter | None = None


def get_cache() -> CacheAdapter:
    global _cache_instance
    if _cache_instance is not None:
        return _cache_instance

    if settings.CACHE_BACKEND.lower() == "redis":
        _cache_instance = RedisCache(settings.REDIS_URL)
    else:
        _cache_instance = InMemoryLRUCache(max_size=settings.CACHE_MAX_SIZE)

    return _cache_instance
