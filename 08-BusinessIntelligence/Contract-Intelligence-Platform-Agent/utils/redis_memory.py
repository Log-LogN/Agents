"""utils/redis_memory.py — Redis session context with in-memory fallback."""

import os, json, logging
from typing import Any, Optional
from dotenv import load_dotenv

load_dotenv()
logger     = logging.getLogger(__name__)
REDIS_URL  = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_TTL = 28800  # 8 hours

_redis_client = None
_mem: dict = {}


def _get_redis():
    global _redis_client
    if _redis_client:
        return _redis_client
    try:
        import redis as r
        c = r.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
        c.ping()
        _redis_client = c
        return c
    except Exception as e:
        logger.warning("Redis unavailable (%s) — using in-memory fallback", e)
        return None


def set_value(key: str, value: Any, ttl: int = SESSION_TTL) -> bool:
    s = json.dumps(value, default=str)
    r = _get_redis()
    if r:
        try:
            r.setex(key, ttl, s); return True
        except Exception: pass
    _mem[key] = s
    return True


def get_value(key: str) -> Optional[Any]:
    r = _get_redis()
    raw = None
    if r:
        try: raw = r.get(key)
        except Exception: pass
    if raw is None:
        raw = _mem.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw


def delete_value(key: str):
    r = _get_redis()
    if r:
        try: r.delete(key)
        except Exception: pass
    _mem.pop(key, None)


def append_message(session_id: str, role: str, content: str, max_history: int = 20):
    key     = f"session:{session_id}:history"
    history = get_value(key) or []
    history.append({"role": role, "content": content})
    if len(history) > max_history:
        history = history[-max_history:]
    set_value(key, history)


def get_chat_history(session_id: str) -> list:
    return get_value(f"session:{session_id}:history") or []


def clear_session(session_id: str):
    delete_value(f"session:{session_id}:history")
    delete_value(f"session:{session_id}:context")


def check_rate_limit(user_id: int, action: str, max_calls: int = 60, window: int = 60) -> bool:
    r = _get_redis()
    if not r:
        return True
    key = f"rate:{user_id}:{action}"
    try:
        count = r.incr(key)
        if count == 1:
            r.expire(key, window)
        return count <= max_calls
    except Exception:
        return True
