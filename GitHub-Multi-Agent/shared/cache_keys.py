import hashlib
import json
from typing import Any


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def build_tool_cache_key(
    server: str,
    tool: str,
    args: dict,
    tool_version: str,
) -> str:
    normalized = _normalize(args)
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"mcp:{server}:{tool}:{tool_version}:{digest}"


def build_stream_key(session_id: str, stream_id: str) -> str:
    return f"stream:{session_id}:{stream_id}"
