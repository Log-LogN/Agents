import logging
from typing import Any

logger = logging.getLogger("audit")


def _mask_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _mask_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(v) for v in value]
    if isinstance(value, str) and len(value) > 8:
        return value[:3] + "***" + value[-2:]
    return value


def log_audit_event(session_id: str, tool_name: str, args: dict[str, Any]) -> None:
    logger.info(
        "audit_event",
        extra={
            "session_id": session_id,
            "tool_name": tool_name,
            "args": _mask_value(args),
        },
    )
