import base64
import hashlib
import hmac
import json
import time
from typing import Any

from shared.config import settings


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_approval_token(tool_name: str, args: dict[str, Any], session_id: str = "default") -> dict:
    now = int(time.time())
    expires_at = now + settings.APPROVAL_TOKEN_TTL_SEC
    payload = {
        "tool_name": tool_name,
        "args": args,
        "session_id": session_id,
        "iat": now,
        "exp": expires_at,
    }
    payload_raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(
        settings.APPROVAL_SECRET.encode("utf-8"),
        payload_raw,
        hashlib.sha256,
    ).hexdigest()
    token = f"{_b64url_encode(payload_raw)}.{sig}"
    return {
        "approval_token": token,
        "expires_at": expires_at,
    }


def validate_approval_token(
    token: str,
    expected_tool_name: str,
    expected_args: dict[str, Any],
    session_id: str = "default",
) -> tuple[bool, str]:
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError:
        return False, "invalid token format"

    payload_raw = _b64url_decode(payload_b64)
    expected_sig = hmac.new(
        settings.APPROVAL_SECRET.encode("utf-8"),
        payload_raw,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        return False, "invalid token signature"

    payload = json.loads(payload_raw.decode("utf-8"))

    if int(payload.get("exp", 0)) < int(time.time()):
        return False, "approval token expired"

    if payload.get("tool_name") != expected_tool_name:
        return False, "tool mismatch"

    if payload.get("session_id") != session_id:
        return False, "session mismatch"

    if payload.get("args") != expected_args:
        return False, "args mismatch"

    return True, "ok"
