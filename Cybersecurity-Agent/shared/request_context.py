from __future__ import annotations

import time
import uuid
from contextvars import ContextVar
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI


_request_id: ContextVar[str] = ContextVar("request_id", default="")
_session_id: ContextVar[str] = ContextVar("session_id", default="")
_service_name: ContextVar[str] = ContextVar("service_name", default="")


def get_request_id() -> str:
    return _request_id.get()


def get_session_id() -> str:
    return _session_id.get()


def get_service_name() -> str:
    return _service_name.get()


def _get_header(scope: dict[str, Any], name: bytes) -> str:
    for k, v in scope.get("headers") or []:
        if k.lower() == name:
            try:
                return v.decode()
            except Exception:
                return ""
    return ""


def _get_query_param(scope: dict[str, Any], key: str) -> str:
    try:
        qs = scope.get("query_string") or b""
        parsed = parse_qs(qs.decode(errors="ignore"))
        vals = parsed.get(key)
        return vals[0] if vals else ""
    except Exception:
        return ""


class RequestContextMiddleware:
    """
    Streaming-safe ASGI middleware (works with SSE).
    """

    def __init__(self, app, *, service_name: str, logger):
        self.app = app
        self.service_name = service_name
        self.logger = logger

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        rid = uuid.uuid4().hex[:12]
        sid = _get_query_param(scope, "session_id") or _get_header(scope, b"x-session-id")

        t0 = time.perf_counter()
        tok_rid = _request_id.set(rid)
        tok_sid = _session_id.set(sid)
        tok_svc = _service_name.set(self.service_name)

        status_code: int | None = None

        async def _send(message):
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 0) or 0)
                headers = list(message.get("headers") or [])
                headers.append((b"x-request-id", rid.encode()))
                message["headers"] = headers
            await send(message)

        try:
            return await self.app(scope, receive, _send)
        finally:
            _request_id.reset(tok_rid)
            _session_id.reset(tok_sid)
            _service_name.reset(tok_svc)

            dt_ms = int((time.perf_counter() - t0) * 1000)
            try:
                self.logger.info(
                    "http_request service=%s method=%s path=%s status=%s ms=%s session_id=%s request_id=%s",
                    self.service_name,
                    scope.get("method", "-"),
                    scope.get("path", "-"),
                    status_code if status_code is not None else "?",
                    dt_ms,
                    sid or "-",
                    rid,
                )
            except Exception:
                pass


def install_request_context(app: FastAPI, *, service_name: str, logger) -> None:
    """
    Installs a lightweight streaming-safe middleware that:
    - sets per-request request_id
    - captures MCP session_id from query params when present
    - logs request end with latency
    - adds X-Request-ID header
    """
    app.add_middleware(RequestContextMiddleware, service_name=service_name, logger=logger)
