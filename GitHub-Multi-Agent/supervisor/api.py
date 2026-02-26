"""
Supervisor API — FastAPI
=========================
Secured entry point for the multi-agent system.

Security layers:
  1. API Key auth  — X-API-Key header required (when SUPERVISOR_API_KEY is set in .env)
  2. Rate limiting — max N requests/minute per IP (slowapi)
  3. Input validation — message length capped, empty messages rejected
  4. Prompt injection guard — basic heuristic check on message content
  5. CORS locked down — only allowed origins

Endpoints:
    POST /chat     — send a message, get routed to the right agent
    GET  /health   — health check (public, no auth needed)
    GET  /agents   — list registered agents and their status (requires auth)
"""

import sys
import os
import time
import logging
import re
import json
import uuid
from collections import defaultdict

import uvicorn
import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import StreamingResponse
from fastapi.security.api_key import APIKeyHeader

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.models import ChatRequest, ChatResponse, ToolCallLog, HealthResponse
from shared.config import settings
from shared.cache import get_cache
from shared.cache_keys import build_stream_key
from shared.telemetry import snapshot, incr
from supervisor.graph import run_supervisor, run_supervisor_stream, AGENT_REGISTRY

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("supervisor-api")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Supervisor Agent API",
    description=(
        "Secured multi-agent orchestrator. Routes requests to: github agent. "
        "Requires X-API-Key header for protected endpoints."
    ),
    version="1.0.0",
    # Hide sensitive schema details in production
    docs_url="/docs",
    redoc_url=None,
)

# ── CORS — lock down to specific origins in production ────────────────────────

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-API-Key"],
)


# ── Security: API Key auth ─────────────────────────────────────────────────────

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Depends(api_key_header)):
    """
    Validate X-API-Key header.
    If SUPERVISOR_API_KEY is not set in .env, auth is disabled (dev mode).
    """
    if not settings.SUPERVISOR_API_KEY:
        # Auth disabled — warn but allow (dev/local mode)
        logger.warning("⚠️  SUPERVISOR_API_KEY not set — API key auth is DISABLED")
        return

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide it in the X-API-Key header.",
        )

    # Constant-time comparison to prevent timing attacks
    import hmac
    if not hmac.compare_digest(api_key, settings.SUPERVISOR_API_KEY):
        logger.warning(f"Invalid API key attempt")
        raise HTTPException(status_code=403, detail="Invalid API key.")


# ── Security: In-memory rate limiter (per IP) ─────────────────────────────────

# { ip: [timestamp, timestamp, ...] }
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(request: Request):
    """Simple sliding-window rate limiter. No Redis needed for single-instance."""
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = 60.0  # 1 minute window

    # Keep only timestamps within the window
    _rate_limit_store[ip] = [
        t for t in _rate_limit_store[ip] if now - t < window
    ]

    if len(_rate_limit_store[ip]) >= settings.RATE_LIMIT_PER_MINUTE:
        incr("supervisor_rate_limit_exceeded")
        logger.warning(f"Rate limit exceeded for IP: {ip}")
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Max {settings.RATE_LIMIT_PER_MINUTE} requests/minute.",
        )

    _rate_limit_store[ip].append(now)


# ── Security: Prompt injection heuristic guard ────────────────────────────────

# Common prompt injection / jailbreak patterns
_INJECTION_PATTERNS = [
    r"ignore (all |previous |above |prior )?instructions",
    r"forget (all |your |previous |prior )?instructions",
    r"you are now",
    r"new persona",
    r"system prompt",
    r"pretend (you are|to be)",
    r"act as (if|a|an)",
    r"jailbreak",
    r"DAN mode",
    r"override (your |all )?rules",
    r"disregard (your |all )?instructions",
    r"\bsudo\b",
    r"bypass",
]

_INJECTION_RE = re.compile(
    "|".join(_INJECTION_PATTERNS), re.IGNORECASE
)


def check_prompt_injection(message: str):
    """Heuristic check for obvious prompt injection attempts."""
    if _INJECTION_RE.search(message):
        logger.warning(f"Potential prompt injection detected: {message[:100]}")
        raise HTTPException(
            status_code=400,
            detail="Your message contains content that cannot be processed.",
        )


# ── Security: Input validation ────────────────────────────────────────────────

def validate_message(message: str):
    """Validate message length and content."""
    message = message.strip()

    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    if len(message) > settings.MAX_MESSAGE_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Message too long. Max {settings.MAX_MESSAGE_LENGTH} characters.",
        )

    return message


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.url}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again."},
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health():
    """Public health check — no auth required."""
    return HealthResponse(status="ok", service="supervisor")


@app.get("/agents", dependencies=[Depends(verify_api_key)])
async def list_agents():
    """List registered agents and their live health status. Requires auth."""
    agent_statuses = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, base_url in AGENT_REGISTRY.items():
            try:
                resp = await client.get(f"{base_url}/health")
                agent_statuses[name] = {
                    "url": base_url,
                    "status": "online" if resp.status_code == 200 else "error",
                }
            except Exception:
                agent_statuses[name] = {"url": base_url, "status": "offline"}

    return {"agents": agent_statuses}


@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(verify_api_key)])
async def chat(request: ChatRequest, http_request: Request):
    """
    Send a natural language message. Supervisor routes it to the correct agent.

    Headers required:
        X-API-Key: <your key from .env SUPERVISOR_API_KEY>

    Example body:
        {
            "message": "List open PRs in microsoft/vscode",
            "session_id": "user-123"
        }
    """
    # ── Security checks ──────────────────────────────────────
    check_rate_limit(http_request)
    clean_message = validate_message(request.message)
    check_prompt_injection(clean_message)

    session_id = request.session_id or str(uuid.uuid4())

    logger.info(
        f"[session={session_id}] "
        f"[ip={http_request.client.host if http_request.client else 'unknown'}] "
        f"Chat: {clean_message[:100]}"
    )

    # ── Run supervisor ───────────────────────────────────────
    try:
        result = await run_supervisor(clean_message)
        incr("supervisor_chat_requests")
    except Exception as e:
        logger.exception("Supervisor execution failed")
        incr("supervisor_chat_errors")
        raise HTTPException(status_code=500, detail="Failed to process request.")

    tool_call_logs = [
        ToolCallLog(
            tool_name=tc["tool_name"],
            tool_input=tc["tool_input"],
            tool_output=tc["tool_output"],
        )
        for tc in result.get("tool_calls", [])
    ]

    return ChatResponse(
        output=result["output"],
        agent_used=result["agent_used"],
        session_id=session_id,
        tool_calls=tool_call_logs,
    )


@app.post("/chat/stream", dependencies=[Depends(verify_api_key)])
async def chat_stream(request: ChatRequest, http_request: Request):
    check_rate_limit(http_request)
    clean_message = validate_message(request.message)
    check_prompt_injection(clean_message)

    session_id = request.session_id or str(uuid.uuid4())
    stream_id = str(uuid.uuid4())
    cache = get_cache()
    stream_key = build_stream_key(session_id=session_id, stream_id=stream_id)
    final_output = {"output": "", "agent_used": "none", "tool_calls": []}

    async def event_gen():
        nonlocal final_output
        try:
            async for evt in run_supervisor_stream(clean_message, session_id=session_id, stream_id=stream_id):
                event = evt.get("event", "error")
                data = evt.get("data", {})
                if event == "llm_final":
                    final_output["output"] = data.get("output", "")
                if "agent" in data:
                    final_output["agent_used"] = data.get("agent", final_output["agent_used"])
                yield f"event: {event}\n"
                yield f"data: {json.dumps(data)}\n"
                yield f"id: {evt.get('timestamp', '')}\n\n"
            cache.set(
                stream_key,
                {
                    "session_id": session_id,
                    "stream_id": stream_id,
                    **final_output,
                },
                ttl=600,
            )
            incr("supervisor_stream_requests")
        except Exception as exc:
            incr("supervisor_stream_errors")
            yield "event: error\n"
            yield f"data: {json.dumps({'message': str(exc), 'session_id': session_id, 'stream_id': stream_id})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/chat/stream/result", dependencies=[Depends(verify_api_key)])
async def get_stream_result(session_id: str, stream_id: str):
    key = build_stream_key(session_id=session_id, stream_id=stream_id)
    data = get_cache().get(key)
    if not data:
        raise HTTPException(status_code=404, detail="Stream result not found or expired.")
    return data


@app.get("/metrics", dependencies=[Depends(verify_api_key)])
async def metrics():
    return snapshot()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "supervisor.api:app",
        host="0.0.0.0",
        port=settings.SUPERVISOR_PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )
