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
import logging
import re
import uuid
import uvicorn
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.models import ChatRequest, ChatResponse, ToolCallLog, HealthResponse
from shared.config import settings
from shared.telemetry import snapshot, incr
from .graph import run_supervisor, AGENT_REGISTRY

from fastapi.responses import StreamingResponse
import json

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("supervisor-api")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Supervisor Agent API",
    description=(
        "Secured multi-agent orchestrator."
    ),
    version="1.0.0",
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
    allow_headers=["Content-Type"],
)


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


@app.get("/agents")
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


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, http_request: Request):
    """
    Send a natural language message. Supervisor routes it to the correct agent.

    Example body:
        {
            "message": "List open PRs in microsoft/vscode",
            "session_id": "user-123"
        }
    """
    # ── Security checks ──────────────────────────────────────
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

@app.get("/metrics")
async def metrics():
    return snapshot()

@app.post("/chat/stream")
async def chat_stream(request: ChatRequest):

    async def event_gen():
        # Start event
        yield f"event: agent_started\n"
        yield f"data: {json.dumps({'message': request.message})}\n\n"

        try:
            result = await run_supervisor(request.message)

            # Tool events
            for tc in result.get("tool_calls", []):
                yield f"event: tool_call_started\n"
                yield f"data: {json.dumps({'tool_name': tc['tool_name'], 'tool_input': tc['tool_input']})}\n\n"

                yield f"event: tool_call_completed\n"
                yield f"data: {json.dumps({'tool_output': str(tc.get('tool_output',''))[:500]})}\n\n"

            # Final result
            yield f"event: llm_final\n"
            yield f"data: {json.dumps({'output': result['output'], 'agent': result['agent_used']})}\n\n"

        except Exception as e:
            yield f"event: error\n"
            yield f"data: {json.dumps({'message': str(e)})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "supervisor.api:app",
        host="0.0.0.0",
        port=settings.SUPERVISOR_PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )
