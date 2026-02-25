"""
GitHub Agent API — FastAPI
===========================
Exposes the GitHub LangGraph agent as an HTTP service.

Endpoints:
    POST /invoke   — run the agent with a message
    GET  /health   — health check

Run:
    uvicorn agents.github.api:app --port 8001 --reload
    OR:
    python -m agents.github.api
"""

import sys
import os
import asyncio
import logging
import json

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.models import InvokeRequest, InvokeResponse, ToolCallLog, HealthResponse
from shared.config import settings
from agents.github.graph import run_github_agent, run_github_agent_stream

# ── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("github-agent")

# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="GitHub Agent API",
    description="LangGraph agent that uses MCP tools to interact with GitHub",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", service="github-agent")


@app.post("/invoke", response_model=InvokeResponse)
async def invoke(request: InvokeRequest):
    """
    Invoke the GitHub agent with a natural language message.

    Example body:
        { "message": "List open issues in anthropics/anthropic-sdk-python" }
    """
    logger.info(f"Received invoke request: {request.message[:100]}")

    try:
        result = await run_github_agent(request.message)
    except Exception as e:
        logger.exception("Agent execution failed")
        raise HTTPException(status_code=500, detail=str(e))

    tool_call_logs = [
        ToolCallLog(
            tool_name=tc["tool_name"],
            tool_input=tc["tool_input"],
            tool_output=tc["tool_output"],
        )
        for tc in result.get("tool_calls", [])
    ]

    logger.info(f"Agent completed. Tools used: {[t.tool_name for t in tool_call_logs]}")

    return InvokeResponse(
        output=result["output"],
        tool_calls=tool_call_logs,
    )


@app.post("/invoke/stream")
async def invoke_stream(request: InvokeRequest):
    async def event_gen():
        async for evt in run_github_agent_stream(request.message):
            yield f"event: {evt['event']}\n"
            yield f"data: {json.dumps(evt['data'])}\n"
            yield f"id: {evt['timestamp']}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "agents.github.api:app",
        host="0.0.0.0",
        port=settings.GITHUB_AGENT_PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )
