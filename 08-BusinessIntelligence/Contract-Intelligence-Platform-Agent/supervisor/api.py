"""
supervisor/api.py
FastAPI server wrapping the Supervisor LangGraph.
Runs on SUPERVISOR_PORT (8000). Started by start_supervisor.py.
"""

import asyncio
import logging
import os
import sys
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

load_dotenv()
logger = logging.getLogger(__name__)

app = FastAPI(title="Contract Intelligence Platform - Supervisor API", version="1.1.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ChatRequest(BaseModel):
    message: str
    user_id: int = 1
    session_id: str = "default"
    role: str = "viewer"
    contract_id: Optional[int] = None


class ChatResponse(BaseModel):
    response: str
    intent: str
    duration_ms: int
    error: str = ""


class DebugChatResponse(ChatResponse):
    debug: dict[str, Any]


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    try:
        from supervisor.graph import run_supervisor

        result = run_supervisor(
            message=req.message,
            user_id=req.user_id,
            session_id=req.session_id,
            role=req.role,
            contract_id=req.contract_id,
        )
        return ChatResponse(**result)
    except Exception as exc:
        logger.error("Chat endpoint error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/debug/chat", response_model=DebugChatResponse)
def debug_chat(req: ChatRequest):
    try:
        from supervisor.graph import run_supervisor_debug

        result = run_supervisor_debug(
            message=req.message,
            user_id=req.user_id,
            session_id=req.session_id,
            role=req.role,
            contract_id=req.contract_id,
        )
        return DebugChatResponse(**result)
    except Exception as exc:
        logger.exception("Debug chat endpoint error")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/debug/agents/tools")
def debug_agents_tools():
    try:
        from supervisor.graph import debug_list_agent_tools

        return asyncio.run(debug_list_agent_tools())
    except Exception as exc:
        logger.exception("Debug agents tools endpoint error")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/health")
def health():
    return {"status": "ok", "service": "supervisor"}


@app.get("/agents/status")
def agents_status():
    import socket

    ports = {
        "draft_agent": int(os.getenv("DRAFT_PORT", "8001")),
        "review_agent": int(os.getenv("REVIEW_PORT", "8002")),
        "approval_agent": int(os.getenv("APPROVAL_PORT", "8003")),
        "execution_agent": int(os.getenv("EXECUTION_PORT", "8004")),
        "obligation_agent": int(os.getenv("OBLIGATION_PORT", "8005")),
        "compliance_agent": int(os.getenv("COMPLIANCE_PORT", "8006")),
        "analytics_agent": int(os.getenv("ANALYTICS_PORT", "8007")),
    }
    statuses = {}
    for name, port in ports.items():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            statuses[name] = {"port": port, "status": "UP"}
        except OSError:
            statuses[name] = {"port": port, "status": "DOWN"}
    return {"agents": statuses}


def main():
    import uvicorn

    port = int(os.getenv("SUPERVISOR_PORT", "8000"))
    logging.basicConfig(level=logging.INFO)
    logger.info("Supervisor API starting on port %d", port)
    uvicorn.run("supervisor.api:app", host="0.0.0.0", port=port, log_level="warning", reload=False)


if __name__ == "__main__":
    main()
