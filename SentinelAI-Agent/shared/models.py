from typing import Any, Union, Dict, List
from pydantic import BaseModel, Field


# ── Inbound requests ────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    """Request body for the Supervisor /chat endpoint."""
    message: str = Field(..., description="User's natural language query")
    session_id: str | None = Field(default=None, description="Session identifier for multi-turn")


class InvokeRequest(BaseModel):
    """
    Request body for each Agent /invoke endpoint.

    Supports:
    - str (legacy)
    - structured payload from Supervisor
    """
    message: Union[str, Dict[str, Any]] = Field(
        ...,
        description="Task message or structured context from supervisor"
    )


# ── Outbound responses ──────────────────────────────────────────────────────

class ToolCallLog(BaseModel):
    """A single tool call made during agent execution."""
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str


class InvokeResponse(BaseModel):
    """Response from each Agent /invoke endpoint."""
    output: str
    tool_calls: List[ToolCallLog] = Field(default_factory=list)


class ChatResponse(BaseModel):
    """Response from the Supervisor /chat endpoint."""
    output: str
    agent_used: str
    session_id: str
    tool_calls: List[ToolCallLog] = Field(default_factory=list)


# ── Health ──────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = ""