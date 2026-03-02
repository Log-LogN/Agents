from typing import Any, Union, Dict, List
from pydantic import BaseModel, Field
import uuid
from shared.config import settings
import redis
import json


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


# ── Session Management ──────────────────────────────────────────────────────

def generate_session_id() -> str:
    """Generate a unique session ID."""
    return str(uuid.uuid4())


class RedisSessionStore:
    """Redis-based session store for conversation memory."""

    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )

    def get_session_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve conversation history for a session."""
        history_json = self.redis.get(f"session:{session_id}:history")
        if history_json:
            return json.loads(history_json)
        return []

    def save_session_history(self, session_id: str, history: List[Dict[str, Any]]):
        """Save conversation history for a session."""
        self.redis.set(f"session:{session_id}:history", json.dumps(history))

    def delete_session(self, session_id: str):
        """Delete a session and its data."""
        self.redis.delete(f"session:{session_id}:history")
