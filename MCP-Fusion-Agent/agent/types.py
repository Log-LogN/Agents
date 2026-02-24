"""Type definitions for the agent workflow state."""

from __future__ import annotations

from typing import Any, Dict, TypedDict


class AgentState(TypedDict):
    user_input: str
    route: str
    llm_text: str
    tool_name: str
    tool_args: Dict[str, Any]
    tool_result: str
    final_response: str
