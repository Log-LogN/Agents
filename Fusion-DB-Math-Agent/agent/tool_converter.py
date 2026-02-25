"""Helpers for converting MCP tool metadata into OpenAI tool schemas."""

from __future__ import annotations

from typing import Any, Dict, List


def _get_attr(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def mcp_tool_to_openai_tool(mcp_tool: Any) -> Dict[str, Any]:
    name = _get_attr(mcp_tool, "name", default="")
    description = _get_attr(mcp_tool, "description", default="") or "MCP tool"
    input_schema = _get_attr(mcp_tool, "inputSchema", "input_schema", default=None)

    if not isinstance(input_schema, dict):
        input_schema = {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
            },
        }

    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": input_schema,
        },
    }


def mcp_tools_to_openai_tools(mcp_tools: List[Any]) -> List[Dict[str, Any]]:
    return [mcp_tool_to_openai_tool(tool) for tool in mcp_tools]
