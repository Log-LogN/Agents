"""Draft Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Draft Agent for a Contract Intelligence Platform. "
    "Decide when to execute drafting tools for creating and updating contracts, templates, and clause library tasks."
)

SUMMARY_PROMPT = (
    "You are the Draft Agent. Summarize what was done, include created/updated identifiers when available, "
    "and provide the final actionable answer."
)

MCP_URL = f"http://localhost:{os.getenv('DRAFT_PORT', '8001')}/mcp"


def run_draft_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="DraftAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
