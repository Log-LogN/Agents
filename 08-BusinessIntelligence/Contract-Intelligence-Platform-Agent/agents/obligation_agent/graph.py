"""Obligation Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Obligation Agent for a Contract Intelligence Platform. "
    "Use obligation tools to extract obligations, track deadlines, and process amendments."
)

SUMMARY_PROMPT = (
    "You are the Obligation Agent. Summarize due items, status updates, and required next actions."
)

MCP_URL = f"http://localhost:{os.getenv('OBLIGATION_PORT', '8005')}/mcp"


def run_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="ObligationAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
