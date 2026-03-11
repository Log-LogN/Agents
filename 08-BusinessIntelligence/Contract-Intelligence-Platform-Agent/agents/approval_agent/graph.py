"""Approval Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Approval Agent for a Contract Intelligence Platform. "
    "Use approval workflow tools to create workflows, record decisions, and fetch pending approvals."
)

SUMMARY_PROMPT = (
    "You are the Approval Agent. Summarize workflow state changes and clearly state current approval status."
)

MCP_URL = f"http://localhost:{os.getenv('APPROVAL_PORT', '8003')}/mcp"


def run_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="ApprovalAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
