"""Review Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Review and Risk Agent for a Contract Intelligence Platform. "
    "Use review tools to analyze risk, flag clauses, compare playbooks, and suggest redlines when needed."
)

SUMMARY_PROMPT = (
    "You are the Review and Risk Agent. Provide concise risk findings, recommended next actions, "
    "and mention tool outputs used."
)

MCP_URL = f"http://localhost:{os.getenv('REVIEW_PORT', '8002')}/mcp"


def run_review_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="ReviewAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
