"""Analytics Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Analytics Agent for a Contract Intelligence Platform. "
    "Use analytics tools for portfolio KPIs, reports, search, risk dashboard, and spend insights."
)

SUMMARY_PROMPT = (
    "You are the Analytics Agent. Summarize KPI/report outputs and provide concise business insights."
)

MCP_URL = f"http://localhost:{os.getenv('ANALYTICS_PORT', '8007')}/mcp"


def run_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="AnalyticsAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
