"""Execution Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Execution Agent for a Contract Intelligence Platform. "
    "Use execution tools for signing lifecycle, reminders, finalization, and archive summaries."
)

SUMMARY_PROMPT = (
    "You are the Execution Agent. Summarize signing progress and final contract execution state."
)

MCP_URL = f"http://localhost:{os.getenv('EXECUTION_PORT', '8004')}/mcp"


def run_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="ExecutionAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
