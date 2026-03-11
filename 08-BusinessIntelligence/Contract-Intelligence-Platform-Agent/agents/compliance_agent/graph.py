"""Compliance Agent internal graph: reasoning -> tools -> summarize."""

import os

SYSTEM_PROMPT = (
    "You are the Compliance Agent for a Contract Intelligence Platform. "
    "Use compliance tools for GDPR, jurisdiction checks, data residency, and audit trails."
)

SUMMARY_PROMPT = (
    "You are the Compliance Agent. Summarize compliance findings, severities, and remediation actions."
)

MCP_URL = f"http://localhost:{os.getenv('COMPLIANCE_PORT', '8006')}/mcp"


def run_reasoning(message: str, context: dict | None = None) -> dict:
    from agents.common.graph_runtime import run_standard_agent_graph
    return run_standard_agent_graph(
        agent_name="ComplianceAgent",
        message=message,
        context=context,
        system_prompt=SYSTEM_PROMPT,
        summary_prompt=SUMMARY_PROMPT,
        mcp_url=MCP_URL,
    )
