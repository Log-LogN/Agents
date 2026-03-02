import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mcp.server.fastmcp import FastMCP
from mcp_tools.reporting.tools.risk_score import risk_score
from mcp_tools.reporting.tools.severity_summary import severity_summary
from mcp_tools.reporting.tools.mitigation_advice import mitigation_advice
from mcp_tools.reporting.tools_phase1 import generate_session_report

mcp = FastMCP("reporting-mcp")


@mcp.tool()
def tool_risk_score(cve_list: list):
    return risk_score(cve_list)


@mcp.tool()
def tool_severity_summary(cve_list: list):
    return severity_summary(cve_list)


@mcp.tool()
def tool_mitigation_advice(risk_level: str):
    return mitigation_advice(risk_level)


@mcp.tool()
def tool_generate_session_report(session_id: str):
    """Generate a Phase-1 Markdown session report and save it locally."""
    return generate_session_report(session_id)


# Correct factory for your FastMCP version
def create_app():
    from fastapi import FastAPI

    # Create a FastAPI app and mount the MCP SSE app
    app = FastAPI()
    sse_app = mcp.sse_app()

    # Mount the SSE app at the root path
    app.mount("/", sse_app)

    from shared.models import HealthResponse

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(service="reporting-mcp")

    return app

