import sys
import os
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from shared.models import HealthResponse
from mcp_tools.risk_engine.tools import calculate_risk
from shared.request_context import install_request_context, get_session_id, get_request_id

logger = logging.getLogger("risk-engine-mcp")

mcp = FastMCP("risk-engine-mcp")


@mcp.tool()
def tool_calculate_risk(
    cvss: float,
    epss: float | None = None,
    exploit_available: bool = False,
    internet_exposed: bool = False,
    open_ports: list[int] | None = None,
    in_kev: bool = False,
):
    """
    Calculate unified risk score (0-10) and severity.
    """
    logger.info("tool_call tool_calculate_risk session_id=%s request_id=%s", get_session_id() or "-", get_request_id() or "-")
    return calculate_risk(
        cvss=cvss,
        epss=epss,
        exploit_available=exploit_available,
        internet_exposed=internet_exposed,
        open_ports=open_ports or [],
        in_kev=in_kev,
    )


def create_app() -> FastAPI:
    # Create a FastAPI app and mount the MCP SSE app
    app = FastAPI()
    sse_app = mcp.sse_app()

    # Mount the SSE app at the root path
    app.mount("/", sse_app)

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(service="risk-engine-mcp")

    install_request_context(app, service_name="risk-engine-mcp", logger=logger)
    return app
