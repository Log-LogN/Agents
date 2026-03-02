import sys
import os
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from shared.models import HealthResponse
from mcp_tools.threat_intel.tools import get_epss, check_exploit_available, check_cisa_kev
from shared.request_context import install_request_context, get_session_id, get_request_id

logger = logging.getLogger("threat-intel-mcp")

mcp = FastMCP("threat-intel-mcp")


@mcp.tool()
async def tool_get_epss(cve: str):
    """Get EPSS score and percentile for a CVE using FIRST."""
    logger.info("tool_call tool_get_epss session_id=%s request_id=%s cve=%s", get_session_id() or "-", get_request_id() or "-", cve)
    return await get_epss(cve)


@mcp.tool()
async def tool_check_exploit_available(cve: str):
    """Check exploit availability (GitHub Search API with deterministic fallback)."""
    logger.info("tool_call tool_check_exploit_available session_id=%s request_id=%s cve=%s", get_session_id() or "-", get_request_id() or "-", cve)
    return await check_exploit_available(cve)


@mcp.tool()
async def tool_check_cisa_kev(cve: str):
    """Check whether a CVE is listed in CISA Known Exploited Vulnerabilities (KEV)."""
    logger.info("tool_call tool_check_cisa_kev session_id=%s request_id=%s cve=%s", get_session_id() or "-", get_request_id() or "-", cve)
    return await check_cisa_kev(cve)


def create_app() -> FastAPI:
    # Create a FastAPI app and mount the MCP SSE app
    app = FastAPI()
    sse_app = mcp.sse_app()

    # Mount the SSE app at the root path
    app.mount("/", sse_app)

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(service="threat-intel-mcp")

    install_request_context(app, service_name="threat-intel-mcp", logger=logger)
    return app
