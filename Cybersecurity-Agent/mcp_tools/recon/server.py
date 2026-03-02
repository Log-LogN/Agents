import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import logging

from mcp.server.fastmcp import FastMCP
from mcp_tools.recon.tools.dns_lookup import dns_lookup
from mcp_tools.recon.tools.port_scan import port_scan
from mcp_tools.recon.tools.whois_lookup import whois_lookup
from mcp_tools.recon.tools.http_security_headers import http_security_headers
from mcp_tools.recon.tools.ssl_info import ssl_info
from shared.models import HealthResponse
from shared.request_context import install_request_context, get_session_id, get_request_id

mcp = FastMCP("recon-mcp")
logger = logging.getLogger("recon-mcp")


@mcp.tool()
def tool_dns_lookup(domain: str):
    """Resolve domain IP addresses."""
    logger.info("tool_call tool_dns_lookup session_id=%s request_id=%s", get_session_id() or "-", get_request_id() or "-")
    return dns_lookup(domain)


@mcp.tool()
def tool_port_scan(host: str):
    """Safe scan of common ports."""
    logger.info("tool_call tool_port_scan session_id=%s request_id=%s host=%s", get_session_id() or "-", get_request_id() or "-", host)
    return port_scan(host)


@mcp.tool()
def tool_whois_lookup(domain: str):
    """Get domain registration details."""
    logger.info("tool_call tool_whois_lookup session_id=%s request_id=%s domain=%s", get_session_id() or "-", get_request_id() or "-", domain)
    return whois_lookup(domain)


@mcp.tool()
async def tool_http_security_headers(host: str):
    """Fetch HTTP(S) headers and report common security headers."""
    logger.info("tool_call tool_http_security_headers session_id=%s request_id=%s host=%s", get_session_id() or "-", get_request_id() or "-", host)
    return await http_security_headers(host)


@mcp.tool()
def tool_ssl_info(host: str, port: int = 443):
    """Inspect TLS certificate details for host:port."""
    logger.info("tool_call tool_ssl_info session_id=%s request_id=%s host=%s port=%s", get_session_id() or "-", get_request_id() or "-", host, port)
    return ssl_info(host, port)


def create_app():
    from fastapi import FastAPI

    # Create a FastAPI app and mount the MCP SSE app
    app = FastAPI()
    sse_app = mcp.sse_app()

    # Mount the SSE app at the root path
    app.mount("/", sse_app)

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(service="recon-mcp")

    install_request_context(app, service_name="recon-mcp", logger=logger)
    return app
