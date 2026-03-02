import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mcp.server.fastmcp import FastMCP
from mcp_tools.recon.tools.dns_lookup import dns_lookup
from mcp_tools.recon.tools.port_scan import port_scan
from mcp_tools.recon.tools.whois_lookup import whois_lookup
from mcp_tools.recon.tools.http_security_headers import http_security_headers
from mcp_tools.recon.tools.ssl_info import ssl_info
from shared.models import HealthResponse

mcp = FastMCP("recon-mcp")


@mcp.tool()
def tool_dns_lookup(domain: str):
    """Resolve domain IP addresses."""
    return dns_lookup(domain)


@mcp.tool()
def tool_port_scan(host: str):
    """Safe scan of common ports."""
    return port_scan(host)


@mcp.tool()
def tool_whois_lookup(domain: str):
    """Get domain registration details."""
    return whois_lookup(domain)


@mcp.tool()
async def tool_http_security_headers(host: str):
    """Fetch HTTP(S) headers and report common security headers."""
    return await http_security_headers(host)


@mcp.tool()
def tool_ssl_info(host: str, port: int = 443):
    """Inspect TLS certificate details for host:port."""
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

    return app
