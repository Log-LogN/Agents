import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mcp.server.fastmcp import FastMCP
from mcp_tools.recon.tools.dns_lookup import dns_lookup
from mcp_tools.recon.tools.port_scan import port_scan
from mcp_tools.recon.tools.whois_lookup import whois_lookup

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


def create_app():
    return mcp.sse_app()