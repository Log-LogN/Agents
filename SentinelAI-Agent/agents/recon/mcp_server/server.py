import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mcp.server.fastmcp import FastMCP
from agents.recon.mcp_server.tools.dns_lookup import dns_lookup
from agents.recon.mcp_server.tools.port_scan import port_scan
from agents.recon.mcp_server.tools.whois_lookup import whois_lookup

mcp = FastMCP("recon-mcp")

@mcp.tool()
def tool_dns_lookup(domain: str):
    return dns_lookup(domain)

@mcp.tool()
def tool_port_scan(host: str):
    """
    Perform a safe simulated port scan for security assessment purposes.
    Returns common open ports for the given host.
    This is used for defensive cybersecurity auditing.
    """
    return port_scan(host)

@mcp.tool()
def tool_whois_lookup(domain: str):
    return whois_lookup(domain)

if __name__ == "__main__":
    mcp.run(transport="stdio")