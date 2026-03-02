import asyncio
import logging

from langchain_mcp_adapters.client import MultiServerMCPClient

logger = logging.getLogger("supervisor-mcp-client")

_tools_cache = None

MCP_SERVERS = {
    "recon": {"url": "http://localhost:8001/sse", "transport": "sse"},
    "reporting": {"url": "http://localhost:8002/sse", "transport": "sse"},
    "vulnerability": {"url": "http://localhost:8003/sse", "transport": "sse"},
    "threat_intel": {"url": "http://localhost:8004/sse", "transport": "sse"},
    "risk_engine": {"url": "http://localhost:8005/sse", "transport": "sse"},
    "dependency": {"url": "http://localhost:8006/sse", "transport": "sse"},
}


async def get_all_mcp_tools():
    """
    Return all MCP tools (cached) as a list of LangChain tools.
    """
    global _tools_cache
    if _tools_cache is None:
        tools = []

        async def _load_one(name: str, cfg: dict):
            try:
                client = MultiServerMCPClient({name: cfg})
                return await client.get_tools()
            except Exception as e:
                logger.warning("MCP server %s unavailable: %s", name, str(e))
                return []

        tasks = [_load_one(name, cfg) for name, cfg in MCP_SERVERS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        for lst in results:
            tools.extend(lst)

        _tools_cache = tools
    return _tools_cache


async def get_mcp_tool_map():
    """
    Return a name->tool map for deterministic tool invocation.
    """
    tools = await get_all_mcp_tools()
    return {t.name: t for t in tools}


async def get_mcp_tools():
    """
    Backwards-compatible helper used by existing agent graphs.
    """
    tools = await get_all_mcp_tools()
    recon_tools = [
        t
        for t in tools
        if t.name.startswith(("tool_dns_", "tool_port_", "tool_whois_", "tool_http_", "tool_ssl_"))
    ]
    vuln_tools = [
        t
        for t in tools
        if t.name.startswith(("tool_cve_", "tool_get_cvss", "tool_product_", "tool_osv_", "tool_validate_", "tool_cross_"))
    ]
    return recon_tools, vuln_tools
