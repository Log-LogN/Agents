from langchain_mcp_adapters.client import MultiServerMCPClient

_client = None
_tools_cache = None


async def _get_client() -> MultiServerMCPClient:
    global _client
    if _client is None:
        _client = MultiServerMCPClient(
            {
                "recon": {"url": "http://localhost:8001/sse", "transport": "sse"},
                "reporting": {"url": "http://localhost:8002/sse", "transport": "sse"},
                "vulnerability": {"url": "http://localhost:8003/sse", "transport": "sse"},
                "threat_intel": {"url": "http://localhost:8004/sse", "transport": "sse"},
                "risk_engine": {"url": "http://localhost:8005/sse", "transport": "sse"},
            }
        )
    return _client


async def get_all_mcp_tools():
    """
    Return all MCP tools (cached) as a list of LangChain tools.
    """
    global _tools_cache
    if _tools_cache is None:
        client = await _get_client()
        _tools_cache = await client.get_tools()
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
    recon_tools = [t for t in tools if "dns" in t.name or "whois" in t.name or "port" in t.name]
    vuln_tools = [t for t in tools if "cve" in t.name or "osv" in t.name or "validate" in t.name or "cross" in t.name]
    return recon_tools, vuln_tools
