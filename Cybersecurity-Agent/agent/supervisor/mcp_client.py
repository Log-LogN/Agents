import asyncio
import logging
from typing import Dict, List

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient

logger = logging.getLogger("supervisor-mcp-client")

# =========================================================
# MCP Server Configuration
# =========================================================

MCP_SERVERS = {
    "vulnerability": {
        "url": "http://localhost:8001/sse",
        "transport": "sse",
    },
    "dependency": {
        "url": "http://localhost:8002/sse",
        "transport": "sse",
    },
}

# In-memory cache
_tools_cache: List[BaseTool] | None = None


# =========================================================
# Load All Tools (Cached)
# =========================================================

async def get_all_mcp_tools() -> List[BaseTool]:
    """
    Load all tools from configured MCP servers.
    Results are cached after first load.
    """
    global _tools_cache

    if _tools_cache is not None:
        return _tools_cache

    tools: List[BaseTool] = []

    async def _load_server(name: str, cfg: dict) -> List[BaseTool]:
        try:
            client = MultiServerMCPClient({name: cfg})
            server_tools = await client.get_tools()
            logger.info("Loaded %d tools from %s", len(server_tools), name)
            return server_tools
        except Exception as e:
            logger.warning("MCP server '%s' unavailable: %s", name, str(e))
            return []

    tasks = [_load_server(name, cfg) for name, cfg in MCP_SERVERS.items()]
    results = await asyncio.gather(*tasks)

    for server_tools in results:
        tools.extend(server_tools)

    _tools_cache = tools
    return tools


# =========================================================
# Tool Map (Deterministic Invocation)
# =========================================================

async def get_mcp_tool_map() -> Dict[str, BaseTool]:
    """
    Return mapping: tool_name -> tool instance
    Useful for deterministic invocation.
    """
    tools = await get_all_mcp_tools()
    return {tool.name: tool for tool in tools}


# =========================================================
# Tool Scopes for Supervisor
# =========================================================

async def get_mcp_tools():
    """
    Return categorized tool groups for agents.

    Returns:
        dependency_tools
        vulnerability_tools
    """

    tools = await get_all_mcp_tools()

    dependency_tools = [
        t for t in tools
        if t.name.startswith((
            "tool_scan_public_repo",
            "tool_scan_dependency_text",
        ))
    ]

    vulnerability_tools = [
        t for t in tools
        if t.name.startswith((
            "tool_cve_",
            "tool_get_cvss",
            "tool_get_advisory",
            "tool_product_",
            "tool_osv_",
            "tool_validate_",
            "tool_cross_",
        ))
    ]

    return dependency_tools, vulnerability_tools