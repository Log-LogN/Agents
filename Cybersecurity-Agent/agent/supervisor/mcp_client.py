from langchain_mcp_adapters.client import MultiServerMCPClient

_client = None
_recon_tools = None
_vuln_tools = None


async def get_mcp_tools():
    _client = MultiServerMCPClient(
        {
            "recon": {
                "url": "http://localhost:8001/sse",
                "transport": "sse",
            },
            "vulnerability": {
                "url": "http://localhost:8003/sse",
                "transport": "sse",
            },
        }
    )

    tools = await _client.get_tools()

    _recon_tools = [t for t in tools if "dns" in t.name or "whois" in t.name or "port" in t.name]
    _vuln_tools = [t for t in tools if "cve" in t.name or "osv" in t.name or "validate" in t.name or "cross" in t.name]

    return _recon_tools, _vuln_tools