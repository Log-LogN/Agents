"""Phase-2 MCP server using official MCP SDK over Streamable HTTP transport."""

from mcp.server.fastmcp import FastMCP

try:
    from .tools import register_tools
except ImportError:  # pragma: no cover - allows direct script execution
    from tools import register_tools  # type: ignore

mcp = FastMCP("Phase-2 MCP Tool Server")
register_tools(mcp)

app = mcp.streamable_http_app()


if __name__ == "__main__":
    # Useful for direct local runs; production/dev runs should use uvicorn with `app`.
    mcp.run(transport="streamable-http")
