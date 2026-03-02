import sys
import os
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mcp.server.fastmcp import FastMCP

from shared.models import HealthResponse
from mcp_tools.dependency.tools import scan_public_github_repo, scan_dependencies_from_text
from shared.request_context import install_request_context, get_session_id, get_request_id

logger = logging.getLogger("dependency-mcp")

mcp = FastMCP("dependency-mcp")


@mcp.tool()
async def tool_scan_public_repo(repo_url: str):
    """Scan a public GitHub repo for requirements.txt/package.json and query OSV."""
    logger.info("tool_call tool_scan_public_repo session_id=%s request_id=%s repo_url=%s", get_session_id() or "-", get_request_id() or "-", repo_url)
    return await scan_public_github_repo(repo_url)


@mcp.tool()
async def tool_scan_dependency_text(content: str, file_type: str):
    """Scan dependency file contents (requirements.txt or package.json) and query OSV."""
    logger.info(
        "tool_call tool_scan_dependency_text session_id=%s request_id=%s file_type=%s content_len=%s",
        get_session_id() or "-",
        get_request_id() or "-",
        file_type,
        len(content or ""),
    )
    return await scan_dependencies_from_text(content, file_type)


def create_app():
    from fastapi import FastAPI

    app = FastAPI()
    sse_app = mcp.sse_app()
    app.mount("/", sse_app)

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(service="dependency-mcp")

    install_request_context(app, service_name="dependency-mcp", logger=logger)
    return app
