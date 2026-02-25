"""
GitHub MCP Server
=================
Runs as a subprocess inside the GitHub Agent container.
Exposes all GitHub tools via the MCP protocol (stdio transport).

Start manually:
    python -m agents.github.mcp_server.server

Or let the agent's graph.py start it automatically via MultiServerMCPClient.
"""

import sys
import os

# Ensure project root is on path when run directly
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..")))
# mcp_server is at agents/github/mcp_server — go up three levels to reach project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from mcp.server.fastmcp import FastMCP
from agents.github.mcp_server.tools import (
    get_repo_info,
    get_file_from_repo,
    list_issues,
    list_pull_requests,
    search_code,
    list_branches,
    get_default_branch,
    list_commits,
    get_commit,
    get_pull_request,
    list_workflows,
    list_workflow_runs,
    get_workflow_run,
    trigger_workflow_dispatch,
    get_artifacts_for_run,
    download_artifact,
)

mcp = FastMCP("github-mcp-server")


# ── Register tools ──────────────────────────────────────────────────────────

@mcp.tool()
def tool_get_repo_info(owner: str, repo: str) -> dict:
    """
    Fetch general metadata about a GitHub repository: description, stars, forks,
    open issues count, primary language, topics, license, and more.
    """
    return get_repo_info(owner, repo)


@mcp.tool()
def tool_get_file_from_repo(owner: str, repo: str, file_path: str, branch: str = None) -> dict:
    """
    Retrieve the decoded text content of a specific file from a GitHub repository.
    Useful for reading README files, source code, configs, etc.
    """
    return get_file_from_repo(owner, repo, file_path, branch)


@mcp.tool()
def tool_list_issues(
    owner: str,
    repo: str,
    state: str = "open",
    labels: str = None,
    per_page: int = 20,
    page: int = 1,
) -> list:
    """
    List issues for a GitHub repository. Supports filtering by state
    (open/closed/all) and labels.
    """
    return list_issues(owner, repo, state, labels, per_page, page)


@mcp.tool()
def tool_list_pull_requests(
    owner: str,
    repo: str,
    state: str = "open",
    base: str = None,
    per_page: int = 20,
    page: int = 1,
) -> list:
    """
    List pull requests for a GitHub repository. Supports filtering by state
    and base branch.
    """
    return list_pull_requests(owner, repo, state, base, per_page, page)


@mcp.tool()
def tool_search_code(
    query: str,
    owner: str = None,
    repo: str = None,
    language: str = None,
    per_page: int = 10,
    page: int = 1,
) -> list:
    """
    Search for code snippets across GitHub using keywords. Can be scoped to a
    specific owner/repo and filtered by programming language.
    """
    return search_code(query, owner, repo, language, per_page, page)


@mcp.tool()
def tool_list_branches(owner: str, repo: str, per_page: int = 20, page: int = 1) -> dict:
    return list_branches(owner, repo, per_page, page)


@mcp.tool()
def tool_get_default_branch(owner: str, repo: str) -> dict:
    return get_default_branch(owner, repo)


@mcp.tool()
def tool_list_commits(
    owner: str,
    repo: str,
    branch: str = None,
    per_page: int = 20,
    page: int = 1,
) -> dict:
    return list_commits(owner, repo, branch, per_page, page)


@mcp.tool()
def tool_get_commit(owner: str, repo: str, sha: str) -> dict:
    return get_commit(owner, repo, sha)


@mcp.tool()
def tool_get_pull_request(owner: str, repo: str, pull_number: int) -> dict:
    return get_pull_request(owner, repo, pull_number)


@mcp.tool()
def tool_list_workflows(owner: str, repo: str, per_page: int = 20, page: int = 1) -> dict:
    return list_workflows(owner, repo, per_page, page)


@mcp.tool()
def tool_list_workflow_runs(
    owner: str,
    repo: str,
    workflow_id: str = None,
    branch: str = None,
    status: str = None,
    per_page: int = 20,
    page: int = 1,
) -> dict:
    return list_workflow_runs(owner, repo, workflow_id, branch, status, per_page, page)


@mcp.tool()
def tool_get_workflow_run(owner: str, repo: str, run_id: int) -> dict:
    return get_workflow_run(owner, repo, run_id)


@mcp.tool()
def tool_trigger_workflow_dispatch(
    owner: str,
    repo: str,
    workflow_id: str,
    ref: str,
    inputs: dict = None,
    approval_token: str = None,
    session_id: str = "default",
) -> dict:
    return trigger_workflow_dispatch(
        owner=owner,
        repo=repo,
        workflow_id=workflow_id,
        ref=ref,
        inputs=inputs or {},
        approval_token=approval_token,
        session_id=session_id,
    )


@mcp.tool()
def tool_get_artifacts_for_run(
    owner: str,
    repo: str,
    run_id: int,
    per_page: int = 20,
    page: int = 1,
) -> dict:
    return get_artifacts_for_run(owner, repo, run_id, per_page, page)


@mcp.tool()
def tool_download_artifact(owner: str, repo: str, artifact_id: int) -> dict:
    return download_artifact(owner, repo, artifact_id)


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run with stdio transport (default for subprocess MCP clients)
    mcp.run(transport="stdio")
