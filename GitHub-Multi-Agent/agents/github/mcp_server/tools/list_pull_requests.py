from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


def list_pull_requests(
    owner: str,
    repo: str,
    state: str = "open",
    base: str = None,
    per_page: int = 20,
    page: int = 1,
) -> list[dict]:
    """
    List pull requests for a GitHub repository.

    Args:
        owner: GitHub username or organization name
        repo: Repository name
        state: PR state — 'open', 'closed', or 'all' (default: 'open')
        base: Filter by base branch name (e.g. 'main')
        per_page: Number of results per page (max 100, default 20)
        page: Page number for pagination (default 1)

    Returns:
        List of pull request dictionaries
    """
    class InputModel(BaseModel):
        owner: str
        repo: str
        state: str = "open"
        base: str | None = None
        per_page: int = Field(default=20, ge=1, le=100)
        page: int = Field(default=1, ge=1)

    payload = InputModel(
        owner=owner,
        repo=repo,
        state=state,
        base=base,
        per_page=per_page,
        page=page,
    )
    client = GitHubClient()

    def _fetch():
        params = {
            "state": payload.state,
            "per_page": payload.per_page,
            "page": payload.page,
        }
        if payload.base:
            params["base"] = payload.base

        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/pulls", params=params)

        pull_requests = []
        for item in data:
            pull_requests.append(
                {
                    "number": item.get("number"),
                    "title": item.get("title"),
                    "state": item.get("state"),
                    "author": item.get("user", {}).get("login"),
                    "head_branch": item.get("head", {}).get("ref"),
                    "base_branch": item.get("base", {}).get("ref"),
                    "draft": item.get("draft"),
                    "labels": [lbl["name"] for lbl in item.get("labels", [])],
                    "created_at": item.get("created_at"),
                    "updated_at": item.get("updated_at"),
                    "url": item.get("html_url"),
                    "body": (item.get("body") or "")[:500],
                }
            )
        return pull_requests

    return cached_tool_call(
        server="github",
        tool_name="list_pull_requests",
        args=payload.model_dump(),
        ttl=90,
        fetcher=_fetch,
    )
