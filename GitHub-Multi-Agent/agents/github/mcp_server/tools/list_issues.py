from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


def list_issues(
    owner: str,
    repo: str,
    state: str = "open",
    labels: str = None,
    per_page: int = 20,
    page: int = 1,
) -> list[dict]:
    """
    List issues for a GitHub repository.

    Args:
        owner: GitHub username or organization name
        repo: Repository name
        state: Issue state — 'open', 'closed', or 'all' (default: 'open')
        labels: Comma-separated label names to filter by (e.g. 'bug,help wanted')
        per_page: Number of results per page (max 100, default 20)
        page: Page number for pagination (default 1)

    Returns:
        List of issue dictionaries
    """
    class InputModel(BaseModel):
        owner: str
        repo: str
        state: str = "open"
        labels: str | None = None
        per_page: int = Field(default=20, ge=1, le=100)
        page: int = Field(default=1, ge=1)

    payload = InputModel(
        owner=owner,
        repo=repo,
        state=state,
        labels=labels,
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
        if payload.labels:
            params["labels"] = payload.labels

        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/issues", params=params)

        issues = []
        for item in data:
            if "pull_request" in item:
                continue
            issues.append(
                {
                    "number": item.get("number"),
                    "title": item.get("title"),
                    "state": item.get("state"),
                    "author": item.get("user", {}).get("login"),
                    "labels": [lbl["name"] for lbl in item.get("labels", [])],
                    "comments": item.get("comments"),
                    "created_at": item.get("created_at"),
                    "updated_at": item.get("updated_at"),
                    "url": item.get("html_url"),
                    "body": (item.get("body") or "")[:500],
                }
            )
        return issues

    return cached_tool_call(
        server="github",
        tool_name="list_issues",
        args=payload.model_dump(),
        ttl=90,
        fetcher=_fetch,
    )
