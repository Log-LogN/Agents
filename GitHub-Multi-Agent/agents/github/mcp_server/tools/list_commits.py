from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    branch: str | None = None
    per_page: int = Field(default=20, ge=1, le=100)
    page: int = Field(default=1, ge=1)


def list_commits(
    owner: str,
    repo: str,
    branch: str | None = None,
    per_page: int = 20,
    page: int = 1,
) -> dict:
    payload = InputModel(owner=owner, repo=repo, branch=branch, per_page=per_page, page=page)
    client = GitHubClient()

    def _fetch():
        params = {"per_page": payload.per_page, "page": payload.page}
        if payload.branch:
            params["sha"] = payload.branch

        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/commits", params=params)
        return [
            {
                "sha": item.get("sha"),
                "author": item.get("commit", {}).get("author", {}).get("name"),
                "message": item.get("commit", {}).get("message"),
                "date": item.get("commit", {}).get("author", {}).get("date"),
                "url": item.get("html_url"),
            }
            for item in data
        ]

    return cached_tool_call(
        server="github",
        tool_name="list_commits",
        args=payload.model_dump(),
        ttl=120,
        fetcher=_fetch,
    )
