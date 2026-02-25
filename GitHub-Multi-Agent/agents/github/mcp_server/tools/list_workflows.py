from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    per_page: int = Field(default=20, ge=1, le=100)
    page: int = Field(default=1, ge=1)


def list_workflows(owner: str, repo: str, per_page: int = 20, page: int = 1) -> dict:
    payload = InputModel(owner=owner, repo=repo, per_page=per_page, page=page)
    client = GitHubClient()

    def _fetch():
        data = client.request(
            "GET",
            f"/repos/{payload.owner}/{payload.repo}/actions/workflows",
            params={"per_page": payload.per_page, "page": payload.page},
        )
        return [
            {
                "id": wf.get("id"),
                "name": wf.get("name"),
                "path": wf.get("path"),
                "state": wf.get("state"),
                "url": wf.get("html_url"),
            }
            for wf in data.get("workflows", [])
        ]

    return cached_tool_call(
        server="github",
        tool_name="list_workflows",
        args=payload.model_dump(),
        ttl=180,
        fetcher=_fetch,
    )
