from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    run_id: int
    per_page: int = Field(default=20, ge=1, le=100)
    page: int = Field(default=1, ge=1)


def get_artifacts_for_run(owner: str, repo: str, run_id: int, per_page: int = 20, page: int = 1) -> dict:
    payload = InputModel(owner=owner, repo=repo, run_id=run_id, per_page=per_page, page=page)
    client = GitHubClient()

    def _fetch():
        data = client.request(
            "GET",
            f"/repos/{payload.owner}/{payload.repo}/actions/runs/{payload.run_id}/artifacts",
            params={"per_page": payload.per_page, "page": payload.page},
        )
        return [
            {
                "id": artifact.get("id"),
                "name": artifact.get("name"),
                "size_in_bytes": artifact.get("size_in_bytes"),
                "expired": artifact.get("expired"),
                "created_at": artifact.get("created_at"),
                "expires_at": artifact.get("expires_at"),
                "download_url": artifact.get("archive_download_url"),
            }
            for artifact in data.get("artifacts", [])
        ]

    return cached_tool_call(
        server="github",
        tool_name="get_artifacts_for_run",
        args=payload.model_dump(),
        ttl=90,
        fetcher=_fetch,
    )
