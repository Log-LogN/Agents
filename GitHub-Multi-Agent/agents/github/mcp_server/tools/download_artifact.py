from pydantic import BaseModel

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    artifact_id: int


def download_artifact(owner: str, repo: str, artifact_id: int) -> dict:
    payload = InputModel(owner=owner, repo=repo, artifact_id=artifact_id)
    client = GitHubClient()

    def _fetch():
        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/actions/artifacts/{payload.artifact_id}")
        return {
            "artifact_id": data.get("id"),
            "name": data.get("name"),
            "expired": data.get("expired"),
            "size_in_bytes": data.get("size_in_bytes"),
            "download_url": data.get("archive_download_url"),
            "note": "Use download_url with authenticated HTTP client to fetch artifact binary.",
        }

    return cached_tool_call(
        server="github",
        tool_name="download_artifact",
        args=payload.model_dump(),
        ttl=120,
        fetcher=_fetch,
    )
