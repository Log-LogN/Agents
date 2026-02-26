from pydantic import BaseModel

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str


def get_default_branch(owner: str, repo: str) -> dict:
    payload = InputModel(owner=owner, repo=repo)
    client = GitHubClient()

    def _fetch():
        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}")
        return {
            "default_branch": data.get("default_branch"),
            "full_name": data.get("full_name"),
        }

    return cached_tool_call(
        server="github",
        tool_name="get_default_branch",
        args=payload.model_dump(),
        ttl=300,
        fetcher=_fetch,
    )
