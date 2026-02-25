from pydantic import BaseModel

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    pull_number: int


def get_pull_request(owner: str, repo: str, pull_number: int) -> dict:
    payload = InputModel(owner=owner, repo=repo, pull_number=pull_number)
    client = GitHubClient()

    def _fetch():
        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/pulls/{payload.pull_number}")
        return {
            "number": data.get("number"),
            "title": data.get("title"),
            "state": data.get("state"),
            "author": data.get("user", {}).get("login"),
            "head_branch": data.get("head", {}).get("ref"),
            "base_branch": data.get("base", {}).get("ref"),
            "merged": data.get("merged"),
            "mergeable": data.get("mergeable"),
            "commits": data.get("commits"),
            "changed_files": data.get("changed_files"),
            "additions": data.get("additions"),
            "deletions": data.get("deletions"),
            "url": data.get("html_url"),
            "body": (data.get("body") or "")[:1000],
        }

    return cached_tool_call(
        server="github",
        tool_name="get_pull_request",
        args=payload.model_dump(),
        ttl=90,
        fetcher=_fetch,
    )
