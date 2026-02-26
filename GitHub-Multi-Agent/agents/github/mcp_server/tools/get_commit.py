from pydantic import BaseModel

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    sha: str


def get_commit(owner: str, repo: str, sha: str) -> dict:
    payload = InputModel(owner=owner, repo=repo, sha=sha)
    client = GitHubClient()

    def _fetch():
        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/commits/{payload.sha}")
        return {
            "sha": data.get("sha"),
            "message": data.get("commit", {}).get("message"),
            "author": data.get("commit", {}).get("author"),
            "committer": data.get("commit", {}).get("committer"),
            "stats": data.get("stats"),
            "files": [
                {
                    "filename": item.get("filename"),
                    "status": item.get("status"),
                    "additions": item.get("additions"),
                    "deletions": item.get("deletions"),
                }
                for item in data.get("files", [])
            ],
            "url": data.get("html_url"),
        }

    return cached_tool_call(
        server="github",
        tool_name="get_commit",
        args=payload.model_dump(),
        ttl=120,
        fetcher=_fetch,
    )
