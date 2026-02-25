import base64
from pydantic import BaseModel

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


def get_file_from_repo(owner: str, repo: str, file_path: str, branch: str = None) -> dict:
    """
    Retrieve the decoded text content of a specific file from a GitHub repository.

    Args:
        owner: GitHub username or organization name
        repo: Repository name
        file_path: Path to the file inside the repo (e.g. 'src/main.py')
        branch: Branch name. Defaults to the repo's default branch.

    Returns:
        Dictionary with file metadata and decoded text content
    """
    class InputModel(BaseModel):
        owner: str
        repo: str
        file_path: str
        branch: str | None = None

    payload = InputModel(owner=owner, repo=repo, file_path=file_path, branch=branch)
    client = GitHubClient()

    def _fetch():
        params = {}
        if payload.branch:
            params["ref"] = payload.branch

        data = client.request(
            "GET",
            f"/repos/{payload.owner}/{payload.repo}/contents/{payload.file_path}",
            params=params,
        )

        raw_content = data.get("content", "")
        decoded_content = base64.b64decode(raw_content).decode("utf-8") if raw_content else ""

        return {
            "name": data.get("name"),
            "path": data.get("path"),
            "sha": data.get("sha"),
            "size": data.get("size"),
            "url": data.get("html_url"),
            "encoding": data.get("encoding"),
            "content": decoded_content,
        }

    return cached_tool_call(
        server="github",
        tool_name="get_file_from_repo",
        args=payload.model_dump(),
        ttl=120,
        fetcher=_fetch,
    )
