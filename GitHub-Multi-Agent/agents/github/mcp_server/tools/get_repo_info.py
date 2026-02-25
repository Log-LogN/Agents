from pydantic import BaseModel

from shared.tooling import cached_tool_call
from shared.github_client import GitHubClient


def get_repo_info(owner: str, repo: str) -> dict:
    """
    Fetch general metadata about a GitHub repository.

    Args:
        owner: GitHub username or organization name (e.g. 'anthropics')
        repo: Repository name (e.g. 'anthropic-sdk-python')

    Returns:
        Dictionary with repository details
    """
    class InputModel(BaseModel):
        owner: str
        repo: str

    payload = InputModel(owner=owner, repo=repo)
    client = GitHubClient()

    def _fetch():
        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}")
        return {
            "name": data.get("name"),
            "full_name": data.get("full_name"),
            "description": data.get("description"),
            "url": data.get("html_url"),
            "stars": data.get("stargazers_count"),
            "forks": data.get("forks_count"),
            "open_issues": data.get("open_issues_count"),
            "language": data.get("language"),
            "default_branch": data.get("default_branch"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "license": data.get("license", {}).get("name") if data.get("license") else None,
            "topics": data.get("topics", []),
            "visibility": data.get("visibility"),
            "size_kb": data.get("size"),
        }

    return cached_tool_call(
        server="github",
        tool_name="get_repo_info",
        args=payload.model_dump(),
        ttl=300,
        fetcher=_fetch,
    )
