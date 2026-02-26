from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


def search_code(
    query: str,
    owner: str = None,
    repo: str = None,
    language: str = None,
    per_page: int = 10,
    page: int = 1,
) -> list[dict]:
    """
    Search for code across GitHub repositories using the GitHub Code Search API.

    Args:
        query: Search keyword or expression (e.g. 'def authenticate')
        owner: Limit search to a specific GitHub user/org (optional)
        repo: Limit search to a specific repo — requires owner (optional)
        language: Filter by programming language (e.g. 'python', 'javascript')
        per_page: Number of results per page (max 100, default 10)
        page: Page number for pagination (default 1)

    Returns:
        List of matching code file dictionaries
    """
    class InputModel(BaseModel):
        query: str
        owner: str | None = None
        repo: str | None = None
        language: str | None = None
        per_page: int = Field(default=10, ge=1, le=100)
        page: int = Field(default=1, ge=1)

    payload = InputModel(
        query=query,
        owner=owner,
        repo=repo,
        language=language,
        per_page=per_page,
        page=page,
    )
    client = GitHubClient()

    def _fetch():
        q = payload.query
        if payload.repo and payload.owner:
            q += f" repo:{payload.owner}/{payload.repo}"
        elif payload.owner:
            q += f" user:{payload.owner}"
        if payload.language:
            q += f" language:{payload.language}"

        params = {"q": q, "per_page": payload.per_page, "page": payload.page}
        data = client.request("GET", "/search/code", params=params)

        results = []
        for item in data.get("items", []):
            results.append(
                {
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "repository": item.get("repository", {}).get("full_name"),
                    "url": item.get("html_url"),
                    "sha": item.get("sha"),
                }
            )
        return results

    return cached_tool_call(
        server="github",
        tool_name="search_code",
        args=payload.model_dump(),
        ttl=60,
        fetcher=_fetch,
    )
