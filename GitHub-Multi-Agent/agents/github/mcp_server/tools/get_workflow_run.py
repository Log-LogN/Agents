from pydantic import BaseModel

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    run_id: int


def get_workflow_run(owner: str, repo: str, run_id: int) -> dict:
    payload = InputModel(owner=owner, repo=repo, run_id=run_id)
    client = GitHubClient()

    def _fetch():
        data = client.request("GET", f"/repos/{payload.owner}/{payload.repo}/actions/runs/{payload.run_id}")
        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "display_title": data.get("display_title"),
            "status": data.get("status"),
            "conclusion": data.get("conclusion"),
            "event": data.get("event"),
            "head_branch": data.get("head_branch"),
            "head_sha": data.get("head_sha"),
            "run_number": data.get("run_number"),
            "run_attempt": data.get("run_attempt"),
            "jobs_url": data.get("jobs_url"),
            "artifacts_url": data.get("artifacts_url"),
            "logs_url": data.get("logs_url"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "url": data.get("html_url"),
        }

    return cached_tool_call(
        server="github",
        tool_name="get_workflow_run",
        args=payload.model_dump(),
        ttl=90,
        fetcher=_fetch,
    )
