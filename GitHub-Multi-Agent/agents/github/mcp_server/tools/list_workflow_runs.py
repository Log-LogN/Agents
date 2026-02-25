from pydantic import BaseModel, Field

from shared.github_client import GitHubClient
from shared.tooling import cached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    workflow_id: str | None = None
    branch: str | None = None
    status: str | None = None
    per_page: int = Field(default=20, ge=1, le=100)
    page: int = Field(default=1, ge=1)


def list_workflow_runs(
    owner: str,
    repo: str,
    workflow_id: str | None = None,
    branch: str | None = None,
    status: str | None = None,
    per_page: int = 20,
    page: int = 1,
) -> dict:
    payload = InputModel(
        owner=owner,
        repo=repo,
        workflow_id=workflow_id,
        branch=branch,
        status=status,
        per_page=per_page,
        page=page,
    )
    client = GitHubClient()

    def _fetch():
        params = {"per_page": payload.per_page, "page": payload.page}
        if payload.branch:
            params["branch"] = payload.branch
        if payload.status:
            params["status"] = payload.status

        if payload.workflow_id:
            path = f"/repos/{payload.owner}/{payload.repo}/actions/workflows/{payload.workflow_id}/runs"
        else:
            path = f"/repos/{payload.owner}/{payload.repo}/actions/runs"

        data = client.request("GET", path, params=params)
        return [
            {
                "id": run.get("id"),
                "name": run.get("name"),
                "display_title": run.get("display_title"),
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
                "event": run.get("event"),
                "head_branch": run.get("head_branch"),
                "head_sha": run.get("head_sha"),
                "created_at": run.get("created_at"),
                "updated_at": run.get("updated_at"),
                "url": run.get("html_url"),
            }
            for run in data.get("workflow_runs", [])
        ]

    return cached_tool_call(
        server="github",
        tool_name="list_workflow_runs",
        args=payload.model_dump(),
        ttl=90,
        fetcher=_fetch,
    )
