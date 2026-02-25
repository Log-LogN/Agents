from pydantic import BaseModel, Field
import time

from shared.approval import generate_approval_token, validate_approval_token
from shared.audit import log_audit_event
from shared.github_client import GitHubClient
from shared.tooling import uncached_tool_call


class InputModel(BaseModel):
    owner: str
    repo: str
    workflow_id: str
    ref: str
    inputs: dict = Field(default_factory=dict)
    approval_token: str | None = None
    session_id: str = "default"


def trigger_workflow_dispatch(
    owner: str,
    repo: str,
    workflow_id: str,
    ref: str,
    inputs: dict | None = None,
    approval_token: str | None = None,
    session_id: str = "default",
) -> dict:
    payload = InputModel(
        owner=owner,
        repo=repo,
        workflow_id=workflow_id,
        ref=ref,
        inputs=inputs or {},
        approval_token=approval_token,
        session_id=session_id,
    )

    approval_args = {
        "owner": payload.owner,
        "repo": payload.repo,
        "workflow_id": payload.workflow_id,
        "ref": payload.ref,
        "inputs": payload.inputs,
    }

    if not payload.approval_token:
        token = generate_approval_token(
            tool_name="trigger_workflow_dispatch",
            args=approval_args,
            session_id=payload.session_id,
        )
        return {
            "data": {
                "approval_required": True,
                "tool_name": "trigger_workflow_dispatch",
                "approval_token": token["approval_token"],
                "expires_at": token["expires_at"],
                "message": "Re-run with approval_token to execute this mutating action.",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "github",
            "duration_ms": 0,
        }

    is_valid, reason = validate_approval_token(
        token=payload.approval_token,
        expected_tool_name="trigger_workflow_dispatch",
        expected_args=approval_args,
        session_id=payload.session_id,
    )
    if not is_valid:
        return {
            "data": {
                "approval_required": True,
                "error": f"approval validation failed: {reason}",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "github",
            "duration_ms": 0,
        }

    client = GitHubClient()

    def _execute():
        log_audit_event(
            session_id=payload.session_id,
            tool_name="trigger_workflow_dispatch",
            args=approval_args,
        )
        client.request(
            "POST",
            f"/repos/{payload.owner}/{payload.repo}/actions/workflows/{payload.workflow_id}/dispatches",
            json_body={
                "ref": payload.ref,
                "inputs": payload.inputs,
            },
        )
        return {
            "status": "queued",
            "workflow_id": payload.workflow_id,
            "ref": payload.ref,
            "inputs": payload.inputs,
        }

    return uncached_tool_call(_execute)
