from __future__ import annotations

from typing import Any, Callable


RUN_ID_TOOLS = {
    "tool_get_workflow_run",
    "tool_get_artifacts_for_run",
}

WORKFLOW_TOOLS = {
    "tool_list_workflow_runs",
    "tool_get_workflow_run",
    "tool_trigger_workflow_dispatch",
}

BRANCH_DEFAULT_TOOLS = {
    "tool_list_commits",
    "tool_list_workflow_runs",
}


def _unwrap_data(result: Any) -> Any:
    if isinstance(result, dict) and "data" in result:
        return result.get("data")
    return result


def _require_repo(args: dict[str, Any]) -> tuple[str, str]:
    owner = (args.get("owner") or "").strip()
    repo = (args.get("repo") or "").strip()
    if not owner or not repo:
        raise ValueError("Missing repository context. Provide owner/repo.")
    return owner, repo


def _resolve_default_branch(
    args: dict[str, Any],
    tool_executor: Callable[[str, dict[str, Any]], Any],
    events: list[dict[str, Any]],
) -> str:
    owner, repo = _require_repo(args)
    resp = tool_executor("tool_get_default_branch", {"owner": owner, "repo": repo})
    data = _unwrap_data(resp) or {}
    branch = data.get("default_branch")
    if not branch:
        raise ValueError("Could not resolve default branch.")
    events.append(
        {
            "event": "parameter_resolved",
            "tool": "tool_get_default_branch",
            "field": "branch",
            "value": branch,
            "message": f"Using default branch: {branch}",
        }
    )
    return branch


def _resolve_workflow_id(
    tool_name: str,
    args: dict[str, Any],
    tool_executor: Callable[[str, dict[str, Any]], Any],
    events: list[dict[str, Any]],
) -> None:
    owner, repo = _require_repo(args)

    workflow_id = args.get("workflow_id")
    workflow_name = (args.get("workflow_name") or "").strip()

    # Nothing to resolve.
    if workflow_id:
        return

    response = tool_executor(
        "tool_list_workflows",
        {"owner": owner, "repo": repo, "per_page": 100, "page": 1},
    )
    workflows = _unwrap_data(response) or []

    if not isinstance(workflows, list):
        raise ValueError("Could not resolve workflows for repository.")

    if workflow_name:
        target = None
        for wf in workflows:
            if (wf.get("name") or "").lower() == workflow_name.lower():
                target = wf
                break
        if not target:
            raise ValueError(f"Workflow '{workflow_name}' not found")

        args["workflow_id"] = str(target.get("id"))
        events.append(
            {
                "event": "parameter_resolved",
                "tool": tool_name,
                "field": "workflow_id",
                "value": args["workflow_id"],
                "message": f"Resolved workflow '{workflow_name}' -> {args['workflow_id']}",
            }
        )
        return

    # Both workflow_name and workflow_id are missing.
    if len(workflows) == 0:
        raise ValueError("No workflows found for this repository")

    if len(workflows) == 1:
        args["workflow_id"] = str(workflows[0].get("id"))
        events.append(
            {
                "event": "parameter_resolved",
                "tool": tool_name,
                "field": "workflow_id",
                "value": args["workflow_id"],
                "message": f"Using only available workflow_id: {args['workflow_id']}",
            }
        )
        return

    raise ValueError(
        "Multiple workflows found. Please provide workflow_name or workflow_id."
    )


def _resolve_run_id(
    tool_name: str,
    args: dict[str, Any],
    tool_executor: Callable[[str, dict[str, Any]], Any],
    events: list[dict[str, Any]],
) -> None:
    if args.get("run_id"):
        return

    owner, repo = _require_repo(args)
    workflow_id = args.get("workflow_id")
    if not workflow_id:
        _resolve_workflow_id(tool_name, args, tool_executor, events)
        workflow_id = args.get("workflow_id")

    response = tool_executor(
        "tool_list_workflow_runs",
        {
            "owner": owner,
            "repo": repo,
            "workflow_id": str(workflow_id),
            "per_page": 50,
            "page": 1,
        },
    )
    runs = _unwrap_data(response) or []

    if not isinstance(runs, list) or not runs:
        raise ValueError("No runs found for workflow")

    runs_sorted = sorted(
        runs,
        key=lambda r: (r.get("created_at") or ""),
        reverse=True,
    )
    selected = runs_sorted[0]
    run_id = selected.get("id")
    if not run_id:
        raise ValueError("Could not resolve latest run_id")

    args["run_id"] = int(run_id)
    events.append(
        {
            "event": "parameter_resolved",
            "tool": tool_name,
            "field": "run_id",
            "value": str(args["run_id"]),
            "message": f"Using latest run_id: {args['run_id']}",
        }
    )


def resolve_parameters(
    tool_name: str,
    args: dict[str, Any],
    tool_executor: Callable[[str, dict[str, Any]], Any],
) -> dict[str, Any]:
    """
    Resolve user-friendly arguments into strict MCP tool args.

    Returns updated args. Resolution events are attached under
    '__resolution_events' for the caller to emit via stream.
    """
    resolved = dict(args or {})
    events: list[dict[str, Any]] = []

    # Normalize branch when optional branch is omitted.
    if tool_name in BRANCH_DEFAULT_TOOLS and not resolved.get("branch"):
        branch = _resolve_default_branch(resolved, tool_executor, events)
        resolved["branch"] = branch

    # Resolve workflow_id for workflow-related tools.
    if tool_name in WORKFLOW_TOOLS and not resolved.get("workflow_id"):
        _resolve_workflow_id(tool_name, resolved, tool_executor, events)

    # Resolve dispatch ref from default branch when omitted.
    if tool_name == "tool_trigger_workflow_dispatch" and not resolved.get("ref"):
        branch = _resolve_default_branch(resolved, tool_executor, events)
        resolved["ref"] = branch
        events.append(
            {
                "event": "parameter_resolved",
                "tool": tool_name,
                "field": "ref",
                "value": branch,
                "message": f"Using default branch as ref: {branch}",
            }
        )

    # Resolve latest run_id when missing.
    if tool_name in RUN_ID_TOOLS and not resolved.get("run_id"):
        _resolve_run_id(tool_name, resolved, tool_executor, events)

    resolved["__resolution_events"] = events
    return resolved
