from __future__ import annotations

from shared.supervisor_intents import extract_github_repo_url
from agent.supervisor.mcp_client import get_mcp_tool_map
from agent._tool_runner import ainvoke_tool


async def run_dependency_agent(message: str) -> dict:
    repo_url = extract_github_repo_url(message)
    if not repo_url:
        return {"output": "Need public GitHub repo URL.", "tool_calls": [], "artifact": {"type": "dependency_scan"}}

    tool_map = await get_mcp_tool_map()
    tool_calls: list[dict] = []
    scan_res, tc = await ainvoke_tool(tool_map, "tool_scan_public_repo", {"repo_url": repo_url})
    tool_calls.append(tc)

    if scan_res.get("status") != "success":
        return {
            "output": f"Dependency scan failed: {scan_res.get('error')}",
            "tool_calls": tool_calls,
            "artifact": {"type": "dependency_scan", "repo_url": repo_url},
        }

    data = scan_res.get("data") or {}
    results = data.get("results") or []

    total_deps = 0
    total_vuln_deps = 0
    top: list[str] = []

    for r in results:
        scan = r.get("scan") or {}
        scan_data = (scan.get("data") or {}) if isinstance(scan, dict) else {}
        deps = scan_data.get("dependencies") or []
        total_deps += len(deps)
        for d in deps:
            if (d.get("vulnerability_count") or 0) > 0:
                total_vuln_deps += 1
                ids = [v.get("id") for v in (d.get("vulnerabilities") or []) if isinstance(v, dict) and v.get("id")]
                top.append(f"{d.get('name')} ({d.get('ecosystem')}): {len(ids)} vuln(s) ({', '.join(ids[:3])})")

    lines = [
        "Dependency Scan",
        f"Repo: {repo_url}",
        f"Files scanned: {data.get('files_found', 0)}",
        f"Dependencies parsed: {total_deps}",
        f"Dependencies with vulnerabilities: {total_vuln_deps}",
    ]
    if top:
        lines.append("Findings:")
        lines.extend([f"- {t}" for t in top[:10]])

    artifact = {"type": "dependency_scan", "repo_url": repo_url, "result": data}
    return {"output": "\n".join(lines), "tool_calls": tool_calls, "artifact": artifact}

