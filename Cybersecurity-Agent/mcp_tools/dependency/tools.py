from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger("dependency-mcp")


def _success(data: Any) -> dict:
    return {"status": "success", "data": data, "error": None}


def _failure(message: str) -> dict:
    return {"status": "error", "data": None, "error": message}


def _parse_requirements_txt(content: str) -> list[dict]:
    deps: list[dict] = []
    for raw in (content or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-r ") or line.startswith("--"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)$", line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2), "pinned": True})
        else:
            m2 = re.match(r"^([A-Za-z0-9_.-]+)(.*)$", line)
            if m2:
                deps.append({"name": m2.group(1), "version": None, "pinned": False, "raw": line})
    return deps


def _parse_package_json(content: str) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(content or "{}")
    except Exception:
        return deps

    semver_re = re.compile(r"^\d+\.\d+\.\d+([-.+].+)?$")

    def _add(section: str):
        items = data.get(section) or {}
        if isinstance(items, dict):
            for name, ver in items.items():
                v = str(ver)
                cleaned = v.strip().lstrip("^~>=< ").strip()
                version_candidate = cleaned if semver_re.match(cleaned or "") else None
                is_exact = bool(version_candidate and v.strip().startswith(version_candidate))
                deps.append(
                    {
                        "name": name,
                        "version": version_candidate,
                        "pinned": is_exact,
                        "raw": v,
                        "scope": section,
                    }
                )

    _add("dependencies")
    _add("devDependencies")
    return deps


async def _osv_query(ecosystem: str, name: str, version: str) -> dict:
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
        r = await client.post(url, json=payload, headers={"User-Agent": "cybersecurity-agent/dependency"})
        r.raise_for_status()
        return r.json()


def _summarize_osv(v: dict) -> dict:
    return {"id": v.get("id"), "summary": v.get("summary"), "severity": (v.get("database_specific") or {}).get("severity")}


async def _latest_pypi(name: str) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            r = await client.get(f"https://pypi.org/pypi/{name}/json", headers={"User-Agent": "cybersecurity-agent/dependency"})
            if r.status_code != 200:
                return None
            data = r.json()
            return ((data.get("info") or {}).get("version")) or None
    except Exception:
        return None


async def _latest_npm(name: str) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            r = await client.get(f"https://registry.npmjs.org/{name}", headers={"User-Agent": "cybersecurity-agent/dependency"})
            if r.status_code != 200:
                return None
            data = r.json()
            tags = data.get("dist-tags") or {}
            return tags.get("latest")
    except Exception:
        return None


async def scan_dependencies_from_text(content: str, file_type: str) -> dict:
    ft = (file_type or "").strip().lower()
    if ft not in ("requirements.txt", "package.json"):
        return _failure("file_type must be requirements.txt or package.json")

    deps = _parse_requirements_txt(content) if ft == "requirements.txt" else _parse_package_json(content)
    if not deps:
        return _success({"file_type": ft, "count": 0, "dependencies": []})

    async def _latest(name: str, ecosystem: str) -> str | None:
        return await (_latest_pypi(name) if ecosystem == "PyPI" else _latest_npm(name))

    async def _scan_one(dep: dict) -> dict:
        name = dep["name"]
        version = dep.get("version")
        pinned = bool(dep.get("pinned"))
        ecosystem = "PyPI" if ft == "requirements.txt" else "npm"

        vulns: list[dict] = []
        # For npm ranges (e.g. "^1.2.3"), we still query OSV using the version candidate.
        if version:
            try:
                osv = await _osv_query(ecosystem, name, version)
                vulns = [_summarize_osv(v) for v in (osv.get("vulns") or [])]
            except Exception as e:
                logger.warning("OSV query failed for %s: %s", name, str(e))

        latest = await _latest(name, ecosystem)

        recs: list[str] = []
        if not pinned:
            recs.append("Pin exact versions (avoid floating ranges) for reproducible triage.")
        if vulns:
            recs.append("Upgrade to a non-vulnerable version; validate via OSV/NVD after bump.")
        if latest and (not version or latest != version):
            recs.append(f"Consider upgrading to latest: {latest}")

        return {
            "name": name,
            "ecosystem": ecosystem,
            "current_version": version,
            "latest_version": latest,
            "pinned": pinned,
            "vulnerability_count": len(vulns),
            "vulnerabilities": vulns,
            "recommendations": recs,
            **({"raw": dep.get("raw")} if dep.get("raw") else {}),
            **({"scope": dep.get("scope")} if dep.get("scope") else {}),
        }

    # Concurrency limit to keep scans fast without overwhelming registries.
    concurrency = 8
    semaphore = asyncio.Semaphore(concurrency)

    async def _guard(dep: dict) -> dict:
        async with semaphore:
            return await _scan_one(dep)

    results = await asyncio.gather(*[_guard(d) for d in deps])

    return _success({"file_type": ft, "count": len(results), "dependencies": results})


async def scan_public_github_repo(repo_url: str) -> dict:
    """
    Best-effort scan for common dependency files in a public GitHub repo.
    Tries main then master for:
    - requirements.txt
    - package.json
    """
    repo_url = (repo_url or "").strip()
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)$", repo_url.rstrip("/"))
    if not m:
        return _failure("repo_url must be a GitHub URL like https://github.com/org/repo")

    owner, repo = m.group(1), m.group(2)
    branches = ["main", "master"]
    paths = ["requirements.txt", "package.json"]

    found: list[dict] = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), headers={"User-Agent": "cybersecurity-agent/dependency"}) as client:
        for path in paths:
            for br in branches:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{br}/{path}"
                try:
                    r = await client.get(raw_url)
                    if r.status_code == 200 and r.text.strip():
                        found.append({"path": path, "branch": br, "content": r.text})
                        break
                except Exception:
                    continue

    if not found:
        return _success({"repo_url": repo_url, "files_found": 0, "results": []})

    results: list[dict] = []
    for f in found:
        scan = await scan_dependencies_from_text(f["content"], f["path"])
        results.append({"path": f["path"], "branch": f["branch"], "scan": scan})

    return _success({"repo_url": repo_url, "files_found": len(found), "results": results})
