from __future__ import annotations

import asyncio
import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

import httpx

logger = logging.getLogger("dependency-mcp")

# =========================================================
# Helpers
# =========================================================

def _success(data: Any) -> dict:
    return {"status": "success", "data": data, "error": None}


def _failure(message: str) -> dict:
    return {"status": "error", "data": None, "error": message}


# =========================================================
# Parsing
# =========================================================

def _parse_requirements_txt(content: str) -> list[dict]:
    deps = []
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)$", line)
        if m:
            deps.append({
                "name": m.group(1),
                "version": m.group(2),
                "pinned": True,
                "ecosystem": "PyPI",
            })
    return deps


def _parse_package_json(content: str) -> list[dict]:
    deps = []
    try:
        data = json.loads(content or "{}")
    except Exception:
        return deps

    for section in ["dependencies", "devDependencies"]:
        items = data.get(section) or {}
        for name, ver in items.items():
            cleaned = str(ver).strip().lstrip("^~>=< ")
            deps.append({
                "name": name,
                "version": cleaned if cleaned else None,
                "pinned": not str(ver).startswith(("^", "~")),
                "ecosystem": "npm",
            })
    return deps


def _parse_pom_xml(content: str) -> list[dict]:
    deps = []
    try:
        root = ET.fromstring(content or "")
    except Exception:
        return deps

    for dep in root.iter():
        if dep.tag.endswith("dependency"):
            group = artifact = version = None
            for child in dep:
                tag = child.tag.split("}")[-1]
                if tag == "groupId":
                    group = child.text
                elif tag == "artifactId":
                    artifact = child.text
                elif tag == "version":
                    version = child.text
            if group and artifact:
                deps.append({
                    "name": f"{group}:{artifact}",
                    "group": group,
                    "artifact": artifact,
                    "version": version,
                    "pinned": bool(version),
                    "ecosystem": "Maven",
                })
    return deps


# =========================================================
# OSV Query
# =========================================================

async def _osv_query(ecosystem: str, name: str, version: str):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()
        return r.json()


# =========================================================
# Main Scan Logic
# =========================================================

async def scan_dependencies_from_text(content: str, file_type: str) -> dict:
    ft = (file_type or "").lower()

    if ft == "requirements.txt":
        deps = _parse_requirements_txt(content)
    elif ft == "package.json":
        deps = _parse_package_json(content)
    elif ft == "pom.xml":
        deps = _parse_pom_xml(content)
    else:
        return _failure("Unsupported file_type")

    if not deps:
        return _success({"file_type": ft, "count": 0, "dependencies": []})

    semaphore = asyncio.Semaphore(8)

    async def _scan(dep: dict):
        async with semaphore:
            vulns = []
            if dep.get("version"):
                try:
                    osv = await _osv_query(
                        dep["ecosystem"],
                        dep["name"],
                        dep["version"],
                    )
                    vulns = osv.get("vulns", [])
                except Exception as e:
                    logger.warning("OSV error %s: %s", dep["name"], str(e))

            return {
                "name": dep["name"],
                "ecosystem": dep["ecosystem"],
                "version": dep.get("version"),
                "pinned": dep.get("pinned"),
                "vulnerability_count": len(vulns),
                "vulnerabilities": [
                    {"id": v.get("id"), "summary": v.get("summary")}
                    for v in vulns
                ],
                "recommendation": (
                    "Upgrade to latest stable version"
                    if vulns
                    else "No known vulnerabilities"
                ),
            }

    results = await asyncio.gather(*[_scan(d) for d in deps])

    return _success({
        "file_type": ft,
        "count": len(results),
        "dependencies": results,
    })


async def scan_public_github_repo(repo_url: str) -> dict:
    repo_url = (repo_url or "").strip()

    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)$", repo_url.rstrip("/"))
    if not m:
        return _failure("Invalid GitHub repo URL")

    owner, repo = m.groups()

    async with httpx.AsyncClient(timeout=20) as client:
        for branch in ["main", "master"]:
            for filename in ["requirements.txt", "package.json", "pom.xml"]:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
                try:
                    r = await client.get(raw_url)
                    if r.status_code == 200:
                        scan = await scan_dependencies_from_text(r.text, filename)
                        return _success({
                            "repo_url": repo_url,
                            "file": filename,
                            "branch": branch,
                            "scan": scan,
                        })
                except Exception:
                    continue

    return _success({
        "repo_url": repo_url,
        "files_found": 0,
        "scan": None,
    })