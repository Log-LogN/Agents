from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from shared.models import RedisSessionStore


def _success(data: Any) -> dict:
    return {"status": "success", "data": data, "error": None}


def _failure(message: str) -> dict:
    return {"status": "error", "data": None, "error": message}


def _ts(ts: int | float | None) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))


def generate_session_report(session_id: str) -> dict:
    """
    Phase-1 session report generator.

    Pulls chat history and structured artifacts from Redis (if available),
    writes a Markdown report to ./reports/<session_id>.md, and returns the path.
    """
    session_id = (session_id or "").strip()
    if not session_id:
        return _failure("session_id is required.")

    store = RedisSessionStore()
    history = store.get_session_history(session_id)
    artifacts = store.get_session_artifacts(session_id)

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / f"{session_id}.md"

    # Identify highest risk artifact, if any (Phase-1 blueprint: type="risk", risk_score key).
    risks = [a for a in artifacts if isinstance(a, dict) and a.get("type") == "risk" and a.get("risk_score") is not None]
    highest = None
    if risks:
        def _score(x: dict) -> float:
            try:
                return float(x.get("risk_score") or 0)
            except Exception:
                return 0.0

        highest = max(risks, key=_score)

    lines: list[str] = []
    lines.append("# Security Session Report")
    lines.append("")
    lines.append(f"- Session ID: `{session_id}`")
    lines.append(f"- Generated: {_ts(time.time())}")
    lines.append("")

    lines.append("## Assets Scanned")
    assets = sorted({a.get("domain") for a in artifacts if isinstance(a, dict) and a.get("domain")})
    if assets:
        for t in assets:
            lines.append(f"- {t}")
    else:
        lines.append("- (none recorded)")
    lines.append("")

    lines.append("## Vulnerabilities Found")
    cves = sorted({a.get("cve") for a in artifacts if isinstance(a, dict) and isinstance(a.get("cve"), str)})
    if cves:
        for cve in cves:
            lines.append(f"- {cve}")
    else:
        lines.append("- (none recorded)")
    lines.append("")

    lines.append("## Highest Risk Issue")
    if highest and isinstance(highest, dict):
        lines.append(f"- CVE: {highest.get('cve', '(unknown)')}")
        lines.append(f"- Domain: {highest.get('domain', '(unknown)')}")
        lines.append(f"- Risk: **{str(highest.get('severity', '(unknown)')).upper()}** ({highest.get('risk_score', '?')})")
        ports = highest.get("ports") or []
        if ports:
            lines.append(f"- Ports: {', '.join(str(p) for p in ports)}")
        lines.append("- Signals:")
        lines.append(f"  - CVSS: {highest.get('cvss', '?')}")
        lines.append(f"  - EPSS: {int(round(float(highest.get('epss') or 0) * 100))}%")
        lines.append(f"  - KEV: {'Yes' if highest.get('kev') else 'No'}")
        lines.append(f"  - Exploit: {'Yes' if highest.get('exploit') else 'No'}")
    else:
        lines.append("- (no risk assessments recorded)")
    lines.append("")

    lines.append("## Session Timeline")
    if history:
        for msg in history:
            t = msg.get("type")
            content = (msg.get("content") or "").strip()
            if not content:
                continue
            label = "User" if t == "human" else "Assistant"
            lines.append(f"### {label}")
            lines.append("")
            lines.append(content)
            lines.append("")
    else:
        lines.append("_No chat history available._")
        lines.append("")

    lines.append("## Artifacts (JSON)")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(artifacts, indent=2)[:20000])
    lines.append("```")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")

    return _success({"session_id": session_id, "report_path": str(out_path)})
