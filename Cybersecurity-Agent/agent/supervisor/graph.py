import asyncio
import logging
from typing import Annotated, List, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, START, END

from shared.config import settings
from shared.models import RedisSessionStore
from shared.supervisor_intents import (
    INTENTS,
    detect_intent,
    extract_advisory_id,
    extract_cve,
    extract_domain,
    extract_github_repo_url,
)
from shared.supervisor_prompts import direct_answer_system_prompt
from shared.supervisor_router import route_with_llm
from agent._tool_runner import ainvoke_tool
from .mcp_client import get_mcp_tool_map
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage

logger = logging.getLogger("supervisor")


# =========================================================
# State
# =========================================================

class SupervisorState(TypedDict, total=False):
    messages: Annotated[List[BaseMessage], add_messages]
    intent: str
    confidence: float
    cve: str | None
    domain: str | None
    repo_url: str | None
    advisory_id: str | None
    needs_clarification: bool
    clarification_question: str | None
    output: str
    tool_calls: list
    session_id: str
    artifact: dict
    tool_map: dict


def _now_ts() -> int:
    import time

    return int(time.time())


def _is_success(result: dict) -> bool:
    status = (result.get("status") or "").lower()
    return status in ("success", "ok")


def _get_data(result: dict) -> dict | None:
    d = result.get("data")
    return d if isinstance(d, dict) else None


# =========================================================
# Nodes
# =========================================================

async def reasoning_node(state: SupervisorState) -> SupervisorState:
    # Get the last human message
    last_message = state["messages"][-1]
    user_message = last_message.content if hasattr(last_message, 'content') else str(last_message)

    match = detect_intent(user_message)
    if match.intent not in INTENTS:
        match = type(match)(intent="direct_answer", cve=match.cve, domain=match.domain)

    decision_intent = match.intent
    confidence = 1.0 if decision_intent != "direct_answer" else 0.0
    cve = match.cve
    domain = match.domain
    repo_url = match.repo_url
    advisory_id = extract_advisory_id(user_message)
    needs_clarification = False
    clarification_question = None

    # If deterministic rules are inconclusive, ask the router LLM.
    if decision_intent == "direct_answer":
        try:
            routed = await route_with_llm(user_message)
            decision_intent = routed.intent
            confidence = routed.confidence
            cve = routed.cve or cve
            domain = routed.domain or domain
            repo_url = routed.repo_url or repo_url
            advisory_id = routed.advisory_id or advisory_id
            needs_clarification = routed.needs_clarification
            clarification_question = routed.clarification_question
        except Exception:
            logger.exception("Router failed; falling back to direct_answer")

    logger.info(
        "Intent %s confidence=%.2f cve=%s domain=%s repo=%s advisory=%s",
        decision_intent,
        confidence,
        cve,
        domain,
        repo_url,
        advisory_id,
    )

    return {
        "intent": decision_intent,
        "confidence": confidence,
        "cve": cve,
        "domain": domain,
        "repo_url": repo_url,
        "advisory_id": advisory_id,
        "needs_clarification": needs_clarification,
        "clarification_question": clarification_question,
    }


def _route_next(state: SupervisorState) -> str:
    if state.get("needs_clarification"):
        return "clarify"
    if state.get("intent") == "direct_answer":
        return "direct_answer"
    return "load_tools"


def _route_intent(state: SupervisorState) -> str:
    return str(state.get("intent") or "direct_answer")


async def clarify_node(state: SupervisorState) -> SupervisorState:
    q = (state.get("clarification_question") or "").strip()
    if not q:
        q = "Please provide the missing detail to continue."
    return {"output": q, "tool_calls": [], "artifact": {"type": "clarification"}}


async def load_tools_node(state: SupervisorState) -> SupervisorState:
    tool_map = await get_mcp_tool_map()
    return {"tool_map": tool_map}


async def direct_answer_node(state: SupervisorState) -> SupervisorState:
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )
    resp = await llm.ainvoke([SystemMessage(content=direct_answer_system_prompt())] + state["messages"])
    return {"output": getattr(resp, "content", "") or "", "tool_calls": [], "artifact": {"type": "direct_answer"}}


async def threat_only_node(state: SupervisorState) -> SupervisorState:
    cve = state.get("cve") or extract_cve((state["messages"][-1].content or ""))
    if not cve:
        return {"output": "Please provide a CVE ID (e.g., CVE-2021-44228).", "tool_calls": [], "artifact": {"type": "threat"}}

    tool_map = state["tool_map"]
    epss_r, epss_log = await ainvoke_tool(tool_map, "tool_get_epss", {"cve": cve})
    kev_r, kev_log = await ainvoke_tool(tool_map, "tool_check_cisa_kev", {"cve": cve})
    exp_r, exp_log = await ainvoke_tool(tool_map, "tool_check_exploit_available", {"cve": cve})

    epss = 0.0
    if _is_success(epss_r) and _get_data(epss_r):
        epss = float((_get_data(epss_r) or {}).get("epss") or 0.0)
    in_kev = bool((_get_data(kev_r) or {}).get("in_kev")) if _is_success(kev_r) else False
    exploit = bool((_get_data(exp_r) or {}).get("exploit_available")) if _is_success(exp_r) else False

    status = "Low"
    if in_kev or epss > 0.7 or exploit:
        status = "High"
    elif epss > 0.3:
        status = "Medium"

    lines = [
        f"Threat Status: {status.upper()}",
        "",
        f"CVE: {cve}",
        f"EPSS: {int(round(epss * 100))}%",
        f"CISA KEV: {'Yes' if in_kev else 'No'}",
        f"Public exploit: {'Available' if exploit else 'Not found'}",
    ]
    if in_kev or epss > 0.7:
        lines += ["", "This vulnerability is actively exploited in the wild (high signal)."]

    return {
        "output": "\n".join(lines).strip(),
        "tool_calls": [epss_log, kev_log, exp_log],
        "artifact": {"type": "threat", "cve": cve, "epss": epss, "kev": in_kev, "exploit": exploit},
    }


async def advisory_explain_node(state: SupervisorState) -> SupervisorState:
    vuln_id = state.get("advisory_id") or extract_advisory_id((state["messages"][-1].content or ""))
    if not vuln_id:
        return {"output": "Please provide an advisory ID (GHSA-xxxx-xxxx-xxxx) or CVE (CVE-YYYY-NNNN).", "tool_calls": [], "artifact": {"type": "advisory"}}

    tool_map = state["tool_map"]
    adv_r, adv_log = await ainvoke_tool(tool_map, "tool_get_advisory", {"vuln_id": vuln_id})
    if not _is_success(adv_r) or not _get_data(adv_r):
        err = adv_r.get("error") or "Advisory lookup failed."
        return {"output": f"Advisory lookup failed: {err}", "tool_calls": [adv_log], "artifact": {"type": "advisory", "vuln_id": vuln_id}}

    data = _get_data(adv_r) or {}
    sev = data.get("severity") or []
    sev_str = (
        ", ".join(
            [f"{s.get('type')}: {s.get('score')}" for s in sev if isinstance(s, dict) and s.get("score") is not None]
        )
        or "Unknown"
    )
    summary = (data.get("summary") or "").strip()
    affected = data.get("affected") or []
    pkgs: list[str] = []
    for a in affected:
        pkg = (a.get("package") or {}) if isinstance(a, dict) else {}
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if eco and name:
            pkgs.append(f"{eco}/{name}")
    pkgs = sorted(set(pkgs))

    out_lines = [
        f"Advisory: {data.get('id') or vuln_id}",
        f"Severity: {sev_str}",
    ]
    if summary:
        out_lines.append(f"Summary: {summary}")
    if pkgs:
        out_lines.append(f"Affected: {', '.join(pkgs[:8])}{'…' if len(pkgs) > 8 else ''}")

    return {"output": "\n".join(out_lines).strip(), "tool_calls": [adv_log], "artifact": {"type": "advisory", "vuln_id": vuln_id}}


async def dependency_scan_node(state: SupervisorState) -> SupervisorState:
    repo_url = state.get("repo_url") or extract_github_repo_url((state["messages"][-1].content or ""))
    if not repo_url:
        return {"output": "Please provide a public GitHub repository URL.", "tool_calls": [], "artifact": {"type": "dependency"}}

    tool_map = state["tool_map"]
    scan_r, scan_log = await ainvoke_tool(tool_map, "tool_scan_public_repo", {"repo_url": repo_url})
    if not _is_success(scan_r) or not _get_data(scan_r):
        err = scan_r.get("error") or "Dependency scan failed."
        return {"output": f"Dependency scan failed: {err}", "tool_calls": [scan_log], "artifact": {"type": "dependency", "repo_url": repo_url}}

    data = _get_data(scan_r) or {}
    results = data.get("results") or []
    files_found = int(data.get("files_found") or 0)

    total_deps = 0
    vuln_deps = 0
    findings: list[str] = []
    highest_pkg = None
    highest_pkg_vulns = -1

    for r in results:
        scan = (r.get("scan") or {}) if isinstance(r, dict) else {}
        scan_data = (scan.get("data") or {}) if isinstance(scan, dict) else {}
        deps = scan_data.get("dependencies") or []
        total_deps += len(deps)
        for d in deps:
            vc = int(d.get("vulnerability_count") or 0) if isinstance(d, dict) else 0
            if vc > 0:
                vuln_deps += 1
                name = d.get("name")
                eco = d.get("ecosystem")
                vulns = d.get("vulnerabilities") or []
                ids = [v.get("id") for v in vulns if isinstance(v, dict) and v.get("id")]
                if name and eco:
                    findings.append(f"- {name} ({eco}): {vc} vuln(s) ({', '.join(ids[:5])}{'…' if len(ids) > 5 else ''})")
                if vc > highest_pkg_vulns:
                    highest_pkg_vulns = vc
                    highest_pkg = (name, eco, ids)

    out_lines = [
        "Dependency Scan",
        f"Repo: {repo_url}",
        f"Files scanned: {files_found}",
        f"Dependencies parsed: {total_deps}",
        f"Dependencies with vulnerabilities: {vuln_deps}",
    ]
    if findings:
        out_lines.append("Findings:")
        out_lines.extend(findings[:20])
        if len(findings) > 20:
            out_lines.append(f"... ({len(findings) - 20} more)")

    artifact = {
        "type": "dependency_scan",
        "repo_url": repo_url,
        "files_found": files_found,
        "dependencies_parsed": total_deps,
        "dependencies_with_vulnerabilities": vuln_deps,
    }
    if highest_pkg:
        artifact["highest_risk_dependency"] = {"name": highest_pkg[0], "ecosystem": highest_pkg[1], "advisories": highest_pkg[2]}

    return {"output": "\n".join(out_lines).strip(), "tool_calls": [scan_log], "artifact": artifact}


async def domain_assessment_node(state: SupervisorState) -> SupervisorState:
    last_message = state["messages"][-1]
    message = last_message.content if hasattr(last_message, "content") else str(last_message)
    domain = state.get("domain") or extract_domain(message)
    if not domain:
        return {"output": "Please provide a target domain (e.g., example.com).", "tool_calls": [], "artifact": {"type": "domain"}}

    msg_l = (message or "").lower()
    tool_map = state["tool_map"]

    # Public IP query: DNS only, strict output.
    if any(k in msg_l for k in ("public ip", "ip address", "what is the ip", "a record", "resolve")):
        dns_r, dns_log = await ainvoke_tool(tool_map, "tool_dns_lookup", {"domain": domain})
        ips = (_get_data(dns_r) or {}).get("ips") if _is_success(dns_r) else None
        if not ips:
            err = dns_r.get("error") or "DNS lookup failed."
            return {"output": f"DNS lookup failed: {err}", "tool_calls": [dns_log], "artifact": {"type": "dns", "domain": domain}}
        return {"output": f"Public IP(s): {', '.join(ips)}", "tool_calls": [dns_log], "artifact": {"type": "dns", "domain": domain, "ips": ips}}

    # Broader domain assessment.
    dns_r, dns_log = await ainvoke_tool(tool_map, "tool_dns_lookup", {"domain": domain})
    port_r, port_log = await ainvoke_tool(tool_map, "tool_port_scan", {"host": domain})
    hdr_r, hdr_log = await ainvoke_tool(tool_map, "tool_http_security_headers", {"host": domain})
    ssl_r, ssl_log = await ainvoke_tool(tool_map, "tool_ssl_info", {"host": domain, "port": 443})

    ips = (_get_data(dns_r) or {}).get("ips") if _is_success(dns_r) else []
    open_ports = (_get_data(port_r) or {}).get("open_ports") if _is_success(port_r) else []
    warning = (_get_data(port_r) or {}).get("warning") if _is_success(port_r) else None
    missing_headers = (_get_data(hdr_r) or {}).get("missing_security_headers") if _is_success(hdr_r) else None
    http_status = (_get_data(hdr_r) or {}).get("status_code") if _is_success(hdr_r) else None
    final_url = (_get_data(hdr_r) or {}).get("final_url") if _is_success(hdr_r) else None

    out_lines = [f"Domain Assessment: {domain}", "", "Findings:"]
    if warning:
        out_lines.append(f"- Port scan unreliable: {warning}")
    else:
        out_lines.append(f"- Internet exposure (open ports: {', '.join(str(p) for p in open_ports) if open_ports else 'none detected'})")
    if http_status and final_url:
        out_lines.append(f"- HTTP check: {http_status} {final_url}")
    if isinstance(missing_headers, list) and missing_headers:
        out_lines.append(f"- Missing security headers: {', '.join(missing_headers)}")
    elif hdr_r.get("error"):
        out_lines.append(f"- HTTP headers check failed: {hdr_r.get('error')}")
    if _is_success(ssl_r):
        days = (_get_data(ssl_r) or {}).get("days_to_expiry")
        if isinstance(days, int):
            out_lines.append(f"- TLS: cert expires in {days} day(s)")
    else:
        out_lines.append(f"- TLS check failed: {ssl_r.get('error')}")

    return {
        "output": "\n".join(out_lines).strip(),
        "tool_calls": [dns_log, port_log, hdr_log, ssl_log],
        "artifact": {"type": "domain_assessment", "domain": domain, "ips": ips, "ports": open_ports},
    }


async def recon_only_node(state: SupervisorState) -> SupervisorState:
    last_message = state["messages"][-1]
    message = last_message.content if hasattr(last_message, "content") else str(last_message)
    domain = state.get("domain") or extract_domain(message)
    if not domain:
        return {"output": "Please provide a target domain or IP.", "tool_calls": [], "artifact": {"type": "recon"}}

    msg_l = (message or "").lower()
    tool_map = state["tool_map"]

    if "whois" in msg_l:
        whois_r, whois_log = await ainvoke_tool(tool_map, "tool_whois_lookup", {"domain": domain})
        if not _is_success(whois_r) or not _get_data(whois_r):
            return {"output": f"WHOIS lookup failed: {whois_r.get('error')}", "tool_calls": [whois_log], "artifact": {"type": "recon", "domain": domain}}
        d = _get_data(whois_r) or {}
        registrar = d.get("registrar") or "Unknown"
        expiry = d.get("expiration_date") or "Unknown"
        return {
            "output": f"WHOIS: registrar={registrar}, expiration={expiry}",
            "tool_calls": [whois_log],
            "artifact": {"type": "recon", "domain": domain, "whois": d},
        }

    if "port" in msg_l:
        port_r, port_log = await ainvoke_tool(tool_map, "tool_port_scan", {"host": domain})
        if not _is_success(port_r):
            return {"output": f"Port scan failed: {port_r.get('error')}", "tool_calls": [port_log], "artifact": {"type": "recon", "domain": domain}}
        data = _get_data(port_r) or {}
        warning = data.get("warning")
        if warning:
            return {"output": f"Port scan unreliable: {warning}", "tool_calls": [port_log], "artifact": {"type": "recon", "domain": domain}}
        ports = data.get("open_ports") or []
        return {"output": f"Open ports: {', '.join(str(p) for p in ports) if ports else 'none detected'}", "tool_calls": [port_log], "artifact": {"type": "recon", "domain": domain, "ports": ports}}

    # Default to DNS lookup for recon-only.
    dns_r, dns_log = await ainvoke_tool(tool_map, "tool_dns_lookup", {"domain": domain})
    ips = (_get_data(dns_r) or {}).get("ips") if _is_success(dns_r) else None
    if not ips:
        return {"output": f"DNS lookup failed: {dns_r.get('error')}", "tool_calls": [dns_log], "artifact": {"type": "recon", "domain": domain}}
    return {"output": f"Public IP(s): {', '.join(ips)}", "tool_calls": [dns_log], "artifact": {"type": "recon", "domain": domain, "ips": ips}}


async def risk_assessment_node(state: SupervisorState) -> SupervisorState:
    last_message = state["messages"][-1]
    message = last_message.content if hasattr(last_message, "content") else str(last_message)
    cve = state.get("cve") or extract_cve(message)
    domain = state.get("domain") or extract_domain(message)

    if not cve:
        return {"output": "Please provide a CVE ID (e.g., CVE-2021-44228).", "tool_calls": [], "artifact": {"type": "risk"}}
    if not domain:
        return {"output": "Please provide a target domain (e.g., example.com).", "tool_calls": [], "artifact": {"type": "risk", "cve": cve}}

    tool_map = state["tool_map"]

    cvss_r, cvss_log = await ainvoke_tool(tool_map, "tool_get_cvss", {"cve": cve})
    cvss = 5.0
    if _is_success(cvss_r) and _get_data(cvss_r):
        try:
            cvss = float((_get_data(cvss_r) or {}).get("cvss") or (_get_data(cvss_r) or {}).get("base_score") or 5.0)
        except Exception:
            cvss = 5.0

    epss_r, kev_r, exp_r = await asyncio.gather(
        ainvoke_tool(tool_map, "tool_get_epss", {"cve": cve}),
        ainvoke_tool(tool_map, "tool_check_cisa_kev", {"cve": cve}),
        ainvoke_tool(tool_map, "tool_check_exploit_available", {"cve": cve}),
    )
    epss_result, epss_log = epss_r
    kev_result, kev_log = kev_r
    exp_result, exp_log = exp_r

    epss = 0.0
    percentile = 0.0
    if _is_success(epss_result) and _get_data(epss_result):
        epss = float((_get_data(epss_result) or {}).get("epss") or 0.0)
        percentile = float((_get_data(epss_result) or {}).get("percentile") or 0.0)
    in_kev = bool((_get_data(kev_result) or {}).get("in_kev")) if _is_success(kev_result) else False
    exploit = bool((_get_data(exp_result) or {}).get("exploit_available")) if _is_success(exp_result) else False

    port_r, port_log = await ainvoke_tool(tool_map, "tool_port_scan", {"host": domain})
    open_ports = (_get_data(port_r) or {}).get("open_ports") if _is_success(port_r) else []
    warning = (_get_data(port_r) or {}).get("warning") if _is_success(port_r) else None
    internet_exposed = bool(open_ports) and not warning

    risk_r, risk_log = await ainvoke_tool(
        tool_map,
        "tool_calculate_risk",
        {
            "cvss": cvss,
            "epss": epss,
            "exploit_available": exploit,
            "internet_exposed": internet_exposed,
            "open_ports": open_ports or [],
            "in_kev": in_kev,
        },
    )
    if not _is_success(risk_r) or not _get_data(risk_r):
        err = risk_r.get("error") or "Risk calculation failed."
        return {
            "output": f"Risk assessment failed: {err}",
            "tool_calls": [cvss_log, epss_log, kev_log, exp_log, port_log, risk_log],
            "artifact": {"type": "risk", "cve": cve, "domain": domain},
        }

    risk_data = _get_data(risk_r) or {}
    overall = float(risk_data.get("overall_score") or 0.0)
    severity = str(risk_data.get("severity") or "Unknown")
    reasons = list(risk_data.get("reasons") or [])

    # Enrich with baseline facts for readability.
    reasons_out = [f"CVSS: {cvss}"]
    reasons_out.append(f"EPSS: {int(round(epss * 100))}%")
    if in_kev and "Listed in CISA KEV" not in reasons_out:
        reasons_out.append("Listed in CISA KEV")
    if exploit:
        reasons_out.append("Public exploit available")
    if warning:
        reasons_out.append("Exposure scan unreliable")
    elif open_ports:
        reasons_out.append(f"Internet exposed (ports: {', '.join(str(p) for p in open_ports)})")
    for r in reasons:
        if r not in reasons_out:
            reasons_out.append(r)

    out_lines = [
        f"Risk: {severity.upper()} ({overall})",
        "",
        f"CVE: {cve}",
        f"Domain: {domain}",
        "",
        "Reasons:",
        *[f"- {r}" for r in reasons_out],
        "",
        "Action:",
        f"{risk_data.get('recommended_priority')}.",
    ]

    artifact = {
        "type": "risk",
        "cve": cve,
        "domain": domain,
        "cvss": cvss,
        "epss": epss,
        "percentile": percentile,
        "kev": in_kev,
        "exploit": exploit,
        "ports": open_ports or [],
        "risk_score": overall,
        "severity": severity,
        "timestamp": _now_ts(),
    }

    return {
        "output": "\n".join(out_lines).strip(),
        "tool_calls": [cvss_log, epss_log, kev_log, exp_log, port_log, risk_log],
        "artifact": artifact,
    }


async def session_analysis_node(state: SupervisorState) -> SupervisorState:
    session_id = state.get("session_id") or ""
    store = RedisSessionStore()
    artifacts = store.get_session_artifacts(session_id) if session_id else []
    if not artifacts:
        return {"output": "No risk assessments found in this session.", "tool_calls": [], "artifact": {"type": "session"}}

    # Prefer risk artifacts.
    risks = [a for a in artifacts if isinstance(a, dict) and a.get("type") == "risk" and isinstance(a.get("risk_score"), (int, float))]
    if risks:
        highest = max(risks, key=lambda x: float(x.get("risk_score") or 0.0))
        out = "\n".join(
            [
                "Highest Risk Issue",
                "",
                f"CVE: {highest.get('cve')}",
                f"Domain: {highest.get('domain')}",
                f"Risk: {str(highest.get('severity') or '').upper()} ({highest.get('risk_score')})",
                "",
                "Recommendation:",
                "Prioritize this vulnerability immediately.",
            ]
        ).strip()
        return {"output": out, "tool_calls": [], "artifact": {"type": "session", "highest": highest}}

    deps = [a for a in artifacts if isinstance(a, dict) and a.get("type") in ("dependency_scan", "dependency")]
    if deps:
        last = deps[-1]
        hr = last.get("highest_risk_dependency") or {}
        if isinstance(hr, dict) and hr.get("name"):
            out = "\n".join(
                [
                    "Highest Risk Dependency Package",
                    f"Package: {hr.get('name')}",
                    f"Ecosystem: {hr.get('ecosystem')}",
                    f"Advisories: {', '.join(hr.get('advisories') or [])}",
                ]
            ).strip()
            return {"output": out, "tool_calls": [], "artifact": {"type": "session", "highest_dependency": hr}}

    return {"output": "No prioritizable findings found in this session.", "tool_calls": [], "artifact": {"type": "session"}}


async def report_generation_node(state: SupervisorState) -> SupervisorState:
    session_id = state.get("session_id") or ""
    if not session_id:
        return {"output": "Missing session_id for report generation.", "tool_calls": [], "artifact": {"type": "report"}}
    tool_map = state["tool_map"]
    rep_r, rep_log = await ainvoke_tool(tool_map, "tool_generate_session_report", {"session_id": session_id})
    if not _is_success(rep_r) or not _get_data(rep_r):
        err = rep_r.get("error") or "Report generation failed."
        return {"output": f"Report generation failed: {err}", "tool_calls": [rep_log], "artifact": {"type": "report", "session_id": session_id}}
    path = (_get_data(rep_r) or {}).get("path") or (_get_data(rep_r) or {}).get("file_path")
    if path:
        return {"output": f"Report saved: {path}", "tool_calls": [rep_log], "artifact": {"type": "report", "path": path}}
    return {"output": "Report generated.", "tool_calls": [rep_log], "artifact": {"type": "report"}}


# ---------------------------------------------------------

async def finalize_node(state: SupervisorState) -> SupervisorState:
    output = state.get("output", "").strip()
    if not output:
        output = "Unable to process request."

    # Add AI response to messages
    return {
        "output": output,
        "messages": [AIMessage(content=output)]
    }


# =========================================================
# Graph
# =========================================================

def build_supervisor_graph(checkpointer=None):
    graph = StateGraph(SupervisorState)

    graph.add_node("reasoning", reasoning_node)
    graph.add_node("clarify", clarify_node)
    graph.add_node("load_tools", load_tools_node)

    graph.add_node("direct_answer", direct_answer_node)
    graph.add_node("risk_assessment", risk_assessment_node)
    graph.add_node("threat_only", threat_only_node)
    graph.add_node("advisory_explain", advisory_explain_node)
    graph.add_node("dependency_scan", dependency_scan_node)
    graph.add_node("domain_assessment", domain_assessment_node)
    graph.add_node("recon_only", recon_only_node)
    graph.add_node("session_analysis", session_analysis_node)
    graph.add_node("report_generation", report_generation_node)

    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "reasoning")
    graph.add_conditional_edges(
        "reasoning",
        _route_next,
        {
            "clarify": "clarify",
            "direct_answer": "direct_answer",
            "load_tools": "load_tools",
        },
    )

    graph.add_conditional_edges(
        "load_tools",
        _route_intent,
        {
            "risk_assessment": "risk_assessment",
            "threat_only": "threat_only",
            "advisory_explain": "advisory_explain",
            "dependency_scan": "dependency_scan",
            "domain_assessment": "domain_assessment",
            "recon_only": "recon_only",
            "session_analysis": "session_analysis",
            "report_generation": "report_generation",
            # Safety fallback
            "direct_answer": "direct_answer",
        },
    )

    for node in (
        "clarify",
        "direct_answer",
        "risk_assessment",
        "threat_only",
        "advisory_explain",
        "dependency_scan",
        "domain_assessment",
        "recon_only",
        "session_analysis",
        "report_generation",
    ):
        graph.add_edge(node, "finalize")

    graph.add_edge("finalize", END)

    return graph.compile(checkpointer=checkpointer)


# =========================================================
# Entry
# =========================================================

async def run_supervisor(user_message: str, session_id: str, graph):
    session_store = RedisSessionStore()

    # Load existing history
    history = session_store.get_session_history(session_id)
    messages = [HumanMessage(content=msg["content"]) if msg["type"] == "human" else AIMessage(content=msg["content"]) for msg in history]

    # Add new human message
    messages.append(HumanMessage(content=user_message))

    # Run graph with messages
    final = await graph.ainvoke({

        "messages": messages,
        "session_id": session_id,
    }, {"configurable": {"thread_id": session_id}})

    # Save updated history
    updated_messages = final.get("messages", messages)
    history_data = [{"type": "human" if isinstance(msg, HumanMessage) else "ai", "content": msg.content} for msg in updated_messages]
    session_store.save_session_history(session_id, history_data)

    # Persist structured artifacts for reporting.
    try:
        artifact = final.get("artifact") or {}
        tool_calls = final.get("tool_calls") or []
        intent = final.get("intent", final.get("selected_agent", ""))

        entry = {"intent": intent, "tool_calls": tool_calls}
        if isinstance(artifact, dict):
            entry.update(artifact)
        if "timestamp" not in entry:
            entry["timestamp"] = _now_ts()
        if "cve" not in entry:
            entry["cve"] = extract_cve(user_message)
        if "domain" not in entry:
            entry["domain"] = extract_domain(user_message)

        session_store.append_session_artifact(session_id, entry)
    except Exception:
        logger.exception("Failed to persist artifacts")

    return {
        "output": final.get("output", ""),
        "agent_used": final.get("intent", final.get("selected_agent", "")),
        "tool_calls": final.get("tool_calls", []),
    }
