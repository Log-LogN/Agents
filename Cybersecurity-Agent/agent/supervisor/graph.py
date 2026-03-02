import json
import logging
import re
from typing import TypedDict, Annotated, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, BaseMessage, AIMessage
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, START, END

from shared.config import settings
from shared.models import RedisSessionStore
from shared.supervisor_intents import detect_intent, extract_cve, extract_domain
from agent.recon_graph import run_recon_agent
from agent.vulnerability_graph import run_vulnerability_agent
from .mcp_client import get_mcp_tools, get_mcp_tool_map

logger = logging.getLogger("supervisor")


# =========================================================
# State
# =========================================================

class SupervisorState(TypedDict, total=False):
    messages: Annotated[List[BaseMessage], add_messages]
    selected_agent: str
    intent: str
    output: str
    tool_calls: list
    session_id: str
    artifact: dict


def _now_ts() -> int:
    import time

    return int(time.time())


def _as_dict(result) -> dict:
    if isinstance(result, dict):
        return result
    try:
        return json.loads(str(result))
    except Exception:
        return {"raw": str(result)}


async def _ainvoke_tool(tool_map: dict, name: str, args: dict) -> tuple[dict, dict]:
    tool = tool_map.get(name)
    if tool is None:
        out = {"status": "error", "data": None, "error": f"Missing tool: {name}"}
        return out, {"tool_name": name, "tool_input": args, "tool_output": json.dumps(out)}
    res = await tool.ainvoke(args)
    out = _as_dict(res)
    return out, {"tool_name": name, "tool_input": args, "tool_output": json.dumps(out)}


async def _run_risk_assessment(message: str, session_id: str) -> dict:
    tool_map = await get_mcp_tool_map()

    cve = extract_cve(message)
    domain = extract_domain(message)

    if not cve:
        return {"output": "Please provide a CVE (e.g., CVE-2024-12345).", "tool_calls": [], "artifact": {"type": "risk"}}

    if not domain:
        return {
            "output": "Please provide a target domain (e.g., example.com)",
            "tool_calls": [],
            "artifact": {"type": "risk", "cve": cve, "domain": None},
        }

    tool_calls: list[dict] = []

    cvss_res, tc = await _ainvoke_tool(tool_map, "tool_get_cvss", {"cve": cve})
    tool_calls.append(tc)
    cvss_val = None
    if cvss_res.get("status") == "success":
        cvss_val = (cvss_res.get("data") or {}).get("cvss")
    try:
        cvss = float(cvss_val) if cvss_val is not None else 5.0
    except Exception:
        cvss = 5.0

    epss_res, tc = await _ainvoke_tool(tool_map, "tool_get_epss", {"cve": cve})
    tool_calls.append(tc)
    epss = 0.0
    if epss_res.get("status") == "success":
        try:
            epss = float((epss_res.get("data") or {}).get("epss") or 0.0)
        except Exception:
            epss = 0.0

    exploit_res, tc = await _ainvoke_tool(tool_map, "tool_check_exploit_available", {"cve": cve})
    tool_calls.append(tc)
    exploit_available = False
    if exploit_res.get("status") == "success":
        d = exploit_res.get("data") or {}
        exploit_available = bool(d.get("exploit_available"))

    kev_res, tc = await _ainvoke_tool(tool_map, "tool_check_cisa_kev", {"cve": cve})
    tool_calls.append(tc)
    in_kev = False
    if kev_res.get("status") == "success":
        in_kev = bool((kev_res.get("data") or {}).get("in_kev"))

    port_res, tc = await _ainvoke_tool(tool_map, "tool_port_scan", {"host": domain})
    tool_calls.append(tc)
    open_ports: list[int] = []
    internet_exposed = False
    if port_res.get("status") == "success":
        d = port_res.get("data") or {}
        open_ports = list(d.get("open_ports") or [])
        internet_exposed = bool(open_ports)

    risk_res, tc = await _ainvoke_tool(
        tool_map,
        "tool_calculate_risk",
        {
            "cvss": cvss,
            "epss": epss,
            "exploit_available": exploit_available,
            "in_kev": in_kev,
            "internet_exposed": internet_exposed,
            "open_ports": open_ports,
        },
    )
    tool_calls.append(tc)

    if isinstance(risk_res, dict) and risk_res.get("status") == "success":
        risk_data = risk_res.get("data") or {}
    else:
        # Defensive fallback: keep the pipeline deterministic even if the risk tool is unavailable.
        score_fallback = min(10.0, round(float(cvss), 1))
        risk_data = {
            "overall_score": score_fallback,
            "severity": "Critical" if score_fallback >= 9 else "High" if score_fallback >= 7 else "Medium" if score_fallback >= 4 else "Low",
            "recommended_priority": "Patch immediately" if score_fallback >= 9 else "Patch ASAP" if score_fallback >= 7 else "Patch soon" if score_fallback >= 4 else "Monitor / schedule fix",
        }
    severity = str(risk_data.get("severity") or "Unknown").upper()
    score = risk_data.get("overall_score", "?")
    priority = risk_data.get("recommended_priority") or "Patch"

    logger.info(
        "Risk Inputs %s",
        {"cvss": cvss, "epss": epss, "kev": in_kev, "exploit": exploit_available, "ports": open_ports},
    )

    ports_text = ", ".join(str(p) for p in open_ports) if open_ports else "(none)"
    output = "\n".join(
        [
            f"Risk: {severity} ({score})",
            "",
            f"CVE: {cve}",
            f"Domain: {domain}",
            "",
            "Reasons:",
            f"- CVSS: {cvss}",
            f"- EPSS: {int(round(epss * 100))}%",
            "- Listed in CISA KEV" if in_kev else "- Listed in CISA KEV: No",
            "- Public exploit available" if exploit_available else "- Public exploit available: No",
            f"- Internet exposed (ports: {ports_text})" if internet_exposed else "- Internet exposed: No",
            "",
            "Action:",
            f"{priority}.",
        ]
    )

    return {
        "output": output,
        "tool_calls": tool_calls,
        "artifact": {
            "type": "risk",
            "cve": cve,
            "domain": domain,
            "cvss": cvss,
            "epss": epss,
            "kev": in_kev,
            "exploit": exploit_available,
            "ports": open_ports,
            "risk_score": risk_data.get("overall_score"),
            "severity": risk_data.get("severity"),
            "timestamp": _now_ts(),
        },
    }


async def _run_threat_only(message: str) -> dict:
    tool_map = await get_mcp_tool_map()
    cve = extract_cve(message)
    if not cve:
        return {"output": "Please provide a CVE (e.g., CVE-2024-12345).", "tool_calls": [], "artifact": {"type": "threat"}}

    tool_calls: list[dict] = []
    epss_res, tc = await _ainvoke_tool(tool_map, "tool_get_epss", {"cve": cve})
    tool_calls.append(tc)
    epss = 0.0
    if epss_res.get("status") == "success":
        try:
            epss = float((epss_res.get("data") or {}).get("epss") or 0.0)
        except Exception:
            epss = 0.0

    kev_res, tc = await _ainvoke_tool(tool_map, "tool_check_cisa_kev", {"cve": cve})
    tool_calls.append(tc)
    kev = False
    if kev_res.get("status") == "success":
        kev = bool((kev_res.get("data") or {}).get("in_kev"))

    exploit_res, tc = await _ainvoke_tool(tool_map, "tool_check_exploit_available", {"cve": cve})
    tool_calls.append(tc)
    exploit = False
    if exploit_res.get("status") == "success":
        exploit = bool((exploit_res.get("data") or {}).get("exploit_available"))

    threat_status = "LOW"
    if kev or exploit or epss >= 0.7:
        threat_status = "HIGH"
    elif epss >= 0.3:
        threat_status = "MEDIUM"

    output = "\n".join(
        [
            f"Threat Status: {threat_status}",
            "",
            f"CVE: {cve}",
            f"EPSS: {int(round(epss * 100))}%",
            f"CISA KEV: {'Yes' if kev else 'No'}",
            f"Public exploit: {'Available' if exploit else 'Not found'}",
            "",
            "This vulnerability is actively exploited in the wild." if threat_status == "HIGH" else "Threat signals are limited; validate exposure and patch based on context.",
        ]
    )

    return {
        "output": output,
        "tool_calls": tool_calls,
        "artifact": {"type": "threat", "cve": cve, "epss": epss, "kev": kev, "exploit": exploit, "timestamp": _now_ts()},
    }


async def _run_session_analysis(session_id: str) -> dict:
    store = RedisSessionStore()
    artifacts = store.get_session_artifacts(session_id)
    risks = [a for a in artifacts if isinstance(a, dict) and a.get("type") == "risk" and a.get("risk_score") is not None]
    if not risks:
        return {"output": "No risk assessments found in this session.", "tool_calls": [], "artifact": {"type": "session_analysis"}}

    def _score(a: dict) -> float:
        try:
            return float(a.get("risk_score") or 0)
        except Exception:
            return 0.0

    highest = max(risks, key=_score)
    output = "\n".join(
        [
            "Highest Risk Issue",
            "",
            f"CVE: {highest.get('cve', '(unknown)')}",
            f"Domain: {highest.get('domain', '(unknown)')}",
            f"Risk: {str(highest.get('severity', '(unknown)')).upper()} ({highest.get('risk_score', '?')})",
            "",
            "Reason:",
            "- High EPSS" if float(highest.get("epss") or 0) > 0.7 else "- Risk assessment recorded in session",
            "- KEV listed" if highest.get("kev") else "- KEV not listed",
            "- Internet exposed" if highest.get("ports") else "- Exposure unknown",
            "",
            "Recommendation:",
            "Prioritize this vulnerability immediately.",
        ]
    )
    return {"output": output, "tool_calls": [], "artifact": {"type": "session_analysis", "highest": highest, "timestamp": _now_ts()}}


async def _run_reporting(session_id: str) -> dict:
    tool_map = await get_mcp_tool_map()
    report_res, tc = await _ainvoke_tool(tool_map, "tool_generate_session_report", {"session_id": session_id})
    if report_res.get("status") == "success":
        path = (report_res.get("data") or {}).get("report_path")
        output = f"Session report generated: {path}"
    else:
        output = f"Report generation failed: {report_res.get('error')}"
    return {"output": output, "tool_calls": [tc], "artifact": {"type": "reporting", "session_id": session_id, "report": report_res.get("data")}}


# =========================================================
# Nodes
# =========================================================

async def reasoning_node(state: SupervisorState) -> SupervisorState:
    # Get the last human message
    last_message = state["messages"][-1]
    user_message = last_message.content if hasattr(last_message, 'content') else str(last_message)
    match = detect_intent(user_message)
    logger.info("Intent %s", match.intent)
    return {"intent": match.intent, "selected_agent": match.intent}


# ---------------------------------------------------------

async def execute_node(state: SupervisorState) -> SupervisorState:
    intent = state.get("intent", state.get("selected_agent", "direct_answer"))
    # Get the last human message
    last_message = state["messages"][-1]
    message = last_message.content if hasattr(last_message, 'content') else str(last_message)
    session_id = state.get("session_id", "")

    # Load MCP tools once
    recon_tools, vuln_tools = await get_mcp_tools()

    def _looks_like_vuln_query(msg: str) -> bool:
        m = (msg or "").lower()
        return any(k in m for k in ("cve search", "vulnerability", "osv", "pypi", "npm", "maven", "dependency", "@"))

    async def _direct_answer() -> dict:
        # Preserve existing vuln agent usefulness without mixing intents.
        if _looks_like_vuln_query(message):
            return await run_vulnerability_agent(state["messages"], vuln_tools)
        llm = ChatOpenAI(model=settings.OPENAI_MODEL, api_key=settings.OPENAI_API_KEY, temperature=0)
        resp = await llm.ainvoke(state["messages"])
        return {"output": resp.content, "tool_calls": [], "artifact": {"type": "direct_answer"}}

    handlers = {
        "risk_assessment": lambda: _run_risk_assessment(message, session_id),
        "threat_only": lambda: _run_threat_only(message),
        "session_analysis": lambda: _run_session_analysis(session_id),
        "report_generation": lambda: _run_reporting(session_id),
        "recon_only": lambda: run_recon_agent(state["messages"], recon_tools),
        "direct_answer": _direct_answer,
    }

    handler = handlers.get(intent, _direct_answer)
    result = await handler()

    return {
        "output": result.get("output", ""),
        "tool_calls": result.get("tool_calls", []),
        "artifact": result.get("artifact", {}),
    }


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
    graph.add_node("execute", execute_node)
    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "reasoning")
    graph.add_edge("reasoning", "execute")
    graph.add_edge("execute", "finalize")
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
