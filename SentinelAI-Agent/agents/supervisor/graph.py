"""
Supervisor Agent — LangGraph StateGraph
========================================
Routes user requests to specialist sub-agents via a dynamic graph pipeline.
"""

import sys
import os
import json
import logging
import re
import time
from typing import Literal, TypedDict

import httpx
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from agents.direct_answer_agent import run_direct_answer

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.config import settings

logger = logging.getLogger("supervisor")

# ── Agent registry ────────────────────────────────────────────────────────────

AGENT_REGISTRY = {
    "recon": settings.RECON_AGENT_URL,
    "vulnerability": settings.VULN_AGENT_URL,
    "reporting": settings.REPORT_AGENT_URL,
}
DIRECT_ANSWER_AGENT = "direct_answer"

AGENT_DESCRIPTIONS = """
- recon: network discovery, domain info, port scanning, enumeration
- vulnerability: detect security issues, CVEs, misconfigurations
- exploitation: simulate controlled attack attempts
- reporting: generate security report, risk analysis, mitigation
"""

KNOWN_AGENTS = list(AGENT_REGISTRY.keys()) + ["none"]


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── Routing system prompt ─────────────────────────────────────────────────────

ROUTING_SYSTEM_PROMPT = f"""
You are the Supervisor of SentinelAI, a multi-agent security system.

Your job is to route user requests to the correct security specialist agent.

Available agents:
{AGENT_DESCRIPTIONS}

Routing guidelines:

recon:
- domain lookup
- IP lookup
- port scanning
- subdomain enumeration
- network discovery

vulnerability:
- vulnerability scanning
- CVE lookup
- service/version weakness
- misconfiguration detection

reporting:
- generate security report
- risk assessment
- mitigation advice
- summarize findings

Rules:
- Route to the most relevant agent.
- If the request is unclear but security-related, choose the closest agent.
- If the request is NOT related to cybersecurity, use agent "none".
- Respond ONLY with JSON.

Format:
{{
  "agent": "<one of: {KNOWN_AGENTS}>",
  "message": "<refined task>",
  "reason": "<one sentence>"
}}
"""


def _clean_json(raw: str) -> str:
    """Strip markdown code fences and whitespace OpenAI sometimes wraps JSON in."""
    raw = raw.strip()
    # Remove ```json ... ``` or ``` ... ```
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    return raw.strip()


# ── Graph state ───────────────────────────────────────────────────────────────

RouteStatus = Literal["selected", "out_of_scope", "undetermined"]


class SupervisorState(TypedDict, total=False):
    user_message: str
    routed_message: str
    selected_agent: str
    routing_reason: str
    route_status: RouteStatus
    output: str
    tool_calls: list[dict]


# ── Routing logic ─────────────────────────────────────────────────────────────

async def route_to_agent(user_message: str) -> tuple[str, str, str, RouteStatus]:
    """
    Decide which agent to call.
    Returns: (agent_name, routed_message, reason, route_status)
    """
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
        model_kwargs={"response_format": {"type": "json_object"}},  # forces pure JSON
    )

    response = await llm.ainvoke([
        SystemMessage(content=ROUTING_SYSTEM_PROMPT),
        HumanMessage(content=user_message),
    ])

    raw = _clean_json(response.content)

    try:
        routing = json.loads(raw)
        agent_name = str(routing.get("agent", "none")).lower().strip()
        routed_message = str(routing.get("message", user_message) or user_message)
        reason = str(routing.get("reason", "") or "")

        if agent_name not in KNOWN_AGENTS:
            logger.warning(f"LLM returned unknown agent '{agent_name}', treating as undetermined")
            return "none", user_message, f"unknown-agent '{agent_name}'", "undetermined"

        status: RouteStatus = "selected"
        if agent_name == "none":
            status = "out_of_scope"

        logger.info(f"Routing decision → agent={agent_name} | status={status} | reason={reason}")
        return agent_name, routed_message, reason, status

    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Routing JSON parse failed: {e!r} | raw='{raw[:200]}'")
        # Last resort: check if message looks GitHub-related
        security_keywords = [
            "scan", "port", "vulnerability", "cve", "exploit",
            "security", "attack", "risk", "domain", "ip"
        ]
        if any(kw in user_message.lower() for kw in security_keywords):
            logger.warning("Routing parse fallback: detected security keywords")
            return "recon", user_message, "security keyword fallback", "selected"
        return "none", user_message, "parse error fallback", "undetermined"


# ── HTTP agent caller ─────────────────────────────────────────────────────────

async def call_agent(agent_name: str, message: str) -> dict:
    """POST to the chosen agent's /invoke endpoint."""
    base_url = AGENT_REGISTRY[agent_name]
    url = f"{base_url}/invoke"
    logger.info(f"Calling agent '{agent_name}' at {url}")

    # If caller passed a structured dict, extract the textual field we use across agents
    payload_message = message
    if isinstance(message, dict):
        # Prefer a 'text' field, fall back to 'message' or string representation
        payload_message = message.get("text") or message.get("message") or str(message)
        logger.debug(f"Extracted payload message for agent {agent_name}: {payload_message}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            # Log the outgoing payload for easier debugging
            try:
                payload_text = json.dumps({"message": payload_message})
            except Exception:
                payload_text = str({"message": payload_message})
            logger.debug(f"Payload to {agent_name}: {payload_text}")

            resp = await client.post(url, json={"message": payload_message})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            # Include response body to surface validation errors like 422
            resp = getattr(e, "response", None)
            resp_text = resp.text if resp is not None else ""
            status = resp.status_code if resp is not None else "(no status)"
            logger.error(
                f"Agent '{agent_name}' returned HTTP {status} for {url}: {resp_text}"
            )
            raise Exception(
                f"Agent '{agent_name}' returned HTTP {status}: {resp_text}"
            )


async def call_agent_stream(agent_name: str, message: str):
    """Stream events from the chosen agent's /invoke/stream endpoint."""
    base_url = AGENT_REGISTRY[agent_name]
    url = f"{base_url}/invoke/stream"
    logger.info(f"Streaming call to agent '{agent_name}' at {url}")

    payload_message = message
    if isinstance(message, dict):
        payload_message = message.get("text") or message.get("message") or str(message)
        logger.debug(f"Extracted payload message for agent {agent_name} (stream): {payload_message}")

    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", url, json={"message": payload_message}) as resp:
            resp.raise_for_status()
            event_name = None
            event_data = ""
            event_id = ""

            async for line in resp.aiter_lines():
                if not line:
                    if event_name:
                        parsed = {}
                        if event_data:
                            try:
                                parsed = json.loads(event_data)
                            except json.JSONDecodeError:
                                parsed = {"raw": event_data}
                        yield {
                            "event": event_name,
                            "data": parsed,
                            "timestamp": event_id,
                        }
                    event_name = None
                    event_data = ""
                    event_id = ""
                    continue

                if line.startswith("event: "):
                    event_name = line[7:].strip()
                elif line.startswith("data: "):
                    event_data = line[6:].strip()
                elif line.startswith("id: "):
                    event_id = line[4:].strip()


# ── Out-of-scope response ─────────────────────────────────────────────────────

OUT_OF_SCOPE_RESPONSE = (
    "This system only handles cybersecurity assessment tasks.\n\n"
    "Supported operations:\n"
    "- Network and domain reconnaissance\n"
    "- Vulnerability analysis\n"
    "- Controlled security testing\n"
    "- Security reporting and risk assessment\n\n"
    "Please ask a cybersecurity-related question."
)

# ── Graph nodes ───────────────────────────────────────────────────────────────

async def reasoning_node(state: SupervisorState) -> SupervisorState:
    """
    Required first node before any agent execution.
    Produces a normalized routed message for subsequent routing.
    """
    cleaned = (state.get("user_message") or "").strip()
    return {
        "routed_message": cleaned,
        "routing_reason": "reasoning-initialized",
        "route_status": "undetermined",
    }


async def routing_node(state: SupervisorState) -> SupervisorState:
    agent_name, routed_message, reason, route_status = await route_to_agent(
        state.get("routed_message") or state.get("user_message", "")
    )
    return {
        "selected_agent": agent_name,
        "routed_message": routed_message,
        "routing_reason": reason,
        "route_status": route_status,
    }


def post_routing_next(state: SupervisorState) -> str:
    route_status = state.get("route_status", "undetermined")
    if route_status == "out_of_scope":
        return "out_of_scope"
    if route_status == "undetermined":
        return "fallback"
    return "execute"


async def fallback_node(state: SupervisorState) -> SupervisorState:
    reason = state.get("routing_reason", "")
    merged_reason = f"{reason}; default-fallback={DIRECT_ANSWER_AGENT}".strip("; ")
    return {
        "selected_agent": DIRECT_ANSWER_AGENT,
        "routing_reason": merged_reason,
        "route_status": "selected",
    }


async def out_of_scope_node(_: SupervisorState) -> SupervisorState:
    return {
        "output": OUT_OF_SCOPE_RESPONSE,
        "selected_agent": "none",
        "tool_calls": [],
    }


async def execute_agent_node(state: SupervisorState) -> SupervisorState:
    selected_agent = state.get("selected_agent")
    message = state.get("routed_message", "")

    execution_chain = plan_execution(selected_agent, message)

    current_input = {
        "text": message,
        "previous_results": []
    }

    all_tool_calls = []
    final_output = ""

    for agent in execution_chain:
        logger.info(f"Auto-chain → calling {agent}")

        result = await call_agent(agent, current_input)

        final_output = result.get("output", "")
        all_tool_calls.extend(result.get("tool_calls", []))

        # Pass structured context forward
        current_input = {
            "text": final_output,
            "previous_results": result.get("tool_calls", [])
        }

    return {
        "output": final_output,
        "tool_calls": all_tool_calls
    }


async def finalize_node(state: SupervisorState) -> SupervisorState:
    output = state.get("output", "").strip()
    if not output:
        output = "I couldn't produce a response. Please try rephrasing your request."
    return {"output": output}


def _build_supervisor_graph():
    graph = StateGraph(SupervisorState)
    graph.add_node("reasoning", reasoning_node)
    graph.add_node("route", routing_node)
    graph.add_node("fallback", fallback_node)
    graph.add_node("out_of_scope", out_of_scope_node)
    graph.add_node("execute", execute_agent_node)
    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "reasoning")
    graph.add_edge("reasoning", "route")
    graph.add_conditional_edges(
        "route",
        post_routing_next,
        {
            "fallback": "fallback",
            "out_of_scope": "out_of_scope",
            "execute": "execute",
        },
    )
    graph.add_edge("fallback", "execute")
    graph.add_edge("execute", "finalize")
    graph.add_edge("finalize", END)
    graph.add_edge("out_of_scope", END)
    return graph.compile()


SUPERVISOR_GRAPH = _build_supervisor_graph()


# ── Main supervisor entry points ──────────────────────────────────────────────

async def run_supervisor(user_message: str) -> dict:
    """
    Run the full supervisor pipeline for one user message.

    Returns:
        {
            "output": str,
            "agent_used": str,      # "none" if out of scope
            "tool_calls": list
        }
    """
    logger.info(f"Supervisor received: {user_message[:120]}")

    final_state = await SUPERVISOR_GRAPH.ainvoke({"user_message": user_message})
    return {
        "output": str(final_state.get("output", "")),
        "agent_used": str(final_state.get("selected_agent", "none")),
        "tool_calls": final_state.get("tool_calls", []),
    }

def plan_execution(agent_name: str, message: str):
    """
    Decide execution chain based on first agent.
    """
    if agent_name == "recon":
        return ["recon", "vulnerability", "reporting"]

    if agent_name == "vulnerability":
        return ["vulnerability", "reporting"]

    return [agent_name]