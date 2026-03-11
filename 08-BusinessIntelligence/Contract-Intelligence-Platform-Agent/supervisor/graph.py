"""Supervisor LangGraph orchestration with direct agent invocation + deep debug tracing."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import time
from typing import Any, Optional, TypedDict

import nest_asyncio
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

# Direct imports for agent functions
from agents.analytics_agent.graph import run_reasoning as run_analytics_reasoning
from agents.approval_agent.graph import run_reasoning as run_approval_reasoning
from agents.compliance_agent.graph import run_reasoning as run_compliance_reasoning
from agents.draft_agent.graph import run_draft_reasoning
from agents.execution_agent.graph import run_reasoning as run_execution_reasoning
from agents.obligation_agent.graph import run_reasoning as run_obligation_reasoning
from agents.review_agent.graph import run_review_reasoning

nest_asyncio.apply()
load_dotenv()
logger = logging.getLogger(__name__)


class SupervisorState(TypedDict):
    user_message: str
    user_id: int
    session_id: str
    role: str
    intent: str
    contract_id: Optional[int]
    agent_response: str
    final_response: str
    error: str
    duration_ms: int



AGENT_FUNCTIONS = {
    "draft": run_draft_reasoning,
    "review": run_review_reasoning,
    "approve": run_approval_reasoning,
    "execute": run_execution_reasoning,
    "obligation": run_obligation_reasoning,
    "compliance": run_compliance_reasoning,
    "analytics": run_analytics_reasoning,
}

AGENT_NAMES = {
    "draft": "Contract Draft Agent",
    "review": "Review & Risk Agent",
    "approve": "Approval Agent",
    "execute": "Execution Agent",
    "obligation": "Obligation Agent",
    "compliance": "Compliance Agent",
    "analytics": "Analytics Agent",
    "UNKNOWN": "Default Answering Agent",
}

CLASSIFY_PROMPT = """You are a Contract Intelligence Platform intent classifier.
Classify the user message into EXACTLY ONE key:
- draft
- review
- approve
- execute
- obligation
- compliance
- analytics
- UNKNOWN

Guidance:
- Use analytics for contract search, contract lists, contract details, portfolio metrics, risk dashboards, spend, expiry reports.
- Use draft for creating or drafting new contracts.
- Use review for risk analysis, missing clauses, redlines, and playbook checks.
- Use obligation for obligations, renewals, deadlines, and obligation status updates.
- Use compliance for compliance checks, GDPR checks, jurisdiction checks, audit trails.
- Use approve for approvals workflow.
- Use execute for execution or signature steps.

Examples:
User: "find my created latest contract" -> analytics
User: "can you provide me the list of all contracts" -> analytics
User: "get Contract CIP-2026-0016 details" -> analytics
User: "I want to create contract" -> draft
User: "Check missing clauses" -> review
User: "List pending obligations due soon" -> obligation
Reply with only the key."""

DEFAULT_SYSTEM = """You are the Default Answering Agent for a Contract Intelligence Platform.
You ONLY answer questions related to contract management topics.
If off-topic, reply exactly:
I can only assist with contract management topics. Please ask me about contracts, clauses, compliance, or contract lifecycle processes."""


def _safe_json_loads(raw: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return raw
    return raw


def _normalize_mcp_raw(raw: Any) -> Any:
    """Normalize MCP adapter responses into a plain dict/str when possible."""
    parsed = _safe_json_loads(raw)

    # Some adapters return content blocks: [{"type":"text","text":"..."}]
    if isinstance(parsed, list) and parsed:
        first = parsed[0]
        if isinstance(first, dict) and "text" in first:
            return _safe_json_loads(first.get("text"))
    return parsed


def classify_intent(message: str) -> str:
    try:
        llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=0, timeout=15)
        result = llm.invoke([SystemMessage(content=CLASSIFY_PROMPT), HumanMessage(content=message)])
        intent = result.content.strip().lower().split()[0]
        valid = set(AGENT_FUNCTIONS.keys()) | {"unknown"}
        if intent not in valid or intent == "unknown":
            return "UNKNOWN"
        return intent
    except Exception as exc:
        logger.warning("Intent classification error: %s", exc)
        return "UNKNOWN"


async def _call_agent_direct(intent: str, message: str, contract_id: Optional[int] = None) -> str:
    response, _ = await _call_agent_direct_debug(intent, message, contract_id)
    return response


async def _call_agent_direct_debug(
    intent: str, message: str, contract_id: Optional[int] = None
) -> tuple[str, dict[str, Any]]:
    debug: dict[str, Any] = {
        "intent": intent,
        "function": AGENT_FUNCTIONS.get(intent).__name__ if AGENT_FUNCTIONS.get(intent) else None,
        "context": {"intent": intent, "contract_id": contract_id},
    }

    func = AGENT_FUNCTIONS.get(intent)
    if not func:
        debug["error"] = f"No agent function configured for intent: {intent}"
        return f"No agent configured for intent: {intent}", debug

    started = time.time()
    try:
        context = {"intent": intent, "contract_id": contract_id}
        result = func(message, context)
        debug["result"] = result
        debug["duration_ms"] = int((time.time() - started) * 1000)

        output = result.get("output", "")
        if output:
            return str(output), debug
        return str(result), debug
    except Exception as exc:
        debug["duration_ms"] = int((time.time() - started) * 1000)
        debug["exception"] = repr(exc)
        logger.error("Direct agent call failed [%s]: %s", intent, exc)
        return f"{AGENT_NAMES.get(intent, 'Agent')}: I encountered an issue processing your request.", debug


async def _call_agent_async(intent: str, message: str, contract_id: Optional[int] = None) -> str:
    return await _call_agent_direct(intent, message, contract_id)


async def _call_agent_async_debug(
    intent: str, message: str, contract_id: Optional[int] = None
) -> tuple[str, dict[str, Any]]:
    return await _call_agent_direct_debug(intent, message, contract_id)


def call_agent(intent: str, message: str, contract_id: Optional[int] = None) -> str:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _call_agent_async(intent, message, contract_id))
                return future.result(timeout=60)
        return loop.run_until_complete(_call_agent_async(intent, message, contract_id))
    except Exception as exc:
        logger.error("call_agent error: %s", exc)
        return "Agent temporarily unavailable. Please try again."


def call_agent_debug(
    intent: str, message: str, contract_id: Optional[int] = None
) -> tuple[str, dict[str, Any]]:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _call_agent_async_debug(intent, message, contract_id))
                return future.result(timeout=60)
        return loop.run_until_complete(_call_agent_async_debug(intent, message, contract_id))
    except Exception as exc:
        logger.error("call_agent_debug error: %s", exc)
        return "Agent temporarily unavailable. Please try again.", {"exception": repr(exc)}


def run_default_agent(message: str) -> str:
    try:
        llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=0.1, timeout=30)
        result = llm.invoke([SystemMessage(content=DEFAULT_SYSTEM), HumanMessage(content=message)])
        return result.content
    except Exception as exc:
        logger.error("Default agent error: %s", exc)
        return "I can help with contract management questions."


def node_classify(state: SupervisorState) -> SupervisorState:
    intent = classify_intent(state["user_message"])
    logger.info("[Supervisor] Classified intent: %s for user %s", intent, state["user_id"])
    return {**state, "intent": intent, "error": ""}


def node_check_permission(state: SupervisorState) -> SupervisorState:
    try:
        from utils.auth import can_access_intent

        intent = state.get("intent", "UNKNOWN")
        role = state.get("role", "viewer")
        if intent != "UNKNOWN" and not can_access_intent(role, intent):
            return {
                **state,
                "intent": "DENIED",
                "error": f"Your role '{role}' does not have permission to access the {AGENT_NAMES.get(intent, 'this agent')}.",
            }
        return {**state, "error": ""}
    except Exception as exc:
        logger.error("node_check_permission error: %s", exc)
        return {**state, "error": ""}


def node_route_agent(state: SupervisorState) -> SupervisorState:
    intent = state.get("intent", "UNKNOWN")
    response = call_agent(intent, state["user_message"], state.get("contract_id"))
    return {**state, "agent_response": response, "error": ""}


def node_default_agent(state: SupervisorState) -> SupervisorState:
    response = run_default_agent(state["user_message"])
    return {**state, "agent_response": response, "error": ""}


def node_denied(state: SupervisorState) -> SupervisorState:
    return {
        **state,
        "agent_response": state.get("error") or "You don't have permission to perform this action.",
        "error": "",
    }


def node_format_response(state: SupervisorState) -> SupervisorState:
    agent_name = AGENT_NAMES.get(state.get("intent", "UNKNOWN"), "Assistant")
    response = state.get("agent_response") or "I couldn't process your request. Please try rephrasing."
    return {**state, "final_response": f"**{agent_name}**\n\n{response}"}


def route_after_permission(state: SupervisorState) -> str:
    intent = state.get("intent", "UNKNOWN")
    if intent == "DENIED":
        return "denied"
    if intent == "UNKNOWN":
        return "default"
    return "agent"


def build_supervisor_graph():
    graph = StateGraph(SupervisorState)
    graph.add_node("classify", node_classify)
    graph.add_node("check_permission", node_check_permission)
    graph.add_node("route_agent", node_route_agent)
    graph.add_node("default_agent", node_default_agent)
    graph.add_node("denied", node_denied)
    graph.add_node("format_response", node_format_response)

    graph.set_entry_point("classify")
    graph.add_edge("classify", "check_permission")
    graph.add_conditional_edges(
        "check_permission",
        route_after_permission,
        {"agent": "route_agent", "default": "default_agent", "denied": "denied"},
    )
    graph.add_edge("route_agent", "format_response")
    graph.add_edge("default_agent", "format_response")
    graph.add_edge("denied", "format_response")
    graph.add_edge("format_response", END)
    return graph.compile()


_graph = None


def get_graph():
    global _graph
    if _graph is None:
        _graph = build_supervisor_graph()
    return _graph


def _write_audit(
    *,
    user_id: int,
    session_id: str,
    contract_id: Optional[int],
    intent: str,
    message: str,
    final: str,
    duration: int,
) -> tuple[bool, str]:
    try:
        from database.db import log_audit

        log_audit(
            user_id,
            session_id,
            contract_id,
            intent,
            intent,
            "tool_agent_graph",
            message,
            final,
            duration,
            "success",
        )
        return True, ""
    except Exception as exc:
        return False, str(exc)


def run_supervisor(
    message: str,
    user_id: int = 1,
    session_id: str = "default",
    role: str = "viewer",
    contract_id: Optional[int] = None,
) -> dict:
    start = time.time()
    try:
        graph = get_graph()
        initial_state: SupervisorState = {
            "user_message": message,
            "user_id": user_id,
            "session_id": session_id,
            "role": role,
            "intent": "",
            "contract_id": contract_id,
            "agent_response": "",
            "final_response": "",
            "error": "",
            "duration_ms": 0,
        }
        result = graph.invoke(initial_state)
        duration = int((time.time() - start) * 1000)
        final = result.get("final_response") or result.get("agent_response") or "No response generated."
        _write_audit(
            user_id=user_id,
            session_id=session_id,
            contract_id=contract_id,
            intent=result.get("intent", ""),
            message=message,
            final=final,
            duration=duration,
        )
        return {
            "response": final,
            "intent": result.get("intent", "UNKNOWN"),
            "duration_ms": duration,
            "error": result.get("error", ""),
        }
    except Exception as exc:
        duration = int((time.time() - start) * 1000)
        logger.error("Supervisor error: %s", exc)
        return {
            "response": "I'm having trouble processing your request. Please try again.",
            "intent": "UNKNOWN",
            "duration_ms": duration,
            "error": str(exc),
        }


def run_supervisor_debug(
    message: str,
    user_id: int = 1,
    session_id: str = "default",
    role: str = "viewer",
    contract_id: Optional[int] = None,
) -> dict[str, Any]:
    t0 = time.time()
    trace: dict[str, Any] = {
        "request": {
            "message": message,
            "user_id": user_id,
            "session_id": session_id,
            "role": role,
            "contract_id": contract_id,
        },
        "config": {
            "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        },
        "graph_trace": [],
        "timings_ms": {},
    }

    try:
        s = time.time()
        intent = classify_intent(message)
        trace["timings_ms"]["classify"] = int((time.time() - s) * 1000)
        trace["classification"] = {"intent": intent}
        trace["graph_trace"].append({"node": "classify", "state": {"intent": intent}})

        from shared.constants import INTENT_PERMISSION
        from utils.auth import can_access_intent

        s = time.time()
        required_permission = INTENT_PERMISSION.get(intent, "")
        allowed = intent == "UNKNOWN" or can_access_intent(role, intent)
        trace["timings_ms"]["permission"] = int((time.time() - s) * 1000)
        trace["permission"] = {
            "allowed": allowed,
            "required_permission": required_permission,
            "role": role,
        }

        if not allowed:
            route = "denied"
            response = f"Your role '{role}' does not have permission to access the {AGENT_NAMES.get(intent, 'this agent')}."
            error = ""
            direct_debug = None
        elif intent == "UNKNOWN":
            route = "default"
            s = time.time()
            response = run_default_agent(message)
            trace["timings_ms"]["default_agent"] = int((time.time() - s) * 1000)
            error = ""
            direct_debug = None
        else:
            route = "agent"
            s = time.time()
            response, direct_debug = call_agent_debug(intent, message, contract_id)
            trace["timings_ms"]["agent"] = int((time.time() - s) * 1000)
            error = ""

        trace["routing"] = {
            "route": route,
            "agent_name": AGENT_NAMES.get(intent, "Default Answering Agent"),
            "intent": intent,
        }
        if direct_debug is not None:
            trace["direct"] = direct_debug

        s = time.time()
        final = f"**{AGENT_NAMES.get(intent, 'Assistant')}**\n\n{response}"
        trace["timings_ms"]["format"] = int((time.time() - s) * 1000)

        total_ms = int((time.time() - t0) * 1000)
        trace["timings_ms"]["total"] = total_ms

        audit_ok, audit_err = _write_audit(
            user_id=user_id,
            session_id=session_id,
            contract_id=contract_id,
            intent=intent,
            message=message,
            final=final,
            duration=total_ms,
        )
        trace["audit"] = {"written": audit_ok, "error": audit_err}
        trace["graph_trace"].append(
            {
                "node": "final",
                "state": {
                    "intent": intent,
                    "route": route,
                    "response_preview": str(response)[:500],
                    "duration_ms": total_ms,
                },
            }
        )

        return {
            "response": final,
            "intent": intent,
            "duration_ms": total_ms,
            "error": error,
            "debug": trace,
        }
    except Exception as exc:
        total_ms = int((time.time() - t0) * 1000)
        trace["timings_ms"]["total"] = total_ms
        trace["exception"] = repr(exc)
        logger.exception("run_supervisor_debug failed")
        return {
            "response": "I'm having trouble processing your request. Please try again.",
            "intent": "UNKNOWN",
            "duration_ms": total_ms,
            "error": str(exc),
            "debug": trace,
        }


async def debug_list_agent_tools() -> dict[str, Any]:
    """List available agents and their functions."""
    output: dict[str, Any] = {"agents": {}}
    for intent, func in AGENT_FUNCTIONS.items():
        entry: dict[str, Any] = {
            "intent": intent,
            "name": AGENT_NAMES.get(intent, intent),
            "function": func.__name__,
            "type": "direct_call"
        }
        output["agents"][intent] = entry
    return output
