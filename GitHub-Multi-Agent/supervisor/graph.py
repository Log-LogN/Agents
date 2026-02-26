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
import uuid
import time
from typing import Literal, TypedDict

import httpx
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.config import settings

logger = logging.getLogger("supervisor")

# ── Agent registry ────────────────────────────────────────────────────────────

AGENT_REGISTRY: dict[str, str] = {
    "github": settings.GITHUB_AGENT_URL,
}
DIRECT_ANSWER_AGENT = "direct_answer"
DEFAULT_FALLBACK_AGENT = DIRECT_ANSWER_AGENT

AGENT_DESCRIPTIONS = """
- github: All GitHub tasks — repo info (stars, forks, language, description),
          open/closed issues, pull requests, reading file contents, searching code.
          Needs: owner/repo name (e.g. "microsoft/vscode") to act on specific data.
"""

KNOWN_AGENTS = list(AGENT_REGISTRY.keys()) + ["none"]


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── Routing system prompt ─────────────────────────────────────────────────────

ROUTING_SYSTEM_PROMPT = f"""
You are a supervisor that routes user requests to the correct specialist agent.

Available agents:
{AGENT_DESCRIPTIONS}

Rules:
- If the request clearly maps to one of the agents above, route to it.
- If the request is vague but plausible (e.g. "check open PRs" without a repo),
  still route to the best agent and pass the message as-is so the agent can ask
  for clarification or attempt the task.
- If the request has NOTHING to do with any available agent (e.g. general chat,
  math, writing, weather), use agent "none".
- Respond ONLY with a valid JSON object. No markdown, no explanation, no code fences.

Response format (strict):
{{
  "agent": "<one of: {KNOWN_AGENTS}>",
  "message": "<refined task description, or original message if already clear>",
  "reason": "<one sentence explaining the routing decision>"
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
        gh_keywords = ["repo", "repository", "issue", "pr", "pull request",
                       "branch", "commit", "github", "code", "star", "fork"]
        if any(kw in user_message.lower() for kw in gh_keywords):
            logger.warning("Routing parse fallback: detected GitHub keywords")
            return "github", user_message, "keyword-based fallback", "selected"
        return "none", user_message, "parse error fallback", "undetermined"


# ── HTTP agent caller ─────────────────────────────────────────────────────────

async def call_agent(agent_name: str, message: str) -> dict:
    """POST to the chosen agent's /invoke endpoint."""
    base_url = AGENT_REGISTRY[agent_name]
    url = f"{base_url}/invoke"
    logger.info(f"Calling agent '{agent_name}' at {url}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json={"message": message})
        resp.raise_for_status()
        return resp.json()


async def call_agent_stream(agent_name: str, message: str):
    """Stream events from the chosen agent's /invoke/stream endpoint."""
    base_url = AGENT_REGISTRY[agent_name]
    url = f"{base_url}/invoke/stream"
    logger.info(f"Streaming call to agent '{agent_name}' at {url}")

    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", url, json={"message": message}) as resp:
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


async def run_direct_answer(message: str) -> str:
    """Internal fallback agent for undecidable routing."""
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0.2,
    )
    response = await llm.ainvoke([
        SystemMessage(content=(
            "You are the default fallback assistant. "
            "When the supervisor cannot confidently select a specialist agent, "
            "provide a direct, concise answer and clearly note any missing context."
        )),
        HumanMessage(content=message),
    ])
    if isinstance(response.content, str):
        return response.content
    return str(response.content)


# ── Out-of-scope response ─────────────────────────────────────────────────────

OUT_OF_SCOPE_RESPONSE = (
    "I'm sorry, I couldn't process that request. "
    "I currently support the following:\n\n"
    "**GitHub** — repository info, issues, pull requests, file contents, code search.\n\n"
    "Please try asking something related to these topics, "
    "and include a repository name (e.g. `owner/repo`) where relevant."
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
    merged_reason = f"{reason}; default-fallback={DEFAULT_FALLBACK_AGENT}".strip("; ")
    return {
        "selected_agent": DEFAULT_FALLBACK_AGENT,
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
    agent_name = state.get("selected_agent", "none")
    routed_message = state.get("routed_message", state.get("user_message", ""))

    if agent_name == "none":
        return {"output": OUT_OF_SCOPE_RESPONSE, "tool_calls": []}
    if agent_name == DIRECT_ANSWER_AGENT:
        output = await run_direct_answer(routed_message)
        return {"output": output, "tool_calls": []}

    logger.info(f"Routed → {agent_name} | msg: {routed_message[:100]}")
    try:
        agent_result = await call_agent(agent_name, routed_message)
    except httpx.HTTPStatusError as e:
        logger.error(f"Agent HTTP error: {e.response.status_code} {e.response.text}")
        return {
            "output": f"The {agent_name} agent encountered an error ({e.response.status_code}). Please try again.",
            "tool_calls": [],
        }
    except httpx.ConnectError:
        logger.error(f"Cannot connect to agent '{agent_name}'")
        return {
            "output": f"The {agent_name} agent is currently unavailable. Please try again later.",
            "tool_calls": [],
        }
    except Exception:
        logger.exception(f"Unexpected error calling agent '{agent_name}'")
        return {"output": "An unexpected error occurred. Please try again.", "tool_calls": []}

    return {
        "output": str(agent_result.get("output", "")),
        "tool_calls": agent_result.get("tool_calls", []),
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


async def run_supervisor_stream(user_message: str, session_id: str = "default", stream_id: str | None = None):
    """
    Stream the supervisor pipeline as SSE-friendly events.
    """
    if not stream_id:
        stream_id = str(uuid.uuid4())

    yield {
        "event": "agent_started",
        "data": {
            "agent": "supervisor",
            "session_id": session_id,
            "stream_id": stream_id,
        },
        "timestamp": _now_iso(),
    }

    # Node: reasoning
    reasoning_state = await reasoning_node({"user_message": user_message})
    yield {
        "event": "routing",
        "data": {
            "stage": "reasoning",
            "reason": reasoning_state.get("routing_reason", ""),
            "stream_id": stream_id,
            "session_id": session_id,
        },
        "timestamp": _now_iso(),
    }

    # Node: route
    route_state = await routing_node({**reasoning_state, "user_message": user_message})
    agent_name = route_state.get("selected_agent", "none")
    routed_message = route_state.get("routed_message", user_message)
    reason = route_state.get("routing_reason", "")
    route_status = route_state.get("route_status", "undetermined")

    if route_status == "undetermined":
        route_state = await fallback_node(route_state)
        agent_name = route_state.get("selected_agent", DEFAULT_FALLBACK_AGENT)
        reason = route_state.get("routing_reason", reason)
        route_status = "selected"

    yield {
        "event": "routing",
        "data": {
            "agent": agent_name,
            "reason": reason,
            "route_status": route_status,
            "stream_id": stream_id,
            "session_id": session_id,
        },
        "timestamp": _now_iso(),
    }

    yield {
        "event": "agent_started",
        "data": {
            "agent": agent_name,
            "reason": reason,
            "stream_id": stream_id,
        },
        "timestamp": _now_iso(),
    }

    if route_status == "out_of_scope" or agent_name == "none":
        yield {
            "event": "llm_final",
            "data": {"output": OUT_OF_SCOPE_RESPONSE, "stream_id": stream_id},
            "timestamp": _now_iso(),
        }
        return

    if agent_name == DIRECT_ANSWER_AGENT:
        try:
            output = await run_direct_answer(routed_message)
            yield {
                "event": "llm_final",
                "data": {"output": output, "stream_id": stream_id, "session_id": session_id},
                "timestamp": _now_iso(),
            }
            return
        except Exception as exc:
            yield {
                "event": "error",
                "data": {"message": str(exc), "stream_id": stream_id, "session_id": session_id},
                "timestamp": _now_iso(),
            }
            return

    try:
        async for evt in call_agent_stream(agent_name, routed_message):
            evt["data"]["stream_id"] = stream_id
            evt["data"]["session_id"] = session_id
            yield evt
    except Exception as exc:
        yield {
            "event": "error",
            "data": {"message": str(exc), "stream_id": stream_id, "session_id": session_id},
            "timestamp": _now_iso(),
        }
