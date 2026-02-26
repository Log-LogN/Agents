"""
Supervisor Agent — LangGraph StateGraph
========================================
Routes user requests to the correct sub-agent via HTTP.

Fixes applied:
  1. JSON parsing is robust — strips markdown fences OpenAI sometimes adds
  2. "none" agent returned when query doesn't match any agent
  3. Routing uses JSON-mode (response_format) so OpenAI always returns pure JSON
  4. Clear "out of scope" response when no agent matches

To add a new agent (e.g. jira):
    1. Add JIRA_AGENT_URL to shared/config.py and .env
    2. Add "jira" to AGENT_REGISTRY + description to AGENT_DESCRIPTIONS
    3. Done — routing LLM handles the rest automatically
"""

import sys
import os
import json
import logging
import re
import uuid
import time

import httpx
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.config import settings

logger = logging.getLogger("supervisor")

# ── Agent registry ────────────────────────────────────────────────────────────

AGENT_REGISTRY: dict[str, str] = {
    "github": settings.GITHUB_AGENT_URL,
    # "jira":  settings.JIRA_AGENT_URL,
    # "slack": settings.SLACK_AGENT_URL,
}

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


# ── Routing logic ─────────────────────────────────────────────────────────────

async def route_to_agent(user_message: str) -> tuple[str, str, str]:
    """
    Use the LLM to decide which agent to call.
    Returns: (agent_name, routed_message, reason)
    agent_name can be "none" if the query doesn't match any agent.
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
        agent_name = routing.get("agent", "none").lower().strip()
        routed_message = routing.get("message", user_message)
        reason = routing.get("reason", "")

        if agent_name not in KNOWN_AGENTS:
            logger.warning(f"LLM returned unknown agent '{agent_name}', treating as none")
            agent_name = "none"

        logger.info(f"Routing decision → agent={agent_name} | reason={reason}")
        return agent_name, routed_message, reason

    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Routing JSON parse failed: {e!r} | raw='{raw[:200]}'")
        # Last resort: check if message looks GitHub-related
        gh_keywords = ["repo", "repository", "issue", "pr", "pull request",
                       "branch", "commit", "github", "code", "star", "fork"]
        if any(kw in user_message.lower() for kw in gh_keywords):
            logger.warning("Fallback: detected GitHub keywords, routing to github")
            return "github", user_message, "keyword-based fallback"
        return "none", user_message, "parse error fallback"


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


# ── Out-of-scope response ─────────────────────────────────────────────────────

OUT_OF_SCOPE_RESPONSE = (
    "I'm sorry, I couldn't process that request. "
    "I currently support the following:\n\n"
    "**GitHub** — repository info, issues, pull requests, file contents, code search.\n\n"
    "Please try asking something related to these topics, "
    "and include a repository name (e.g. `owner/repo`) where relevant."
)


# ── Main supervisor entry point ───────────────────────────────────────────────

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

    # Step 1: Route
    agent_name, routed_message, reason = await route_to_agent(user_message)

    # Step 2: Handle out-of-scope
    if agent_name == "none":
        logger.info(f"Out-of-scope request. Reason: {reason}")
        return {
            "output": OUT_OF_SCOPE_RESPONSE,
            "agent_used": "none",
            "tool_calls": [],
        }

    logger.info(f"Routed → {agent_name} | msg: {routed_message[:100]}")

    # Step 3: Call agent
    try:
        agent_result = await call_agent(agent_name, routed_message)
    except httpx.HTTPStatusError as e:
        logger.error(f"Agent HTTP error: {e.response.status_code} {e.response.text}")
        return {
            "output": f"The {agent_name} agent encountered an error ({e.response.status_code}). Please try again.",
            "agent_used": agent_name,
            "tool_calls": [],
        }
    except httpx.ConnectError:
        logger.error(f"Cannot connect to agent '{agent_name}'")
        return {
            "output": f"The {agent_name} agent is currently unavailable. Please try again later.",
            "agent_used": agent_name,
            "tool_calls": [],
        }
    except Exception as e:
        logger.exception(f"Unexpected error calling agent '{agent_name}'")
        return {
            "output": "An unexpected error occurred. Please try again.",
            "agent_used": agent_name,
            "tool_calls": [],
        }

    return {
        "output": agent_result.get("output", ""),
        "agent_used": agent_name,
        "tool_calls": agent_result.get("tool_calls", []),
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

    agent_name, routed_message, reason = await route_to_agent(user_message)
    yield {
        "event": "agent_started",
        "data": {
            "agent": agent_name,
            "reason": reason,
            "stream_id": stream_id,
        },
        "timestamp": _now_iso(),
    }

    if agent_name == "none":
        yield {
            "event": "llm_final",
            "data": {"output": OUT_OF_SCOPE_RESPONSE, "stream_id": stream_id},
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
