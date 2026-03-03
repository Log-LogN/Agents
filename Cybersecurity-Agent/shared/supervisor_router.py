from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from shared.config import settings
from shared.supervisor_intents import INTENTS, extract_advisory_id, extract_cve, extract_domain, extract_github_repo_url
from shared.supervisor_prompts import router_system_prompt

logger = logging.getLogger("supervisor-router")


@dataclass(frozen=True)
class RouteDecision:
    intent: str
    confidence: float
    cve: str | None = None
    domain: str | None = None
    repo_url: str | None = None
    advisory_id: str | None = None
    needs_clarification: bool = False
    clarification_question: str | None = None


def _coerce_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _parse_json_object(text: str) -> dict[str, Any] | None:
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        # Try to salvage the first JSON object in the text.
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                obj = json.loads(s[start : end + 1])
                return obj if isinstance(obj, dict) else None
            except Exception:
                return None
    return None


def _from_payload(payload: dict[str, Any], user_message: str) -> RouteDecision:
    intent = str(payload.get("intent") or "direct_answer")
    if intent not in INTENTS:
        intent = "direct_answer"

    conf = _coerce_float(payload.get("confidence"), 0.0)
    entities = payload.get("entities") or {}
    if not isinstance(entities, dict):
        entities = {}

    cve = entities.get("cve") or extract_cve(user_message)
    domain = entities.get("domain") or extract_domain(user_message)
    repo_url = entities.get("repo_url") or extract_github_repo_url(user_message)
    advisory_id = entities.get("advisory_id") or extract_advisory_id(user_message)

    needs = bool(payload.get("needs_clarification") or False)
    question = payload.get("clarification_question")
    question = str(question).strip() if isinstance(question, str) and question.strip() else None

    return RouteDecision(
        intent=intent,
        confidence=max(0.0, min(1.0, conf)),
        cve=str(cve).upper() if isinstance(cve, str) and cve else None,
        domain=str(domain) if isinstance(domain, str) and domain else None,
        repo_url=str(repo_url) if isinstance(repo_url, str) and repo_url else None,
        advisory_id=str(advisory_id) if isinstance(advisory_id, str) and advisory_id else None,
        needs_clarification=needs,
        clarification_question=question,
    )


async def route_with_llm(user_message: str) -> RouteDecision:
    """
    LLM router used only as a fallback when deterministic rules are inconclusive.
    """
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
        # Best-effort JSON mode for models that support it.
        model_kwargs={"response_format": {"type": "json_object"}},
    )

    resp = await llm.ainvoke(
        [
            SystemMessage(content=router_system_prompt()),
            HumanMessage(content=user_message),
        ]
    )
    payload = _parse_json_object(getattr(resp, "content", "") or "")
    if not payload:
        logger.warning("Router returned non-JSON content")
        # Fall back to deterministic extraction with direct_answer.
        return RouteDecision(
            intent="direct_answer",
            confidence=0.0,
            cve=extract_cve(user_message),
            domain=extract_domain(user_message),
            repo_url=extract_github_repo_url(user_message),
            advisory_id=extract_advisory_id(user_message),
            needs_clarification=False,
        )
    return _from_payload(payload, user_message)

