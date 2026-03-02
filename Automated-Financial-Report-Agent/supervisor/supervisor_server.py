"""
supervisor/supervisor_server.py
════════════════════════════════
Supervisor MCP Server — binds to port 9001 via streamable-http.

Architecture:
  Streamlit UI (app.py)
      │  HTTP POST /mcp → JSON-RPC 2.0 → tools/call → chat()
      ▼
  supervisor_server.py  (port 9001)
      │  calls build_graph() from graph.py
      ▼
  LangGraph Supervisor
      ├─► GL Agent       → http://127.0.0.1:8001/mcp
      ├─► P&L Agent      → http://127.0.0.1:8002/mcp
      ├─► BS Agent       → http://127.0.0.1:8003/mcp
      ├─► CF Agent       → http://127.0.0.1:8004/mcp
      ├─► Budget Agent   → http://127.0.0.1:8005/mcp
      ├─► KPI Agent      → http://127.0.0.1:8006/mcp
      ├─► Report Agent   → http://127.0.0.1:8007/mcp
      └─► General Agent  → in-graph default fallback (no MCP port)
"""

import sys
import os
import asyncio
import json
import logging
import time
import hashlib
import ast
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI
from mcp.server.fastmcp import FastMCP

from supervisor.graph import build_graph, serialise_messages, build_trace

nest_asyncio.apply()
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [SupervisorServer]  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)
GRAPH_REQUEST_TIMEOUT_SEC = int(os.getenv("GRAPH_REQUEST_TIMEOUT_SEC", "90"))
REDIS_ENABLED = os.getenv("REDIS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
REDIS_THREAD_NAMESPACE = os.getenv("REDIS_THREAD_NAMESPACE", os.getenv("REDIS_KEY_PREFIX", "finreport:thread"))
REDIS_THREAD_TTL_SEC = int(os.getenv("REDIS_THREAD_TTL_SEC", "604800"))
REDIS_THREAD_TEXT_LIMIT = int(os.getenv("REDIS_THREAD_TEXT_LIMIT", os.getenv("THREAD_CHAR_LIMIT", "16000")))
REDIS_THREAD_KEEP_MESSAGES = int(os.getenv("REDIS_THREAD_KEEP_MESSAGES", os.getenv("THREAD_KEEP_TURNS", "8")))
REDIS_THREAD_CONTEXT_MESSAGES = int(os.getenv("REDIS_THREAD_CONTEXT_MESSAGES", os.getenv("THREAD_CONTEXT_TURNS", "8")))
REDIS_SUMMARY_MAX_CHARS = int(os.getenv("REDIS_SUMMARY_MAX_CHARS", "8000"))
REDIS_SUMMARY_MODEL = os.getenv("REDIS_SUMMARY_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
THREAD_CACHE_LIMIT = int(os.getenv("THREAD_CACHE_LIMIT", "20"))

try:
    import redis
    _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True) if REDIS_ENABLED else None
except Exception:
    _redis_client = None


# ── FastMCP server — port 9001 ────────────────────────────────────────────────
mcp = FastMCP(
    "FinReportSupervisor",
    host="127.0.0.1",
    port=9001,
    stateless_http=True,
    json_response=True,
)


def _decode_messages(raw_msgs: list) -> list:
    """Convert plain dicts → LangChain message objects."""
    lc_messages = []
    for m in raw_msgs:
        role    = m.get("role", "human")
        content = m.get("content", "")
        if role == "human":
            lc_messages.append(HumanMessage(content=content))
        elif role == "ai":
            lc_messages.append(AIMessage(
                content=content,
                tool_calls=m.get("tool_calls", []),
            ))
        elif role == "tool":
            lc_messages.append(ToolMessage(
                content=content,
                name=m.get("name", "unknown"),
                tool_call_id=m.get("tool_call_id", ""),
            ))
        else:
            lc_messages.append(HumanMessage(content=content))
    return lc_messages


def _latest_human_text(raw_msgs: list) -> str:
    for m in reversed(raw_msgs):
        if m.get("role") == "human":
            return str(m.get("content", "")).strip()
    return ""


def _is_send_like_request(text: str) -> bool:
    q = (text or "").lower()
    keys = ["send", "email", "board pack", "report", "alert", "recipient"]
    return any(k in q for k in keys)


def _thread_key(thread_id: str) -> str:
    safe = (thread_id or "default").strip() or "default"
    return f"{REDIS_THREAD_NAMESPACE}:{safe}"


def _extract_approval_request(msgs: list) -> dict | None:
    def _is_approval_dict(d: dict) -> bool:
        return bool(isinstance(d, dict) and d.get("requires_approval") and d.get("approval_token"))

    def _extract_candidate_dicts_from_text(text: str) -> list[dict]:
        out = []
        if not text:
            return out
        # Fast path
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
                if isinstance(parsed, dict):
                    out.append(parsed)
            except Exception:
                pass
        # Fallback for wrapped/stringified payloads
        if "requires_approval" in text:
            for m in re.findall(r"(\{[\s\S]*?requires_approval[\s\S]*?\})", text):
                for parser in (json.loads, ast.literal_eval):
                    try:
                        parsed = parser(m)
                        if isinstance(parsed, dict):
                            out.append(parsed)
                            break
                    except Exception:
                        continue
        return out

    def _parse_any(value):
        if value is None:
            return None
        if isinstance(value, dict):
            # Check direct and common nested payload keys.
            for k in ("payload", "data", "result", "value", "response"):
                nested = value.get(k)
                if isinstance(nested, dict) and _is_approval_dict(nested):
                    return nested
            return value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    # MCP often wraps tool outputs as [{"type":"text","text":"...json..."}]
                    if "text" in item:
                        parsed = _parse_any(item.get("text"))
                        if isinstance(parsed, dict):
                            return parsed
                    if "content" in item:
                        parsed = _parse_any(item.get("content"))
                        if isinstance(parsed, dict):
                            return parsed
                    parsed = _parse_any(item)
                    if isinstance(parsed, dict) and parsed.get("requires_approval"):
                        return parsed
                else:
                    parsed = _parse_any(item)
                    if isinstance(parsed, dict):
                        return parsed
            return None
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            for d in _extract_candidate_dicts_from_text(text):
                if isinstance(d, dict):
                    return d
            return None
        # Support object-wrapped content blocks from tool libraries.
        for attr in ("text", "content", "data", "value"):
            if hasattr(value, attr):
                parsed = _parse_any(getattr(value, attr))
                if isinstance(parsed, dict):
                    return parsed
        if hasattr(value, "model_dump"):
            try:
                parsed = _parse_any(value.model_dump())
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return None
        return None

    for msg in reversed(msgs):
        if not isinstance(msg, ToolMessage):
            continue
        raw = getattr(msg, "content", "")
        payload = _parse_any(raw)
        if _is_approval_dict(payload):
            return payload
    return None


def _load_thread_state(thread_id: str) -> dict:
    if not _redis_client:
        return {"summary": "", "turns": [], "cache": {}}
    try:
        raw = _redis_client.get(_thread_key(thread_id))
        if not raw:
            return {"summary": "", "turns": [], "cache": {}}
        state = json.loads(raw)
        if not isinstance(state, dict):
            return {"summary": "", "turns": [], "cache": {}}
        state.setdefault("summary", "")
        state.setdefault("turns", [])
        state.setdefault("cache", {})
        return state
    except Exception:
        return {"summary": "", "turns": [], "cache": {}}


def _save_thread_state(thread_id: str, state: dict) -> None:
    if not _redis_client:
        return
    try:
        key = _thread_key(thread_id)
        payload = json.dumps(state, ensure_ascii=False)
        if REDIS_THREAD_TTL_SEC > 0:
            _redis_client.setex(key, REDIS_THREAD_TTL_SEC, payload)
        else:
            _redis_client.set(key, payload)
    except Exception:
        pass


def _state_char_count(state: dict) -> int:
    total = len(str(state.get("summary", "")))
    for t in state.get("turns", []):
        total += len(str(t.get("request", ""))) + len(str(t.get("response", "")))
    return total


async def _summarise_overflow(summary: str, old_turns: list[dict]) -> str:
    model = ChatOpenAI(model=REDIS_SUMMARY_MODEL, temperature=0, max_tokens=220)
    lines = []
    for i, t in enumerate(old_turns, start=1):
        q = str(t.get("request", "")).strip()
        a = str(t.get("response", "")).strip()
        lines.append(f"{i}. User: {q}\nAssistant: {a}")
    prompt = (
        "Summarise the prior conversation memory for financial assistant continuity.\n"
        "Keep it compact and factual (6-10 bullets max), include key entities, periods, and user preferences.\n"
        "Do not add new facts.\n\n"
        f"Existing summary:\n{summary or '(none)'}\n\n"
        f"Turns:\n{chr(10).join(lines)}"
    )
    out = await model.ainvoke([HumanMessage(content=prompt)])
    new_summary = str(getattr(out, "content", "")).strip() or summary
    return new_summary[:REDIS_SUMMARY_MAX_CHARS]


@mcp.tool()
def chat(messages_json: str, thread_id: str = "default") -> str:
    """
    Primary entry-point for the FinReport Supervisor (port 9001).

    Parameters
    ----------
    messages_json : str
        JSON-encoded list of message dicts.
        [{"role": "human", "content": "Show me the P&L for February 2026"}, ...]

    Returns
    -------
    str
        JSON-encoded: {"final_reply": "...", "trace": [...], "messages": [...]}
        On error:     {"error": "...", "final_reply": "...", "trace": []}
    """
    # ── Step 1: Parse JSON ────────────────────────────────────────────
    try:
        raw_msgs: list = json.loads(messages_json)
    except Exception as exc:
        log.error("JSON decode error: %s", exc)
        return json.dumps({
            "error":       f"Invalid messages_json: {exc}",
            "final_reply": "⚠️ Could not parse your message. Please try again.",
            "trace":       [],
        })

    if not isinstance(raw_msgs, list):
        return json.dumps({
            "error":       "messages_json must be a JSON array",
            "final_reply": "⚠️ Invalid input format.",
            "trace":       [],
        })

    started = time.perf_counter()
    log.info("chat() — received %d message(s)", len(raw_msgs))

    # ── Step 2: Rebuild LangChain messages ────────────────────────────
    lc_messages = _decode_messages(raw_msgs)
    latest_user = _latest_human_text(raw_msgs)
    use_redis_thread = bool(_redis_client and thread_id)

    state = {"summary": "", "turns": [], "cache": {}}
    request_hash = hashlib.sha1(latest_user.encode("utf-8")).hexdigest() if latest_user else ""
    if use_redis_thread and not _is_send_like_request(latest_user):
        state = _load_thread_state(thread_id)
        cached = state.get("cache", {}).get(request_hash)
        if cached and isinstance(cached, dict):
            log.info("chat() — cache hit for thread %s", thread_id)
            return json.dumps({
                "final_reply": cached.get("final_reply", ""),
                "trace": cached.get("trace", []),
                "approval_request": cached.get("approval_request"),
                "messages": [],
            })

    # Build context from Redis thread memory when available.
    invoke_messages = lc_messages
    if use_redis_thread and latest_user:
        invoke_messages = []
        summary = str(state.get("summary", "")).strip()
        if summary:
            invoke_messages.append(
                HumanMessage(content=f"[Conversation summary]\n{summary}")
            )
        for t in state.get("turns", [])[-REDIS_THREAD_CONTEXT_MESSAGES:]:
            q = str(t.get("request", "")).strip()
            a = str(t.get("response", "")).strip()
            if q:
                invoke_messages.append(HumanMessage(content=q))
            if a:
                invoke_messages.append(AIMessage(content=a))
        invoke_messages.append(HumanMessage(content=latest_user))

    # ── Step 3: Build LangGraph and run ──────────────────────────────
    try:
        loop   = asyncio.get_event_loop()
        graph  = loop.run_until_complete(asyncio.wait_for(build_graph(), timeout=20))
        result = loop.run_until_complete(
            asyncio.wait_for(
                graph.ainvoke({"messages": invoke_messages}),
                timeout=GRAPH_REQUEST_TIMEOUT_SEC,
            )
        )
    except asyncio.TimeoutError:
        elapsed = round(time.perf_counter() - started, 2)
        log.error("Graph request timed out after %.2fs", elapsed)
        return json.dumps({
            "error": "timeout",
            "final_reply": (
                "⚠️ The request took too long to complete.\n\n"
                "This is usually caused by a slow or unresponsive specialist agent.\n"
                "Please retry once. If it repeats, restart servers and check `logs/`."
            ),
            "trace": [{"type": "error", "label": "❌ Request timed out in supervisor"}],
        })
    except Exception as exc:
        log.error("Graph execution error: %s", exc, exc_info=True)
        # Crash-proof fallback — never return an empty response
        return json.dumps({
            "error":       str(exc),
            "final_reply": (
                f"⚠️ I encountered an error while processing your request.\n\n"
                f"**Error details:** {str(exc)}\n\n"
                f"Please check that all specialist agent servers are running "
                f"(ports 8001-8007) and try again."
            ),
            "trace": [{"type": "error", "label": f"❌ Error: {str(exc)[:100]}"}],
        })

    msgs = result.get("messages", [])
    # Keep trace scoped to this turn only (not the entire conversation history).
    # Slice by the actual invoke context length (not raw UI history length),
    # so tool outputs like approval requests are never dropped.
    new_msgs = msgs[len(invoke_messages):] if len(msgs) >= len(invoke_messages) else msgs

    # ── Step 4: Extract final reply ──────────────────────────────────
    final_reply = None
    for msg in reversed(msgs):
        if (isinstance(msg, AIMessage)
                and msg.content
                and not getattr(msg, "tool_calls", None)):
            final_reply = msg.content
            break

    # Hard fallback — should never reach here, but crash-proof guarantee
    if not final_reply:
        final_reply = (
            "I processed your request but couldn't generate a specific reply. "
            "Please try rephrasing your question or ask me something like: "
            "'Show the P&L for February 2026' or 'What is our cash position?'"
        )

    # ── Step 5: Build trace + serialise ──────────────────────────────
    trace   = build_trace(new_msgs)
    history = serialise_messages(msgs)
    approval_request = _extract_approval_request(new_msgs) or _extract_approval_request(msgs)

    log.info(
        "chat() — reply: %d chars | trace: %d steps | history: %d msgs | elapsed %.2fs",
        len(final_reply), len(trace), len(history), time.perf_counter() - started,
    )

    if use_redis_thread and latest_user:
        turns = state.get("turns", [])
        turns.append({"request": latest_user, "response": final_reply})
        state["turns"] = turns

        cache = state.get("cache", {})
        if request_hash and not approval_request:
            cache[request_hash] = {"final_reply": final_reply, "trace": trace, "approval_request": None}
            # Keep cache bounded.
            if len(cache) > THREAD_CACHE_LIMIT:
                for k in list(cache.keys())[: len(cache) - THREAD_CACHE_LIMIT]:
                    cache.pop(k, None)
        state["cache"] = cache

        if _state_char_count(state) > REDIS_THREAD_TEXT_LIMIT and len(state["turns"]) > REDIS_THREAD_KEEP_MESSAGES:
            old = state["turns"][:-REDIS_THREAD_KEEP_MESSAGES]
            keep = state["turns"][-REDIS_THREAD_KEEP_MESSAGES:]
            try:
                loop = asyncio.get_event_loop()
                state["summary"] = loop.run_until_complete(
                    asyncio.wait_for(
                        _summarise_overflow(str(state.get("summary", "")), old),
                        timeout=20,
                    )
                )
                state["turns"] = keep
            except Exception as exc:
                log.warning("Thread summarisation skipped: %s", exc)

        _save_thread_state(thread_id, state)

    return json.dumps({
        "final_reply": final_reply,
        "trace":       trace,
        "approval_request": approval_request,
        "messages":    [] if use_redis_thread else history,
    })


def main() -> None:
    """Start the Supervisor MCP Server on http://127.0.0.1:9001/mcp"""
    from database.db import init_db
    init_db()
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(build_graph())
        log.info("✅ Supervisor graph warm-up complete.")
    except Exception as exc:
        log.warning("⚠️ Supervisor graph warm-up failed: %s", exc)
    log.info("🧠  FinReport Supervisor  →  http://127.0.0.1:9001/mcp")
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
