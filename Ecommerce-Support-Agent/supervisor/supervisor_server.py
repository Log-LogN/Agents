"""
supervisor/supervisor_server.py
═══════════════════════════════
Supervisor HTTP API — FastAPI app on port 9001.

This is a thin HTTP wrapper around the LangGraph-based supervisor defined
in `supervisor/graph.py`. The Streamlit UI talks to this service via a
simple JSON POST request to `/chat`.
"""

import asyncio
import logging
import os
import sys
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
import uvicorn

# Ensure project root is on the path so `from database.db` works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from supervisor.graph import build_graph, serialise_messages, build_trace

nest_asyncio.apply()
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [SupervisorAPI]  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

app = FastAPI(title="ShopAI Supervisor API")

# Cached compiled LangGraph supervisor (built once then reused)
GRAPH = None
GRAPH_LOCK = asyncio.Lock()
MAX_INPUT_MESSAGES = 16


def _compact_raw_messages(raw_msgs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep only conversational context from the client payload.
    This avoids replaying tool traces that inflate latency on later turns.
    """
    cleaned: List[Dict[str, Any]] = []
    for m in raw_msgs:
        role = m.get("role", "human")
        content = m.get("content", "")
        if role == "human":
            cleaned.append({"role": "human", "content": content})
        elif role == "ai" and not m.get("tool_calls"):
            cleaned.append({"role": "ai", "content": content})
    return cleaned[-MAX_INPUT_MESSAGES:]


def _decode_messages(raw_msgs: List[Dict[str, Any]]) -> List[Any]:
    """
    Convert a list of plain dicts (received over HTTP) back into
    LangChain message objects so the LangGraph can process them.
    """
    lc_messages: List[Any] = []
    for m in raw_msgs:
        role = m.get("role", "human")
        content = m.get("content", "")

        if role == "human":
            lc_messages.append(HumanMessage(content=content))
        elif role == "ai":
            lc_messages.append(
                AIMessage(
                    content=content,
                    tool_calls=m.get("tool_calls", []),
                )
            )
        elif role == "tool":
            lc_messages.append(
                ToolMessage(
                    content=content,
                    name=m.get("name", "unknown"),
                    tool_call_id=m.get("tool_call_id", ""),
                )
            )
        else:
            lc_messages.append(HumanMessage(content=content))
    return lc_messages


async def _ensure_graph():
    """
    Build the LangGraph supervisor once and cache it globally.
    Subsequent calls reuse the compiled graph instead of rebuilding it.
    """
    global GRAPH
    if GRAPH is not None:
        return GRAPH
    async with GRAPH_LOCK:
        if GRAPH is None:
            GRAPH = await build_graph()
    return GRAPH


async def _run_chat(raw_msgs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Core supervisor logic: given a list of plain message dicts, run the
    LangGraph supervisor and return a response dict.
    """
    if not isinstance(raw_msgs, list):
        return {
            "error": "messages must be a JSON array",
            "final_reply": "⚠️ Invalid input format.",
            "trace": [],
        }

    log.info("chat() — received %d message(s)", len(raw_msgs))

    compact_msgs = _compact_raw_messages(raw_msgs)
    log.info(
        "chat() - compact context: %d -> %d message(s)",
        len(raw_msgs),
        len(compact_msgs),
    )
    lc_messages = _decode_messages(compact_msgs)

    try:
        graph = await _ensure_graph()
        result = await graph.ainvoke({"messages": lc_messages})
    except Exception as exc:
        log.error("Graph execution error: %s", exc, exc_info=True)
        return {
            "error": str(exc),
            "final_reply": f"⚠️ An error occurred while processing your request: {exc}",
            "trace": [],
        }

    msgs = result["messages"]

    final_reply = "I couldn't process that request. Please try again."
    for msg in reversed(msgs):
        if (
            isinstance(msg, AIMessage)
            and msg.content
            and not getattr(msg, "tool_calls", None)
        ):
            final_reply = msg.content
            break

    trace = build_trace(msgs)
    history = serialise_messages(msgs)

    log.info(
        "chat() — reply: %d chars | trace steps: %d | history: %d msgs",
        len(final_reply),
        len(trace),
        len(history),
    )

    return {
        "final_reply": final_reply,
        "trace": trace,
        "messages": history,
    }


@app.post("/chat")
async def chat_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    HTTP endpoint for the Streamlit UI.

    Expects: {"messages": [ {role, content, ...}, ... ]}
    Returns: {"final_reply", "trace", "messages", "error?"}
    """
    if "messages" not in payload:
        raise HTTPException(status_code=400, detail="Missing 'messages' field")
    messages = payload.get("messages") or []
    return await _run_chat(messages)


def main() -> None:
    """
    Start the Supervisor HTTP API on http://127.0.0.1:9001/chat.
    """
    from database.db import init_db

    init_db()
    log.info("[SUPERVISOR]  Supervisor HTTP API  →  http://127.0.0.1:9001/chat")
    uvicorn.run(
        "supervisor.supervisor_server:app",
        host="127.0.0.1",
        port=9001,
        log_level="info",
    )


if __name__ == "__main__":
    main()
