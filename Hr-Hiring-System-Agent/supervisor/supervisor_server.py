"""
supervisor/supervisor_server.py
Supervisor MCP Server (port 9001, streamable-http).
"""

import sys
import os
import asyncio
import json
import logging
import time
import socket
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from mcp.server.fastmcp import FastMCP
from supervisor.graph import SPECIALIST_SERVERS, build_graph, serialise_messages, build_trace

nest_asyncio.apply()
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [SupervisorServer]  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

mcp = FastMCP(
    "HRSupervisorServer",
    host="127.0.0.1",
    port=9001,
    stateless_http=True,
    json_response=True,
)

_CACHED_GRAPH = None
_OPENAI_REACHABLE = None
_OPENAI_CONNECT_ERROR = ""
GRAPH_BUILD_TIMEOUT_SEC = float(os.getenv("GRAPH_BUILD_TIMEOUT_SEC", "45"))
GRAPH_INVOKE_TIMEOUT_SEC = float(os.getenv("GRAPH_INVOKE_TIMEOUT_SEC", "95"))
SPECIALIST_PING_TIMEOUT_SEC = float(os.getenv("SPECIALIST_PING_TIMEOUT_SEC", "0.7"))


def _ensure_openai_reachable(timeout_sec: float = 2.5) -> bool:
    """Fast connectivity probe to avoid long model timeouts when outbound is blocked."""
    global _OPENAI_REACHABLE, _OPENAI_CONNECT_ERROR
    if _OPENAI_REACHABLE is not None:
        return _OPENAI_REACHABLE

    host = os.getenv("OPENAI_API_HOST", "api.openai.com")
    try:
        sock = socket.create_connection((host, 443), timeout=timeout_sec)
        sock.close()
        _OPENAI_REACHABLE = True
        _OPENAI_CONNECT_ERROR = ""
        log.info("OpenAI connectivity check passed.")
    except Exception as e:
        _OPENAI_REACHABLE = False
        _OPENAI_CONNECT_ERROR = str(e)
        log.error("OpenAI connectivity check failed: %s", _OPENAI_CONNECT_ERROR)

    return _OPENAI_REACHABLE


def _specialist_host_port(cfg: dict) -> tuple:
    parsed = urlparse(cfg.get("url", ""))
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    return host, port


def _unreachable_specialists(timeout_sec: float = SPECIALIST_PING_TIMEOUT_SEC) -> list:
    down = []
    for key, cfg in SPECIALIST_SERVERS.items():
        host, port = _specialist_host_port(cfg)
        try:
            sock = socket.create_connection((host, port), timeout=timeout_sec)
            sock.close()
        except Exception:
            down.append(f"{key} ({host}:{port})")
    return down


def _specialist_down_response(down: list) -> str:
    joined = ", ".join(down)
    msg = (
        "Supervisor cannot continue because one or more specialist MCP servers are unreachable: "
        f"{joined}. Start all services with `python start_servers.py` and retry."
    )
    return json.dumps({"error": "SpecialistUnavailable", "final_reply": msg, "trace": []})


def _offline_response(raw: list) -> str:
    """Deterministic fallback when OpenAI is unreachable."""
    user_text = ""
    for m in reversed(raw):
        if isinstance(m, dict) and m.get("role") == "human":
            user_text = (m.get("content") or "").strip()
            break
    q = user_text.lower()

    conn = None
    try:
        from database.db import get_connection

        conn = get_connection()
        cur = conn.cursor()

        if any(k in q for k in ["open jobs", "list jobs", "job postings", "open roles"]):
            cur.execute(
                """
                SELECT id, title, department, location
                FROM jobs
                WHERE status='open'
                ORDER BY created_at DESC
                LIMIT 10
                """
            )
            rows = cur.fetchall()
            if rows:
                lines = ["Open jobs:"]
                for row in rows:
                    lines.append(f"- #{row[0]} {row[1]} ({row[2] or 'N/A'}, {row[3] or 'N/A'})")
                msg = "\n".join(lines)
            else:
                msg = "No open jobs found."
            return json.dumps({"final_reply": msg, "trace": [{"type": "route", "to": "Job Management"}]})

        if any(k in q for k in ["pipeline", "summary", "analytics"]):
            cur.execute(
                """
                SELECT status, COUNT(*)
                FROM candidates
                GROUP BY status
                ORDER BY status
                """
            )
            rows = cur.fetchall()
            if rows:
                lines = ["Pipeline summary:"]
                lines.extend([f"- {status}: {count}" for status, count in rows])
                msg = "\n".join(lines)
            else:
                msg = "No candidate data found."
            return json.dumps({"final_reply": msg, "trace": [{"type": "route", "to": "Analytics"}]})

        if "interview" in q and any(k in q for k in ["upcoming", "next", "scheduled"]):
            cur.execute(
                """
                SELECT i.id, c.name, i.scheduled_at
                FROM interviews i
                LEFT JOIN candidates c ON c.id = i.candidate_id
                WHERE i.scheduled_at >= NOW()
                ORDER BY i.scheduled_at ASC
                LIMIT 10
                """
            )
            rows = cur.fetchall()
            if rows:
                lines = ["Upcoming interviews:"]
                for iid, cname, dt in rows:
                    lines.append(f"- Interview #{iid} | {cname or 'Unknown'} | {str(dt)[:16]}")
                msg = "\n".join(lines)
            else:
                msg = "No upcoming interviews found."
            return json.dumps({"final_reply": msg, "trace": [{"type": "route", "to": "Interview Scheduling"}]})

    except Exception as e:
        log.warning("Offline fallback query failed: %s", e)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    msg = (
        "OpenAI is unreachable from this machine, so AI routing is in offline mode.\n"
        f"Network error: {_OPENAI_CONNECT_ERROR}\n"
        "Try one of: 'list open jobs', 'pipeline summary', or 'upcoming interviews'."
    )
    return json.dumps({"final_reply": msg, "trace": []})


def _warm_graph(max_attempts: int = 2, retry_delay_sec: float = 1.0) -> None:
    """Build and cache the compiled graph before first user request."""
    global _CACHED_GRAPH
    if _CACHED_GRAPH is not None:
        return

    down = _unreachable_specialists()
    if down:
        log.warning("Skipping graph warm-up; unreachable specialist servers: %s", ", ".join(down))
        return

    if not _ensure_openai_reachable():
        log.warning("Skipping graph warm-up because OpenAI is unreachable.")
        return

    for attempt in range(1, max_attempts + 1):
        try:
            _CACHED_GRAPH = asyncio.run(
                asyncio.wait_for(build_graph(), timeout=GRAPH_BUILD_TIMEOUT_SEC)
            )
            log.info("Supervisor graph warm-up complete.")
            return
        except asyncio.TimeoutError:
            log.warning(
                "Graph warm-up attempt %d/%d timed out after %.1fs",
                attempt,
                max_attempts,
                GRAPH_BUILD_TIMEOUT_SEC,
            )
            if attempt < max_attempts:
                time.sleep(retry_delay_sec)
        except Exception as e:
            log.warning("Graph warm-up attempt %d/%d failed: %s", attempt, max_attempts, e)
            if attempt < max_attempts:
                time.sleep(retry_delay_sec)

    log.warning("Graph warm-up deferred to first chat request.")


def _decode_messages(raw: list) -> list:
    lc = []
    for m in raw:
        role = m.get("role", "human")
        content = m.get("content", "")
        if role == "human":
            lc.append(HumanMessage(content=content))
        elif role == "ai":
            lc.append(AIMessage(content=content, tool_calls=m.get("tool_calls", [])))
        elif role == "tool":
            lc.append(
                ToolMessage(
                    content=content,
                    name=m.get("name", "unknown"),
                    tool_call_id=m.get("tool_call_id", ""),
                )
            )
        else:
            lc.append(HumanMessage(content=content))
    return lc


@mcp.tool()
def chat(messages_json: str) -> str:
    """Primary entry-point for the HR Hiring Supervisor MCP Server."""
    try:
        raw = json.loads(messages_json)
    except Exception as e:
        return json.dumps({"error": str(e), "final_reply": "[ERROR] Invalid message format.", "trace": []})

    request_start = time.perf_counter()
    log.info("chat() - %d message(s)", len(raw))

    down = _unreachable_specialists()
    if down:
        return _specialist_down_response(down)

    if not _ensure_openai_reachable():
        return _offline_response(raw)

    lc_messages = _decode_messages(raw)

    try:
        global _CACHED_GRAPH
        loop = asyncio.get_event_loop()
        if _CACHED_GRAPH is None:
            log.info("Building supervisor graph (first request)...")
            _CACHED_GRAPH = loop.run_until_complete(
                asyncio.wait_for(build_graph(), timeout=GRAPH_BUILD_TIMEOUT_SEC)
            )
        graph = _CACHED_GRAPH
        result = loop.run_until_complete(
            asyncio.wait_for(
                graph.ainvoke({"messages": lc_messages}),
                timeout=GRAPH_INVOKE_TIMEOUT_SEC,
            )
        )
    except asyncio.TimeoutError:
        msg = (
            f"Supervisor timed out after {GRAPH_INVOKE_TIMEOUT_SEC:.0f}s while processing the request. "
            "This is usually caused by slow OpenAI responses or an unavailable specialist MCP server."
        )
        log.error(msg)
        return json.dumps({"error": "SupervisorTimeout", "final_reply": msg, "trace": []})
    except Exception as e:
        log.error("Graph error: %s", e, exc_info=True)
        return json.dumps({
            "error": "SupervisorGraphError",
            "final_reply": (
                "I could not complete that request due to an internal processing error. "
                "Please retry with valid inputs. If it persists, check supervisor logs."
            ),
            "trace": [],
        })

    msgs = result["messages"]
    final = "I couldn't process that request. Please try again."
    for msg in reversed(msgs):
        if isinstance(msg, AIMessage) and msg.content and not getattr(msg, "tool_calls", None):
            final = msg.content
            break

    trace = build_trace(msgs)
    history = serialise_messages(msgs)
    elapsed = time.perf_counter() - request_start
    log.info("chat() latency: %.2fs", elapsed)

    return json.dumps({"final_reply": final, "trace": trace, "messages": history})


def main() -> None:
    from database.db import init_db

    init_db()
    _ensure_openai_reachable()
    _warm_graph()
    log.info("[OK]  HR Supervisor MCP Server -> http://127.0.0.1:9001/mcp")
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
