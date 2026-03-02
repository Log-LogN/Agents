"""HTTP client helpers for supervisor and report MCP servers."""

import json

import httpx
import streamlit as st

from ui.config import HTTP_TIMEOUT, REPORT_URL, SUPERVISOR_URL


def call_supervisor(history: list) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "chat",
            "arguments": {
                "messages_json": json.dumps(history),
                "thread_id": st.session_state.get("thread_id", "default"),
            },
        },
    }
    try:
        resp = httpx.post(
            SUPERVISOR_URL,
            json=payload,
            timeout=HTTP_TIMEOUT,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        raw = data.get("result", {})
        if isinstance(raw, str):
            raw = json.loads(raw)
        content = raw.get("content", [])
        if isinstance(content, list) and content:
            inner = content[0].get("text", "{}")
            return json.loads(inner) if isinstance(inner, str) else inner
        if isinstance(raw, dict) and "final_reply" in raw:
            return raw
        return {"final_reply": str(raw), "trace": [], "messages": []}
    except httpx.TimeoutException:
        return {
            "final_reply": (
                "⚠️ **Request timed out** — The supervisor took too long to respond.\n\n"
                "Please retry. If it continues, restart servers and check `logs/`."
            ),
            "trace": [{"type": "error", "label": "❌ Request timed out"}],
            "messages": [],
        }
    except Exception:
        return {
            "final_reply": (
                "⚠️ **Connection error** — Could not reach the supervisor.\n\n"
                "Make sure all servers are running:\n"
                "```\npython start_servers.py\n```\n\n"
                "Check server logs in `logs/` for details."
            ),
            "trace": [{"type": "error", "label": "❌ Supervisor unreachable"}],
            "messages": [],
        }


def call_report_tool(tool_name: str, arguments: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    try:
        resp = httpx.post(
            REPORT_URL,
            json=payload,
            timeout=HTTP_TIMEOUT,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        raw = data.get("result", {})
        if isinstance(raw, str):
            raw = json.loads(raw)
        content = raw.get("content", [])
        if isinstance(content, list) and content:
            inner = content[0].get("text", "{}")
            return json.loads(inner) if isinstance(inner, str) else inner
        return raw if isinstance(raw, dict) else {"success": False, "message": str(raw)}
    except Exception as exc:
        return {"success": False, "message": f"Could not execute approval action: {exc}"}

