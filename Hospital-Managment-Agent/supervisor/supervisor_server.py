"""
supervisor/supervisor_server.py
-------------------------------
Runs the Hospital Supervisor Agent as a standalone FastAPI server on port 9001.
Exposes /invoke (JSON) and /stream (SSE) endpoints.

Usage:  python supervisor/supervisor_server.py
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

nest_asyncio.apply()

app = FastAPI(title="Hospital Supervisor Agent", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Message serialization helpers
# ---------------------------------------------------------------------------

def _msg_to_dict(msg) -> dict:
    """Convert a LangChain message object to a JSON-safe dict."""
    if isinstance(msg, HumanMessage):
        return {"type": "human", "content": msg.content}
    elif isinstance(msg, AIMessage):
        d = {"type": "ai", "content": msg.content}
        if getattr(msg, "tool_calls", None):
            d["tool_calls"] = msg.tool_calls
        return d
    elif isinstance(msg, SystemMessage):
        return {"type": "system", "content": msg.content}
    elif isinstance(msg, ToolMessage):
        return {
            "type": "tool",
            "content": msg.content,
            "name": getattr(msg, "name", ""),
            "tool_call_id": getattr(msg, "tool_call_id", ""),
        }
    else:
        return {"type": "unknown", "content": str(msg)}


def _dict_to_msg(d: dict):
    """Convert a JSON dict back to a LangChain message object."""
    msg_type = d.get("type", "human")
    content = d.get("content", "")

    if msg_type == "human":
        return HumanMessage(content=content)
    elif msg_type == "ai":
        msg = AIMessage(content=content)
        if d.get("tool_calls"):
            msg.tool_calls = d["tool_calls"]
        return msg
    elif msg_type == "system":
        return SystemMessage(content=content)
    elif msg_type == "tool":
        return ToolMessage(
            content=content,
            name=d.get("name", ""),
            tool_call_id=d.get("tool_call_id", ""),
        )
    else:
        return HumanMessage(content=content)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/invoke")
async def invoke(request: Request):
    """Run the supervisor agent and return the full result as JSON."""
    from supervisor.graph import ainvoke

    body = await request.json()
    raw_messages = body.get("messages", [])
    actor = body.get("actor", None)

    # Convert dicts -> LangChain message objects
    messages = [_dict_to_msg(m) for m in raw_messages]

    result = await ainvoke(messages, actor=actor)

    # Convert LangChain messages back -> dicts for JSON response
    return JSONResponse({
        "messages": [_msg_to_dict(m) for m in result["messages"]],
        "final_reply": result["final_reply"],
        "trace": result["trace"],
    })


@app.post("/stream")
async def stream(request: Request):
    """Run the supervisor agent and stream trace steps + final reply via SSE."""
    from supervisor.graph import ainvoke

    body = await request.json()
    raw_messages = body.get("messages", [])
    actor = body.get("actor", None)

    messages = [_dict_to_msg(m) for m in raw_messages]

    async def event_generator():
        # Run the agent (full invoke, then stream results)
        result = await ainvoke(messages, actor=actor)

        # Stream each trace step
        for step in result.get("trace", []):
            yield f"data: {json.dumps({'type': 'trace', 'step': step})}\n\n"
            await asyncio.sleep(0.01)  # Small delay for client buffering

        # Stream the final reply
        yield f"data: {json.dumps({'type': 'final_reply', 'content': result['final_reply']})}\n\n"

        # Stream the full messages for state sync
        yield f"data: {json.dumps({'type': 'messages', 'messages': [_msg_to_dict(m) for m in result['messages']]})}\n\n"

        # Signal end of stream
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def main():
    print("[READY] Supervisor Agent Server on http://127.0.0.1:9001")
    print("        Endpoints: /invoke, /stream, /health")
    uvicorn.run(app, host="127.0.0.1", port=9001, log_level="warning")


if __name__ == "__main__":
    main()
