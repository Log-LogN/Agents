from fastapi import FastAPI
from fastapi.responses import StreamingResponse
import json

from .graph import build_supervisor_graph, run_supervisor
from .mcp_client import get_mcp_tools
from shared.models import ChatRequest, ChatResponse, generate_session_id, RedisSessionStore


app = FastAPI(title="Supervisor API")

# Build graph without checkpointer for now
SUPERVISOR_GRAPH = build_supervisor_graph()


# Load tools once
@app.on_event("startup")
async def startup():
    recon_tools, vuln_tools = await get_mcp_tools()

    print("\nSupervisor loaded tools")
    print("Recon:", [t.name for t in recon_tools])
    print("Vulnerability:", [t.name for t in vuln_tools])
    print()


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    session_id = req.session_id or generate_session_id()
    result = await run_supervisor(req.message, session_id, SUPERVISOR_GRAPH)
    return ChatResponse(
        output=result["output"],
        agent_used=result["agent_used"],
        session_id=session_id,
        tool_calls=result["tool_calls"]
    )


@app.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    session_id = req.session_id or generate_session_id()

    async def generate_response():
        # Yield start event
        yield f"data: {json.dumps({'type': 'start', 'session_id': session_id})}\n\n"

        result = await run_supervisor(req.message, session_id, SUPERVISOR_GRAPH)

        # Yield tool calls
        for tool in result["tool_calls"]:
            yield f"data: {json.dumps({'type': 'tool_call', 'data': tool})}\n\n"

        # Yield output
        yield f"data: {json.dumps({'type': 'output', 'data': result['output']})}\n\n"

        # Yield final output node
        yield f"data: {json.dumps({'type': 'final_output', 'agent_used': result['agent_used'], 'session_id': session_id})}\n\n"

        # Yield end
        yield f"data: {json.dumps({'type': 'end'})}\n\n"

    return StreamingResponse(generate_response(), media_type="text/event-stream")


@app.get("/chat/history/{session_id}")
async def get_chat_history(session_id: str):
    session_store = RedisSessionStore()
    history = session_store.get_session_history(session_id)
    return {"history": history}
