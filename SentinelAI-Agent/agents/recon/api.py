import sys
import os
import logging
import json
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.models import InvokeRequest, InvokeResponse, ToolCallLog, HealthResponse
from shared.config import settings
from agents.recon.graph import run_recon_agent, run_recon_agent_stream

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("recon-agent")

app = FastAPI(
    title="Recon Agent API",
    description="SentinelAI Recon Agent",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", service="recon-agent")


@app.post("/invoke", response_model=InvokeResponse)
async def invoke(request: InvokeRequest):
    logger.info(f"Recon request: {request.message[:100]}")

    try:
        result = await run_recon_agent(request.message)
    except Exception as e:
        logger.exception("Recon agent failed")
        raise HTTPException(status_code=500, detail=str(e))

    tool_logs = [
        ToolCallLog(
            tool_name=tc["tool_name"],
            tool_input=tc["tool_input"],
            tool_output=tc["tool_output"],
        )
        for tc in result.get("tool_calls", [])
    ]

    return InvokeResponse(
        output=result["output"],
        tool_calls=tool_logs,
    )


@app.post("/invoke/stream")
async def invoke_stream(request: InvokeRequest):
    async def event_gen():
        async for evt in run_recon_agent_stream(request.message):
            yield f"event: {evt['event']}\n"
            yield f"data: {json.dumps(evt['data'])}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run(
        "agents.recon.api:app",
        host="0.0.0.0",
        port=settings.RECON_AGENT_URL,
        reload=False,
    )