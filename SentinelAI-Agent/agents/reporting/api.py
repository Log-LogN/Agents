import sys
import os
import logging
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.models import InvokeRequest, InvokeResponse, ToolCallLog, HealthResponse
from shared.config import settings
from agents.reporting.graph import build_graph
from langchain_core.messages import HumanMessage

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("reporting-agent")

app = FastAPI(title="Reporting Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", service="reporting-agent")


@app.post("/invoke", response_model=InvokeResponse)
async def invoke(request: InvokeRequest):
    try:
        graph, client = await build_graph()

        final_state = await graph.ainvoke({
            "messages": [HumanMessage(content=request.message)]
        })

        output = final_state.get("final_output", "")

        return InvokeResponse(
            output=output,
            tool_calls=[]
        )

    except Exception as e:
        logger.exception("Reporting agent failed")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(
        "agents.reporting.api:app",
        host="0.0.0.0",
        port=8004,
    )