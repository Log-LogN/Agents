"""Obligation Agent MCP Server - Port 8005"""

import json
import logging
import os
import sys
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Fix Python path
root_dir = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(root_dir))
os.chdir(str(root_dir))

load_dotenv()

logger = logging.getLogger(__name__)
PORT = int(os.getenv("OBLIGATION_PORT", "8005"))
mcp = FastMCP("ObligationAgent")

from agents.obligation_agent.graph import run_reasoning
from agents.obligation_agent.mcp_server.tools.obligation_tools import (
    create_renewal_alert,
    extract_obligations,
    get_obligations,
    get_upcoming_deadlines,
    process_amendment,
    update_obligation_status,
)


@mcp.tool()
def tool_extract_obligations(contract_id: int) -> str:
    return json.dumps(extract_obligations(contract_id))


@mcp.tool()
def tool_get_obligations(contract_id: int = 0, status: str = "") -> str:
    return json.dumps(get_obligations(contract_id, status))


@mcp.tool()
def tool_update_obligation_status(obligation_id: int, new_status: str) -> str:
    return json.dumps(update_obligation_status(obligation_id, new_status))


@mcp.tool()
def tool_get_upcoming_deadlines(days_ahead: int = 30) -> str:
    return json.dumps(get_upcoming_deadlines(days_ahead))


@mcp.tool()
def tool_create_renewal_alert(contract_id: int, notice_days: int = 90) -> str:
    return json.dumps(create_renewal_alert(contract_id, notice_days))


@mcp.tool()
def tool_process_amendment(contract_id: int, changes: str) -> str:
    return json.dumps(process_amendment(contract_id, changes))


@mcp.tool()
def tool_agent_graph(message: str, context_json: str = "{}") -> str:
    try:
        context = json.loads(context_json) if context_json else {}
        if not isinstance(context, dict):
            context = {}
    except Exception:
        context = {}
    return json.dumps(run_reasoning(message, context), default=str)


def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("Obligation Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
