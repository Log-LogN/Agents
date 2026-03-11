"""Execution Agent MCP Server - Port 8004"""

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
PORT = int(os.getenv("EXECUTION_PORT", "8004"))
mcp = FastMCP("ExecutionAgent")

from agents.execution_agent.graph import run_reasoning
from agents.execution_agent.mcp_server.tools.execution_tools import (
    finalize_contract,
    generate_execution_summary,
    get_signing_status,
    initiate_signing,
    send_signing_reminder,
    store_executed_contract,
)


@mcp.tool()
def tool_initiate_signing(contract_id: int, signatories_csv: str) -> str:
    return json.dumps(initiate_signing(contract_id, signatories_csv))


@mcp.tool()
def tool_get_signing_status(contract_id: int) -> str:
    return json.dumps(get_signing_status(contract_id))


@mcp.tool()
def tool_finalize_contract(contract_id: int) -> str:
    return json.dumps(finalize_contract(contract_id))


@mcp.tool()
def tool_send_signing_reminder(contract_id: int, signatory_email: str) -> str:
    return json.dumps(send_signing_reminder(contract_id, signatory_email))


@mcp.tool()
def tool_store_executed_contract(contract_id: int) -> str:
    return json.dumps(store_executed_contract(contract_id))


@mcp.tool()
def tool_generate_execution_summary(contract_id: int) -> str:
    return json.dumps(generate_execution_summary(contract_id))


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
    logger.info("Execution Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
