"""Draft Agent MCP Server - Port 8001"""

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
PORT = int(os.getenv("DRAFT_PORT", "8001"))
mcp = FastMCP("DraftAgent")

from agents.draft_agent.graph import run_draft_reasoning
from agents.draft_agent.mcp_server.tools.draft_tools import (
    create_contract,
    get_clause_library,
    get_templates,
    save_draft,
    update_contract,
)


@mcp.tool()
def tool_create_contract(
    contract_type: str,
    title: str,
    party_a: str,
    party_b: str,
    party_a_email: str = "",
    party_b_email: str = "",
    value: float = 0,
    jurisdiction: str = "New York",
    user_id: int = 1,
) -> str:
    return json.dumps(
        create_contract(
            contract_type,
            title,
            party_a,
            party_b,
            party_a_email,
            party_b_email,
            value,
            "USD",
            jurisdiction,
            user_id,
        )
    )


@mcp.tool()
def tool_get_templates(contract_type: str = "") -> str:
    return json.dumps(get_templates(contract_type))


@mcp.tool()
def tool_get_clause_library(category: str = "") -> str:
    return json.dumps(get_clause_library(category))


@mcp.tool()
def tool_update_contract(contract_id: int, field: str, value: str) -> str:
    return json.dumps(update_contract(contract_id, field, value))


@mcp.tool()
def tool_save_draft(contract_id: int, version_note: str = "Draft saved", user_id: int = 1) -> str:
    return json.dumps(save_draft(contract_id, version_note, user_id))


@mcp.tool()
def tool_agent_graph(message: str, context_json: str = "{}") -> str:
    try:
        context = json.loads(context_json) if context_json else {}
        if not isinstance(context, dict):
            context = {}
    except Exception:
        context = {}
    return json.dumps(run_draft_reasoning(message, context), default=str)


def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("Draft Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
