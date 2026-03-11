"""Review Agent MCP Server - Port 8002"""

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
PORT = int(os.getenv("REVIEW_PORT", "8002"))
mcp = FastMCP("ReviewAgent")

# Import after path is set
from agents.review_agent.graph import run_review_reasoning
from agents.review_agent.mcp_server.tools.review_tools import (
    analyze_contract,
    check_missing_clauses,
    compare_to_playbook,
    flag_clauses,
    get_risk_score,
    suggest_redlines,
)


@mcp.tool()
def tool_analyze_contract(contract_id: int) -> str:
    return json.dumps(analyze_contract(contract_id))


@mcp.tool()
def tool_get_risk_score(contract_id: int) -> str:
    return json.dumps(get_risk_score(contract_id))


@mcp.tool()
def tool_suggest_redlines(contract_id: int) -> str:
    return json.dumps(suggest_redlines(contract_id))


@mcp.tool()
def tool_flag_clauses(contract_id: int, risk_level: str = "HIGH") -> str:
    return json.dumps(flag_clauses(contract_id, risk_level))


@mcp.tool()
def tool_compare_to_playbook(contract_id: int) -> str:
    return json.dumps(compare_to_playbook(contract_id))


@mcp.tool()
def tool_check_missing_clauses(contract_id: int, contract_type: str = "MSA") -> str:
    return json.dumps(check_missing_clauses(contract_id, contract_type))


@mcp.tool()
def tool_agent_graph(message: str, context_json: str = "{}") -> str:
    try:
        context = json.loads(context_json) if context_json else {}
        if not isinstance(context, dict):
            context = {}
    except Exception:
        context = {}
    return json.dumps(run_review_reasoning(message, context), default=str)


def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("Review Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
