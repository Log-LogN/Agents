"""Approval Agent MCP Server - Port 8003"""

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
PORT = int(os.getenv("APPROVAL_PORT", "8003"))
mcp = FastMCP("ApprovalAgent")

from agents.approval_agent.graph import run_reasoning
from agents.approval_agent.mcp_server.tools.approval_tools import (
    approve_contract,
    create_approval_workflow,
    escalate_approval,
    get_approval_status,
    get_pending_approvals,
    reject_contract,
)


@mcp.tool()
def tool_create_approval_workflow(contract_id: int, approvers_csv: str, deadline_days: int = 7, created_by: int = 1) -> str:
    approvers = [a.strip() for a in approvers_csv.split(",") if a.strip()]
    return json.dumps(create_approval_workflow(contract_id, approvers, deadline_days, created_by))


@mcp.tool()
def tool_get_approval_status(contract_id: int) -> str:
    return json.dumps(get_approval_status(contract_id))


@mcp.tool()
def tool_approve_contract(contract_id: int, approver_email: str, comments: str = "") -> str:
    return json.dumps(approve_contract(contract_id, approver_email, comments))


@mcp.tool()
def tool_reject_contract(contract_id: int, approver_email: str, reason: str = "") -> str:
    return json.dumps(reject_contract(contract_id, approver_email, reason))


@mcp.tool()
def tool_escalate_approval(contract_id: int, reason: str = "") -> str:
    return json.dumps(escalate_approval(contract_id, reason))


@mcp.tool()
def tool_get_pending_approvals(user_email: str = "") -> str:
    return json.dumps(get_pending_approvals(user_email))


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
    logger.info("Approval Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
