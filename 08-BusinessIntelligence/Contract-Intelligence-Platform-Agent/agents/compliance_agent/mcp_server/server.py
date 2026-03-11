"""Compliance Agent MCP Server - Port 8006"""

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
PORT = int(os.getenv("COMPLIANCE_PORT", "8006"))
mcp = FastMCP("ComplianceAgent")

# Import after path is set
from agents.compliance_agent.graph import run_reasoning
from agents.compliance_agent.mcp_server.tools.compliance_tools import (
    check_compliance,
    check_data_residency,
    generate_audit_trail,
    get_compliance_issues,
    run_gdpr_check,
    run_jurisdiction_check,
)


@mcp.tool()
def tool_check_compliance(contract_id: int, regulations: str = "GDPR,general") -> str:
    return json.dumps(check_compliance(contract_id, regulations))


@mcp.tool()
def tool_get_compliance_issues(contract_id: int) -> str:
    return json.dumps(get_compliance_issues(contract_id))


@mcp.tool()
def tool_run_gdpr_check(contract_id: int) -> str:
    return json.dumps(run_gdpr_check(contract_id))


@mcp.tool()
def tool_run_jurisdiction_check(contract_id: int, jurisdiction: str = "New York") -> str:
    return json.dumps(run_jurisdiction_check(contract_id, jurisdiction))


@mcp.tool()
def tool_generate_audit_trail(contract_id: int) -> str:
    return json.dumps(generate_audit_trail(contract_id))


@mcp.tool()
def tool_check_data_residency(contract_id: int) -> str:
    return json.dumps(check_data_residency(contract_id))


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
    logger.info("Compliance Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
