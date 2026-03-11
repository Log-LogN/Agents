"""Analytics Agent MCP Server - Port 8007"""

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
PORT = int(os.getenv("ANALYTICS_PORT", "8007"))
mcp = FastMCP("AnalyticsAgent")

from agents.analytics_agent.graph import run_reasoning
from agents.analytics_agent.mcp_server.tools.analytics_tools import (
    export_report,
    get_cycle_time_report,
    get_expiry_report,
    get_portfolio_summary,
    get_risk_dashboard,
    get_spend_analytics,
    search_contracts,
)


@mcp.tool()
def tool_get_portfolio_summary(user_id: int = 0) -> str:
    return json.dumps(get_portfolio_summary(user_id))


@mcp.tool()
def tool_get_expiry_report(days_ahead: int = 90) -> str:
    return json.dumps(get_expiry_report(days_ahead))


@mcp.tool()
def tool_get_risk_dashboard() -> str:
    return json.dumps(get_risk_dashboard())


@mcp.tool()
def tool_search_contracts(query: str = "", contract_type: str = "", status: str = "") -> str:
    return json.dumps(search_contracts(query, contract_type, status))


@mcp.tool()
def tool_get_spend_analytics(period_days: int = 365) -> str:
    return json.dumps(get_spend_analytics(period_days))


@mcp.tool()
def tool_get_cycle_time_report() -> str:
    return json.dumps(get_cycle_time_report())


@mcp.tool()
def tool_export_report(report_type: str = "portfolio", fmt: str = "json") -> str:
    return json.dumps(export_report(report_type, fmt))


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
    logger.info("Analytics Agent MCP Server starting on port %d", PORT)
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
