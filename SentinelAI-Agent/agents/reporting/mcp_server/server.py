import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mcp.server.fastmcp import FastMCP
from agents.reporting.mcp_server.tools.risk_score import risk_score
from agents.reporting.mcp_server.tools.severity_summary import severity_summary
from agents.reporting.mcp_server.tools.mitigation_advice import mitigation_advice

mcp = FastMCP("reporting-mcp")


@mcp.tool()
def tool_risk_score(cve_list: list):
    return risk_score(cve_list)


@mcp.tool()
def tool_severity_summary(cve_list: list):
    return severity_summary(cve_list)


@mcp.tool()
def tool_mitigation_advice(risk_level: str):
    return mitigation_advice(risk_level)


if __name__ == "__main__":
    mcp.run(transport="stdio")