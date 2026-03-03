"""
Risk Agent Internal Graph
=========================
Tool-first LangGraph agent for comprehensive risk assessment.
Pattern: agent → tools (loop) → summarize
"""

import sys
import os
import logging
import time
import json
import ast
from typing import TypedDict, Annotated, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage
from langchain_core.tools import BaseTool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.config import settings

logger = logging.getLogger("risk-agent")


# =========================================================
# State
# =========================================================

class RiskAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

RISK_SYSTEM_PROMPT = SystemMessage(content="""
You are a comprehensive cybersecurity risk assessment specialist.

Always perform complete risk assessment using all available tools:

Phase 1: Input Validation
- Require both CVE (e.g., CVE-2021-44228) and domain (e.g., example.com)
- If either is missing, ask the user for it

Phase 2: Vulnerability Severity Assessment
- tool_get_cvss(cve) → Get CVSS base score (0-10 scale)
- Fallback: If CVSS unavailable, use 5.0 as default

Phase 3: Exploit Likelihood Assessment
- tool_get_epss(cve) → Get EPSS score (0-1 scale, higher = more likely exploited)
- tool_check_cisa_kev(cve) → Check if CVE is in CISA Known Exploited Vulnerabilities
- tool_check_exploit_available(cve) → Check if public POC/exploit is available

Phase 4: Exposure Assessment
- tool_port_scan(domain) → Scan for open ports
- Interpretation: If ports found = internet exposed; if scan has warnings, treat as unreliable

Phase 5: Overall Risk Calculation
- tool_calculate_risk(cvss, epss, exploit_available, in_kev, internet_exposed, open_ports)
- Fallback: If risk service fails, calculate as min(10.0, cvss) and assign severity

Never invent risk scores or exposure data.
Base assessment only on tool results.
Always use fallbacks if services unavailable.
""")

RISK_SUMMARY_PROMPT = SystemMessage(content="""
Provide a comprehensive risk assessment summary:

Include:
- Overall Risk Score (0-10 with severity: Critical/High/Medium/Low)
- CVE ID and CVSS Score
- Exploit Likelihood (EPSS%, KEV status, POC availability)
- Internet Exposure (open ports, scan reliability)
- Risk Severity Justification (why this score)
- Recommended Action (Patch immediately/ASAP/soon/monitor with priority)
- Exposure Details (which ports exposed, services at risk)
- Confidence Level (based on data availability)

Be clear about fallback values used (e.g., "CVSS defaulted to 5.0").
Be actionable and specific.
""")


# =========================================================
# Helpers
# =========================================================

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _extract_tool_output(content):
    try:
        if isinstance(content, dict):
            return content

        if isinstance(content, list):
            if content and "text" in content[0]:
                text = content[0]["text"]
                try:
                    return json.loads(text)
                except:
                    return text

        if isinstance(content, str):
            try:
                parsed = ast.literal_eval(content)
                if isinstance(parsed, list) and parsed and "text" in parsed[0]:
                    text = parsed[0]["text"]
                    try:
                        return json.loads(text)
                    except:
                        return text
            except:
                pass

        return content
    except Exception:
        return str(content)


# =========================================================
# Agent Execution
# =========================================================

async def run_risk_agent(messages: List[BaseMessage], tools: List[BaseTool]) -> dict:
    logger.info(f"Risk agent started: {messages[:100]}")

    if not tools:
        return {
            "output": "No risk assessment tools available.",
            "tool_calls": []
        }

    # LLM
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )
    llm_with_tools = llm.bind_tools(tools)

    # =====================================================
    # Nodes
    # =====================================================

    async def reasoning_node(state: RiskAgentState):
        response = await llm_with_tools.ainvoke(
            [RISK_SYSTEM_PROMPT] + state["messages"]
        )

        logger.info(f"Tool decision: {getattr(response, 'tool_calls', None)}")

        return {"messages": [response]}

    def should_continue(state: RiskAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: RiskAgentState):
        summary = await llm.ainvoke(
            [RISK_SUMMARY_PROMPT] + state["messages"]
        )

        text = summary.content if isinstance(summary.content, str) else str(summary.content)

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph
    # =====================================================

    graph = StateGraph(RiskAgentState)
    tool_node = ToolNode(tools)

    graph.add_node("reasoning", reasoning_node)
    graph.add_node("tools", tool_node)
    graph.add_node("summarize", summarize_node)

    graph.add_edge(START, "reasoning")

    graph.add_conditional_edges(
        "reasoning",
        should_continue,
        {
            "tools": "tools",
            "summarize": "summarize",
        }
    )

    # Loop for multiple tool calls
    graph.add_edge("tools", "reasoning")

    graph.add_edge("summarize", END)

    compiled_graph = graph.compile()

    # =====================================================
    # Execute
    # =====================================================

    try:
        initial_state = {"messages": messages}
        final_state = await compiled_graph.ainvoke(initial_state)

        output = final_state.get("final_output", "")

        # Extract tool calls
        tool_calls = []
        messages = final_state["messages"]

        for i, msg in enumerate(messages):
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_output = ""
                    if i + 1 < len(messages):
                        next_msg = messages[i + 1]
                        if hasattr(next_msg, "content"):
                            tool_output = _extract_tool_output(next_msg.content)

                    tool_calls.append({
                        "tool_name": tc["name"],
                        "tool_input": tc["args"],
                        "tool_output": str(tool_output),
                    })

        return {
            "output": output,
            "tool_calls": tool_calls
        }

    except Exception as e:
        logger.exception("Risk agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": []
        }


# =========================================================
# Streaming
# =========================================================

async def run_risk_agent_stream(message: str, tools: List[BaseTool]):
    yield {
        "event": "agent_started",
        "data": {"agent": "risk", "message": message},
        "timestamp": _now_iso(),
    }

    try:
        result = await run_risk_agent([HumanMessage(content=message)], tools)
        yield {
            "event": "agent_completed",
            "data": result,
            "timestamp": _now_iso(),
        }
    except Exception as e:
        yield {
            "event": "error",
            "data": {"error": str(e)},
            "timestamp": _now_iso(),
        }

