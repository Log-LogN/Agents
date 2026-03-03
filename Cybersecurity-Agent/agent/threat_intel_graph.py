"""
Threat Intel Agent Internal Graph
==================================
Tool-first LangGraph agent for threat intelligence analysis.
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

logger = logging.getLogger("threat-intel-agent")


# =========================================================
# State
# =========================================================

class ThreatIntelAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

THREAT_INTEL_SYSTEM_PROMPT = SystemMessage(content="""
You are a cybersecurity threat intelligence analyst.

Always use these tools to assess threat severity for CVEs:

1. tool_get_epss(cve) → Get EPSS exploit prediction score (0-1 scale, higher = more likely to be exploited)
2. tool_check_cisa_kev(cve) → Check if CVE is in CISA Known Exploited Vulnerabilities database
3. tool_check_exploit_available(cve) → Check if public exploit/POC is available on GitHub

Tool selection sequence:

1. Extract CVE ID from user input (format: CVE-XXXX-XXXXX)
2. If no CVE provided, ask for one
3. Call all three tools for comprehensive threat assessment:
   - tool_get_epss(cve)
   - tool_check_cisa_kev(cve)
   - tool_check_exploit_available(cve)

Threat Level Decision Logic (use this after getting tool results):
- HIGH: If (KEV is true) OR (exploit_available is true) OR (EPSS >= 0.7)
- MEDIUM: If (EPSS >= 0.3 and < 0.7)
- LOW: If (EPSS < 0.3 and KEV is false and exploit not available)

Never invent exploit or threat information.
Base assessment only on tool results.
Include EPSS percentile interpretation (e.g., "EPSS 75% means more dangerous than 75% of other CVEs").
""")

THREAT_INTEL_SUMMARY_PROMPT = SystemMessage(content="""
Provide a comprehensive threat intelligence summary:

Include:
- CVE ID
- EPSS Score with interpretation (e.g., "EPSS 85% = Likely exploited soon")
- CISA KEV Status (Is this CVE actively exploited in the wild?)
- Public Exploit Availability (Documented POC on GitHub or public exploit code?)
- Overall Threat Level (LOW / MEDIUM / HIGH)
- Risk Implication (What does this threat mean?)
- Recommended Actions (Monitor / Patch ASAP / Deploy WAF / etc.)
- Confidence Level (Based on data availability)

Be concise but actionable.
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

async def run_threat_intel_agent(messages: List[BaseMessage], tools: List[BaseTool]) -> dict:
    logger.info(f"Threat Intel agent started: {messages[:100]}")

    if not tools:
        return {
            "output": "No threat intelligence tools available.",
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

    async def reasoning_node(state: ThreatIntelAgentState):
        response = await llm_with_tools.ainvoke(
            [THREAT_INTEL_SYSTEM_PROMPT] + state["messages"]
        )

        logger.info(f"Tool decision: {getattr(response, 'tool_calls', None)}")

        return {"messages": [response]}

    def should_continue(state: ThreatIntelAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: ThreatIntelAgentState):
        summary = await llm.ainvoke(
            [THREAT_INTEL_SUMMARY_PROMPT] + state["messages"]
        )

        text = summary.content if isinstance(summary.content, str) else str(summary.content)

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph
    # =====================================================

    graph = StateGraph(ThreatIntelAgentState)
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
        logger.exception("Threat Intel agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": []
        }


# =========================================================
# Streaming
# =========================================================

async def run_threat_intel_agent_stream(message: str, tools: List[BaseTool]):
    yield {
        "event": "agent_started",
        "data": {"agent": "threat_intel", "message": message},
        "timestamp": _now_iso(),
    }

    try:
        result = await run_threat_intel_agent([HumanMessage(content=message)], tools)
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

