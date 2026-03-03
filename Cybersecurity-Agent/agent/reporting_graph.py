"""
Reporting Agent Internal Graph
===============================
Tool-first LangGraph agent for comprehensive security reporting.
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

logger = logging.getLogger("reporting-agent")


# =========================================================
# State
# =========================================================

class ReportingAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

REPORTING_SYSTEM_PROMPT = SystemMessage(content="""
You are a security reporting specialist.

Always use reporting tools to generate comprehensive security reports:

Tool selection based on input:

1. CVE List provided → tool_severity_summary(cve_list)
   - Generates severity breakdown by CVE
   
2. Risk scoring needed → tool_risk_score(cve_list)
   - Calculates risk scores for each CVE
   
3. Mitigation guidance needed → Extract risk_level from previous results
   - tool_mitigation_advice(risk_level)
   - Provides actionable mitigation strategies
   
4. Session ID provided → tool_generate_session_report(session_id)
   - Generates comprehensive markdown session report

Always call tools to retrieve data.
Build comprehensive report from tool results.
Never invent mitigation strategies or risk assessments.
""")

REPORTING_SUMMARY_PROMPT = SystemMessage(content="""
Provide a comprehensive security report summary:

Include:
- Executive Summary (total CVEs, highest risk level, key metrics)
- Severity Breakdown (critical/high/medium/low counts)
- Risk Scores (individual CVE risk scores and overall risk)
- Affected Assets (which systems/packages affected)
- Mitigation Recommendations (prioritized by severity)
- Action Items (immediate, short-term, long-term)
- Report Path (if session report generated)

Be thorough, well-organized, and actionable.
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

async def run_reporting_agent(messages: List[BaseMessage], tools: List[BaseTool]) -> dict:
    logger.info(f"Reporting agent started: {messages[:100]}")

    if not tools:
        return {
            "output": "No reporting tools available.",
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

    async def reasoning_node(state: ReportingAgentState):
        response = await llm_with_tools.ainvoke(
            [REPORTING_SYSTEM_PROMPT] + state["messages"]
        )

        logger.info(f"Tool decision: {getattr(response, 'tool_calls', None)}")

        return {"messages": [response]}

    def should_continue(state: ReportingAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: ReportingAgentState):
        summary = await llm.ainvoke(
            [REPORTING_SUMMARY_PROMPT] + state["messages"]
        )

        text = summary.content if isinstance(summary.content, str) else str(summary.content)

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph
    # =====================================================

    graph = StateGraph(ReportingAgentState)
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
        logger.exception("Reporting agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": []
        }


# =========================================================
# Streaming
# =========================================================

async def run_reporting_agent_stream(message: str, tools: List[BaseTool]):
    yield {
        "event": "agent_started",
        "data": {"agent": "reporting", "message": message},
        "timestamp": _now_iso(),
    }

    try:
        result = await run_reporting_agent([HumanMessage(content=message)], tools)
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

