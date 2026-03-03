"""
Advisory Agent
==============
Deterministic advisory lookup agent.

Flow:
reasoning → tools (once) → summarize → END
"""

import logging
import time
import json
import ast
from typing import TypedDict, Annotated, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import (
    HumanMessage,
    SystemMessage,
    BaseMessage,
    AIMessage,
)
from langchain_core.tools import BaseTool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from shared.config import settings

logger = logging.getLogger("advisory-agent")


# =========================================================
# State
# =========================================================

class AdvisoryAgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

ADVISORY_SYSTEM_PROMPT = SystemMessage(content="""
You are a cybersecurity advisory analysis assistant.

You MUST perform exactly ONE tool call.

Rules:
- If input contains GHSA-XXXX-XXXX-XXXX → tool_get_advisory(vuln_id)
- If input contains CVE-XXXX-XXXX → tool_get_advisory(vuln_id)
- If no valid advisory ID is provided → do NOT call tools and ask for a valid ID

Never invent advisory data.
Do not repeat tool calls.
Wait for tool result before summarizing.
""")

ADVISORY_SUMMARY_PROMPT = SystemMessage(content="""
Provide a structured advisory summary including:

- Advisory ID
- Aliases (CVE/GHSA)
- Description
- Severity (CVSS if available)
- Affected packages/ecosystems
- Recommended remediation
- References

Use only tool results.
""")


# =========================================================
# Helpers
# =========================================================

def _extract_tool_output(content):
    try:
        if isinstance(content, dict):
            return content

        if isinstance(content, list) and content:
            if "text" in content[0]:
                return json.loads(content[0]["text"])

        if isinstance(content, str):
            try:
                parsed = ast.literal_eval(content)
                if isinstance(parsed, list) and parsed and "text" in parsed[0]:
                    return json.loads(parsed[0]["text"])
            except Exception:
                pass

        return content
    except Exception:
        return str(content)


# =========================================================
# Main Execution
# =========================================================

async def run_advisory_agent(
    messages: List[BaseMessage],
    tools: List[BaseTool],
) -> dict:

    logger.info("Advisory agent started")

    if not tools:
        return {
            "output": "Advisory tools unavailable.",
            "tool_calls": [],
        }

    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )

    llm_with_tools = llm.bind_tools(tools)

    # =====================================================
    # Nodes
    # =====================================================

    async def reasoning_node(state: AdvisoryAgentState):
        response = await llm_with_tools.ainvoke(
            [ADVISORY_SYSTEM_PROMPT] + state["messages"]
        )
        return {"messages": [response]}

    def route_after_reasoning(state: AdvisoryAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: AdvisoryAgentState):
        summary = await llm.ainvoke(
            [ADVISORY_SUMMARY_PROMPT] + state["messages"]
        )

        text = (
            summary.content
            if isinstance(summary.content, str)
            else str(summary.content)
        )

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph (NO LOOP)
    # =====================================================

    graph = StateGraph(AdvisoryAgentState)
    tool_node = ToolNode(tools)

    graph.add_node("reasoning", reasoning_node)
    graph.add_node("tools", tool_node)
    graph.add_node("summarize", summarize_node)

    graph.add_edge(START, "reasoning")

    graph.add_conditional_edges(
        "reasoning",
        route_after_reasoning,
        {
            "tools": "tools",
            "summarize": "summarize",
        },
    )

    # 🔥 IMPORTANT: tools go directly to summarize
    graph.add_edge("tools", "summarize")
    graph.add_edge("summarize", END)

    compiled_graph = graph.compile()

    # =====================================================
    # Execute
    # =====================================================

    try:
        final_state = await compiled_graph.ainvoke(
            {"messages": messages}
        )

        output = final_state.get("final_output", "")

        tool_calls = []
        final_messages = final_state["messages"]

        for i, msg in enumerate(final_messages):
            if getattr(msg, "tool_calls", None):
                for tc in msg.tool_calls:
                    tool_output = ""
                    if i + 1 < len(final_messages):
                        tool_output = _extract_tool_output(
                            final_messages[i + 1].content
                        )

                    tool_calls.append({
                        "tool_name": tc["name"],
                        "tool_input": tc["args"],
                        "tool_output": str(tool_output),
                    })

        return {
            "output": output,
            "tool_calls": tool_calls,
        }

    except Exception as e:
        logger.exception("Advisory agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": [],
        }


# =========================================================
# Streaming
# =========================================================

async def run_advisory_agent_stream(message: str, tools: List[BaseTool]):
    yield {
        "event": "agent_started",
        "data": {"agent": "advisory", "message": message},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    try:
        result = await run_advisory_agent([HumanMessage(content=message)], tools)
        yield {
            "event": "agent_completed",
            "data": result,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except Exception as e:
        yield {
            "event": "error",
            "data": {"error": str(e)},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }