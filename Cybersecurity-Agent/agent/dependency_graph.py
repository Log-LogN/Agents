"""
Dependency Agent
================
Deterministic tool-first agent for dependency vulnerability scanning.

Flow:
reasoning → tools (max once) → summarize → END
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

logger = logging.getLogger("dependency-agent")


# =========================================================
# State
# =========================================================

class DependencyAgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

DEPENDENCY_SYSTEM_PROMPT = SystemMessage(content="""
You are a dependency vulnerability scanning assistant.

You MUST call exactly ONE scanning tool based on the user input.

Rules:

1. If a GitHub repository URL is provided
   → Call tool_scan_public_repo(repo_url)

2. If dependency file content is provided
   → Call tool_scan_dependency_text(content, file_type)

Never call multiple tools.
Never repeat a tool call.
Wait for the tool result before summarizing.
Do not invent vulnerabilities.
""")

DEPENDENCY_SUMMARY_PROMPT = SystemMessage(content="""
Provide a structured dependency vulnerability summary including:

- Total Dependencies
- Vulnerable Dependencies
- Severity Breakdown
- Critical Packages
- Affected Versions
- Recommended Upgrades
- Unpatched Issues (if any)

Base your answer strictly on tool output.
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

async def run_dependency_agent(
    messages: List[BaseMessage],
    tools: List[BaseTool],
) -> dict:

    logger.info("Dependency agent started")

    if not tools:
        return {
            "output": "Dependency scanning tools unavailable.",
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

    async def reasoning_node(state: DependencyAgentState):
        response = await llm_with_tools.ainvoke(
            [DEPENDENCY_SYSTEM_PROMPT] + state["messages"]
        )
        return {"messages": [response]}

    def route_after_reasoning(state: DependencyAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: DependencyAgentState):
        summary = await llm.ainvoke(
            [DEPENDENCY_SUMMARY_PROMPT] + state["messages"]
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
    # Graph (NO LOOP BACK)
    # =====================================================

    graph = StateGraph(DependencyAgentState)
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

    # 🔥 IMPORTANT: NO LOOP BACK TO reasoning
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

        # Extract tool calls
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
        logger.exception("Dependency agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": [],
        }