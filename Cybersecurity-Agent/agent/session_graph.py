"""
Session Agent Internal Graph
============================
Tool-first LangGraph agent for session analysis and aggregation.
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
from shared.models import RedisSessionStore

logger = logging.getLogger("session-agent")


# =========================================================
# State
# =========================================================

class SessionAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

SESSION_SYSTEM_PROMPT = SystemMessage(content="""
You are a security session analysis specialist.

Analyze session artifacts and provide comprehensive summary:

Session artifacts contain:
- Risk assessments (CVE + domain risk scores)
- Threat intelligence analysis
- Dependency vulnerability scans
- Domain reconnaissance findings
- Advisory lookups

Analysis tasks:

1. Extract session_id from user input
2. Retrieve session artifacts from session history
3. Identify highest-risk items (risk assessments, vulnerabilities)
4. Summarize findings:
   - Total vulnerabilities found
   - Highest risk CVE or dependency
   - Critical issues requiring immediate action
   - Overall session risk posture

Never invent data.
Base analysis only on session artifacts.
Provide actionable recommendations.
""")

SESSION_SUMMARY_PROMPT = SystemMessage(content="""
Provide a comprehensive session analysis summary:

Include:
- Session Overview (number of scans, tools used)
- Highest Risk Finding (CVE, domain, or dependency)
- Risk Breakdown (by severity, by type)
- Critical Issues Identified
- Affected Assets (CVEs, domains, packages)
- Recommended Actions (prioritized)
- Overall Session Risk Assessment

Be concise but thorough.
Highlight critical findings.
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


def _get_session_artifacts(session_id: str):
    """Retrieve artifacts from session store"""
    try:
        store = RedisSessionStore()
        return store.get_session_artifacts(session_id) or []
    except Exception as e:
        logger.error(f"Failed to retrieve session artifacts: {e}")
        return []


# =========================================================
# Agent Execution
# =========================================================

async def run_session_agent(messages: List[BaseMessage], tools: List[BaseTool], session_id: str = None) -> dict:
    logger.info(f"Session agent started: {messages[:100]}")

    # Get session artifacts
    artifacts = _get_session_artifacts(session_id) if session_id else []
    logger.info(f"Retrieved {len(artifacts)} artifacts from session {session_id}")

    if not tools:
        return {
            "output": "No session analysis tools available.",
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

    async def reasoning_node(state: SessionAgentState):
        # Add session context to prompt
        context = f"\n\nSession ID: {session_id}\nSession Artifacts ({len(artifacts)} found):\n"
        if artifacts:
            context += json.dumps(artifacts[:5], indent=2, default=str)  # First 5 artifacts
        
        prompt_with_context = [
            SystemMessage(content=SESSION_SYSTEM_PROMPT.content + context)
        ] + state["messages"]
        
        response = await llm_with_tools.ainvoke(prompt_with_context)
        logger.info(f"Tool decision: {getattr(response, 'tool_calls', None)}")

        return {"messages": [response]}

    def should_continue(state: SessionAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: SessionAgentState):
        summary = await llm.ainvoke(
            [SESSION_SUMMARY_PROMPT] + state["messages"]
        )

        text = summary.content if isinstance(summary.content, str) else str(summary.content)

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph
    # =====================================================

    graph = StateGraph(SessionAgentState)
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
        logger.exception("Session agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": []
        }


# =========================================================
# Streaming
# =========================================================

async def run_session_agent_stream(message: str, tools: List[BaseTool], session_id: str = None):
    yield {
        "event": "agent_started",
        "data": {"agent": "session", "message": message, "session_id": session_id},
        "timestamp": _now_iso(),
    }

    try:
        result = await run_session_agent([HumanMessage(content=message)], tools, session_id)
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
