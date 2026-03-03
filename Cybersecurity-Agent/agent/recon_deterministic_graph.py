"""
Recon Deterministic Agent Internal Graph
========================================
Tool-first LangGraph agent for deterministic reconnaissance.
Pattern: agent → tools (loop) → summarize
(Similar to recon_graph.py - use recon_graph instead)
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

logger = logging.getLogger("recon-deterministic-agent")


# =========================================================
# State
# =========================================================

class ReconDeterministicAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

RECON_DETERMINISTIC_SYSTEM_PROMPT = SystemMessage(content="""
You are a deterministic reconnaissance specialist.

Available tools:
1. tool_dns_lookup(domain) → IP resolution
2. tool_port_scan(host) → Open port scanning
3. tool_whois_lookup(domain) → Domain registration
4. tool_http_security_headers(host) → HTTP security analysis
5. tool_ssl_info(host, port=443) → TLS certificate info

Tool selection:
- IP/domain resolution → tool_dns_lookup
- Port enumeration → tool_port_scan
- Domain registration → tool_whois_lookup
- Web security headers → tool_http_security_headers
- TLS certificate → tool_ssl_info

Call appropriate tools based on user query.
Never invent reconnaissance results.
""")

RECON_DETERMINISTIC_SUMMARY_PROMPT = SystemMessage(content="""
Summarize reconnaissance findings:

Include:
- Target domain/IP
- Resolved IP addresses
- Open ports
- Domain registration info
- HTTP security posture
- TLS certificate status

Be concise and technical.
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

async def run_recon_deterministic_agent(messages: List[BaseMessage], tools: List[BaseTool]) -> dict:
    logger.info(f"Recon Deterministic agent started: {messages[:100]}")

    if not tools:
        return {
            "output": "No reconnaissance tools available.",
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

    async def reasoning_node(state: ReconDeterministicAgentState):
        response = await llm_with_tools.ainvoke(
            [RECON_DETERMINISTIC_SYSTEM_PROMPT] + state["messages"]
        )

        logger.info(f"Tool decision: {getattr(response, 'tool_calls', None)}")

        return {"messages": [response]}

    def should_continue(state: ReconDeterministicAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: ReconDeterministicAgentState):
        summary = await llm.ainvoke(
            [RECON_DETERMINISTIC_SUMMARY_PROMPT] + state["messages"]
        )

        text = summary.content if isinstance(summary.content, str) else str(summary.content)

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph
    # =====================================================

    graph = StateGraph(ReconDeterministicAgentState)
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
        logger.exception("Recon Deterministic agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": []
        }


# =========================================================
# Streaming
# =========================================================

async def run_recon_deterministic_agent_stream(message: str, tools: List[BaseTool]):
    yield {
        "event": "agent_started",
        "data": {"agent": "recon_deterministic", "message": message},
        "timestamp": _now_iso(),
    }

    try:
        result = await run_recon_deterministic_agent([HumanMessage(content=message)], tools)
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

