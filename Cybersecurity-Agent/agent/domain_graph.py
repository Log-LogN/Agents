"""
Domain Agent Internal Graph
===========================
Tool-first LangGraph agent for comprehensive domain analysis.
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

logger = logging.getLogger("domain-agent")


# =========================================================
# State
# =========================================================

class DomainAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


# =========================================================
# Prompts
# =========================================================

DOMAIN_SYSTEM_PROMPT = SystemMessage(content="""
You are a domain intelligence and security analysis assistant.

Always use tools to gather complete domain information:

Tool selection for domain queries:

1. IP resolution
   → tool_dns_lookup(domain)
   - Returns A records (IPv4 addresses)

2. Domain registration details
   → tool_whois_lookup(domain)
   - Returns registrant, registrar, expiry, nameservers

3. Open ports/services
   → tool_port_scan(host)
   - Scans common ports on IP
   - Note: May return warning if unreliable

4. Web security posture
   → tool_http_security_headers(host)
   - Analyzes HTTP security headers
   - Lists missing critical headers

5. TLS certificate details
   → tool_ssl_info(host, port=443)
   - Certificate issuer, expiry, key size
   - Days to expiry

Call all relevant tools to provide comprehensive domain assessment.
Never invent domain information.
Always use tool results.
""")

DOMAIN_SUMMARY_PROMPT = SystemMessage(content="""
Provide a comprehensive domain analysis summary:

Include:
- Domain Name
- IP Addresses Resolved
- Domain Registration Info (owner, registrar, expiry)
- Internet Exposure (open ports, services)
- Web Security Posture (HTTP headers analysis)
- TLS Certificate Status (issuer, expiry, days remaining)
- Security Issues Identified (missing headers, certificate expiry risk)
- Overall Risk Assessment

Be technical and organized.
Highlight security concerns prominently.
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

async def run_domain_agent(messages: List[BaseMessage], tools: List[BaseTool]) -> dict:
    logger.info(f"Domain agent started: {messages[:100]}")

    if not tools:
        return {
            "output": "No domain analysis tools available.",
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

    async def reasoning_node(state: DomainAgentState):
        response = await llm_with_tools.ainvoke(
            [DOMAIN_SYSTEM_PROMPT] + state["messages"]
        )

        logger.info(f"Tool decision: {getattr(response, 'tool_calls', None)}")

        return {"messages": [response]}

    def should_continue(state: DomainAgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: DomainAgentState):
        summary = await llm.ainvoke(
            [DOMAIN_SUMMARY_PROMPT] + state["messages"]
        )

        text = summary.content if isinstance(summary.content, str) else str(summary.content)

        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    # =====================================================
    # Graph
    # =====================================================

    graph = StateGraph(DomainAgentState)
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
        logger.exception("Domain agent failed")
        return {
            "output": f"Execution failed: {str(e)}",
            "tool_calls": []
        }


# =========================================================
# Streaming
# =========================================================

async def run_domain_agent_stream(message: str, tools: List[BaseTool]):
    yield {
        "event": "agent_started",
        "data": {"agent": "domain", "message": message},
        "timestamp": _now_iso(),
    }

    try:
        result = await run_domain_agent([HumanMessage(content=message)], tools)
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
