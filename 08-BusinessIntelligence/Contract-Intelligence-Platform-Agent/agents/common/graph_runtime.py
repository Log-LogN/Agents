"""Reusable LangGraph runtime for specialist agents."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
from typing import Annotated, Any, Callable, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.graph.message import add_messages
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

logger = logging.getLogger(__name__)
_USER_FACING_ERROR = "Service temporarily unavailable. Please try again."


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    final_output: str


def _extract_tool_output(content: Any) -> str:
    if isinstance(content, str):
        return content
    return str(content)


async def _build_graph_async(
    *,
    agent_name: str,
    system_prompt: str,
    summary_prompt: str,
    mcp_url: str,
):
    llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=0.1, timeout=30)

    client = MultiServerMCPClient(
        connections={
            "self": {
                "transport": "streamable_http",
                "url": mcp_url,
            }
        }
    )
    tools = await client.get_tools(server_name="self")
    llm_with_tools = llm.bind_tools(tools)
    tool_node = ToolNode(tools)

    async def reasoning_node(state: AgentState):
        tool_names = ", ".join([t.name for t in tools])
        response = await llm_with_tools.ainvoke(
            [
                SystemMessage(
                    content=(
                        f"{system_prompt}\n\n"
                        f"Available domain tools: {tool_names}\n"
                        "Call the appropriate MCP tools directly when needed."
                    )
                )
            ]
            + state["messages"]
        )
        return {"messages": [response]}

    def route_after_reasoning(state: AgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: AgentState):
        summary = await llm.ainvoke([SystemMessage(content=summary_prompt)] + state["messages"])
        text = summary.content if isinstance(summary.content, str) else str(summary.content)
        return {"messages": [AIMessage(content=text)], "final_output": text}

    graph = StateGraph(AgentState)
    graph.add_node("reasoning", reasoning_node)
    graph.add_node("tools", tool_node)
    graph.add_node("summarize", summarize_node)
    graph.add_edge(START, "reasoning")
    graph.add_conditional_edges("reasoning", route_after_reasoning, {"tools": "tools", "summarize": "summarize"})
    graph.add_edge("tools", "summarize")
    graph.add_edge("summarize", END)

    return graph.compile()


def _build_graph(
    *,
    agent_name: str,
    system_prompt: str,
    summary_prompt: str,
    mcp_url: str,
):
    # Since _build_graph_async is async, we need to run it in a thread or something
    # But to keep it simple, we'll make the whole thing async later
    # For now, assume we call it from async context
    pass  # Will handle in run_standard_agent_graph


async def _run_graph_async(
    *,
    agent_name: str,
    message: str,
    context: dict[str, Any],
    system_prompt: str,
    summary_prompt: str,
    mcp_url: str,
) -> dict[str, Any]:
    compiled_graph = await _build_graph_async(
        agent_name=agent_name,
        system_prompt=system_prompt,
        summary_prompt=summary_prompt,
        mcp_url=mcp_url,
    )
    context_text = json.dumps(context or {}, default=str)
    messages = [HumanMessage(content=f"{message}\n\nContext JSON: {context_text}")]

    try:
        final_state = await compiled_graph.ainvoke({"messages": messages, "final_output": ""})
        output = final_state.get("final_output", "")
        tool_calls: list[dict[str, Any]] = []
        final_messages = final_state.get("messages", [])

        for i, msg in enumerate(final_messages):
            if getattr(msg, "tool_calls", None):
                for tc in msg.tool_calls:
                    tool_output = ""
                    if i + 1 < len(final_messages):
                        tool_output = _extract_tool_output(final_messages[i + 1].content)
                    tool_calls.append(
                        {
                            "tool_name": tc.get("name"),
                            "tool_input": tc.get("args"),
                            "tool_output": str(tool_output),
                        }
                    )

        return {"output": output, "tool_calls": tool_calls}
    except Exception as exc:
        logger.exception("[%s] graph execution failed", agent_name)
        return {"output": _USER_FACING_ERROR, "tool_calls": []}


def run_standard_agent_graph(
    *,
    agent_name: str,
    message: str,
    context: dict[str, Any] | None,
    system_prompt: str,
    summary_prompt: str,
    mcp_url: str,
) -> dict[str, Any]:
    ctx = context or {}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    _run_graph_async(
                        agent_name=agent_name,
                        message=message,
                        context=ctx,
                        system_prompt=system_prompt,
                        summary_prompt=summary_prompt,
                        mcp_url=mcp_url,
                    ),
                )
                return future.result(timeout=60)
        return loop.run_until_complete(
            _run_graph_async(
                agent_name=agent_name,
                message=message,
                context=ctx,
                system_prompt=system_prompt,
                summary_prompt=summary_prompt,
                mcp_url=mcp_url,
            )
        )
    except Exception as exc:
        logger.exception("[%s] run_standard_agent_graph failed", agent_name)
        return {"output": _USER_FACING_ERROR, "tool_calls": []}
