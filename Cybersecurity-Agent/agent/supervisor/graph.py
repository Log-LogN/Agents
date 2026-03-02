import json
import logging
from typing import TypedDict, Annotated, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, START, END

from shared.config import settings
from shared.models import RedisSessionStore
from agent.recon_graph import run_recon_agent
from agent.vulnerability_graph import run_vulnerability_agent
from .mcp_client import get_mcp_tools

logger = logging.getLogger("supervisor")


# =========================================================
# State
# =========================================================

class SupervisorState(TypedDict, total=False):
    messages: Annotated[List[BaseMessage], add_messages]
    selected_agent: str
    output: str
    tool_calls: list


# =========================================================
# Routing Prompt
# =========================================================

ROUTER_PROMPT = """
You are a cybersecurity supervisor.

Choose the correct handler.

Agents:

recon:
- DNS
- WHOIS
- Port scan
- Domain/IP info

vulnerability:
- CVE lookup
- Package vulnerabilities
- Dependency security

direct_answer:
- General cybersecurity questions
- Concept explanations
- When no specific agent applies
- Fallback for unclear requests

Respond ONLY JSON:

{
  "agent": "recon" | "vulnerability" | "direct_answer"
}
"""


# =========================================================
# Nodes
# =========================================================

async def reasoning_node(state: SupervisorState) -> SupervisorState:
    # Get the last human message
    last_message = state["messages"][-1]
    user_message = last_message.content if hasattr(last_message, 'content') else str(last_message)

    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
        model_kwargs={"response_format": {"type": "json_object"}},
    )

    resp = await llm.ainvoke([
        SystemMessage(content=ROUTER_PROMPT),
        HumanMessage(content=user_message)
    ])

    try:
        data = json.loads(resp.content)
        agent = data.get("agent", "direct_answer").lower()
    except Exception:
        agent = "direct_answer"

    logger.info(f"Supervisor route → {agent}")

    return {"selected_agent": agent}


# ---------------------------------------------------------

async def execute_node(state: SupervisorState) -> SupervisorState:
    agent = state.get("selected_agent", "direct_answer")
    # Get the last human message
    last_message = state["messages"][-1]
    message = last_message.content if hasattr(last_message, 'content') else str(last_message)

    # Load MCP tools once
    recon_tools, vuln_tools = await get_mcp_tools()

    if agent == "recon":
        result = await run_recon_agent(state["messages"], recon_tools)

    elif agent == "vulnerability":
        result = await run_vulnerability_agent(state["messages"], vuln_tools)

    else:
        # Direct answer
        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            api_key=settings.OPENAI_API_KEY,
            temperature=0,
        )
        resp = await llm.ainvoke(state["messages"])
        result = {"output": resp.content, "tool_calls": []}

    return {
        "output": result.get("output", ""),
        "tool_calls": result.get("tool_calls", []),
    }


# ---------------------------------------------------------

async def finalize_node(state: SupervisorState) -> SupervisorState:
    output = state.get("output", "").strip()
    if not output:
        output = "Unable to process request."

    # Add AI response to messages
    return {
        "output": output,
        "messages": [AIMessage(content=output)]
    }


# =========================================================
# Graph
# =========================================================

def build_supervisor_graph(checkpointer=None):
    graph = StateGraph(SupervisorState)

    graph.add_node("reasoning", reasoning_node)
    graph.add_node("execute", execute_node)
    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "reasoning")
    graph.add_edge("reasoning", "execute")
    graph.add_edge("execute", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile(checkpointer=checkpointer)


# =========================================================
# Entry
# =========================================================

async def run_supervisor(user_message: str, session_id: str, graph):
    session_store = RedisSessionStore()

    # Load existing history
    history = session_store.get_session_history(session_id)
    messages = [HumanMessage(content=msg["content"]) if msg["type"] == "human" else AIMessage(content=msg["content"]) for msg in history]

    # Add new human message
    messages.append(HumanMessage(content=user_message))

    # Run graph with messages
    final = await graph.ainvoke({

        "messages": messages
    }, {"configurable": {"thread_id": session_id}})

    # Save updated history
    updated_messages = final.get("messages", messages)
    history_data = [{"type": "human" if isinstance(msg, HumanMessage) else "ai", "content": msg.content} for msg in updated_messages]
    session_store.save_session_history(session_id, history_data)

    return {
        "output": final.get("output", ""),
        "agent_used": final.get("selected_agent", ""),
        "tool_calls": final.get("tool_calls", []),
    }