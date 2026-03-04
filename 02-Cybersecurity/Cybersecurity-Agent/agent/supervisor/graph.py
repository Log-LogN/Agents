import logging
from typing import TypedDict, Annotated, List, Optional
import inspect

from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from shared.config import settings
from shared.models import RedisSessionStore

from agent.vulnerability_graph import run_vulnerability_agent

from agent.dependency_graph import run_dependency_agent

from agent.advisory_graph import run_advisory_agent
from .mcp_client import get_mcp_tools, get_all_mcp_tools

logger = logging.getLogger("supervisor")


AGENT_TOOL_SCOPE = {
    "dependency": "all",
    "vulnerability": "vuln",
    "advisory": "vuln",
}
# =========================================================
# State
# =========================================================

class SupervisorState(TypedDict, total=False):
    messages: Annotated[List[BaseMessage], add_messages]
    selected_agent: str
    output: str
    tool_calls: list
    session_id: str
    artifact: dict


# =========================================================
# Agent Registry (Dynamic)
# =========================================================
AGENT_REGISTRY = {
    "dependency": run_dependency_agent,
    "vulnerability": run_vulnerability_agent,
    "advisory": run_advisory_agent,
    "direct_answer": lambda messages, tools: {
        "output": "I could not determine the correct agent to handle this request.",
        "tool_calls": [],
    },
}

# =========================================================
# Structured Router Model
# =========================================================

class RouterDecision(BaseModel):
    agent: Optional[str]
    reason: str


# =========================================================
# Reasoning Node (LLM Router)
# =========================================================

async def reasoning_node(state: SupervisorState) -> SupervisorState:
    messages = state["messages"]

    last_user_input = messages[-1].content.strip()

    history_text = "\n".join(
        m.content for m in messages[:-1] if isinstance(m, (HumanMessage, AIMessage))
    )

    system_prompt = f"""
You are a strict cybersecurity supervisor router.

Your job is to select EXACTLY ONE best agent.

You MUST follow these routing rules in priority order:

HARD RULES (strict priority):

1. If the user message contains a GitHub repository URL → dependency
2. If user asks to scan repository → dependency
3. If user provides package@version → vulnerability
4. If user provides CVE-XXXX-XXXX → advisory
5. If user provides GHSA-XXXX-XXXX-XXXX → advisory

Ignore history if a HARD RULE matches.

If none match → agent = direct_answer

SOFT RULES:

- If the user is asking about dependency files (package.json, requirements.txt, pom.xml) → agent = "dependency"
- If the user wants full security report → agent = "reporting"
- If user refers to previous session summary → agent = "session"

History Usage:

- ONLY use conversation history if the current message is ambiguous.
- If the current message clearly matches a HARD RULE, ignore history.

If no rule matches, return agent = null.

Available agents:
{", ".join(AGENT_REGISTRY.keys())}

Return structured output only.
"""

    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        temperature=0
    )

    structured_llm = llm.with_structured_output(RouterDecision)

    decision = await structured_llm.ainvoke([
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": f"History:\n{history_text}\n\nUser:\n{last_user_input}"
        }
    ])

    logger.info("Router decision: %s", decision.model_dump())

    return {"selected_agent": decision.agent}

async def resolve_tools(scope: str):
    recon_tools, vuln_tools = await get_mcp_tools()
    all_tools = await get_all_mcp_tools()

    scope_map = {
        "recon": recon_tools,
        "vuln": vuln_tools,
        "all": all_tools,
    }

    return scope_map.get(scope, all_tools)


# =========================================================
# Agent Executor Node (Dynamic Dispatch)
# =========================================================

async def agent_executor_node(state: SupervisorState) -> SupervisorState:
    # Ensure agent_name is always a string (fallback to empty string)
    agent_name = state.get("selected_agent") or ""

    handler = AGENT_REGISTRY.get(agent_name)
    scope = AGENT_TOOL_SCOPE.get(agent_name, "all")

    if not handler:
        return {
            "output": "",
            "tool_calls": [],
        }

    tools = await resolve_tools(scope)

    # Support both async handlers (coroutine functions) and sync handlers.
    result = handler(state["messages"], tools)
    if inspect.isawaitable(result):
        result = await result

    # Normalize result to a dict-like object with expected keys.
    if not isinstance(result, dict):
        # If a handler returns a plain string or other scalar, treat it as output.
        result = {"output": str(result), "tool_calls": []}

    output = result.get("output", "")
    # Coerce output to string (could be list/other from buggy handlers)
    if not isinstance(output, str):
        output = str(output)

    tool_calls = result.get("tool_calls", []) or []
    if not isinstance(tool_calls, list):
        tool_calls = [tool_calls]

    artifact = result.get("artifact", {}) or {}
    if not isinstance(artifact, dict):
        artifact = {"value": artifact}

    return {
        "output": output,
        "tool_calls": tool_calls,
        "artifact": artifact,
        "selected_agent": str(agent_name),
    }


# =========================================================
# Direct Answer Node
# =========================================================

async def direct_answer_node(state: SupervisorState) -> SupervisorState:
    return {
        "output": "I could not determine the correct agent to handle this request.",
        "tool_calls": [],
    }


# =========================================================
# Finalize Node
# =========================================================

async def finalize_node(state: SupervisorState) -> SupervisorState:
    output = state.get("output", "").strip()

    if not output:
        output = "Unable to process request."

    return {
        "output": output,
        "messages": [AIMessage(content=output)],
    }


# =========================================================
# Graph Builder (Fully Dynamic)
# =========================================================

def build_supervisor_graph(checkpointer=None):
    graph = StateGraph(SupervisorState)

    graph.add_node("reasoning", reasoning_node)
    graph.add_node("agent_executor", agent_executor_node)
    graph.add_node("direct_answer", direct_answer_node)

    graph.add_edge(START, "reasoning")

    graph.add_conditional_edges(
        "reasoning",
        lambda state: "agent_executor"
        if state.get("selected_agent")
        else "direct_answer"
    )

    graph.add_node("finalize", finalize_node)
    graph.add_edge("agent_executor", "finalize")
    graph.add_edge("direct_answer", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile(checkpointer=checkpointer)


# =========================================================
# Entry Function (UNCHANGED LOGIC)
# =========================================================

async def run_supervisor(user_message: str, session_id: str, graph):
    session_store = RedisSessionStore()

    history = session_store.get_session_history(session_id)

    messages = [
        HumanMessage(content=m["content"]) if m["type"] == "human"
        else AIMessage(content=m["content"])
        for m in history
    ]

    messages.append(HumanMessage(content=user_message))

    final = await graph.ainvoke(
        {
            "messages": messages,
            "session_id": session_id,
        },
        {"configurable": {"thread_id": session_id}},
    )

    updated_messages = final.get("messages", messages)

    history_data = [
        {"type": "human" if isinstance(m, HumanMessage) else "ai", "content": m.content}
        for m in updated_messages
    ]

    session_store.save_session_history(session_id, history_data)

    # Save artifacts for the individual turn
    artifact = final.get("artifact") or {}
    if artifact:
        session_store.append_session_artifact(session_id, {
            "intent": artifact.get("intent") or agent_used,
            "tool_calls": final.get("tool_calls", []),
            "timestamp": int(time.time()),
        })

    # Coerce selected_agent to a safe string (empty string if None). This
    # prevents None from being returned to the API which expects a string.
    agent_val = final.get("selected_agent")
    if agent_val is None:
        agent_used = ""
    elif isinstance(agent_val, str):
        agent_used = agent_val
    else:
        # Fall back to a stable string representation for unexpected types
        agent_used = str(agent_val)

    return {
        "output": final.get("output", ""),
        "agent_used": agent_used,
        "tool_calls": final.get("tool_calls", []),
    }