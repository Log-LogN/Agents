"""
GitHub Agent — LangGraph StateGraph
=====================================
Connects to the GitHub MCP Server via stdio subprocess,
loads tools into LangChain format, and runs a ReAct-style
agent loop using OpenAI GPT-4o.

Flow:
    user message → reasoning node → agent node (LLM decides tools once)
    → optional tool node (single pass) → summarize node → final answer
"""

import sys
import os
import asyncio
import time
import ast
from typing import Annotated, TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from shared.config import settings
from shared.github_client import GitHubClient, GitHubAPIError

# ── Agent state ─────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    execution_brief: str
    final_output: str


# ── System prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = SystemMessage(content=(
    "You are an expert GitHub assistant. You have access to tools that let you "
    "inspect GitHub repositories, read files, list issues and pull requests, and "
    "search code. Use them as needed to answer the user's question accurately. "
    "When showing code or file contents, always use markdown code blocks. "
    "Be concise but complete in your answers."
))

SUMMARY_SYSTEM_PROMPT = SystemMessage(content=(
    "You are finalizing a GitHub agent run. Summarize the completed tool-assisted analysis "
    "into a clear final answer for the user. Include concrete findings and next actions when useful. "
    "Do not mention internal graph nodes."
))


# ── MCP server config ─────────────────────────────────────────────────────

def get_mcp_server_config() -> dict:
    """Return the MCP server connection config for MultiServerMCPClient."""
    server_script = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "mcp_server/server.py")
    )
    return {
        "github": {
            # Use the same Python interpreter that's running this process
            "command": sys.executable,
            "args": [server_script],
            "transport": "stdio",
            "env": {
                **os.environ,
                "GITHUB_TOKEN": settings.GITHUB_TOKEN,
            },
        }
    }


# ── Graph builder ─────────────────────────────────────────────────────────

async def build_graph():
    """
    Build and compile the LangGraph StateGraph with MCP tools bound.
    Returns: (compiled_graph, mcp_client) — caller must close client when done.
    """
    mcp_client = MultiServerMCPClient(get_mcp_server_config())
    tools = await mcp_client.get_tools()

    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )
    llm_with_tools = llm.bind_tools(tools)

    # ── Nodes ──────────────────────────────────────────────────────────────

    async def reasoning_node(state: AgentState) -> AgentState:
        """
        First node for every run.
        Builds a compact execution brief that guides tool selection and answer style.
        """
        user_text = ""
        for msg in reversed(state["messages"]):
            if isinstance(getattr(msg, "content", None), str) and msg.content:
                user_text = msg.content.strip()
                break
        brief = (
            "Plan: identify repo/owner context, gather only required GitHub facts via tools, "
            "then provide a concise, evidence-backed answer. "
            f"User request: {user_text[:400]}"
        )
        return {"execution_brief": brief}

    async def agent_node(state: AgentState) -> AgentState:
        """LLM decides whether to call a tool or return final answer."""
        guidance = SystemMessage(content=f"Execution brief: {state.get('execution_brief', '')}")
        messages = [SYSTEM_PROMPT, guidance] + state["messages"]
        response = await llm_with_tools.ainvoke(messages)
        return {"messages": [response]}

    def should_continue(state: AgentState) -> str:
        """Route: tool_calls present → tools node, else → summarize."""
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        return "summarize"

    async def summarize_node(state: AgentState) -> AgentState:
        """
        Final node to produce the user-facing summary response.
        Keeps tool-loop reasoning separate from final presentation quality.
        """
        messages = [SUMMARY_SYSTEM_PROMPT] + state["messages"]
        summary = await llm.ainvoke(messages)
        summary_text = summary.content if isinstance(summary.content, str) else str(summary.content)
        return {
            "messages": [AIMessage(content=summary_text)],
            "final_output": summary_text,
        }

    # ── Graph assembly ─────────────────────────────────────────────────────

    tool_node = ToolNode(tools)

    graph = StateGraph(AgentState)
    graph.add_node("reasoning", reasoning_node)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("summarize", summarize_node)

    graph.add_edge(START, "reasoning")
    graph.add_edge("reasoning", "agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", "summarize": "summarize"})
    graph.add_edge("tools", "summarize")
    graph.add_edge("summarize", END)

    compiled = graph.compile()
    return compiled, mcp_client


# ── Public interface ─────────────────────────────────────────────────────

async def run_github_agent(message: str) -> dict:
    """
    Run the GitHub agent for a single message.

    Returns:
        {
            "output": str,          # final answer
            "tool_calls": list      # log of all tool calls made
        }
    """
    graph, mcp_client = await build_graph()

    try:
        initial_state = {"messages": [HumanMessage(content=message)]}
        final_state = await graph.ainvoke(initial_state)

        output = str(final_state.get("final_output", "") or "")
        if not output:
            for msg in reversed(final_state["messages"]):
                if hasattr(msg, "content") and isinstance(msg.content, str) and msg.content:
                    output = msg.content
                    break

        # Collect tool call logs
        tool_calls = []
        messages = final_state["messages"]
        for i, msg in enumerate(messages):
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    # Find the corresponding tool result
                    tool_output = ""
                    if i + 1 < len(messages):
                        next_msg = messages[i + 1]
                        if hasattr(next_msg, "content"):
                            tool_output = str(next_msg.content)[:500]
                    tool_calls.append({
                        "tool_name": tc["name"],
                        "tool_input": tc["args"],
                        "tool_output": tool_output,
                    })

        return {"output": output, "tool_calls": tool_calls}

    finally:
        # MultiServerMCPClient is not an async context manager anymore.
        # If the client library provides an async close method, call it;
        # otherwise, do nothing — sessions are created per operation and
        # cleaned up by the adapter.
        aclose = getattr(mcp_client, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception:
                # Best-effort cleanup; ignore errors during shutdown
                pass


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


async def run_github_agent_stream(message: str):
    """
    Stream agent execution events using LangGraph astream().

    Yields event dicts:
        {"event": str, "data": dict, "timestamp": str}
    """
    graph, mcp_client = await build_graph()
    seen_tool_calls: set[str] = set()
    tool_call_by_id: dict[str, dict] = {}
    gh_client = GitHubClient()

    yield {"event": "agent_started", "data": {"message": message}, "timestamp": _now_iso()}

    try:
        initial_state = {"messages": [HumanMessage(content=message)]}
        final_state = None

        async for state in graph.astream(initial_state, stream_mode="values"):
            final_state = state
            messages = state.get("messages", [])
            if not messages:
                continue

            last = messages[-1]
            tool_calls = getattr(last, "tool_calls", None) or []
            if tool_calls:
                for tc in tool_calls:
                    tc_id = tc.get("id") or f"{tc.get('name')}:{tc.get('args')}"
                    if tc_id in seen_tool_calls:
                        continue
                    seen_tool_calls.add(tc_id)
                    tool_call_by_id[tc_id] = tc
                    yield {
                        "event": "tool_call_started",
                        "data": {
                            "tool_name": tc.get("name"),
                            "tool_input": tc.get("args", {}),
                            "tool_call_id": tc.get("id"),
                        },
                        "timestamp": _now_iso(),
                    }
                continue

            if getattr(last, "type", "") == "tool":
                tool_call_id = getattr(last, "tool_call_id", None)
                yield {
                    "event": "tool_call_completed",
                    "data": {
                        "tool_call_id": tool_call_id,
                        "tool_output": str(getattr(last, "content", ""))[:2000],
                    },
                    "timestamp": _now_iso(),
                }

                started_tc = tool_call_by_id.get(tool_call_id or "")
                if started_tc and started_tc.get("name") == "tool_trigger_workflow_dispatch":
                    tc_args = started_tc.get("args", {})
                    tool_output_raw = getattr(last, "content", "")

                    dispatch_output = {}
                    if isinstance(tool_output_raw, str):
                        try:
                            dispatch_output = ast.literal_eval(tool_output_raw)
                        except (ValueError, SyntaxError):
                            dispatch_output = {}
                    elif isinstance(tool_output_raw, dict):
                        dispatch_output = tool_output_raw

                    data_obj = dispatch_output.get("data", {}) if isinstance(dispatch_output, dict) else {}
                    if data_obj.get("approval_required"):
                        continue

                    owner = tc_args.get("owner")
                    repo = tc_args.get("repo")
                    workflow_id = tc_args.get("workflow_id")
                    ref = tc_args.get("ref")
                    if owner and repo and workflow_id:
                        async for workflow_evt in _poll_workflow_status_events(
                            gh_client=gh_client,
                            owner=owner,
                            repo=repo,
                            workflow_id=str(workflow_id),
                            ref=ref,
                        ):
                            yield workflow_evt
                continue

            # Avoid streaming duplicate partial chunks from final summarize node.
            if "final_output" in state:
                continue

            if isinstance(getattr(last, "content", None), str) and last.content:
                yield {
                    "event": "llm_partial",
                    "data": {"text": last.content},
                    "timestamp": _now_iso(),
                }

        output = str(final_state.get("final_output", "") or "") if final_state else ""
        if final_state:
            if not output:
                for msg in reversed(final_state.get("messages", [])):
                    if hasattr(msg, "content") and isinstance(msg.content, str) and msg.content:
                        output = msg.content
                        break

        yield {"event": "llm_final", "data": {"output": output}, "timestamp": _now_iso()}

    except Exception as exc:
        yield {"event": "error", "data": {"message": str(exc)}, "timestamp": _now_iso()}
    finally:
        aclose = getattr(mcp_client, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception:
                pass


async def _poll_workflow_status_events(
    gh_client: GitHubClient,
    owner: str,
    repo: str,
    workflow_id: str,
    ref: str | None,
):
    yield {
        "event": "tool_call_started",
        "data": {
            "tool_name": "workflow_status_poll",
            "tool_input": {
                "owner": owner,
                "repo": repo,
                "workflow_id": workflow_id,
                "ref": ref,
            },
        },
        "timestamp": _now_iso(),
    }

    last_signature = None
    max_checks = 24

    for _ in range(max_checks):
        try:
            def _fetch_runs():
                params = {"per_page": 1, "page": 1}
                if ref:
                    params["branch"] = ref
                return gh_client.request(
                    "GET",
                    f"/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs",
                    params=params,
                )

            data = await asyncio.to_thread(_fetch_runs)
            runs = data.get("workflow_runs", []) if isinstance(data, dict) else []
            if not runs:
                await asyncio.sleep(5)
                continue

            run = runs[0]
            signature = (run.get("id"), run.get("status"), run.get("conclusion"))
            if signature != last_signature:
                last_signature = signature
                payload = {
                    "tool_name": "workflow_status_poll",
                    "run_id": run.get("id"),
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                    "url": run.get("html_url"),
                    "head_branch": run.get("head_branch"),
                    "event": run.get("event"),
                }
                yield {
                    "event": "tool_call_completed",
                    "data": payload,
                    "timestamp": _now_iso(),
                }

            if run.get("status") == "completed":
                return

            await asyncio.sleep(5)

        except GitHubAPIError as exc:
            yield {
                "event": "error",
                "data": {"message": f"workflow poll failed: {exc}"},
                "timestamp": _now_iso(),
            }
            return


# ── CLI test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    async def main():
        query = "What are the top 3 open issues in anthropics/anthropic-sdk-python?"
        print(f"Query: {query}\n")
        result = await run_github_agent(query)
        print(f"Answer:\n{result['output']}")
        print(f"\nTool calls made: {len(result['tool_calls'])}")
        for tc in result["tool_calls"]:
            print(f"  - {tc['tool_name']}({tc['tool_input']})")

    asyncio.run(main())
