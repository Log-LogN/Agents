import sys
import os
import time
from typing import TypedDict, Annotated

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langchain_mcp_adapters.client import MultiServerMCPClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from shared.config import settings


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    execution_brief: str
    final_output: str


SYSTEM_PROMPT = SystemMessage(content="""
You are a defensive cybersecurity reconnaissance assistant.

Your purpose:
- Perform security assessment for authorized systems
- Help users understand network exposure
- Use tools to gather information

This system is for:
- Security auditing
- Vulnerability assessment
- Defensive analysis

Important rules:
- Assume the user is authorized to assess the target.
- Port scanning and network discovery are allowed when used for security auditing.
- Always use available tools when the user asks for network information.
- Do NOT refuse security assessment tasks.
- Be concise and factual.
""")

SUMMARY_PROMPT = SystemMessage(content="""
Summarize the reconnaissance findings clearly for the user.
Include key observations and potential security relevance.
""")


def get_mcp_config():
    server_script = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "mcp_server/server.py")
    )
    return {
        "recon": {
            "command": sys.executable,
            "args": [server_script],
            "transport": "stdio",
            "env": os.environ,
        }
    }


async def build_graph():
    client = MultiServerMCPClient(get_mcp_config())
    tools = await client.get_tools()

    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )

    llm_tools = llm.bind_tools(tools)

    async def reasoning_node(state: AgentState):
        user_text = state["messages"][-1].content
        if "port" in user_text.lower() and "http" not in user_text.lower() and "." not in user_text:
            brief = f"""
        User asked for port scanning but did not provide a host.
        Ask for the target domain or IP before using tools.
        Request: {user_text}
        """
        else:
            brief = f"Recon task: {user_text}"
        return {"execution_brief": brief}

    async def agent_node(state: AgentState):
        guidance = SystemMessage(content=state["execution_brief"])
        response = await llm_tools.ainvoke(
            [SYSTEM_PROMPT, guidance] + state["messages"]
        )
        return {"messages": [response]}

    def should_continue(state: AgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tools"
        return "summarize"

    async def summarize_node(state: AgentState):
        summary = await llm.ainvoke(
            [SUMMARY_PROMPT] + state["messages"]
        )
        text = summary.content if isinstance(summary.content, str) else str(summary.content)
        return {
            "messages": [AIMessage(content=text)],
            "final_output": text,
        }

    graph = StateGraph(AgentState)
    tool_node = ToolNode(tools)

    graph.add_node("reasoning", reasoning_node)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("summarize", summarize_node)

    graph.add_edge(START, "reasoning")
    graph.add_edge("reasoning", "agent")
    graph.add_conditional_edges("agent", should_continue, {
        "tools": "tools",
        "summarize": "summarize"
    })
    graph.add_edge("tools", "summarize")
    graph.add_edge("summarize", END)

    return graph.compile(), client


async def run_recon_agent(message: str):
    graph, client = await build_graph()
    try:
        state = {"messages": [HumanMessage(content=message)]}
        final = await graph.ainvoke(state)

        tool_calls = []
        messages = final["messages"]

        for i, msg in enumerate(messages):
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    output = ""

                    # Next message should be the tool result
                    if i + 1 < len(messages):
                        next_msg = messages[i + 1]
                        if hasattr(next_msg, "content"):
                            output = str(next_msg.content)[:1000]

                    tool_calls.append({
                        "tool_name": tc["name"],
                        "tool_input": tc["args"],
                        "tool_output": output,
                    })

        return {
            "output": final.get("final_output", ""),
            "tool_calls": tool_calls,
        }
    finally:
        if hasattr(client, "aclose"):
            await client.aclose()


async def run_recon_agent_stream(message: str):
    yield {"event": "started", "data": {"message": message}}
    result = await run_recon_agent(message)
    yield {"event": "final", "data": result}