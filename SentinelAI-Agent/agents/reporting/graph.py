import sys
import os
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
You are a security reporting assistant.

Your job:
- Analyze vulnerability findings
- Calculate risk using tools
- Produce an executive security summary

Always use tools when CVE data is provided.
""")

SUMMARY_PROMPT = SystemMessage(content="""
Generate a final executive security report.

Include:
- Overall risk level
- Number of critical/high issues
- Clear action recommendation
""")

def get_mcp_config():
    server_script = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "mcp_server/server.py")
    )
    return {
        "reporting": {
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
        return {"execution_brief": f"Reporting task: {user_text}"}

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
        summary = await llm.ainvoke([SUMMARY_PROMPT] + state["messages"])
        text = summary.content if isinstance(summary.content, str) else str(summary.content)
        return {"messages": [AIMessage(content=text)], "final_output": text}

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