"""Terminal chat agent using OpenAI + strict MCP tool discovery."""

from __future__ import annotations

import asyncio
import os

from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

load_dotenv()

SYSTEM_PROMPT = """
You are a sales analytics assistant.
Use MCP tools to answer data questions accurately.

Tool usage rules:
- Always execute tools before answering if the user asks for numbers, rankings, reports, comparisons, or details.
- Default sequence for ranking/report requests:
  1) top_products({"n": requested_n_or_5, "group_by": user_requested_dimension})
  2) generate_report({"top_products_data": <top_products_output>, "query": <user_query>})
- For exclusion or "remove X" follow-ups, call revenue_after_exclusion({"exclude_name": "...", "n": 5, "group_by": "PRODUCTLINE"}).
- For ambiguous ranking questions, first ask whether grouping should be PRODUCTLINE or PRODUCTCODE.
- For detailed row-level examples, call product_details({"limit": requested_n_or_5}).
- If user asks to save output, call save_report({"report": <final_text>, "output_path": <path>}).
- Never invent sales values without a tool result.
- For follow-up questions, use prior conversation context, but recompute key numbers via tools.

Response style:
- Keep responses concise and business-friendly.
- Use sections: Summary, Key numbers, Next action.
- Show currency with commas and 2 decimals.
"""

MAX_HISTORY_MESSAGES = 16
CLARIFY_PROMPT = (
    "Do you want ranking by PRODUCTLINE or PRODUCTCODE? "
    "Reply with one of these."
)


def _wants_ranking(text: str) -> bool:
    lowered = text.lower()
    keywords = ("top", "highest", "best", "rank", "compare", "high sales")
    return any(word in lowered for word in keywords)


def _mentions_dimension(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in ("productline", "product line", "productcode", "product code")
    )


def _resolve_dimension(text: str) -> str | None:
    lowered = text.lower()
    if "productline" in lowered or "product line" in lowered:
        return "PRODUCTLINE"
    if "productcode" in lowered or "product code" in lowered:
        return "PRODUCTCODE"
    return None


async def run_query(messages: list[tuple[str, str]]) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    mcp_client = MultiServerMCPClient(
        {
            "sales_server": {
                "url": "http://127.0.0.1:8000/mcp",
                "transport": "streamable_http",
            }
        }
    )

    tools = await mcp_client.get_tools()
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    agent = create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)
    result = await agent.ainvoke({"messages": messages})

    output_messages = result.get("messages", [])
    if not output_messages:
        return "No response from agent."
    return str(output_messages[-1].content)


def run_terminal_chat() -> None:
    print("Strict MCP terminal chat. Type 'exit' to quit.")
    history: list[tuple[str, str]] = []
    pending_ambiguous_query: str | None = None
    while True:
        user_input = input("\nYou: ").strip()
        if user_input.lower() in {"exit", "quit"}:
            break
        if not user_input:
            continue

        try:
            if pending_ambiguous_query is not None:
                dimension = _resolve_dimension(user_input)
                if dimension is None:
                    print(f"Agent: {CLARIFY_PROMPT}")
                    continue
                user_input = (
                    f"{pending_ambiguous_query}\n"
                    f"User clarification: group results by {dimension}."
                )
                pending_ambiguous_query = None
            elif _wants_ranking(user_input) and not _mentions_dimension(user_input):
                history.append(("user", user_input))
                history.append(("assistant", CLARIFY_PROMPT))
                pending_ambiguous_query = user_input
                print(f"Agent: {CLARIFY_PROMPT}")
                continue

            history.append(("user", user_input))
            if len(history) > MAX_HISTORY_MESSAGES:
                history = history[-MAX_HISTORY_MESSAGES:]
            answer = asyncio.run(run_query(history))
            history.append(("assistant", answer))
            if len(history) > MAX_HISTORY_MESSAGES:
                history = history[-MAX_HISTORY_MESSAGES:]
            print(f"Agent: {answer}")
        except Exception as exc:
            print(f"Agent error: {type(exc).__name__}: {exc}")
            print("Tip: ensure MCP server is running at http://127.0.0.1:8000/mcp")


if __name__ == "__main__":
    run_terminal_chat()
