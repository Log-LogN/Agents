"""
supervisor/graph.py
Pure LangGraph core for FinReport supervisor orchestration.
"""

import sys
import os
import asyncio
from typing import Annotated
from typing_extensions import TypedDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.messages import SystemMessage, AIMessage, ToolMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_mcp_adapters.client import MultiServerMCPClient

nest_asyncio.apply()
load_dotenv()

SPECIALIST_SERVERS = {
    "gl": {"transport": "streamable_http", "url": "http://127.0.0.1:8001/mcp"},
    "pl": {"transport": "streamable_http", "url": "http://127.0.0.1:8002/mcp"},
    "bs": {"transport": "streamable_http", "url": "http://127.0.0.1:8003/mcp"},
    "cf": {"transport": "streamable_http", "url": "http://127.0.0.1:8004/mcp"},
    "budget": {"transport": "streamable_http", "url": "http://127.0.0.1:8005/mcp"},
    "kpi": {"transport": "streamable_http", "url": "http://127.0.0.1:8006/mcp"},
    "report": {"transport": "streamable_http", "url": "http://127.0.0.1:8007/mcp"},
}

GL_PROMPT = """You are the GL & Transaction Specialist for FinReport AI.
Handle: posting journal entries, account balances, transaction listings, chart of accounts,
trial balance generation, account reconciliation, department expenses, revenue by category.
- Always validate account codes before posting.
- Show account name + code in responses.
- For reconciliation, clearly state the discrepancy amount if found.
- Format amounts as INR X,XX,XXX.XX"""

PL_PROMPT = """You are the Profit & Loss Specialist for FinReport AI.
Handle: income statements, revenue breakdown, COGS analysis, operating expenses,
gross margin calculation, EBITDA, period comparisons, revenue growth rates.
- Always present a full P&L waterfall: Revenue -> Gross Profit -> EBITDA -> Net Income.
- Show all margin percentages alongside absolute amounts.
- Highlight significant period-over-period changes (>5%).
- Format amounts as INR X,XX,XXX.XX with % margins beside each line."""

BS_PROMPT = """You are the Balance Sheet Specialist for FinReport AI.
Handle: full balance sheet, current assets, current liabilities, long-term items,
current ratio, working capital, debt-to-equity, balance check.
- Always verify Assets = Liabilities + Equity.
- Show liquidity ratios alongside the balance sheet.
- Flag any concerning ratios vs benchmarks.
- Format amounts as INR X,XX,XXX.XX"""

CF_PROMPT = """You are the Cash Flow Specialist for FinReport AI.
Handle: cash flow statement, operating cash flow, live cash position across all accounts,
cash runway, AR aging, AP aging, cash transaction recording, cash alerts.
- Always show total cash across all accounts, not just one.
- For runway: show days and months remaining.
- Proactively flag AR that is 60+ days overdue.
- For cash below threshold, recommend sending an alert."""

BUDGET_PROMPT = """You are the Budget & Variance Specialist for FinReport AI.
Handle: setting budgets, retrieving budgets, variance reports, top overspend departments,
budget utilisation, forecast vs actual, forecast updates, variance alerts.
- Always show both amount variance and percent variance.
- Rank departments by absolute overspend in variance reports.
- Proactively suggest alerts for significant overruns (>10%)."""

KPI_PROMPT = """You are the KPI & Analytics Specialist for FinReport AI.
Handle: KPI dashboards, profitability ratios, liquidity ratios, efficiency ratios,
leverage ratios, KPI trends, benchmark comparisons, weekly KPI digests.
- Always show benchmark comparison alongside each KPI.
- For trend analysis, show clear direction.
- Present ratios in a clear table format."""

REPORT_PROMPT = """You are the Report Delivery Specialist for FinReport AI.
Handle: generating report summaries, emailing reports, sending board packs,
report history, scheduling recurring reports, executive alerts, logging deliveries.
- Email tools now require a user approval step before send.
- If a send tool returns requires_approval=true, explain that approval is pending and do NOT claim the email is sent.
- Confirm email sent with recipient details only after the approved send call succeeds.
- For board packs: confirm all three sections (P&L, BS, CF) are included.
- Log every report delivery for compliance.
- Show report history with date, type, recipients, and status."""

GENERAL_PROMPT = """You are the General Finance fallback agent for FinReport AI.

Strict style:
- Keep answers short (2-4 lines max).
- Give direct answer first.
- Do not produce long explanations.

If the question is not financial:
- Reply exactly with: "I cannot process your request. Please rephrase your request."
"""

GENERAL_GUIDANCE_REPLY = "I cannot process your request. Please rephrase your request."

ROUTE_TOOL_BY_NODE = {
    "gl_agent": "transfer_to_gl",
    "pl_agent": "transfer_to_pl",
    "bs_agent": "transfer_to_bs",
    "cf_agent": "transfer_to_cf",
    "budget_agent": "transfer_to_budget",
    "kpi_agent": "transfer_to_kpi",
    "report_agent": "transfer_to_report",
    "general_agent": "transfer_to_general",
}

def _make_agent(llm, tools, prompt):
    return create_agent(model=llm, tools=tools, system_prompt=prompt)


class FinState(TypedDict):
    messages: Annotated[list, add_messages]


_GRAPH_CACHE = None
_GRAPH_LOCK: asyncio.Lock | None = None


def _pick_route_node(text: str) -> str:
    """Route only on high-confidence intent; otherwise fallback to default agent."""
    q = (text or "").lower()
    if not q.strip():
        return "general_agent"

    route_rules = {
        "gl_agent": {
            "strong": ["chart of accounts", "trial balance", "post journal", "journal entry"],
            "soft":   ["journal", "ledger", "gl", "reconcile", "debit", "credit", "transaction", "account"],
        },
        "pl_agent": {
            "strong": ["profit and loss", "income statement"],
            "soft":   ["p&l", "ebitda", "cogs", "gross margin", "operating expense", "net income", "revenue growth"],
        },
        "bs_agent": {
            "strong": ["balance sheet", "debt-to-equity", "working capital"],
            "soft":   ["assets", "liabilities", "equity", "current ratio", "accounts receivable", "accounts payable"],
        },
        "cf_agent": {
            "strong": ["cash flow", "cash position", "cash runway"],
            "soft":   ["runway", "burn rate", "operating cash", "ar aging", "ap aging", "liquidity", "cash alert"],
        },
        "budget_agent": {
            "strong": ["budget variance", "actual vs plan", "over budget", "top 5 departments"],
            "soft":   ["budget", "variance", "forecast", "overspend", "utilisation", "utilization", "over budget", "department spend"],
        },
        "kpi_agent": {
            "strong": ["kpi dashboard", "benchmark comparison"],
            "soft":   ["kpi", "roe", "roa", "benchmark", "ratio", "trend", "analytics", "leverage", "profitability"],
        },
        "report_agent": {
            "strong": ["board pack", "send report", "schedule report", "send to cfo", "send to all cfo", "email cfo"],
            "soft":   ["report", "send email", "distribute", "executive summary", "audit trail", "send", "email", "cfo", "recipients"],
        },
    }

    best_node = "general_agent"
    best_score = 0
    for node, rules in route_rules.items():
        if any(k in q for k in rules["strong"]):
            return node
        soft_hits = sum(1 for k in rules["soft"] if k in q)
        if soft_hits > best_score:
            best_score = soft_hits
            best_node = node

    # Require at least 2 soft keyword hits for specialist routing.
    if best_score >= 2:
        return best_node
    return "general_agent"


async def build_graph():
    global _GRAPH_CACHE, _GRAPH_LOCK
    if _GRAPH_CACHE is not None:
        return _GRAPH_CACHE

    if _GRAPH_LOCK is None:
        _GRAPH_LOCK = asyncio.Lock()

    async with _GRAPH_LOCK:
        if _GRAPH_CACHE is not None:
            return _GRAPH_CACHE

        llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=0)
        general_llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            temperature=0,
            max_tokens=180,
        )
        client = MultiServerMCPClient(SPECIALIST_SERVERS)
        all_tools = await client.get_tools()

        gl_tools = [t for t in all_tools if any(k in t.name for k in ["transaction", "account", "gl", "trial", "reconcile", "revenue", "department"])]
        pl_tools = [t for t in all_tools if any(k in t.name for k in ["income", "revenue_summary", "cogs", "operating_expenses", "gross_margin", "ebitda", "period", "growth"])]
        bs_tools = [t for t in all_tools if any(k in t.name for k in ["balance_sheet", "current_assets", "current_liabilities", "long_term", "current_ratio", "working_capital", "debt_to_equity", "check_balance"])]
        cf_tools = [t for t in all_tools if any(k in t.name for k in ["cash_flow", "operating_cash", "cash_position", "runway", "receivable_aging", "payable_aging", "record_cash", "cash_alert"])]
        budget_tools = [t for t in all_tools if any(k in t.name for k in ["budget", "variance", "overspend", "utilisation", "forecast"])]
        kpi_tools = [t for t in all_tools if any(k in t.name for k in ["kpi", "profitability", "liquidity", "efficiency", "leverage", "kpi_trend", "benchmark", "digest"])]
        report_tools = [t for t in all_tools if any(k in t.name for k in ["report", "board_pack", "schedule_report", "executive_alert", "log_report", "recipients"])]

        if not gl_tools:
            gl_tools = all_tools
        if not pl_tools:
            pl_tools = all_tools
        if not bs_tools:
            bs_tools = all_tools
        if not cf_tools:
            cf_tools = all_tools
        if not budget_tools:
            budget_tools = all_tools
        if not kpi_tools:
            kpi_tools = all_tools
        if not report_tools:
            report_tools = all_tools

        gl_agent = _make_agent(llm, gl_tools, GL_PROMPT)
        pl_agent = _make_agent(llm, pl_tools, PL_PROMPT)
        bs_agent = _make_agent(llm, bs_tools, BS_PROMPT)
        cf_agent = _make_agent(llm, cf_tools, CF_PROMPT)
        budget_agent = _make_agent(llm, budget_tools, BUDGET_PROMPT)
        kpi_agent = _make_agent(llm, kpi_tools, KPI_PROMPT)
        report_agent = _make_agent(llm, report_tools, REPORT_PROMPT)

        async def supervisor_agent(state: FinState):
            msgs = state.get("messages", [])
            last_human = ""
            for m in reversed(msgs):
                if isinstance(m, HumanMessage):
                    last_human = str(getattr(m, "content", ""))
                    break
            node = _pick_route_node(last_human)
            return {
                "messages": [
                    AIMessage(
                        content=f"ROUTE::{node}",
                    )
                ]
            }

        async def general_agent(state: FinState):
            msgs = state.get("messages", [])
            last_human = ""
            for m in reversed(msgs):
                if isinstance(m, HumanMessage):
                    last_human = str(getattr(m, "content", "")).strip()
                    break
            if len(last_human) < 6:
                return {"messages": [AIMessage(content=GENERAL_GUIDANCE_REPLY)]}

            reply = await general_llm.ainvoke([SystemMessage(content=GENERAL_PROMPT), *msgs])
            if isinstance(reply, AIMessage) and str(reply.content).strip():
                return {"messages": [reply]}
            return {"messages": [AIMessage(content=GENERAL_GUIDANCE_REPLY)]}

        def _route(state: FinState) -> str:
            msgs = state.get("messages", [])
            for msg in reversed(msgs):
                if not isinstance(msg, AIMessage):
                    continue
                text = str(getattr(msg, "content", "") or "")
                if text.startswith("ROUTE::"):
                    route_node = text.replace("ROUTE::", "", 1).strip()
                    if route_node in ROUTE_TOOL_BY_NODE:
                        return route_node
                calls = getattr(msg, "tool_calls", None) or []
                for tc in calls:
                    name = tc.get("name", "")
                    if "gl" in name:
                        return "gl_agent"
                    if "pl" in name:
                        return "pl_agent"
                    if "_bs" in name or "balance" in name:
                        return "bs_agent"
                    if "_cf" in name or "cash" in name:
                        return "cf_agent"
                    if "budget" in name:
                        return "budget_agent"
                    if "kpi" in name:
                        return "kpi_agent"
                    if "report" in name:
                        return "report_agent"
                    if "general" in name:
                        return "general_agent"
            return "general_agent"

        graph = StateGraph(FinState)
        graph.add_node("supervisor", supervisor_agent)
        graph.add_node("gl_agent", gl_agent)
        graph.add_node("pl_agent", pl_agent)
        graph.add_node("bs_agent", bs_agent)
        graph.add_node("cf_agent", cf_agent)
        graph.add_node("budget_agent", budget_agent)
        graph.add_node("kpi_agent", kpi_agent)
        graph.add_node("report_agent", report_agent)
        graph.add_node("general_agent", general_agent)

        graph.add_edge(START, "supervisor")
        graph.add_conditional_edges("supervisor", _route, {
            "gl_agent": "gl_agent",
            "pl_agent": "pl_agent",
            "bs_agent": "bs_agent",
            "cf_agent": "cf_agent",
            "budget_agent": "budget_agent",
            "kpi_agent": "kpi_agent",
            "report_agent": "report_agent",
            "general_agent": "general_agent",
            END: END,
        })

        for node in [
            "gl_agent", "pl_agent", "bs_agent", "cf_agent",
            "budget_agent", "kpi_agent", "report_agent", "general_agent",
        ]:
            graph.add_edge(node, END)

        _GRAPH_CACHE = graph.compile()
        return _GRAPH_CACHE


def serialise_messages(msgs: list) -> list:
    out = []
    for m in msgs:
        if isinstance(m, HumanMessage):
            out.append({"role": "human", "content": str(m.content)})
        elif isinstance(m, AIMessage):
            out.append({"role": "ai", "content": str(m.content), "tool_calls": getattr(m, "tool_calls", []) or []})
        elif isinstance(m, ToolMessage):
            out.append({
                "role": "tool",
                "name": getattr(m, "name", ""),
                "content": str(m.content),
                "tool_call_id": getattr(m, "tool_call_id", ""),
            })
    return out


def build_trace(msgs: list) -> list:
    trace = []
    for m in msgs:
        if isinstance(m, AIMessage):
            calls = getattr(m, "tool_calls", None) or []
            for tc in calls:
                name = tc.get("name", "")
                if "transfer_to_" in name:
                    label = "Routed to " + name.replace("transfer_to_", "").replace("_", " ").title()
                else:
                    label = f"Called tool: {name}"
                trace.append({"type": "tool_call", "label": label, "tool": name})
            if m.content and not calls:
                trace.append({"type": "reply", "label": f"Final reply ({len(str(m.content))} chars)"})
        elif isinstance(m, ToolMessage):
            preview = str(m.content)[:80].replace("\n", " ")
            trace.append({"type": "tool_result", "label": f"Result: {preview}..."})
    return trace
