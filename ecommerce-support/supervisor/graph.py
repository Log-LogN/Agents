"""
supervisor/graph.py
═══════════════════
Pure LangGraph core — no MCP, no HTTP server, no entry point.

Responsibilities
────────────────
  • All agent system prompts
  • ShopState TypedDict
  • _build_graph()  — builds & compiles the LangGraph with all 6 specialist agents
  • _serialise_messages() — LangChain msg objects → JSON-safe dicts
  • _build_trace()        — routing trace builder for the UI

This module is imported by supervisor_server.py which wraps it in an MCP server.
Nothing in this file starts a server or binds to a port.
"""

import sys
import os
import asyncio
import json
import logging
import inspect as _inspect
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv
from typing import Annotated
from typing_extensions import TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.messages import (
    SystemMessage, AIMessage, ToolMessage, HumanMessage,
)
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

nest_asyncio.apply()
load_dotenv()

log = logging.getLogger(__name__)


# ── Downstream specialist MCP server URLs ─────────────────────────────────────
SPECIALIST_SERVERS = {
    "order":      {"transport": "streamable_http", "url": "http://127.0.0.1:8001/mcp"},
    "returns":    {"transport": "streamable_http", "url": "http://127.0.0.1:8002/mcp"},
    "product":    {"transport": "streamable_http", "url": "http://127.0.0.1:8003/mcp"},
    "payment":    {"transport": "streamable_http", "url": "http://127.0.0.1:8004/mcp"},
    "complaints": {"transport": "streamable_http", "url": "http://127.0.0.1:8005/mcp"},
    "loyalty":    {"transport": "streamable_http", "url": "http://127.0.0.1:8006/mcp"},
}


# ── Agent system prompts ──────────────────────────────────────────────────────
SUPERVISOR_PROMPT = """You are the ShopAI Customer Support Supervisor.
Read every customer message and route it to exactly ONE specialist. Never answer directly.

ROUTING RULES:
  ORDER AGENT       → order, track, where is, delivery, shipment, cancel order, status, shipping address
  RETURNS AGENT     → return, refund, send back, wrong item, damaged, exchange, money back, defective
  PRODUCT AGENT     → product, stock, available, price, description, size, restock, catalogue
  PAYMENT AGENT     → payment, charged, invoice, billing, duplicate charge, coupon, transaction, failed
  COMPLAINTS AGENT  → complaint, review, feedback, replace, broken, bad experience, escalate, unhappy
  LOYALTY AGENT     → points, loyalty, reward, promo code, discount, tier, voucher, membership, cashback

Default: ORDER AGENT."""

ORDER_PROMPT = """You are the Order Tracking Specialist for ShopAI.
Handle: order status, delivery tracking, estimated delivery, cancellations, address updates, order history.
- Use customer email to find orders first.
- Show tracking number and carrier proactively.
- For out-for-delivery orders mention expected arrival time.
- Send a status email when the customer seems anxious about their order."""

RETURNS_PROMPT = """You are the Returns & Refunds Specialist for ShopAI.
Handle: eligibility checks, fraud detection, initiating returns, approvals/rejections, refund processing.
- Always run eligibility + fraud check before creating a return.
- Clearly explain rejections and why.
- If fraud risk is HIGH → do not approve, explain professionally.
- Offer store credit as an alternative to bank refunds where appropriate."""

PRODUCT_PROMPT = """You are the Product & Inventory Specialist for ShopAI.
Handle: product info, stock availability, pricing, category browsing, low-stock alerts, restock dates.
- Always check real stock levels before confirming availability.
- For out-of-stock items provide restock ETA.
- Be specific about features, brand, and price.
- For searches return multiple relevant results."""

PAYMENT_PROMPT = """You are the Payment & Billing Specialist for ShopAI.
Handle: payment verification, duplicate charge detection, coupon validation, invoices, transaction history, store credit.
- Verify charges against the order total before escalating.
- Flag duplicate charges immediately and explain the refund timeline.
- Validate coupon codes with the actual order total.
- Be precise with amounts — customers are sensitive about money."""

COMPLAINTS_PROMPT = """You are the Reviews & Complaints Specialist for ShopAI.
Handle: filing complaints, checking status, replacement requests, urgent escalations, reviews.
- Acknowledge every complaint with empathy.
- Auto-escalate billing issues and product-safety complaints to 'urgent'.
- Always confirm with a timeline when a complaint is filed.
- For 1-star reviews, offer to make things right."""

LOYALTY_PROMPT = """You are the Loyalty & Promotions Specialist for ShopAI.
Handle: points balance, tier status, redemptions, promo code validation, active promotions, rewards history.
- Always show monetary value of points (1 point = ₹1).
- Tell customers how many points to the next tier.
- Validate promo codes with minimum order amounts.
- Be enthusiastic — loyalty rewards drive retention!"""


# ── Version-safe create_react_agent helper ────────────────────────────────────
MAX_SUPERVISOR_CONTEXT_MESSAGES = 8
MAX_SPECIALIST_CONTEXT_MESSAGES = 10

# Fast-path keyword router for common requests.
# If this produces a clear winner, we skip the supervisor LLM call.
FAST_ROUTE_KEYWORDS = {
    "transfer_to_order": (
        "order", "track", "tracking", "delivery", "shipment", "shipping",
        "where is", "cancel order", "address update", "status",
    ),
    "transfer_to_returns": (
        "return", "refund", "exchange", "wrong item", "damaged",
        "defective", "money back", "send back",
    ),
    "transfer_to_product": (
        "product", "stock", "available", "availability", "price",
        "restock", "catalog", "catalogue", "size",
    ),
    "transfer_to_payment": (
        "payment", "charged", "charge", "duplicate charge", "invoice",
        "billing", "coupon", "transaction", "failed payment",
    ),
    "transfer_to_complaints": (
        "complaint", "review", "feedback", "bad experience", "broken",
        "replace", "replacement", "escalate", "unhappy",
    ),
    "transfer_to_loyalty": (
        "loyalty", "points", "reward", "promo", "promo code",
        "discount", "tier", "voucher", "membership", "cashback",
    ),
}

_PROMPT_KEY = (
    "state_modifier"
    if "state_modifier" in _inspect.signature(create_react_agent).parameters
    else "prompt"
)

def _make_agent(llm, tools, prompt: str):
    """Create a ReAct agent, compatible with both old and new LangGraph versions."""
    return create_react_agent(llm, tools, **{_PROMPT_KEY: prompt})


# ── LangGraph state ───────────────────────────────────────────────────────────
class ShopState(TypedDict):
    messages: Annotated[list, add_messages]


def _compact_messages(messages: list, max_messages: int) -> list:
    """
    Keep only conversational context (human + plain AI replies) and
    drop tool traffic that causes token growth across turns.
    """
    cleaned = []
    for m in messages:
        if isinstance(m, HumanMessage):
            cleaned.append(m)
        elif isinstance(m, AIMessage) and not getattr(m, "tool_calls", None):
            cleaned.append(m)
    return cleaned[-max_messages:] if max_messages > 0 else cleaned


def _latest_user_text(messages: list) -> str:
    """Return the most recent user utterance as normalized text."""
    for m in reversed(messages):
        if isinstance(m, HumanMessage):
            return str(m.content).strip().lower()
    return ""


def _fast_route_tool(messages: list) -> str | None:
    """
    Deterministic router for common intents.
    Returns transfer tool name when there is a single clear winner.
    """
    text = _latest_user_text(messages)
    if not text:
        return None

    scores: dict[str, int] = defaultdict(int)
    for tool_name, keywords in FAST_ROUTE_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                scores[tool_name] += 1

    if not scores:
        return None

    top_score = max(scores.values())
    winners = [name for name, score in scores.items() if score == top_score]
    if len(winners) != 1:
        # Ambiguous message: fall back to LLM router.
        return None
    return winners[0]


# ── Helper: clean history for specialist agents ────────────────────────────────
def _for_specialist(state: ShopState) -> dict:
    """
    Return a messages list suitable for a specialist agent.

    Newer LangGraph versions require that any AIMessage with tool_calls
    has a matching ToolMessage in the history. The supervisor routing
    message (with transfer_to_* tool_calls) is only a handoff signal and
    should NOT be passed into the specialist agent's chat history.

    We therefore drop any AIMessage that contains tool_calls before
    forwarding the history to a specialist agent.
    """
    return {
        "messages": _compact_messages(
            state["messages"],
            MAX_SPECIALIST_CONTEXT_MESSAGES,
        )
    }

# ── Build compiled LangGraph ──────────────────────────────────────────────────
async def build_graph():
    """
    Build and return a compiled LangGraph supervisor with all 6 specialist agents.

    Each specialist agent is scoped exclusively to its own MCP server tools.
    The supervisor uses handoff tools to route — it never calls domain tools directly.

    Returns
    -------
    CompiledGraph
        Ready to call with .ainvoke({"messages": [...]})
    """
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        api_key=os.getenv("OPENAI_API_KEY"),
    )

    async def _load(key: str):
        """Load tools from a single specialist MCP server."""
        client = MultiServerMCPClient({key: SPECIALIST_SERVERS[key]})
        return await client.get_tools()

    # Load all 6 specialist tool-sets concurrently
    (
        order_tools, ret_tools,  prod_tools,
        pay_tools,   comp_tools, loyal_tools,
    ) = await asyncio.gather(
        _load("order"),   _load("returns"),    _load("product"),
        _load("payment"), _load("complaints"), _load("loyalty"),
    )

    log.info(
        "Tools loaded — order:%d returns:%d product:%d payment:%d complaints:%d loyalty:%d",
        len(order_tools), len(ret_tools), len(prod_tools),
        len(pay_tools),   len(comp_tools), len(loyal_tools),
    )

    # One specialist agent per domain
    order_agent = _make_agent(llm, order_tools,  ORDER_PROMPT)
    ret_agent   = _make_agent(llm, ret_tools,    RETURNS_PROMPT)
    prod_agent  = _make_agent(llm, prod_tools,   PRODUCT_PROMPT)
    pay_agent   = _make_agent(llm, pay_tools,    PAYMENT_PROMPT)
    comp_agent  = _make_agent(llm, comp_tools,   COMPLAINTS_PROMPT)
    loyal_agent = _make_agent(llm, loyal_tools,  LOYALTY_PROMPT)

    # ── Supervisor handoff tools (routing signals only) ───────────────
    @tool
    def transfer_to_order():
        """Route to Order Agent: tracking, status, delivery, cancel, address."""
        return "Routing to Order Agent..."

    @tool
    def transfer_to_returns():
        """Route to Returns Agent: returns, refunds, exchange, damaged/wrong items."""
        return "Routing to Returns Agent..."

    @tool
    def transfer_to_product():
        """Route to Product Agent: stock, availability, pricing, info, restock."""
        return "Routing to Product Agent..."

    @tool
    def transfer_to_payment():
        """Route to Payment Agent: billing, charges, coupons, invoices, transactions."""
        return "Routing to Payment Agent..."

    @tool
    def transfer_to_complaints():
        """Route to Complaints Agent: complaints, reviews, replacements, escalations."""
        return "Routing to Complaints Agent..."

    @tool
    def transfer_to_loyalty():
        """Route to Loyalty Agent: points, tiers, promo codes, rewards, discounts."""
        return "Routing to Loyalty Agent..."

    sup_llm = llm.bind_tools([
        transfer_to_order, transfer_to_returns, transfer_to_product,
        transfer_to_payment, transfer_to_complaints, transfer_to_loyalty,
    ])

    # ── Graph nodes ───────────────────────────────────────────────────
    def supervisor_node(state: ShopState):
        fast_tool = _fast_route_tool(state["messages"])
        if fast_tool:
            log.info("fast-route: %s", fast_tool)
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[{
                            "name": fast_tool,
                            "args": {},
                            "id": f"fast_route_{fast_tool}",
                            "type": "tool_call",
                        }],
                    )
                ]
            }

        result = sup_llm.invoke(
            [SystemMessage(content=SUPERVISOR_PROMPT)]
            + _compact_messages(state["messages"], MAX_SUPERVISOR_CONTEXT_MESSAGES)
        )
        return {"messages": [result]}

    def _route(state: ShopState) -> str:
        last = state["messages"][-1]
        tc   = getattr(last, "tool_calls", None)
        if not tc:
            return END
        return {
            "transfer_to_order":      "order_agent",
            "transfer_to_returns":    "returns_agent",
            "transfer_to_product":    "product_agent",
            "transfer_to_payment":    "payment_agent",
            "transfer_to_complaints": "complaints_agent",
            "transfer_to_loyalty":    "loyalty_agent",
        }.get(tc[0]["name"], END)

    async def run_order(s):
        r = await order_agent.ainvoke(_for_specialist(s))
        return {"messages": r["messages"]}

    async def run_returns(s):
        r = await ret_agent.ainvoke(_for_specialist(s))
        return {"messages": r["messages"]}

    async def run_product(s):
        r = await prod_agent.ainvoke(_for_specialist(s))
        return {"messages": r["messages"]}

    async def run_payment(s):
        r = await pay_agent.ainvoke(_for_specialist(s))
        return {"messages": r["messages"]}

    async def run_comp(s):
        r = await comp_agent.ainvoke(_for_specialist(s))
        return {"messages": r["messages"]}

    async def run_loyal(s):
        r = await loyal_agent.ainvoke(_for_specialist(s))
        return {"messages": r["messages"]}

    # ── Assemble and compile the graph ────────────────────────────────
    g = StateGraph(ShopState)
    g.add_node("supervisor",       supervisor_node)
    g.add_node("order_agent",      run_order)
    g.add_node("returns_agent",    run_returns)
    g.add_node("product_agent",    run_product)
    g.add_node("payment_agent",    run_payment)
    g.add_node("complaints_agent", run_comp)
    g.add_node("loyalty_agent",    run_loyal)

    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", _route, {
        "order_agent":      "order_agent",
        "returns_agent":    "returns_agent",
        "product_agent":    "product_agent",
        "payment_agent":    "payment_agent",
        "complaints_agent": "complaints_agent",
        "loyalty_agent":    "loyalty_agent",
        END: END,
    })
    for node in [
        "order_agent", "returns_agent", "product_agent",
        "payment_agent", "complaints_agent", "loyalty_agent",
    ]:
        g.add_edge(node, END)

    return g.compile()


# ── Message serialiser ────────────────────────────────────────────────────────
def serialise_messages(msgs: list) -> list:
    """
    Convert LangChain message objects to JSON-safe plain dicts.
    Used by supervisor_server.py before returning the response over HTTP.
    """
    out = []
    for m in msgs:
        if isinstance(m, HumanMessage):
            out.append({"role": "human", "content": m.content})
        elif isinstance(m, AIMessage):
            out.append({
                "role":       "ai",
                "content":    m.content,
                "tool_calls": getattr(m, "tool_calls", []),
            })
        elif isinstance(m, ToolMessage):
            out.append({
                "role":         "tool",
                "name":         m.name,
                "content":      m.content,
                "tool_call_id": getattr(m, "tool_call_id", ""),
            })
    return out


# ── Trace builder ─────────────────────────────────────────────────────────────
def build_trace(msgs: list) -> list:
    """
    Walk the full message list and produce a step-by-step routing trace
    suitable for rendering in the Streamlit live trace panel.

    Each step is one of:
      {"type": "route",       "to": "<agent name>"}
      {"type": "tool_call",   "agent": "...", "tool": "...", "args": {...}}
      {"type": "tool_result", "agent": "...", "tool": "...", "result": ...}
    """
    trace        = []
    active_agent = "Supervisor"

    for msg in msgs:
        # Tool-call steps (supervisor routing + specialist tool calls)
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                name = tc["name"]
                if name.startswith("transfer_to_"):
                    label        = name.replace("transfer_to_", "").replace("_", " ").title()
                    active_agent = label
                    trace.append({"type": "route", "to": label})
                else:
                    trace.append({
                        "type":  "tool_call",
                        "agent": active_agent,
                        "tool":  name,
                        "args":  tc.get("args", {}),
                    })

        # Tool result steps
        if isinstance(msg, ToolMessage):
            raw = msg.content
            if isinstance(raw, list):
                raw = " ".join(
                    c.get("text", "") if isinstance(c, dict) else str(c)
                    for c in raw
                )
            try:
                data = json.loads(raw)
            except Exception:
                data = raw
            # Skip the bare "Routing to …" handoff acknowledgements
            if not (isinstance(data, str) and data.startswith("Routing")):
                trace.append({
                    "type":   "tool_result",
                    "agent":  active_agent,
                    "tool":   msg.name,
                    "result": data,
                })

    return trace
