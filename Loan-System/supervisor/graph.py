"""
supervisor/graph.py
-------------------
Multi-Agent Supervisor for the Loan & Credit Processing System.

Flow:
  User → Supervisor Agent → routes to one of 5 Specialist Agents → MCP Server → DB

Supervisor never executes tools — it only decides who handles the task.
Each specialist only has access to its own MCP server tools.
"""
import sys, os, asyncio, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv
from typing import Annotated
from typing_extensions import TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, AIMessage, ToolMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

nest_asyncio.apply()
load_dotenv()

# ── Version-safe create_react_agent helper ────────────────────────────────────
import inspect as _inspect
_PROMPT_KEY = "state_modifier" if "state_modifier" in _inspect.signature(create_react_agent).parameters else "prompt"

def _make_agent(llm, tools, prompt_text: str):
    return create_react_agent(llm, tools, **{_PROMPT_KEY: prompt_text})

# ── MCP Server URLs ───────────────────────────────────────────────────────────
MCP_SERVERS = {
    "application":  {"transport": "streamable_http", "url": "http://127.0.0.1:8001/mcp"},
    "kyc":          {"transport": "streamable_http", "url": "http://127.0.0.1:8002/mcp"},
    "credit_risk":  {"transport": "streamable_http", "url": "http://127.0.0.1:8003/mcp"},
    "underwriting": {"transport": "streamable_http", "url": "http://127.0.0.1:8004/mcp"},
    "repayment":    {"transport": "streamable_http", "url": "http://127.0.0.1:8005/mcp"},
}

# ── System Prompts ────────────────────────────────────────────────────────────
SUPERVISOR_PROMPT = """You are the Loan System Supervisor AI. Your ONLY responsibility is to read
the user's message and route it to the correct specialist agent. You never answer directly —
you always hand off to a specialist.

ROUTING RULES:
- APPLICATION AGENT  → apply for loan, register, check application status, loan types, update application
- KYC AGENT          → verify identity, check documents, AML, sanctions, fraud flag, KYC status
- CREDIT RISK AGENT  → credit score, risk assessment, debt-to-income, existing loans, risk summary
- UNDERWRITING AGENT → approve/reject loan, loan terms, EMI, decision, escalate, underwriting
- REPAYMENT AGENT    → payment, installment, EMI due, missed payment, restructure, default risk, reminder

Always route to the single most appropriate agent. If unsure, route to APPLICATION AGENT."""

APPLICATION_PROMPT = """You are the Application Specialist Agent for a loan processing system.
You handle: applicant registration, loan application submission, application status tracking,
available loan types, and application updates.
Rules:
- Always check if applicant is registered before submitting applications.
- Use email as the applicant's unique identifier (no phone numbers).
- Loan types: personal, home, education, business, vehicle.
- Be clear about required fields: name, email, age, employment_type, employer, annual_income.
- Rule: Applicants MUST have their KYC approved before they can submit a loan application. If they haven't, tell them to see the KYC Agent first.
"""

KYC_PROMPT = """You are the KYC & Fraud Detection Specialist Agent.
You handle: identity verification, document authenticity, employment verification,
AML checks, sanctions screening, fraud flagging, and KYC approval.
Rules:
- Run checks in order: identity → documents → employment → AML → sanctions → approve.
- If any fraud is detected, immediately flag and do NOT approve.
- Explain clearly what failed and why if KYC cannot be approved.
- KYC must be fully approved before underwriting can proceed."""

CREDIT_PROMPT = """You are the Credit Risk Specialist Agent.
You handle: credit score calculation, debt-to-income ratio analysis, existing loan checks,
risk level assessment, and comprehensive risk reports for underwriting.
Rules:
- Always calculate a fresh credit score before assessment.
- Explain what factors drove the score (income, DTI, missed payments, employment).
- Provide clear risk levels: Low / Medium / High / Very High.
- Generate a full risk summary when preparing for underwriting."""

UNDERWRITING_PROMPT = """You are the Underwriting Specialist Agent — the final decision maker.
You handle: loan approval/rejection decisions, loan term calculation, EMI computation,
escalation to human reviewers, and retrieving past decisions.
Rules:
- KYC must be approved and credit score must exist before you can decide.
- Explain the decision clearly — what was approved, at what rate, for how long.
- If rejecting, explain exactly why and what the applicant can do.
- If escalating, give the specific reason for human review.
- Show EMI and total interest when approving."""

REPAYMENT_PROMPT = """You are the Repayment & Collections Specialist Agent.
You handle: checking loan status, viewing repayment schedules, recording payments,
sending payment reminders, flagging missed payments, assessing default risk, and restructuring loans.
Rules:
- Always check loan status first before acting.
- When recording payments, confirm the installment and new outstanding balance.
- Proactively suggest restructuring if the borrower is in difficulty.
- Assess default risk when a borrower mentions financial trouble.
- Be empathetic — suggest options before escalating to collections."""

# ── State ─────────────────────────────────────────────────────────────────────
class LoanState(TypedDict):
    messages: Annotated[list, add_messages]

# ── LLM ──────────────────────────────────────────────────────────────────────
def _get_llm():
    return ChatOpenAI(model="gpt-4o-mini", temperature=0,
                      api_key=os.getenv("OPENAI_API_KEY"))

# ── Build full supervisor graph ───────────────────────────────────────────────
async def _build_graph():
    llm = _get_llm()

    async def _tools(server: str):
        client = MultiServerMCPClient({server: MCP_SERVERS[server]})
        return await client.get_tools()

    # Load tools per specialist
    appl_tools  = await _tools("application")
    kyc_tools   = await _tools("kyc")
    cr_tools    = await _tools("credit_risk")
    uw_tools    = await _tools("underwriting")
    rep_tools   = await _tools("repayment")

    # Build specialist agents
    appl_agent = _make_agent(llm, appl_tools,  APPLICATION_PROMPT)
    kyc_agent  = _make_agent(llm, kyc_tools,   KYC_PROMPT)
    cr_agent   = _make_agent(llm, cr_tools,    CREDIT_PROMPT)
    uw_agent   = _make_agent(llm, uw_tools,    UNDERWRITING_PROMPT)
    rep_agent  = _make_agent(llm, rep_tools,   REPAYMENT_PROMPT)

    # Handoff tools (return value is ignored — routing is via conditional edges)
    @tool
    def transfer_to_application():
        """Route to Application Agent: registrations, applications, status, loan types."""
        return "Routing to Application Agent..."

    @tool
    def transfer_to_kyc():
        """Route to KYC Agent: identity, documents, AML, sanctions, fraud, KYC status."""
        return "Routing to KYC Agent..."

    @tool
    def transfer_to_credit_risk():
        """Route to Credit Risk Agent: credit score, DTI, risk level, risk summary."""
        return "Routing to Credit Risk Agent..."

    @tool
    def transfer_to_underwriting():
        """Route to Underwriting Agent: approve/reject, loan terms, EMI, escalate."""
        return "Routing to Underwriting Agent..."

    @tool
    def transfer_to_repayment():
        """Route to Repayment Agent: payments, schedule, missed EMI, default risk, restructure."""
        return "Routing to Repayment Agent..."

    handoff_tools = [
        transfer_to_application, transfer_to_kyc, transfer_to_credit_risk,
        transfer_to_underwriting, transfer_to_repayment,
    ]

    supervisor_llm = llm.bind_tools(handoff_tools)

    # ── Nodes ─────────────────────────────────────────────────────────────
    def supervisor_node(state: LoanState) -> LoanState:
        msgs = [SystemMessage(content=SUPERVISOR_PROMPT)] + state["messages"]
        response = supervisor_llm.invoke(msgs)
        output = [response]
        if response.tool_calls:
            for tc in response.tool_calls:
                output.append(ToolMessage(
                    content=f"Routing to {tc['name'].replace('transfer_to_', '').title()} agent...",
                    tool_call_id=tc["id"],
                    name=tc["name"]
                ))
        return {"messages": output}

    def _route(state: LoanState) -> str:
        # Find the last AIMessage that has tool calls
        last_ai = None
        for m in reversed(state["messages"]):
            if isinstance(m, AIMessage) and m.tool_calls:
                last_ai = m
                break
        if not last_ai:
            return END
        mapping = {
            "transfer_to_application":  "application_agent",
            "transfer_to_kyc":          "kyc_agent",
            "transfer_to_credit_risk":  "credit_risk_agent",
            "transfer_to_underwriting": "underwriting_agent",
            "transfer_to_repayment":    "repayment_agent",
        }
        return mapping.get(last_ai.tool_calls[0]["name"], END)

    async def run_appl(state): result = await appl_agent.ainvoke({"messages": state["messages"]}); return {"messages": result["messages"]}
    async def run_kyc (state): result = await kyc_agent.ainvoke ({"messages": state["messages"]}); return {"messages": result["messages"]}
    async def run_cr  (state): result = await cr_agent.ainvoke  ({"messages": state["messages"]}); return {"messages": result["messages"]}
    async def run_uw  (state): result = await uw_agent.ainvoke  ({"messages": state["messages"]}); return {"messages": result["messages"]}
    async def run_rep (state): result = await rep_agent.ainvoke ({"messages": state["messages"]}); return {"messages": result["messages"]}

    # ── Graph ─────────────────────────────────────────────────────────────
    g = StateGraph(LoanState)
    g.add_node("supervisor",        supervisor_node)
    g.add_node("application_agent", run_appl)
    g.add_node("kyc_agent",         run_kyc)
    g.add_node("credit_risk_agent", run_cr)
    g.add_node("underwriting_agent",run_uw)
    g.add_node("repayment_agent",   run_rep)

    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", _route, {
        "application_agent":  "application_agent",
        "kyc_agent":          "kyc_agent",
        "credit_risk_agent":  "credit_risk_agent",
        "underwriting_agent": "underwriting_agent",
        "repayment_agent":    "repayment_agent",
        END: END,
    })
    for node in ["application_agent","kyc_agent","credit_risk_agent","underwriting_agent","repayment_agent"]:
        g.add_edge(node, END)

    return g.compile()


# ── Public API ────────────────────────────────────────────────────────────────
async def ainvoke(messages: list) -> dict:
    graph  = await _build_graph()
    result = await graph.ainvoke({"messages": messages})
    msgs   = result["messages"]

    # Build live trace
    trace        = []
    active_agent = "Supervisor"

    # Only trace the new messages added during this invocation
    new_messages = msgs[len(messages):]

    for msg in new_messages:
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                name = tc["name"]
                if name.startswith("transfer_to_"):
                    label = name.replace("transfer_to_", "").replace("_", " ").title()
                    active_agent = label
                    trace.append({"type": "route", "to": label})
                else:
                    trace.append({
                        "type": "tool_call",
                        "agent": active_agent,
                        "tool": name,
                        "args": tc.get("args", {}),
                    })

        if isinstance(msg, ToolMessage):
            raw = msg.content
            if isinstance(raw, list):
                raw = " ".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in raw)
            try:
                data = json.loads(raw)
            except Exception:
                data = raw
            if not (isinstance(data, str) and "Routing" in data):
                trace.append({
                    "type": "tool_result",
                    "agent": active_agent,
                    "tool": msg.name,
                    "result": data,
                })

    final = "I could not process that request. Please try again."
    for msg in reversed(msgs):
        if isinstance(msg, AIMessage) and msg.content and not getattr(msg, "tool_calls", None):
            final = msg.content
            break

    return {"messages": msgs, "final_reply": final, "trace": trace}


def run_sync(messages: list) -> dict:
    """Synchronous wrapper — safe to call from Streamlit."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(ainvoke(messages))