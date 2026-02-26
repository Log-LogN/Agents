"""
supervisor/graph.py
-------------------
Multi-Agent Supervisor System with role-based tool access.
"""

import asyncio
import json
import os
import sys
from typing import Annotated, Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv
from typing_extensions import TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import create_react_agent

# create_react_agent 'prompt' param was renamed to 'state_modifier' in newer langgraph
import inspect as _inspect

_react_params = _inspect.signature(create_react_agent).parameters
_PROMPT_KWARG = "state_modifier" if "state_modifier" in _react_params else "prompt"


def make_agent(llm, tools, prompt_text: str):
    """Create a react agent compatible with any LangGraph version."""
    return create_react_agent(llm, tools, **{_PROMPT_KWARG: prompt_text})


nest_asyncio.apply()
load_dotenv()

DEPARTMENT_ORDER = ["appointment", "billing", "inventory", "pharmacy", "lab", "ward"]
VALID_ROLES = {
    "patient",
    "frontdesk",
    "billing",
    "inventory",
    "pharmacy",
    "lab",
    "ward",
    "admin",
}

AGENT_TOOL_NAMES: Dict[str, Set[str]] = {
    "appointment": {
        "validate_patient_info",
        "register_patient",
        "get_doctors",
        "check_doctor_availability",
        "book_appointment",
        "cancel_appointment",
        "edit_appointment",
        "get_patient_appointments",
    },
    "billing": {
        "get_patient_bill",
        "generate_invoice",
        "update_invoice_status",
        "calculate_charges",
        "get_pending_invoices",
        "get_revenue_summary",
    },
    "inventory": {
        "get_all_stock",
        "get_low_stock_items",
        "check_item_stock",
        "update_stock",
        "create_reorder_alert",
        "get_open_reorder_alerts",
        "resolve_reorder_alert",
    },
    "pharmacy": {
        "create_prescription",
        "get_patient_prescriptions",
        "check_drug_interactions",
        "check_dosage_safety",
        "dispense_medication",
        "cancel_prescription",
    },
    "lab": {
        "order_lab_test",
        "get_patient_lab_results",
        "update_lab_result",
        "get_pending_lab_tests",
        "get_critical_flags",
        "mark_doctor_notified",
    },
    "ward": {
        "get_bed_availability",
        "get_ward_beds",
        "assign_bed",
        "discharge_patient",
        "mark_bed_cleaned",
        "transfer_patient",
        "get_ward_events",
    },
}

ROLE_TOOL_ACCESS: Dict[str, Dict[str, Set[str]]] = {
    "frontdesk": {
        "appointment": set(AGENT_TOOL_NAMES["appointment"]),
        "ward": {"get_bed_availability"},
    },
    "billing": {"billing": set(AGENT_TOOL_NAMES["billing"])},
    "inventory": {"inventory": set(AGENT_TOOL_NAMES["inventory"])},
    "pharmacy": {"pharmacy": set(AGENT_TOOL_NAMES["pharmacy"])},
    "lab": {"lab": set(AGENT_TOOL_NAMES["lab"])},
    "ward": {"ward": set(AGENT_TOOL_NAMES["ward"])},
}

TRANSFER_TOOL_RESPONSES = {
    "transfer_to_appointment": "Transferring to Appointment Agent...",
    "transfer_to_billing": "Transferring to Billing Agent...",
    "transfer_to_inventory": "Transferring to Inventory Agent...",
    "transfer_to_pharmacy": "Transferring to Pharmacy Agent...",
    "transfer_to_lab": "Transferring to Lab Agent...",
    "transfer_to_ward": "Transferring to Ward Agent...",
}

# MCP Server URLs
MCP_SERVERS = {
    "appointment": {"transport": "streamable_http", "url": "http://127.0.0.1:8001/mcp"},
    "billing": {"transport": "streamable_http", "url": "http://127.0.0.1:8002/mcp"},
    "inventory": {"transport": "streamable_http", "url": "http://127.0.0.1:8003/mcp"},
    "pharmacy": {"transport": "streamable_http", "url": "http://127.0.0.1:8004/mcp"},
    "lab": {"transport": "streamable_http", "url": "http://127.0.0.1:8005/mcp"},
    "ward": {"transport": "streamable_http", "url": "http://127.0.0.1:8006/mcp"},
}

SUPERVISOR_PROMPT = """You are the Hospital System Supervisor. Your only job is to read the user's message
and decide which specialist agent should handle it. You never answer directly, you always hand off.

Route to the correct agent based on these rules:
- APPOINTMENT AGENT: book/cancel/reschedule appointment, register patient, view doctors, view appointments
- BILLING AGENT: invoice, bill, payment, charges, insurance, revenue, outstanding amount
- INVENTORY AGENT: stock, supplies, inventory, reorder, gloves, masks, equipment shortage
- PHARMACY AGENT: prescription, medicine, drug, medication, dosage, interaction, dispense
- LAB AGENT: lab test, blood test, result, sample, critical value, pathology
- WARD AGENT: bed, ward, admit, discharge, room, transfer, occupancy, cleaning

Always transfer to the most appropriate allowed agent."""

APPOINTMENT_PROMPT = """You are the Appointment Specialist Agent for a hospital system.
You handle patient registration, doctor information, appointment booking, cancellation, and rescheduling.
Date format: YYYY-MM-DD, time format: HH:MM."""

BILLING_PROMPT = """You are the Billing Specialist Agent for a hospital system.
You handle invoice generation, bill enquiries, payment status, revenue summaries, and charge calculations."""

INVENTORY_PROMPT = """You are the Inventory Specialist Agent for a hospital system.
You handle stock levels, low stock alerts, reorder management, and stock updates."""

PHARMACY_PROMPT = """You are the Pharmacy Specialist Agent for a hospital system.
You handle prescriptions, drug interaction checks, dosage safety, and dispensing."""

LAB_PROMPT = """You are the Lab Specialist Agent for a hospital system.
You handle lab test orders, result entry, critical value flagging, and pending test tracking."""

WARD_PROMPT = """You are the Ward Management Specialist Agent for a hospital system.
You handle bed availability, patient admission, discharge, transfer, and bed cleaning."""


class SupervisorState(TypedDict, total=False):
    messages: Annotated[list, add_messages]
    actor: dict


def get_llm():
    return ChatOpenAI(model="gpt-4o-mini", temperature=0, api_key=os.getenv("OPENAI_API_KEY"))


def _normalize_actor(actor: Optional[dict]) -> dict:
    actor = actor or {}
    role = str(actor.get("role", "admin")).strip().lower()
    if role not in VALID_ROLES:
        role = "admin"
    return {
        "username": str(actor.get("username", "anonymous")).strip() or "anonymous",
        "role": role,
        "email": str(actor.get("email", "")).strip() or None,
    }


def _normalize_message_history(messages: list) -> list:
    """Ensure every AI tool call has a matching ToolMessage."""
    normalized = []
    resolved_tool_call_ids = {
        msg.tool_call_id
        for msg in messages
        if isinstance(msg, ToolMessage) and getattr(msg, "tool_call_id", None)
    }

    for msg in messages:
        normalized.append(msg)
        if not isinstance(msg, AIMessage) or not getattr(msg, "tool_calls", None):
            continue

        for idx, tool_call in enumerate(msg.tool_calls):
            tc_id = tool_call.get("id")
            if not tc_id:
                tc_id = f"recovered_tool_call_{len(normalized)}_{idx}"
                tool_call["id"] = tc_id
            if tc_id in resolved_tool_call_ids:
                continue

            tool_name = tool_call.get("name", "unknown_tool")
            fallback_content = TRANSFER_TOOL_RESPONSES.get(
                tool_name, f"Recovered missing ToolMessage for '{tool_name}'."
            )
            normalized.append(
                ToolMessage(content=fallback_content, name=tool_name, tool_call_id=tc_id)
            )
            resolved_tool_call_ids.add(tc_id)

    return normalized


def _filter_tools_by_name(tools: list, allowed_names: Set[str]) -> list:
    return [t for t in tools if getattr(t, "name", "") in allowed_names]


def _build_patient_scoped_tools(agent_name: str, tools: list, user_email: Optional[str]) -> list:
    lookup = {getattr(t, "name", ""): t for t in tools}
    scoped = []

    if agent_name == "appointment":
        for name in ["validate_patient_info", "get_doctors", "check_doctor_availability"]:
            if name in lookup:
                scoped.append(lookup[name])

        if user_email and "register_patient" in lookup:
            base = lookup["register_patient"]

            @tool("register_patient")
            def register_self(name: str, age: int) -> dict:
                """Register the currently logged in patient profile."""
                return base.invoke({"name": name, "email": user_email, "age": age})

            scoped.append(register_self)

        if user_email and "book_appointment" in lookup:
            base = lookup["book_appointment"]

            @tool("book_appointment")
            def book_self_appointment(
                doctor_id: int, appointment_date: str, appointment_time: str, reason: str
            ) -> dict:
                """Book appointment for the currently logged in patient."""
                return base.invoke(
                    {
                        "patient_email": user_email,
                        "doctor_id": doctor_id,
                        "appointment_date": appointment_date,
                        "appointment_time": appointment_time,
                        "reason": reason,
                    }
                )

            scoped.append(book_self_appointment)

        if user_email and "cancel_appointment" in lookup:
            base = lookup["cancel_appointment"]

            @tool("cancel_appointment")
            def cancel_self_appointment(appointment_id: int) -> dict:
                """Cancel own appointment by ID."""
                return base.invoke({"appointment_id": appointment_id, "patient_email": user_email})

            scoped.append(cancel_self_appointment)

        if user_email and "edit_appointment" in lookup:
            base = lookup["edit_appointment"]

            @tool("edit_appointment")
            def edit_self_appointment(appointment_id: int, new_date: str, new_time: str) -> dict:
                """Reschedule own appointment by ID."""
                return base.invoke(
                    {
                        "appointment_id": appointment_id,
                        "patient_email": user_email,
                        "new_date": new_date,
                        "new_time": new_time,
                    }
                )

            scoped.append(edit_self_appointment)

        if user_email and "get_patient_appointments" in lookup:
            base = lookup["get_patient_appointments"]

            @tool("get_patient_appointments")
            def get_self_appointments() -> list:
                """Get appointments for the currently logged in patient."""
                return base.invoke({"patient_email": user_email})

            scoped.append(get_self_appointments)

    elif agent_name == "billing":
        if user_email and "get_patient_bill" in lookup:
            base = lookup["get_patient_bill"]

            @tool("get_patient_bill")
            def get_self_bill() -> list:
                """Get bills for the currently logged in patient."""
                return base.invoke({"patient_email": user_email})

            scoped.append(get_self_bill)

    elif agent_name == "pharmacy":
        if user_email and "get_patient_prescriptions" in lookup:
            base = lookup["get_patient_prescriptions"]

            @tool("get_patient_prescriptions")
            def get_self_prescriptions() -> list:
                """Get prescriptions for the currently logged in patient."""
                return base.invoke({"patient_email": user_email})

            scoped.append(get_self_prescriptions)

    elif agent_name == "lab":
        if user_email and "get_patient_lab_results" in lookup:
            base = lookup["get_patient_lab_results"]

            @tool("get_patient_lab_results")
            def get_self_lab_results() -> list:
                """Get lab results for the currently logged in patient."""
                return base.invoke({"patient_email": user_email})

            scoped.append(get_self_lab_results)

    elif agent_name == "ward":
        if "get_bed_availability" in lookup:
            scoped.append(lookup["get_bed_availability"])

    return scoped


def _prepare_tools_for_role(agent_name: str, tools: list, actor: dict) -> list:
    role = actor["role"]

    if role == "admin":
        return tools

    if role == "patient":
        return _build_patient_scoped_tools(agent_name, tools, actor.get("email"))

    allowed_map = ROLE_TOOL_ACCESS.get(role, {})
    allowed_names = allowed_map.get(agent_name, set())
    if not allowed_names:
        return []

    return _filter_tools_by_name(tools, allowed_names)


async def build_supervisor_async(actor: Optional[dict] = None):
    actor = _normalize_actor(actor)
    role = actor["role"]

    llm = get_llm()

    async def get_tools_for(server_name: str):
        client = MultiServerMCPClient({server_name: MCP_SERVERS[server_name]})
        return await client.get_tools()

    raw_tools = {
        "appointment": await get_tools_for("appointment"),
        "billing": await get_tools_for("billing"),
        "inventory": await get_tools_for("inventory"),
        "pharmacy": await get_tools_for("pharmacy"),
        "lab": await get_tools_for("lab"),
        "ward": await get_tools_for("ward"),
    }

    scoped_tools = {
        dept: _prepare_tools_for_role(dept, tool_list, actor)
        for dept, tool_list in raw_tools.items()
    }

    accessible_departments = [dept for dept in DEPARTMENT_ORDER if scoped_tools.get(dept)]

    role_guard = (
        f"\n\nCurrent logged-in role: {role}."
        f"\nCurrent logged-in email: {actor.get('email') or 'N/A'}."
        f"\nAllowed departments for this role: {', '.join(d.title() for d in accessible_departments) or 'None'}."
        "\nNever call tools outside these limits."
    )

    appt_agent = (
        make_agent(llm, scoped_tools["appointment"], APPOINTMENT_PROMPT + role_guard)
        if scoped_tools["appointment"]
        else None
    )
    bill_agent = (
        make_agent(llm, scoped_tools["billing"], BILLING_PROMPT + role_guard)
        if scoped_tools["billing"]
        else None
    )
    inv_agent = (
        make_agent(llm, scoped_tools["inventory"], INVENTORY_PROMPT + role_guard)
        if scoped_tools["inventory"]
        else None
    )
    pharm_agent = (
        make_agent(llm, scoped_tools["pharmacy"], PHARMACY_PROMPT + role_guard)
        if scoped_tools["pharmacy"]
        else None
    )
    lab_agent = (
        make_agent(llm, scoped_tools["lab"], LAB_PROMPT + role_guard)
        if scoped_tools["lab"]
        else None
    )
    ward_agent = (
        make_agent(llm, scoped_tools["ward"], WARD_PROMPT + role_guard)
        if scoped_tools["ward"]
        else None
    )

    @tool
    def transfer_to_appointment():
        """Transfer to Appointment Agent for scheduling, registration, doctors."""
        return "Transferring to Appointment Agent..."

    @tool
    def transfer_to_billing():
        """Transfer to Billing Agent for invoices, payments, charges."""
        return "Transferring to Billing Agent..."

    @tool
    def transfer_to_inventory():
        """Transfer to Inventory Agent for stock, supplies, reorders."""
        return "Transferring to Inventory Agent..."

    @tool
    def transfer_to_pharmacy():
        """Transfer to Pharmacy Agent for prescriptions, drugs, dispensing."""
        return "Transferring to Pharmacy Agent..."

    @tool
    def transfer_to_lab():
        """Transfer to Lab Agent for test orders, results, critical values."""
        return "Transferring to Lab Agent..."

    @tool
    def transfer_to_ward():
        """Transfer to Ward Agent for beds, admissions, discharges, transfers."""
        return "Transferring to Ward Agent..."

    transfer_tool_map = {
        "appointment": transfer_to_appointment,
        "billing": transfer_to_billing,
        "inventory": transfer_to_inventory,
        "pharmacy": transfer_to_pharmacy,
        "lab": transfer_to_lab,
        "ward": transfer_to_ward,
    }
    transfer_tools = [transfer_tool_map[d] for d in accessible_departments if d in transfer_tool_map]

    supervisor_llm = llm.bind_tools(transfer_tools) if transfer_tools else llm

    def supervisor_node(state: SupervisorState) -> SupervisorState:
        msgs = [SystemMessage(content=SUPERVISOR_PROMPT + role_guard)] + state["messages"]
        response = supervisor_llm.invoke(msgs)
        out_messages = [response]
        for idx, tool_call in enumerate(getattr(response, "tool_calls", []) or []):
            tc_id = tool_call.get("id")
            if not tc_id:
                tc_id = f"transfer_tool_call_{idx}"
                tool_call["id"] = tc_id
            out_messages.append(
                ToolMessage(
                    content=TRANSFER_TOOL_RESPONSES.get(
                        tool_call.get("name", ""), "Transferring to selected specialist agent..."
                    ),
                    name=tool_call.get("name", "transfer"),
                    tool_call_id=tc_id,
                )
            )
        return {"messages": out_messages}

    def route_supervisor(state: SupervisorState) -> str:
        tool_name = None
        for msg in reversed(state["messages"]):
            if not isinstance(msg, AIMessage):
                continue
            if getattr(msg, "tool_calls", None):
                tool_name = msg.tool_calls[0].get("name")
            break
        if not tool_name:
            return END
        routes = {
            "transfer_to_appointment": "appointment_agent",
            "transfer_to_billing": "billing_agent",
            "transfer_to_inventory": "inventory_agent",
            "transfer_to_pharmacy": "pharmacy_agent",
            "transfer_to_lab": "lab_agent",
            "transfer_to_ward": "ward_agent",
        }
        return routes.get(tool_name, END)

    async def run_specialist(agent_obj, department: str, state: SupervisorState) -> SupervisorState:
        if agent_obj is None:
            return {
                "messages": [
                    AIMessage(
                        content=(
                            f"Access denied: role '{role}' cannot use {department.title()} tools. "
                            "Please use an authorized account."
                        )
                    )
                ]
            }
        result = await agent_obj.ainvoke({"messages": state["messages"]})
        return {"messages": result["messages"]}

    async def run_appointment(state: SupervisorState) -> SupervisorState:
        return await run_specialist(appt_agent, "appointment", state)

    async def run_billing(state: SupervisorState) -> SupervisorState:
        return await run_specialist(bill_agent, "billing", state)

    async def run_inventory(state: SupervisorState) -> SupervisorState:
        return await run_specialist(inv_agent, "inventory", state)

    async def run_pharmacy(state: SupervisorState) -> SupervisorState:
        return await run_specialist(pharm_agent, "pharmacy", state)

    async def run_lab(state: SupervisorState) -> SupervisorState:
        return await run_specialist(lab_agent, "lab", state)

    async def run_ward(state: SupervisorState) -> SupervisorState:
        return await run_specialist(ward_agent, "ward", state)

    graph = StateGraph(SupervisorState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("appointment_agent", run_appointment)
    graph.add_node("billing_agent", run_billing)
    graph.add_node("inventory_agent", run_inventory)
    graph.add_node("pharmacy_agent", run_pharmacy)
    graph.add_node("lab_agent", run_lab)
    graph.add_node("ward_agent", run_ward)

    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_supervisor,
        {
            "appointment_agent": "appointment_agent",
            "billing_agent": "billing_agent",
            "inventory_agent": "inventory_agent",
            "pharmacy_agent": "pharmacy_agent",
            "lab_agent": "lab_agent",
            "ward_agent": "ward_agent",
            END: END,
        },
    )

    for agent_node in [
        "appointment_agent",
        "billing_agent",
        "inventory_agent",
        "pharmacy_agent",
        "lab_agent",
        "ward_agent",
    ]:
        graph.add_edge(agent_node, END)

    return graph.compile()


async def ainvoke(messages: list, actor: Optional[dict] = None) -> dict:
    """Run the multi-agent system and return messages + trace."""
    actor = _normalize_actor(actor)
    graph = await build_supervisor_async(actor)
    safe_input_messages = _normalize_message_history(messages)
    result = await graph.ainvoke({"messages": safe_input_messages, "actor": actor})
    all_msgs = _normalize_message_history(result["messages"])

    trace = []
    active_agent = "supervisor"
    for msg in all_msgs:
        if isinstance(msg, AIMessage) and hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                if tc["name"].startswith("transfer_to_"):
                    agent_name = tc["name"].replace("transfer_to_", "").replace("_", " ").title()
                    active_agent = agent_name
                    trace.append({"type": "route", "to": agent_name, "args": tc.get("args", {})})
                else:
                    trace.append(
                        {
                            "type": "tool_call",
                            "agent": active_agent,
                            "tool": tc["name"],
                            "args": tc.get("args", {}),
                        }
                    )
        if isinstance(msg, ToolMessage):
            raw = msg.content
            if isinstance(raw, list):
                raw = " ".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in raw)
            try:
                result_data = json.loads(raw)
            except Exception:
                result_data = raw
            if not (isinstance(result_data, str) and "Transferring" in result_data):
                trace.append(
                    {
                        "type": "tool_result",
                        "agent": active_agent,
                        "tool": msg.name,
                        "result": result_data,
                    }
                )

    final_reply = "Sorry, I could not process that request."
    for msg in reversed(all_msgs):
        if isinstance(msg, AIMessage) and msg.content and not getattr(msg, "tool_calls", None):
            final_reply = msg.content
            break

    return {"messages": all_msgs, "final_reply": final_reply, "trace": trace}


def run_sync(messages: list, actor: Optional[dict] = None) -> dict:
    """Sync wrapper safe to call from Streamlit."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(ainvoke(messages, actor=actor))
