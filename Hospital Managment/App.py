"""
App.py - Multi-Agent Hospital System Streamlit UI
Shows: chat + live agent trace with routing visualization
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
from langchain_core.messages import AIMessage, HumanMessage

from database.db import init_db
from supervisor.graph import run_sync

st.set_page_config(
    page_title="Hospital Management System",
    page_icon="H",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
.stApp,[data-testid="stAppViewContainer"]{background:#0d1117!important;color:#e6edf3!important}
.stApp p,.stApp span,.stApp div,.stApp li,.stApp h1,.stApp h2,.stApp h3,.stApp label{color:#e6edf3!important}
[data-testid="stSidebar"]{background:#161b22!important;border-right:1px solid #30363d}
[data-testid="stSidebar"] .stButton>button{background:#1f6feb!important;color:#fff!important;border:none!important;
  border-radius:8px!important;width:100%!important;margin-bottom:6px!important;padding:10px 14px!important;font-size:13px!important}
[data-testid="stSidebar"] .stButton>button:hover{background:#388bfd!important}
[data-testid="stChatMessage"]{background:#161b22!important;border:1px solid #30363d!important;border-radius:12px!important;
  padding:12px 16px!important;margin-bottom:10px!important}
.header-box{background:linear-gradient(135deg,#161b22,#1f6feb);padding:20px 28px;border-radius:12px;
  margin-bottom:18px;border:1px solid #30363d}
.trace-header{font-size:12px;font-weight:700;color:#58a6ff!important;text-transform:uppercase;
  letter-spacing:1px;padding:8px 0 6px;border-bottom:1px solid #30363d;margin-bottom:10px}
.route-card{background:#1a2635;border:1px solid #1f6feb;border-left:4px solid #1f6feb;
  border-radius:8px;padding:10px 14px;margin-bottom:8px}
.route-label{font-size:11px;font-weight:700;color:#58a6ff!important;margin-bottom:4px;letter-spacing:0.5px}
.route-agent{font-size:14px;font-weight:700;color:#ffa657!important}
.tool-call-card{background:#1c2a3a;border:1px solid #1f6feb;border-left:4px solid #1f6feb;
  border-radius:8px;padding:10px 14px;margin-bottom:8px}
.tool-result-card{background:#1a2a1a;border:1px solid #238636;border-left:4px solid #238636;
  border-radius:8px;padding:10px 14px;margin-bottom:8px}
.card-label{font-size:11px;font-weight:700;letter-spacing:0.5px;margin-bottom:4px}
.tool-call-card .card-label{color:#58a6ff!important}
.tool-result-card .card-label{color:#3fb950!important}
.card-tool{font-size:13px;font-weight:700;color:#ffa657!important;margin-bottom:4px}
.card-content{color:#c9d1d9!important;font-size:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all}
.agent-badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 10px;border-radius:12px;margin-bottom:6px}
hr{border-color:#30363d!important}
</style>
""",
    unsafe_allow_html=True,
)

AGENT_COLORS = {
    "Appointment": "#1f6feb",
    "Billing": "#b91c1c",
    "Inventory": "#d97706",
    "Pharmacy": "#1f6feb",
    "Lab": "#7c3aed",
    "Ward": "#238636",
}
AGENT_ICONS = {
    "Appointment": "A",
    "Billing": "B",
    "Inventory": "I",
    "Pharmacy": "P",
    "Lab": "L",
    "Ward": "W",
}

QUICK = {
    "Book Appointment": "I want to book an appointment",
    "Register Patient": "I want to register as a new patient",
    "View Doctors": "Show me all available doctors",
    "My Bill": "Show my invoice and billing details",
    "Check Stock": "Show all inventory stock levels",
    "Check Prescription": "Show my prescriptions",
    "Order Lab Test": "I want to order a lab test",
    "Bed Availability": "What beds are available?",
    "Low Stock Alerts": "Show low stock and reorder alerts",
    "Critical Lab Values": "Show any critical lab results",
}

# Database is initialized by start_servers.py; App.py assumes it's already set up.
if "messages" not in st.session_state:
    st.session_state.messages = []
if "trace_log" not in st.session_state:
    st.session_state.trace_log = []
if "trace_cursor" not in st.session_state:
    st.session_state.trace_cursor = 0

def run_agent(user_text: str):
    st.session_state.messages.append(HumanMessage(content=user_text))
    result = run_sync(st.session_state.messages)

    st.session_state.messages = result["messages"]
    full_trace = result.get("trace", [])
    prev_cursor = st.session_state.trace_cursor

    # Keep only the new trace steps produced by this turn.
    if 0 <= prev_cursor <= len(full_trace):
        turn_trace = full_trace[prev_cursor:]
    else:
        turn_trace = full_trace

    st.session_state.trace_cursor = len(full_trace)
    st.session_state.trace_log.append(turn_trace)
    return result["final_reply"], turn_trace


def render_trace(trace):
    if not trace:
        return
    with st.expander("Execution Trace", expanded=False):
        for step in trace:
            if step["type"] == "route":
                agent = step["to"]
                icon = AGENT_ICONS.get(agent, "S")
                st.markdown(
                    f"""<div class="route-card">
<div class="route-label">SUPERVISOR ROUTED TO</div>
<div class="route-agent">{icon} {agent} Agent</div>
</div>""",
                    unsafe_allow_html=True,
                )

            elif step["type"] == "tool_call":
                agent = step.get("agent", "")
                icon = AGENT_ICONS.get(agent, "S")
                color = AGENT_COLORS.get(agent, "#1f6feb")
                args_str = json.dumps(step["args"], indent=2)
                st.markdown(
                    f"""<div class="tool-call-card">
<div class="agent-badge" style="background:{color}22;color:{color}">{icon} {agent} Agent</div>
<div class="card-label">TOOL CALLED</div>
<div class="card-tool">{step['tool']}</div>
<div class="card-content">{args_str}</div>
</div>""",
                    unsafe_allow_html=True,
                )

            elif step["type"] == "tool_result":
                agent = step.get("agent", "")
                icon = AGENT_ICONS.get(agent, "S")
                color = AGENT_COLORS.get(agent, "#238636")
                result_data = step["result"]
                result_str = (
                    json.dumps(result_data, indent=2)
                    if isinstance(result_data, (dict, list))
                    else str(result_data)
                )
                if len(result_str) > 500:
                    result_str = result_str[:500] + "\n...(truncated)"
                st.markdown(
                    f"""<div class="tool-result-card">
<div class="agent-badge" style="background:{color}22;color:{color}">{icon} {agent} Agent</div>
<div class="card-label">MCP RESULT</div>
<div class="card-tool">{step['tool']}</div>
<div class="card-content">{result_str}</div>
</div>""",
                    unsafe_allow_html=True,
                )


with st.sidebar:
    st.markdown("## Hospital Management System")
    st.markdown("---")
    st.markdown("### Quick Actions")

    for label, msg in QUICK.items():
        if st.button(label, key=f"q_{label}"):
            st.session_state.pending = msg

    st.markdown("---")
    st.markdown("### Agents Online")
    for agent, icon in AGENT_ICONS.items():
        color = AGENT_COLORS[agent]
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
            f'<span style="font-size:14px">{icon}</span>'
            f'<span style="color:#e6edf3;font-size:13px;font-weight:500">{agent} Agent</span>'
            f'<span style="background:{color};width:8px;height:8px;border-radius:50%;display:inline-block"></span>'
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("---")
    if st.button("Clear Chat"):
        st.session_state.messages = []
        st.session_state.trace_log = []
        st.session_state.trace_cursor = 0
        st.rerun()

    st.caption("LangGraph Supervisor + 6 MCP Servers + PostgreSQL")

st.markdown(
    """
<div class="header-box">
  <h1 style="margin:0">Hospital Management System - Multi-Agent System</h1>
  <p style="margin-top:6px">Supervisor routes your request to the right specialist agent automatically.</p>
</div>
""",
    unsafe_allow_html=True,
)

chat_col = st.container()

with chat_col:
    if not st.session_state.messages:
        st.markdown("### Welcome")
        st.markdown("Use Quick Actions or type a request in chat.")
        st.markdown("---")

    trace_idx = 0
    for msg in st.session_state.messages:
        if isinstance(msg, HumanMessage):
            with st.chat_message("user", avatar="👤"):
                st.write(msg.content)
        elif isinstance(msg, AIMessage) and msg.content and not getattr(msg, "tool_calls", None):
            with st.chat_message("assistant", avatar="🤖"):
                st.write(msg.content)
                if trace_idx < len(st.session_state.trace_log):
                    render_trace(st.session_state.trace_log[trace_idx])
            trace_idx += 1

if "pending" in st.session_state:
    pending_message = st.session_state.pop("pending")
    with chat_col:
        with st.chat_message("user", avatar="👤"):
            st.write(pending_message)
        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("Supervisor is routing..."):
                reply, trace = run_agent(pending_message)
            st.write(reply)
            render_trace(trace)
    st.rerun()

with chat_col:
    user_input = st.chat_input("Ask anything. Example: 'Book appointment', 'Check stock', 'Show my bill'.")

if user_input:
    with chat_col:
        with st.chat_message("user", avatar="👤"):
            st.write(user_input)
        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("Supervisor is routing to the right agent..."):
                reply, trace = run_agent(user_input)
            st.write(reply)
            render_trace(trace)
