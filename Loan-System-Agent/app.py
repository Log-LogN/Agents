"""
app.py — Loan & Credit Multi-Agent System
Streamlit UI with Chat + Integrated Supervisor Trace Expanders
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
from langchain_core.messages import HumanMessage, AIMessage
from database.db import init_db
from langchain_mcp_adapters.client import MultiServerMCPClient
import asyncio
AGENTS = {
    "Application":  {"icon": "📝", "color": "#1d4ed8", "port": 8001},
    "Kyc":          {"icon": "🔍", "color": "#c2410c", "port": 8002},
    "Credit Risk":  {"icon": "📊", "color": "#5b21b6", "port": 8003},
    "Underwriting": {"icon": "⚖️",  "color": "#15803d", "port": 8004},
    "Repayment":    {"icon": "💳", "color": "#9b1c1c", "port": 8005},
}

# ── Quick actions ─────────────────────────────────────────────────────────────
QUICK = {
    "📝 Apply for Loan":          "I want to apply for a personal loan of ₹5,00,000",
    "👤 Register as Applicant":   "I want to register as a new loan applicant",
    "🔍 Check KYC Status":        "Check my KYC verification status for aarav.sharma@email.com",
    "📊 Get Credit Score":        "Calculate my credit score for aarav.sharma@email.com",
    "⚖️ Approve a Loan":           "Run underwriting decision for application #1",
    "💳 Make a Payment":          "I want to record a payment for my loan",
    "📋 View Loan Status":        "Show my loan status for aarav.sharma@email.com",
    "📅 View Repayment Schedule": "Show repayment schedule for loan #1",
    "⚠️ Missed Payment Help":     "I missed my payment this month, what can I do?",
    "🚨 Default Risk Check":      "Check default risk for defaulter.mike@email.com",
    "💡 Loan Types Available":    "What types of loans do you offer?",
    "📈 View All Applications":   "Show all applications for aarav.sharma@email.com",
}

# ── Trace renderer ────────────────────────────────────────────────────────────
def render_trace(trace: list):
    if not trace:
        st.info("No routing trace available for this message.")
        return
    for step in trace:
        if step["type"] == "route":
            agent = step["to"]
            meta  = AGENTS.get(agent, AGENTS.get(agent.split()[0], {"icon":"🤖","color":"#1d4ed8"}))
            st.markdown(f"""<div class="route-card">
              <div class="route-label">🧠 SUPERVISOR ROUTED TO</div>
              <div class="route-to">{meta['icon']} {agent} Agent</div>
            </div>""", unsafe_allow_html=True)

        elif step["type"] == "tool_call":
            agent = step.get("agent", "")
            meta  = AGENTS.get(agent, AGENTS.get(agent.split()[0], {"icon":"🤖","color":"#1d4ed8"}))
            args  = json.dumps(step["args"], indent=2, ensure_ascii=False)
            st.markdown(f"""<div class="tool-call">
              <span class="card-agent" style="background:{meta['color']}22;color:{meta['color']}">{meta['icon']} {agent} Agent</span>
              <div class="card-label">🔧 TOOL CALLED</div>
              <div class="card-name">{step['tool']}</div>
              <div class="card-body">{args}</div>
            </div>""", unsafe_allow_html=True)

        elif step["type"] == "tool_result":
            agent = step.get("agent", "")
            meta  = AGENTS.get(agent, AGENTS.get(agent.split()[0], {"icon":"🤖","color":"#15803d"}))
            r     = step["result"]
            text  = json.dumps(r, indent=2, ensure_ascii=False) if isinstance(r, (dict, list)) else str(r)
            if len(text) > 600: text = text[:600] + "\n...(truncated)"
            st.markdown(f"""<div class="tool-result">
              <span class="card-agent" style="background:{meta['color']}22;color:{meta['color']}">{meta['icon']} {agent} Agent</span>
              <div class="card-label">✅ MCP RESULT</div>
              <div class="card-name">{step['tool']}</div>
              <div class="card-body">{text}</div>
            </div>""", unsafe_allow_html=True)

import requests

# ── Run agent (Via HTTP) ──────────────────────────────────────────────────────
def run_agent(user_text: str):
    st.session_state.messages.append(HumanMessage(content=user_text))
    
    # We serialize the message history and send it to the Supervisor FastAPI server
    msgs_for_mcp = []
    for m in st.session_state.messages:
        if isinstance(m, HumanMessage):
            msgs_for_mcp.append({"role": "user", "content": m.content})
        elif isinstance(m, AIMessage):
            msgs_for_mcp.append({"role": "assistant", "content": m.content, "tool_calls": getattr(m, "tool_calls", [])})
        elif getattr(m, "type", "") == "tool":
            msgs_for_mcp.append({"role": "tool", "content": m.content, "tool_call_id": getattr(m, "tool_call_id", ""), "name": getattr(m, "name", "")})
    
    try:
        url = "http://127.0.0.1:9001/chat"
        resp = requests.post(url, json={"messages": msgs_for_mcp}, timeout=120)
        
        if resp.status_code != 200:
            return f"Error from Supervisor: {resp.text}", []
            
        parsed = resp.json()
            
        # Update chat history from the server's response
        new_history = []
        for m in parsed.get("messages", []):
            role = m.get("role", "")
            content = m.get("content", "")
            if role in ("human", "user"):
                new_history.append(HumanMessage(content=content))
            elif role in ("ai", "assistant"):
                new_history.append(AIMessage(content=content, tool_calls=m.get("tool_calls", [])))
            elif role == "tool":
                from langchain_core.messages import ToolMessage
                new_history.append(ToolMessage(content=content, tool_call_id=m.get("tool_call_id", ""), name=m.get("name", "")))
                
        st.session_state.messages = new_history
        st.session_state.trace_log.append(parsed.get("trace", []))
        
        return parsed.get("final_reply", "No reply received"), parsed.get("trace", [])
            
    except Exception as e:
        import traceback
        return f"Error connecting to Supervisor Server: {e}\\n{traceback.format_exc()}", []

def main():
    st.set_page_config(
        page_title="Loan AI System",
        page_icon="🏦",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ── Styles ────────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    .stApp,[data-testid="stAppViewContainer"]{background:#0f172a!important}
    .stApp *{color:#e2e8f0!important}
    [data-testid="stSidebar"]{background:#1e293b!important;border-right:1px solid #334155}
    [data-testid="stSidebar"] .stButton>button{
      background:#1d4ed8!important;color:#fff!important;border:none!important;
      border-radius:8px!important;width:100%!important;margin-bottom:6px!important;
      padding:10px 14px!important;font-size:13px!important;text-align:left!important}
    [data-testid="stSidebar"] .stButton>button:hover{background:#2563eb!important}
    [data-testid="stChatMessage"]{background:#1e293b!important;border:1px solid #334155!important;
      border-radius:12px!important;padding:12px 16px!important;margin-bottom:10px!important}
    [data-testid="stChatInput"] textarea{background:#1e293b!important;color:#e2e8f0!important;
      border:1px solid #334155!important;border-radius:10px!important}
    [data-testid="stChatInput"]{background:#0f172a!important;border-top:1px solid #334155!important}
    .header-card{background:linear-gradient(135deg,#1e3a5f,#1d4ed8);
      padding:20px 26px;border-radius:12px;margin-bottom:18px;border:1px solid #334155}
    .header-card h1{margin:0;font-size:22px;color:#fff!important}
    .header-card p{margin:4px 0 0;font-size:13px;color:#93c5fd!important}
    .trace-title{font-size:11px;font-weight:700;color:#60a5fa!important;letter-spacing:1px;
      text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid #334155;margin-bottom:12px}
    .route-card{background:#1e3a5f;border:1px solid #1d4ed8;border-left:5px solid #1d4ed8;
      border-radius:8px;padding:12px 16px;margin-bottom:8px}
    .route-to{font-size:14px;font-weight:700;color:#fbbf24!important}
    .route-label{font-size:11px;font-weight:600;color:#60a5fa!important;margin-bottom:4px}
    .tool-call{background:#162032;border:1px solid #1d4ed8;border-left:4px solid #1d4ed8;
      border-radius:8px;padding:10px 14px;margin-bottom:8px}
    .tool-result{background:#0f2e16;border:1px solid #15803d;border-left:4px solid #15803d;
      border-radius:8px;padding:10px 14px;margin-bottom:8px}
    .card-agent{font-size:11px;font-weight:600;padding:2px 10px;border-radius:12px;margin-bottom:6px;display:inline-block}
    .card-label{font-size:11px;font-weight:700;letter-spacing:0.5px;margin-bottom:4px}
    .tool-call .card-label{color:#60a5fa!important}
    .tool-result .card-label{color:#4ade80!important}
    .card-name{font-size:13px;font-weight:700;color:#fbbf24!important;margin-bottom:4px}
    .card-body{font-size:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#cbd5e1!important}
    .agent-online{display:flex;align-items:center;gap:8px;margin-bottom:8px}
    ::-webkit-scrollbar{width:4px}
    ::-webkit-scrollbar-thumb{background:#334155;border-radius:4px}
    hr{border-color:#334155!important}
    </style>
    """, unsafe_allow_html=True)

    # ── Init ──────────────────────────────────────────────────────────────────────
    if "db_ready"   not in st.session_state:
        init_db(); st.session_state.db_ready = True
    if "messages"   not in st.session_state: st.session_state.messages   = []
    if "trace_log"  not in st.session_state: st.session_state.trace_log  = []

    # ── Sidebar ───────────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("## 🏦 Loan AI System")
        st.markdown("---")
        st.markdown("### ⚡ Quick Actions")
        for label, msg in QUICK.items():
            if st.button(label, key=f"qa_{label}"):
                st.session_state.pending_msg = msg

        st.markdown("---")
        st.markdown("### 🤖 Agents Online")
        for agent, meta in AGENTS.items():
            st.markdown(
                f'<div class="agent-online">'
                f'<span style="font-size:16px">{meta["icon"]}</span>'
                f'<span style="font-size:13px;font-weight:500">{agent} Agent</span>'
                f'<span style="width:8px;height:8px;border-radius:50%;background:{meta["color"]};display:inline-block;margin-left:auto"></span>'
                f'</div>', unsafe_allow_html=True
            )

        st.markdown("---")
        st.markdown("### 🌱 Seeded Test Accounts")
        st.markdown("""
    <div style="font-size:12px;color:#94a3b8!important">
    <b style="color:#60a5fa!important">Good applicant:</b><br>
    aarav.sharma@email.com<br><br>
    <b style="color:#f59e0b!important">Fraud flagged:</b><br>
    fraud.test@email.com<br><br>
    <b style="color:#f87171!important">High default risk:</b><br>
    defaulter.mike@email.com
    </div>""", unsafe_allow_html=True)

        st.markdown("---")
        if st.button("🗑️ Clear Chat", key="clear_chat"):
            st.session_state.messages  = []
            st.session_state.trace_log = []
            st.rerun()
        st.caption("LangGraph Supervisor + 5 MCP Agents + PostgreSQL")

    # ── Layout ────────────────────────────────────────────────────────────────────
    st.markdown("""<div class="header-card">
      <h1>🏦 Loan & Credit AI — Multi-Agent System</h1>
      <p>Supervisor routes your request to the right specialist: Application · KYC · Credit Risk · Underwriting · Repayment</p>
    </div>""", unsafe_allow_html=True)

    # Welcome grid
    if not st.session_state.messages:
        st.markdown("### 👋 Welcome — what can I help you with?")
        cols = st.columns(3)
        cards = [
            ("📝", "Application",  "Apply for loans, register, check status"),
            ("🔍", "KYC",          "Identity, document & AML verification"),
            ("📊", "Credit Risk",  "Credit score, DTI, risk assessment"),
            ("⚖️",  "Underwriting", "Loan approval, EMI & terms"),
            ("💳", "Repayment",   "Payments, schedule, restructuring"),
            ("🌱", "Seed Data",   "12 applicants pre-loaded — try them!"),
        ]
        for i, (icon, title, desc) in enumerate(cards):
            with cols[i % 3]:
                st.markdown(
                    f'<div style="background:#1e293b;border:1px solid #334155;border-radius:8px;'
                    f'padding:14px;margin-bottom:10px">'
                    f'<div style="font-size:22px">{icon}</div>'
                    f'<div style="font-weight:700;color:#60a5fa!important;margin:6px 0 4px">{title}</div>'
                    f'<div style="font-size:12px;color:#64748b!important">{desc}</div></div>',
                    unsafe_allow_html=True
                )
        st.markdown("---")

    # Chat history
    ai_msg_count = 0
    for msg in st.session_state.messages:
        if isinstance(msg, HumanMessage):
            with st.chat_message("user", avatar="👤"):
                st.write(msg.content)
        elif isinstance(msg, AIMessage) and msg.content and not getattr(msg, "tool_calls", None):
            with st.chat_message("assistant", avatar="🏦"):
                st.write(msg.content)
                # Find the trace for this assistant message
                if ai_msg_count < len(st.session_state.trace_log):
                    with st.expander("🔍 Show Supervisor Routing Trace"):
                        render_trace(st.session_state.trace_log[ai_msg_count])
                ai_msg_count += 1

    # Quick action handler
    if "pending_msg" in st.session_state:
        user_input = st.session_state.pop("pending_msg")
        with st.chat_message("user", avatar="👤"): st.write(user_input)
        with st.chat_message("assistant", avatar="🏦"):
            with st.spinner("🧠 Routing to specialist agent..."):
                reply, trace = run_agent(user_input)
            st.write(reply)
            with st.expander("🔍 Show Supervisor Routing Trace", expanded=True):
                render_trace(trace)
        st.rerun()

    # Chat input
    user_input = st.chat_input(
        "Ask anything... e.g. 'Apply for a home loan', 'Check my credit score', 'Record payment for loan #1'"
    )

    if user_input:
        with st.chat_message("user", avatar="👤"): st.write(user_input)
        with st.chat_message("assistant", avatar="🏦"):
            with st.spinner("🧠 Supervisor routing to best agent..."):
                reply, trace = run_agent(user_input)
            st.write(reply)
            with st.expander("🔍 Show Supervisor Routing Trace", expanded=True):
                render_trace(trace)

if __name__ == "__main__":
    main()
