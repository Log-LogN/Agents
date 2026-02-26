"""
app.py
══════
ShopAI Customer Support — Streamlit UI

How it works
────────────
  This file contains ZERO LangGraph / LangChain imports.
  Every customer message is sent as JSON to the Supervisor MCP Server
  running on http://127.0.0.1:9001/mcp (streamable-http transport).
  The supervisor routes the request, calls the right specialist agent,
  and returns { final_reply, trace, messages } back over HTTP.

  UI  ──HTTP──►  Supervisor MCP (port 9001)
                     └──► Order / Returns / Product /
                           Payment / Complaints / Loyalty
                           (ports 8001 – 8006)

Usage
─────
    # Terminal 1
    python start_servers.py

    # Terminal 2
    streamlit run app.py
"""

import json
import html
import sys
import os

import httpx
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db import init_db   # only used for first-run DB init


# ── Supervisor endpoint ───────────────────────────────────────────────────────
SUPERVISOR_URL = "http://127.0.0.1:9001/chat"
HTTP_TIMEOUT   = 120   # seconds — LLM calls can be slow
MAX_CHAT_CONTEXT_MESSAGES = 16


# ── Page config ───────────────────────────────────────────────────────────────
def _page_config() -> None:
    st.set_page_config(
        page_title="ShopAI Support",
        page_icon="🛒",
        layout="wide",
        initial_sidebar_state="expanded",
    )


# ── Styles ────────────────────────────────────────────────────────────────────
_CSS = """
<style>
.stApp,[data-testid="stAppViewContainer"]{background:#0f172a!important}
.stApp *{color:#e2e8f0!important}
[data-testid="stSidebar"]{background:#1e293b!important;border-right:1px solid #334155}
[data-testid="stSidebar"] .stButton>button{
  background:#1d4ed8!important;color:#fff!important;border:none!important;
  border-radius:8px!important;width:100%!important;margin-bottom:5px!important;
  padding:9px 14px!important;font-size:13px!important;text-align:left!important}
[data-testid="stSidebar"] .stButton>button:hover{background:#2563eb!important}
[data-testid="stChatMessage"]{
  background:#1e293b!important;border:1px solid #334155!important;
  border-radius:12px!important;padding:12px 16px!important;margin-bottom:10px!important}
[data-testid="stChatInput"] textarea{
  background:#1e293b!important;color:#e2e8f0!important;
  border:1px solid #334155!important;border-radius:10px!important}
[data-testid="stChatInput"]{background:#0f172a!important;border-top:1px solid #334155!important}
.header-card{
  background:linear-gradient(135deg,#1e3a5f,#1d4ed8);
  padding:18px 24px;border-radius:12px;margin-bottom:16px;border:1px solid #334155}
.header-card h1{margin:0;font-size:20px;color:#fff!important}
.header-card p{margin:4px 0 0;font-size:12px;color:#93c5fd!important}
.trace-title{
  font-size:11px;font-weight:700;color:#60a5fa!important;letter-spacing:1px;
  text-transform:uppercase;padding-bottom:8px;
  border-bottom:1px solid #334155;margin-bottom:10px}
.route-card{
  background:#1e3a5f;border:1px solid #1d4ed8;border-left:5px solid #1d4ed8;
  border-radius:8px;padding:10px 14px;margin-bottom:8px}
.route-label{font-size:10px;font-weight:700;color:#60a5fa!important;margin-bottom:4px}
.route-to{font-size:14px;font-weight:700;color:#fbbf24!important}
.tool-call{
  background:#162032;border:1px solid #1d4ed8;border-left:4px solid #1d4ed8;
  border-radius:8px;padding:9px 13px;margin-bottom:7px}
.tool-result{
  background:#0f2e16;border:1px solid #15803d;border-left:4px solid #15803d;
  border-radius:8px;padding:9px 13px;margin-bottom:7px}
.badge{
  font-size:10px;font-weight:600;padding:2px 9px;border-radius:12px;
  margin-bottom:5px;display:inline-block}
.lbl{font-size:10px;font-weight:700;letter-spacing:0.5px;margin-bottom:3px}
.tool-call .lbl{color:#60a5fa!important}
.tool-result .lbl{color:#4ade80!important}
.tool-name{font-size:13px;font-weight:700;color:#fbbf24!important;margin-bottom:3px}
.tool-body{
  font-size:11px;font-family:monospace;white-space:pre-wrap;
  word-break:break-all;color:#cbd5e1!important}
.agent-row{display:flex;align-items:center;gap:8px;margin-bottom:7px}
.welcome-card{
  background:#1e293b;border:1px solid #334155;
  border-radius:8px;padding:14px;margin-bottom:10px}
.sup-badge{
  display:inline-block;background:#1e3a5f;border:1px solid #1d4ed8;
  color:#60a5fa!important;font-size:11px;font-weight:700;padding:3px 12px;
  border-radius:20px;margin-bottom:6px}
[data-testid="stExpander"]{
  border:1px solid #334155!important;border-radius:12px!important;
  background:#0f172a!important}
[data-testid="stExpander"] details summary p{
  font-weight:700!important;color:#dbeafe!important}
[data-testid="stExpander"] details summary{
  padding:2px 0!important}
.trace-shell{
  background:linear-gradient(180deg,#13213b,#0f172a);
  border:1px solid #334155;border-radius:12px;padding:10px 12px;margin:2px 0 10px}
.trace-overview{display:flex;flex-wrap:wrap;gap:8px}
.trace-pill{
  background:#1e293b;border:1px solid #334155;border-radius:999px;
  font-size:11px;font-weight:700;color:#93c5fd!important;padding:4px 10px}
.trace-step{
  border-radius:12px;padding:12px 14px;margin-bottom:10px;
  border:1px solid #334155;background:#111827}
.trace-step.route{border-left:4px solid #1d4ed8;background:#1b3358}
.trace-step.call{border-left:4px solid #2563eb;background:#15263f}
.trace-step.result{border-left:4px solid #16a34a;background:#102a1f}
.trace-step.other{border-left:4px solid #64748b}
.trace-step-head{display:flex;align-items:center;gap:8px;margin-bottom:7px}
.trace-step-index{
  background:#0f172a;border:1px solid #334155;border-radius:999px;
  font-size:10px;font-weight:700;padding:2px 8px;color:#93c5fd!important}
.trace-step-kind{
  font-size:10px;font-weight:800;letter-spacing:.5px;
  text-transform:uppercase;color:#60a5fa!important}
.trace-step-title{font-size:14px;font-weight:700;color:#f8fafc!important;line-height:1.35}
.trace-step-meta{font-size:12px;color:#bfdbfe!important;margin-top:4px}
.trace-details summary{cursor:pointer;font-size:11px;color:#93c5fd!important;margin-top:8px}
.trace-code{
  margin-top:8px;background:#0b1220;border:1px solid #334155;border-radius:8px;
  padding:10px;font-size:11px;line-height:1.4;color:#cbd5e1!important;
  white-space:pre-wrap;word-break:break-word}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-thumb{background:#334155;border-radius:4px}
hr{border-color:#334155!important}
</style>
"""

# ── Agent metadata (for trace colour-coding) ──────────────────────────────────
AGENTS = {
    "Order":      {"icon": "📦", "color": "#1d4ed8", "port": 8001},
    "Returns":    {"icon": "🔄", "color": "#c2410c", "port": 8002},
    "Product":    {"icon": "🏪", "color": "#0e7490", "port": 8003},
    "Payment":    {"icon": "💳", "color": "#5b21b6", "port": 8004},
    "Complaints": {"icon": "⭐", "color": "#b45309", "port": 8005},
    "Loyalty":    {"icon": "🎁", "color": "#15803d", "port": 8006},
}

QUICK_ACTIONS = {
    "📦 Track My Order":            "Where is my order? My email is aarav.sharma@shop.com",
    "🔄 Start a Return":            "I want to return an item from order #1. My email is aarav.sharma@shop.com",
    "💳 Check for Duplicate Charge":"I think I was charged twice for order #9. My email is anjali.nair@shop.com",
    "🏪 Check Product Stock":       "Is the Sony WH-1000XM5 in stock?",
    "⭐ File a Complaint":           "I want to file a complaint about order #3. Email is vikram.singh@shop.com",
    "🎁 Check Loyalty Points":      "How many loyalty points do I have? My email is sneha.patel@shop.com",
    "🔍 Search Products":           "Show me all electronics products you have",
    "🎟️  Validate Promo Code":      "Is the promo code SAVE10 valid for a ₹2000 order?",
    "📋 View All My Orders":        "Show all my orders for priya.mehta@shop.com",
    "💰 Get My Invoice":            "Get invoice for order #5. My email is sneha.patel@shop.com",
    "🏆 View Tier Status":          "What is my loyalty tier? My email is anjali.nair@shop.com",
    "🚨 Fraud Return Test":         "I want to return order #15. My email is serial.returner@shop.com",
}


# ── HTTP client: call Supervisor HTTP API on port 9001 ────────────────────────
def _call_supervisor(messages: list) -> dict:
    """
    Send the conversation history to the Supervisor HTTP API (port 9001)
    and return the parsed response dict.

    The API expects a JSON body:
      { "messages": [ { "role": ..., "content": ... }, ... ] }

    Returns a dict with keys: final_reply, trace, messages.
    On error returns: { "error": "...", "final_reply": "...", "trace": [] }
    """
    payload = {"messages": messages}

    try:
        resp = httpx.post(
            SUPERVISOR_URL,
            json=payload,
            timeout=HTTP_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        result = resp.json()

        if not isinstance(result, dict) or "final_reply" not in result:
            return {
                "error":       "Empty or malformed response from Supervisor server.",
                "final_reply": "⚠️ Supervisor server returned an empty response. Is it running?",
                "trace":       [],
                "messages":    messages,
            }

        return result

    except httpx.ConnectError:
        msg = (
            "⚠️ Cannot connect to the Supervisor Server on port 9001. "
            "Please run `python start_servers.py` in a separate terminal first."
        )
        return {"error": "ConnectError", "final_reply": msg, "trace": [], "messages": messages}
    except httpx.TimeoutException:
        msg = "⚠️ Supervisor Server timed out. The LLM call took too long."
        return {"error": "Timeout", "final_reply": msg, "trace": [], "messages": messages}
    except Exception as exc:
        msg = f"⚠️ Unexpected error calling Supervisor: {exc}"
        return {"error": str(exc), "final_reply": msg, "trace": [], "messages": messages}


# ── Trace renderer ────────────────────────────────────────────────────────────
def _render_trace(trace: list, placeholder) -> None:
    with placeholder.container():
        if not trace:
            st.markdown(
                '<p style="color:#475569;font-size:12px">'
                'Send a message to see live agent routing here!</p>',
                unsafe_allow_html=True,
            )
            return

        for step in trace:
            stype = step.get("type", "")

            if stype == "route":
                agent = step["to"]
                meta  = AGENTS.get(agent, AGENTS.get(agent.split()[0], {"icon": "🤖", "color": "#1d4ed8"}))
                st.markdown(
                    f'<div class="route-card">'
                    f'<div class="route-label">🧠 SUPERVISOR ROUTED TO</div>'
                    f'<div class="route-to">{meta["icon"]} {agent} Agent</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            elif stype == "tool_call":
                a    = step.get("agent", "")
                meta = AGENTS.get(a, AGENTS.get(a.split()[0], {"icon": "🤖", "color": "#1d4ed8"}))
                args = json.dumps(step.get("args", {}), indent=2, ensure_ascii=False)
                st.markdown(
                    f'<div class="tool-call">'
                    f'<span class="badge" style="background:{meta["color"]}22;color:{meta["color"]}">'
                    f'{meta["icon"]} {a} Agent</span>'
                    f'<div class="lbl">🔧 TOOL CALLED</div>'
                    f'<div class="tool-name">{step["tool"]}</div>'
                    f'<div class="tool-body">{args}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            elif stype == "tool_result":
                a    = step.get("agent", "")
                meta = AGENTS.get(a, AGENTS.get(a.split()[0], {"icon": "🤖", "color": "#15803d"}))
                r    = step.get("result", "")
                text = json.dumps(r, indent=2, ensure_ascii=False) if isinstance(r, (dict, list)) else str(r)
                if len(text) > 600:
                    text = text[:600] + "\n…(truncated)"
                st.markdown(
                    f'<div class="tool-result">'
                    f'<span class="badge" style="background:{meta["color"]}22;color:{meta["color"]}">'
                    f'{meta["icon"]} {a} Agent</span>'
                    f'<div class="lbl">✅ MCP RESULT</div>'
                    f'<div class="tool-name">{step["tool"]}</div>'
                    f'<div class="tool-body">{text}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )


# ── Conversation state helpers ─────────────────────────────────────────────────
def _render_trace_in_chat(trace: list) -> None:
    """
    Render routing trace inside the assistant chat message as a dropdown.
    """
    if not trace:
        return

    routes = sum(1 for step in trace if step.get("type") == "route")
    calls = sum(1 for step in trace if step.get("type") == "tool_call")
    results = sum(1 for step in trace if step.get("type") == "tool_result")

    with st.expander(f"Show Supervisor Routing Trace ({len(trace)} steps)", expanded=False):
        st.markdown(
            f'<div class="trace-shell"><div class="trace-overview">'
            f'<span class="trace-pill">{routes} routed</span>'
            f'<span class="trace-pill">{calls} tool calls</span>'
            f'<span class="trace-pill">{results} tool results</span>'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        for idx, step in enumerate(trace, start=1):
            stype = step.get("type", "trace")

            if stype == "route":
                agent = step.get("to", "Unknown")
                meta = AGENTS.get(agent, AGENTS.get(str(agent).split()[0], {"icon": "->", "color": "#1d4ed8"}))
                kind = "Route"
                title = f"Supervisor routed to {html.escape(str(agent))} Agent"
                subtitle = f"{meta['icon']} {html.escape(str(agent))} Agent selected"
                raw = html.escape(json.dumps(step, indent=2, ensure_ascii=False))
                css_class = "route"
            elif stype == "tool_call":
                agent = step.get("agent", "Agent")
                tool = step.get("tool", "tool")
                meta = AGENTS.get(agent, AGENTS.get(str(agent).split()[0], {"icon": "->", "color": "#1d4ed8"}))
                kind = "Tool Called"
                title = f"{html.escape(str(agent))} called {html.escape(str(tool))}"
                subtitle = f"{meta['icon']} waiting for MCP response"
                raw = html.escape(json.dumps(step.get("args", {}), indent=2, ensure_ascii=False))
                css_class = "call"
            elif stype == "tool_result":
                agent = step.get("agent", "Agent")
                tool = step.get("tool", "tool")
                meta = AGENTS.get(agent, AGENTS.get(str(agent).split()[0], {"icon": "->", "color": "#16a34a"}))
                kind = "MCP Result"
                title = f"{html.escape(str(agent))} received result from {html.escape(str(tool))}"
                subtitle = f"{meta['icon']} response returned to agent"
                result_payload = step.get("result", "")
                if isinstance(result_payload, (dict, list)):
                    raw_text = json.dumps(result_payload, indent=2, ensure_ascii=False)
                else:
                    raw_text = str(result_payload)
                if len(raw_text) > 800:
                    raw_text = raw_text[:800] + "\n...(truncated)"
                raw = html.escape(raw_text)
                css_class = "result"
            else:
                kind = "Trace"
                title = html.escape(stype.replace("_", " ").title())
                subtitle = "Additional trace event"
                raw = html.escape(json.dumps(step, indent=2, ensure_ascii=False))
                css_class = "other"

            st.markdown(
                f'<div class="trace-step {css_class}">'
                f'<div class="trace-step-head">'
                f'<span class="trace-step-index">Step {idx}</span>'
                f'<span class="trace-step-kind">{kind}</span>'
                f'</div>'
                f'<div class="trace-step-title">{title}</div>'
                f'<div class="trace-step-meta">{subtitle}</div>'
                f'<details class="trace-details">'
                f'<summary>View raw details</summary>'
                f'<pre class="trace-code">{raw}</pre>'
                f'</details>'
                f'</div>',
                unsafe_allow_html=True,
            )


def _to_plain(messages: list) -> list:
    """
    Convert the session's message list to plain dicts for JSON transport.
    The session stores either plain dicts (from previous exchanges) or
    Streamlit-friendly dicts with role/content.
    """
    out = []
    for m in messages:
        if isinstance(m, dict):
            role = m.get("role", "human")
            content = m.get("content", "")
            # Keep only chat turns; never resend tool traffic as context.
            if role == "human":
                out.append({"role": "human", "content": content})
            elif role == "ai" and not m.get("tool_calls"):
                out.append({"role": "ai", "content": content})
        else:
            # Fallback for any stray non-dict
            out.append({"role": "human", "content": str(m)})
    return out[-MAX_CHAT_CONTEXT_MESSAGES:]


# ── Run one turn through the supervisor ───────────────────────────────────────
def _run_turn(user_text: str) -> tuple[str, list]:
    """
    Append the user message, call the Supervisor MCP server,
    store the updated history, and return (reply, trace).
    """
    # Append user message as plain dict
    st.session_state.messages.append({"role": "human", "content": user_text})

    result = _call_supervisor(_to_plain(st.session_state.messages))

    # Keep UI history lightweight: human + final ai only.
    st.session_state.messages.append({
        "role": "ai",
        "content": result.get("final_reply", ""),
    })
    st.session_state.messages = _to_plain(st.session_state.messages)

    st.session_state.trace_log.append(result.get("trace", []))
    return result.get("final_reply", ""), result.get("trace", [])


# ── Sidebar ───────────────────────────────────────────────────────────────────
def _sidebar() -> None:
    with st.sidebar:
        st.markdown("## 🛒 ShopAI Support")
        st.markdown(
            '<div class="sup-badge">🧠 Supervisor → port 9001</div>',
            unsafe_allow_html=True,
        )
        st.markdown("---")

        st.markdown("### ⚡ Quick Actions")
        for label, msg in QUICK_ACTIONS.items():
            if st.button(label, key=f"qa_{label}"):
                st.session_state.pending_msg = msg

        st.markdown("---")
        st.markdown("### 🤖 Agents Online")
        # Supervisor row
        st.markdown(
            '<div class="agent-row">'
            '<span style="font-size:15px">🧠</span>'
            '<span style="font-size:12px;font-weight:500">Supervisor Agent</span>'
            '<span style="width:7px;height:7px;border-radius:50%;'
            'background:#f59e0b;display:inline-block;margin-left:auto"></span>'
            '</div>',
            unsafe_allow_html=True,
        )
        # Specialist rows
        for agent, meta in AGENTS.items():
            st.markdown(
                f'<div class="agent-row">'
                f'<span style="font-size:15px">{meta["icon"]}</span>'
                f'<span style="font-size:12px;font-weight:500">{agent} Agent</span>'
                f'<span style="width:7px;height:7px;border-radius:50%;'
                f'background:{meta["color"]};display:inline-block;margin-left:auto"></span>'
                f'</div>',
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.markdown("### 🌱 Test Accounts")
        st.markdown("""
<div style="font-size:11px;color:#94a3b8!important;line-height:1.9">
<b style="color:#60a5fa!important">Gold member:</b><br>aarav.sharma@shop.com<br><br>
<b style="color:#a78bfa!important">Platinum member:</b><br>anjali.nair@shop.com<br><br>
<b style="color:#f59e0b!important">Serial returner:</b><br>serial.returner@shop.com<br><br>
<b style="color:#f87171!important">Duplicate charge:</b><br>anjali.nair@shop.com, Order #9
</div>""", unsafe_allow_html=True)

        st.markdown("---")
        if st.button("🗑️ Clear Chat", key="clear_chat"):
            st.session_state.messages  = []
            st.session_state.trace_log = []
            st.rerun()
        st.caption("Supervisor MCP :9001 → Specialists :8001–8006")


# ── Welcome cards (shown on empty chat) ──────────────────────────────────────
def _welcome_cards() -> None:
    st.markdown("### 👋 How can I help you today?")
    cols  = st.columns(3)
    cards = [
        ("📦", "Order Tracking",    "Track delivery, cancel, update address"),
        ("🔄", "Returns & Refunds", "Returns, refunds, fraud detection"),
        ("🏪", "Products",          "Stock, pricing, catalogue, restock"),
        ("💳", "Payments",          "Charges, coupons, invoices, billing"),
        ("⭐", "Complaints",        "Reviews, replacements, escalations"),
        ("🎁", "Loyalty",           "Points, tiers, promo codes, rewards"),
    ]
    for i, (icon, title, desc) in enumerate(cards):
        with cols[i % 3]:
            st.markdown(
                f'<div class="welcome-card">'
                f'<div style="font-size:20px">{icon}</div>'
                f'<div style="font-weight:700;color:#60a5fa!important;margin:5px 0 3px">{title}</div>'
                f'<div style="font-size:11px;color:#64748b!important">{desc}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    st.markdown("---")


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    """
    Entry point for the Streamlit app.

    Initialises the DB (first run only), renders the UI, and handles
    all user input by forwarding it to the Supervisor MCP server.
    """
    _page_config()
    st.markdown(_CSS, unsafe_allow_html=True)

    # ── Session state init ────────────────────────────────────────────
    if "db_ready"   not in st.session_state:
        init_db()
        st.session_state.db_ready = True
    if "messages"   not in st.session_state:
        st.session_state.messages  = []
    if "trace_log"  not in st.session_state:
        st.session_state.trace_log = []

    # ── Sidebar ───────────────────────────────────────────────────────
    _sidebar()

    # ── Page header ───────────────────────────────────────────────────
    st.markdown(
        '<div class="header-card">'
        '<h1>🛒 ShopAI Customer Support — Multi-Agent System</h1>'
        '<p>Supervisor (port 9001) routes every query to the right specialist '
        '— Orders · Returns · Products · Payments · Complaints · Loyalty</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Two-column layout ─────────────────────────────────────────────
    chat_col = st.container()

    # Welcome cards (only on empty chat)
    with chat_col:
        if not st.session_state.messages:
            _welcome_cards()


    # Chat history
    with chat_col:
        ai_turn_idx = 0
        for msg in st.session_state.messages:
            role    = msg.get("role", "human") if isinstance(msg, dict) else "human"
            content = msg.get("content", "")   if isinstance(msg, dict) else str(msg)
            # Show only human and final-AI messages (skip tool messages)
            if role == "human":
                with st.chat_message("user", avatar="👤"):
                    st.write(content)
            elif role == "ai" and content and not msg.get("tool_calls"):
                with st.chat_message("assistant", avatar="🛒"):
                    st.write(content)
                    if ai_turn_idx < len(st.session_state.trace_log):
                        _render_trace_in_chat(st.session_state.trace_log[ai_turn_idx])
                ai_turn_idx += 1

    # ── Quick action handler ──────────────────────────────────────────
    if "pending_msg" in st.session_state:
        user_input = st.session_state.pop("pending_msg")
        with chat_col:
            with st.chat_message("user", avatar="👤"):
                st.write(user_input)
            with st.chat_message("assistant", avatar="🛒"):
                with st.spinner("🧠 Supervisor routing to specialist agent…"):
                    reply, trace = _run_turn(user_input)
                st.write(reply)
                _render_trace_in_chat(trace)
        st.rerun()

    # ── Chat input ────────────────────────────────────────────────────
    # Moved OUTSIDE of chat_col to ensure it sticks to the bottom
    user_input = st.chat_input(
        "Ask anything… e.g. 'Where is my order?', "
        "'I want to return an item', 'Check my loyalty points'"
    )

    if user_input:
        with chat_col:
            with st.chat_message("user", avatar="👤"):
                st.write(user_input)
            with st.chat_message("assistant", avatar="🛒"):
                with st.spinner("🧠 Supervisor routing to best agent…"):
                    reply, trace = _run_turn(user_input)
                st.write(reply)
                _render_trace_in_chat(trace)
        st.rerun()


if __name__ == "__main__":
    main()
