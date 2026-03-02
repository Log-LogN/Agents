"""Top-level page renderers for login and chat screens."""

import uuid

import streamlit as st

from ui.components import (
    render_agent_action_hub,
    render_email_approval_panel,
    render_header,
    render_sidebar,
    render_trace_panel,
)
from ui.services import call_report_tool, call_supervisor
from ui.styles import apply_styles
from utils.auth import authenticate


def _init_chat_state() -> None:
    if "chat" not in st.session_state:
        st.session_state.chat = []
    if "history" not in st.session_state:
        st.session_state.history = []
    if "trace" not in st.session_state:
        st.session_state.trace = []
    if "pending_email_approval" not in st.session_state:
        st.session_state.pending_email_approval = None


def render_login_page() -> None:
    apply_styles()
    st.markdown(
        """
        <div style='text-align:center;padding:30px 0 10px'>
          <h1 style='color:#fff;font-size:32px;margin-bottom:4px'>📊 FinReport AI</h1>
          <p style='color:#94a3b8;font-size:15px'>Automated Financial Report Generator</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _, center, _ = st.columns([1, 2, 1])
    with center:
        st.markdown('<div class="login-card">', unsafe_allow_html=True)
        st.markdown(
            '<p style="text-align:center;color:#60a5fa;font-size:18px;font-weight:700;margin-bottom:20px">Sign In</p>',
            unsafe_allow_html=True,
        )
        with st.form("login_form"):
            email = st.text_input("Email Address", placeholder="cfo@finapp.com")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submitted = st.form_submit_button("Sign In →")
            if submitted:
                if not email or not password:
                    st.error("Please enter both email and password.")
                else:
                    user = authenticate(email, password)
                    if user:
                        st.session_state.user = user
                        st.session_state.chat = []
                        st.session_state.history = []
                        st.session_state.trace = []
                        st.session_state.thread_id = str(uuid.uuid4())
                        st.rerun()
                    else:
                        st.error("❌ Invalid email or password. Please try again.")
        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander("🔑 Test Credentials", expanded=False):
        st.markdown(
            """
| Role | Email | Password |
|------|-------|----------|
| 🛡️ Admin | `admin@finapp.com` | admin123 |
| 💼 CFO | `cfo@finapp.com` | cfo123 |
| 📊 FP&A Analyst | `analyst@finapp.com` | analyst123 |
| 🏦 Controller | `controller@finapp.com` | ctrl123 |
            """
        )


def render_chat_page(user: dict) -> None:
    apply_styles()
    render_sidebar(user)
    render_header(user)
    render_agent_action_hub(user)
    _init_chat_state()

    assistant_idx = 0
    for msg in st.session_state.chat:
        with st.chat_message(msg["role"], avatar="👤" if msg["role"] == "user" else "📊"):
            st.markdown(msg["content"])
            if msg["role"] == "assistant" and msg.get("trace"):
                assistant_idx += 1
                render_trace_panel(msg.get("trace", []), trace_id=assistant_idx)

    if st.session_state.get("pending_email_approval"):
        with st.chat_message("assistant", avatar="📊"):
            render_email_approval_panel(call_report_tool)

    default_prompt = st.session_state.pop("quick_prompt", None)
    has_pending_approval = bool(st.session_state.get("pending_email_approval"))
    user_input = st.chat_input(
        "Ask about P&L, cash position, KPIs, budgets, balance sheet…",
        disabled=has_pending_approval,
    ) or default_prompt

    if not user_input:
        return

    st.session_state.chat.append({"role": "user", "content": user_input})
    with st.chat_message("user", avatar="👤"):
        st.markdown(user_input)

    enriched_msg = (
        f"[User: {user['name']} | Role: {user['role']} | Email: {user['email']}]\n\n"
        f"{user_input}"
    )
    st.session_state.history.append({"role": "human", "content": enriched_msg})

    with st.chat_message("assistant", avatar="📊"):
        with st.spinner("Analysing…"):
            result = call_supervisor(st.session_state.history)
        reply = result.get("final_reply", "⚠️ No response received.")
        st.markdown(reply)

    reply_trace = result.get("trace", [])
    st.session_state.chat.append({"role": "assistant", "content": reply, "trace": reply_trace})
    st.session_state.history.append({"role": "ai", "content": reply})
    st.session_state.trace = reply_trace

    approval_request = result.get("approval_request")
    if isinstance(approval_request, dict) and approval_request.get("requires_approval"):
        st.session_state.pending_email_approval = approval_request

    if result.get("messages"):
        st.session_state.history = result["messages"]

    st.rerun()

