"""Reusable Streamlit UI components."""

import html
import json
import uuid

import streamlit as st

from ui.constants import AGENT_ICONS, ROLE_QUICK_ACTIONS, actions_for_agent
from utils.auth import ROLE_AGENTS, ROLE_COLORS, ROLE_LABELS


def render_sidebar(user: dict) -> None:
    role = user["role"]
    color = ROLE_COLORS.get(role, "#1d4ed8")
    agents = ROLE_AGENTS.get(role, [])

    with st.sidebar:
        st.markdown(
            f"""
            <div style='padding:12px;background:#0f172a;border-radius:8px;margin-bottom:12px;
                        border:1px solid #334155;text-align:center'>
              <p style='margin:0;font-weight:700;font-size:15px;color:#e2e8f0'>{user["name"]}</p>
              <p style='margin:2px 0;font-size:12px;color:#94a3b8'>{user["email"]}</p>
              <span class='role-badge' style='background:{color}20;color:{color};border:1px solid {color}40'>
                {ROLE_LABELS.get(role, role)}
              </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("---")
        st.markdown(
            "<p style='color:#94a3b8;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase'>Quick Actions</p>",
            unsafe_allow_html=True,
        )
        for label, prompt in ROLE_QUICK_ACTIONS.get(role, []):
            if st.button(label, key=f"qa_{label}"):
                st.session_state.quick_prompt = prompt

        st.markdown(
            f"<p style='color:#94a3b8;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase'>Your Agents ({len(agents)})</p>",
            unsafe_allow_html=True,
        )
        for agent in agents:
            icon = AGENT_ICONS.get(agent, "🤖")
            st.markdown(
                f"""
                <div style='padding:7px 10px;background:#0f172a;border-radius:6px;margin-bottom:4px;
                            border:1px solid #1e293b;font-size:12px'>
                  {icon} {agent}
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🗑️ Clear", use_container_width=True):
                st.session_state.chat = []
                st.session_state.history = []
                st.session_state.trace = []
                st.session_state.pending_email_approval = None
                st.session_state.thread_id = str(uuid.uuid4())
                st.rerun()
        with col2:
            if st.button("🚪 Logout", use_container_width=True):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()


def render_header(user: dict) -> None:
    role = user["role"]
    color = ROLE_COLORS.get(role, "#1d4ed8")
    st.markdown(
        f"""
        <div class="header-card">
          <h1>📊 FinReport AI — Financial Intelligence Platform</h1>
          <p>Logged in as <strong style="color:#fff">{user["name"]}</strong>
             &nbsp;|&nbsp; Role: <strong style="color:{color}">{ROLE_LABELS.get(role, role)}</strong>
             &nbsp;|&nbsp; Department: {user.get("department","—")}
             &nbsp;|&nbsp; Access: {len(ROLE_AGENTS.get(role,[]))} agents</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_agent_action_hub(user: dict) -> None:
    role = user["role"]
    agents = ROLE_AGENTS.get(role, [])
    if not agents:
        return

    if "selected_agent" not in st.session_state:
        st.session_state.selected_agent = None
    if st.session_state.selected_agent not in agents:
        st.session_state.selected_agent = None

    st.markdown(
        """
        <div class="agent-hub">
          <div class="agent-hub-title">Agent Action Hub</div>
          <div class="agent-hub-sub">Click an agent card to open that agent's quick actions.</div>
        """,
        unsafe_allow_html=True,
    )

    selected_agent = st.session_state.selected_agent
    if not selected_agent:
        cols = st.columns(4)
        for idx, agent in enumerate(agents):
            icon = AGENT_ICONS.get(agent, "🤖")
            with cols[idx % 4]:
                if st.button(f"{icon} {agent}", key=f"agent_card_{agent}", use_container_width=True):
                    st.session_state.selected_agent = agent
                    st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        return

    top1, top2 = st.columns([4, 1])
    with top1:
        st.markdown(
            f"<p style='font-size:12px;color:#93c5fd;margin:10px 0 8px'>Actions for: <strong>{selected_agent}</strong></p>",
            unsafe_allow_html=True,
        )
    with top2:
        if st.button("⬅ Back", key="agent_hub_back", use_container_width=True):
            st.session_state.selected_agent = None
            st.rerun()

    action_cols = st.columns(3)
    for idx, (label, prompt) in enumerate(actions_for_agent(role, selected_agent)):
        with action_cols[idx % 3]:
            if st.button(label, key=f"agent_action_{selected_agent}_{idx}", use_container_width=True):
                st.session_state.quick_prompt = prompt
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def render_trace_panel(trace: list, trace_id: int | None = None) -> None:
    if not trace:
        return

    routed = 0
    tool_calls = 0
    tool_results = 0
    for step in trace:
        stype = step.get("type", "")
        label = str(step.get("label", "")).lower()
        if stype == "tool_result":
            tool_results += 1
        elif stype == "tool_call":
            if "routed to" in label:
                routed += 1
            else:
                tool_calls += 1

    title = f"Show Supervisor Routing Trace ({len(trace)} steps)"
    if trace_id is not None:
        title = f"Show Supervisor Routing Trace · Reply {trace_id} ({len(trace)} steps)"

    with st.expander(title, expanded=False):
        st.markdown(
            f"""
            <div class="trace-shell">
              <div class="trace-badges">
                <span class="trace-pill">{routed} routed</span>
                <span class="trace-pill">{tool_calls} tool calls</span>
                <span class="trace-pill">{tool_results} tool results</span>
              </div>
            """,
            unsafe_allow_html=True,
        )
        for idx, step in enumerate(trace, start=1):
            label = str(step.get("label", "")).strip()
            stype = step.get("type", "")
            label_l = label.lower()

            if stype == "tool_call" and "routed to" in label_l:
                kind = "ROUTE"
                css_class = "route"
                note = "Supervisor selected specialist agent"
            elif stype == "tool_call":
                kind = "TOOL CALLED"
                css_class = "tool_call"
                note = "Specialist invoked MCP tool"
            elif stype == "tool_result":
                kind = "MCP RESULT"
                css_class = "tool_result"
                note = "Tool response returned to specialist"
            elif stype == "reply":
                kind = "FINAL REPLY"
                css_class = "reply"
                note = "Final answer generated"
            else:
                kind = "ERROR"
                css_class = "error"
                note = "Execution issue detected"

            safe_label = html.escape(label)
            raw_json = html.escape(json.dumps(step, ensure_ascii=True, indent=2))
            st.markdown(
                f"""
                <div class="trace-card {css_class}">
                  <div class="trace-step-top">
                    <span class="trace-step-num">Step {idx}</span>
                    <span class="trace-step-kind">{kind}</span>
                  </div>
                  <div class="trace-step-title">{safe_label}</div>
                  <div class="trace-step-note">{note}</div>
                  <details class="trace-details">
                    <summary>View raw details</summary>
                    <pre>{raw_json}</pre>
                  </details>
                </div>
                """,
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)


def render_email_approval_panel(call_report_tool_fn) -> None:
    pending = st.session_state.get("pending_email_approval")
    if not pending:
        return

    preview = pending.get("email_preview", {})
    st.markdown(
        """
        <div class="approval-shell">
          <div class="approval-title">Email Approval Required</div>
          <div style="font-size:12px;color:#94a3b8">Review this outgoing email request before sending.</div>
        """,
        unsafe_allow_html=True,
    )

    title = preview.get("title", "Email")
    to_val = preview.get("to", "N/A")
    subject = preview.get("subject", "N/A")
    period = preview.get("period", "N/A")
    st.markdown(
        f"""
        <div class="approval-grid">
          <div class="approval-cell"><div class="approval-label">Type</div><div class="approval-value">{html.escape(str(title))}</div></div>
          <div class="approval-cell"><div class="approval-label">To</div><div class="approval-value">{html.escape(str(to_val))}</div></div>
          <div class="approval-cell"><div class="approval-label">Subject</div><div class="approval-value">{html.escape(str(subject))}</div></div>
          <div class="approval-cell"><div class="approval-label">Period</div><div class="approval-value">{html.escape(str(period))}</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if preview.get("summary_preview") and not isinstance(preview.get("summary_preview"), dict):
        st.markdown("**Content Preview**")
        st.code(str(preview.get("summary_preview")), language="text")
    if preview.get("message_preview"):
        st.markdown("**Message Preview**")
        st.code(str(preview.get("message_preview")), language="text")
    if preview.get("message_full"):
        with st.expander("Full Alert Message", expanded=True):
            st.code(str(preview.get("message_full")), language="text")
    if preview.get("summary_preview") and isinstance(preview["summary_preview"], dict):
        st.markdown("**Section Preview**")
        st.json(preview["summary_preview"])
    if preview.get("full_sections") and isinstance(preview["full_sections"], dict):
        with st.expander("Full Board Pack Sections", expanded=False):
            st.json(preview["full_sections"])

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Approve & Send", key="email_approval_approve", use_container_width=True):
            with st.spinner("Sending approved email..."):
                result = call_report_tool_fn(
                    pending.get("tool_name", ""),
                    {"approval_token": pending.get("approval_token", "")},
                )
            ok = bool(result.get("success"))
            msg = result.get("message", "Email action completed." if ok else "Email action failed.")
            text = f"✅ Approval granted. {msg}" if ok else f"⚠️ Approval granted, but send failed: {msg}"
            st.session_state.chat.append({"role": "assistant", "content": text, "trace": []})
            st.session_state.history.append({"role": "ai", "content": text})
            st.session_state.pending_email_approval = None
            st.rerun()
    with c2:
        if st.button("Reject", key="email_approval_reject", use_container_width=True):
            st.session_state.pending_email_approval = None
            reject_msg = "❌ Email sending request rejected. Pending email action has been stopped."
            st.session_state.chat.append({"role": "assistant", "content": reject_msg, "trace": []})
            st.session_state.history.append({"role": "ai", "content": reject_msg})
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

