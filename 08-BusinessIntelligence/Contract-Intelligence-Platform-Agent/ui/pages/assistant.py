"""Chat Assistant page - multi-agent natural language interface with optional debug trace."""

import os
import uuid

import streamlit as st


def render_assistant():
    st.title("AI Contract Assistant")
    st.caption("Powered by multi-agent AI - ask anything about your contracts")

    user = st.session_state.get("user", {})
    user_id = user.get("id", 1)
    role = user.get("role", "viewer")

    session_id = st.session_state.get("session_id", str(uuid.uuid4()))
    if "session_id" not in st.session_state:
        st.session_state["session_id"] = session_id

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    if "assistant_debug_mode" not in st.session_state:
        st.session_state["assistant_debug_mode"] = False

    st.toggle("Debug Mode", key="assistant_debug_mode", help="Use /debug/chat and show full supervisor trace")

    st.markdown("**Quick Actions:**")
    qcols = st.columns(4)
    quick = [
        ("Portfolio Overview", "Give me a summary of my contract portfolio"),
        ("Expiring Contracts", "Show contracts expiring in the next 90 days"),
        ("High Risk Contracts", "Show me high risk contracts that need attention"),
        ("Pending Obligations", "List all pending obligations due soon"),
    ]

    for i, (label, prompt) in enumerate(quick):
        if qcols[i].button(label, use_container_width=True):
            st.session_state["chat_history"].append({"role": "user", "content": prompt})
            with st.spinner("Processing..."):
                response_data = _call_supervisor(prompt, user_id, session_id, role, st.session_state["assistant_debug_mode"])
            st.session_state["chat_history"].append({"role": "assistant", **response_data})
            st.rerun()

    st.markdown("---")

    with st.container():
        for msg in st.session_state["chat_history"]:
            if msg["role"] == "user":
                with st.chat_message("user"):
                    st.markdown(msg["content"])
            else:
                with st.chat_message("assistant", avatar="⚖️"):
                    st.markdown(msg.get("content", ""))
                    debug_payload = msg.get("debug")
                    if debug_payload:
                        with st.expander("Debug Trace"):
                            st.json(debug_payload)

    if prompt := st.chat_input("Ask about contracts, compliance, obligations, risk..."):
        st.session_state["chat_history"].append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant", avatar="⚖️"):
            with st.spinner("Thinking..."):
                response_data = _call_supervisor(prompt, user_id, session_id, role, st.session_state["assistant_debug_mode"])
            st.markdown(response_data.get("content", ""))
            if response_data.get("debug"):
                with st.expander("Debug Trace"):
                    st.json(response_data["debug"])

        st.session_state["chat_history"].append({"role": "assistant", **response_data})

    if st.session_state["chat_history"]:
        if st.button("Clear Chat", key="clear_chat"):
            st.session_state["chat_history"] = []
            st.rerun()


def _call_supervisor(message: str, user_id: int, session_id: str, role: str, debug_mode: bool) -> dict:
    try:
        import httpx

        port = os.getenv("SUPERVISOR_PORT", "8000")
        endpoint = "/debug/chat" if debug_mode else "/chat"

        response = httpx.post(
            f"http://localhost:{port}{endpoint}",
            json={"message": message, "user_id": user_id, "session_id": session_id, "role": role},
            timeout=60,
        )
        if response.status_code == 200:
            payload = response.json()
            return {
                "content": payload.get("response", "No response received."),
                "debug": payload.get("debug") if debug_mode else None,
                "intent": payload.get("intent", "UNKNOWN"),
                "duration_ms": payload.get("duration_ms", 0),
                "error": payload.get("error", ""),
            }
        return {
            "content": f"Supervisor returned status {response.status_code}.",
            "debug": {"http_status": response.status_code, "body": response.text} if debug_mode else None,
            "intent": "UNKNOWN",
            "duration_ms": 0,
            "error": "http_error",
        }
    except Exception as exc:
        # Fallback: call supervisor graph directly
        try:
            from supervisor.graph import run_supervisor, run_supervisor_debug

            if debug_mode:
                payload = run_supervisor_debug(message, user_id, session_id, role)
            else:
                payload = run_supervisor(message, user_id, session_id, role)
            return {
                "content": payload.get("response", "No response."),
                "debug": payload.get("debug") if debug_mode else None,
                "intent": payload.get("intent", "UNKNOWN"),
                "duration_ms": payload.get("duration_ms", 0),
                "error": payload.get("error", ""),
            }
        except Exception as fallback_exc:
            return {
                "content": f"Supervisor unavailable. Error: {fallback_exc}",
                "debug": {"exception": repr(exc), "fallback_exception": repr(fallback_exc)} if debug_mode else None,
                "intent": "UNKNOWN",
                "duration_ms": 0,
                "error": "unavailable",
            }
