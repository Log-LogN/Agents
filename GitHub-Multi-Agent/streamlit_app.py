import html
import json
import re
import uuid
from typing import Any, Generator

import requests
import streamlit as st

SUPERVISOR_URL = "http://localhost:8000"
STREAM_ENDPOINT = "/chat/stream"
MAX_SUPERVISOR_MESSAGE_LEN = 1800


def stream_chat(
    query: str,
    session_id: str,
    supervisor_url: str = SUPERVISOR_URL,
    api_key: str | None = None,
) -> Generator[dict[str, Any], None, None]:
    """Stream SSE events from supervisor /chat/stream."""
    url = f"{supervisor_url.rstrip('/')}{STREAM_ENDPOINT}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {"message": query, "session_id": session_id}

    try:
        with requests.post(
            url,
            headers=headers,
            json=payload,
            stream=True,
            timeout=(10, 120),
        ) as resp:
            resp.raise_for_status()

            event_name = None
            data_lines: list[str] = []
            event_id = None

            for raw_line in resp.iter_lines(decode_unicode=True):
                if raw_line is None:
                    continue

                line = raw_line.strip("\r")

                # Empty line marks end of one SSE event block.
                if line == "":
                    if event_name:
                        raw_data = "\n".join(data_lines).strip()
                        parsed_data: dict[str, Any] = {}
                        if raw_data:
                            try:
                                parsed_data = json.loads(raw_data)
                            except json.JSONDecodeError:
                                parsed_data = {"raw": raw_data}

                        yield {
                            "event": event_name,
                            "data": parsed_data,
                            "timestamp": event_id or parsed_data.get("timestamp", ""),
                        }

                    event_name = None
                    data_lines = []
                    event_id = None
                    continue

                if line.startswith("event:"):
                    event_name = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].strip())
                elif line.startswith("id:"):
                    event_id = line[3:].strip()

            # Flush final event if stream ends without trailing blank line.
            if event_name:
                raw_data = "\n".join(data_lines).strip()
                parsed_data: dict[str, Any] = {}
                if raw_data:
                    try:
                        parsed_data = json.loads(raw_data)
                    except json.JSONDecodeError:
                        parsed_data = {"raw": raw_data}
                yield {
                    "event": event_name,
                    "data": parsed_data,
                    "timestamp": event_id or parsed_data.get("timestamp", ""),
                }

    except requests.HTTPError as exc:
        detail = ""
        if exc.response is not None:
            try:
                detail = exc.response.text[:400]
            except Exception:
                detail = ""
        yield {
            "event": "error",
            "data": {"message": f"HTTP error: {exc}. {detail}"},
            "timestamp": "",
        }
    except requests.RequestException as exc:
        yield {
            "event": "error",
            "data": {"message": f"Connection error: {exc}"},
            "timestamp": "",
        }
    except Exception as exc:
        yield {
            "event": "error",
            "data": {"message": f"Unexpected stream error: {exc}"},
            "timestamp": "",
        }


def _init_state() -> None:
    if "session_id" not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "active_tools" not in st.session_state:
        st.session_state.active_tools = []
    if "workflow_updates" not in st.session_state:
        st.session_state.workflow_updates = []
    if "event_feed" not in st.session_state:
        st.session_state.event_feed = []
    if "supervisor_url" not in st.session_state:
        st.session_state.supervisor_url = SUPERVISOR_URL
    if "api_key" not in st.session_state:
        st.session_state.api_key = ""
    if "current_repo" not in st.session_state:
        st.session_state.current_repo = ""


def _bubble_html(role: str, content: str) -> str:
    role_class = "user" if role == "user" else "assistant"
    safe_content = html.escape(content).replace("\n", "<br>")
    return (
        f"<div class='msg-row {role_class}'>"
        f"  <div class='msg-bubble {role_class}'>{safe_content}</div>"
        "</div>"
    )


def _render_chat(chat_placeholder: Any) -> None:
    rows = [
        _bubble_html(message["role"], message["content"])
        for message in st.session_state.messages
    ]
    block = (
        "<div class='chat-scroll'>"
        + "".join(rows)
        + "</div>"
    )
    chat_placeholder.markdown(block, unsafe_allow_html=True)


def _render_sidebar(active_tools_placeholder: Any, workflow_placeholder: Any) -> None:
    active_tools = st.session_state.active_tools
    if active_tools:
        active_md = "\n".join([f"- `{tool}`" for tool in active_tools])
    else:
        active_md = "- None"

    updates = st.session_state.workflow_updates[-20:]
    workflow_md = "\n".join([f"- {update}" for update in updates]) if updates else "- No updates yet"

    active_tools_placeholder.markdown(f"### Active Tools\n{active_md}")
    workflow_placeholder.markdown(f"### Workflow Status\n{workflow_md}")


def _render_event_feed(feed_placeholder: Any) -> None:
    lines = st.session_state.event_feed[-12:]
    if not lines:
        feed_placeholder.info("No events yet.")
        return
    feed_placeholder.markdown("\n".join([f"- {line}" for line in lines]))


def _merge_partial(existing: str, new_text: str) -> str:
    if not new_text:
        return existing
    if new_text.startswith(existing):
        return new_text
    if existing.endswith(new_text):
        return existing
    return existing + new_text


def _add_workflow_update(text: str) -> None:
    st.session_state.workflow_updates.append(text)
    st.session_state.event_feed.append(text)


def _truncate_text(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _extract_repo_ref(text: str) -> str:
    """
    Extract first owner/repo reference from text.
    """
    if not text:
        return ""
    match = re.search(r"\\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\\b", text)
    return match.group(1) if match else ""


def _build_contextual_query(current_query: str, current_repo: str, max_turns: int = 4) -> str:
    """
    Build a compact context-aware prompt because backend /chat/stream is stateless.
    Includes recent chat turns, then the current user query.
    """
    history = st.session_state.messages[-max_turns:]
    if not history:
        return current_query

    lines = []
    for msg in history:
        role = "User" if msg.get("role") == "user" else "Assistant"
        content = _truncate_text((msg.get("content") or "").strip(), 280)
        if content:
            lines.append(f"{role}: {content}")

    if not lines:
        return current_query

    context_block = "\n".join(lines)
    effective_request = current_query
    if current_repo and not _extract_repo_ref(current_query):
        effective_request = (
            f"{current_query}\n\n"
            f"Repository to use for this request: {current_repo}.\n"
            "Do not ask for repository name unless the user explicitly asks to change repository."
        )
    repo_block = (
        f"Current repository context: {current_repo}\n"
        "Use this repository for ambiguous follow-up requests "
        "(e.g., 'this PR', 'explain above'). "
        "Only switch repository if the user explicitly provides a new owner/repo.\n\n"
    ) if current_repo else ""
    composed = (
        "Use the conversation context to resolve references like "
        "'this PR'/'above PR'.\n\n"
        f"{repo_block}"
        f"Conversation context:\n{context_block}\n\n"
        f"Current user request:\n{effective_request}"
    )

    # Keep payload under supervisor max message size guard.
    return _truncate_text(composed, MAX_SUPERVISOR_MESSAGE_LEN)


def main() -> None:
    st.set_page_config(page_title="DevOps AI Console", layout="wide")

    st.markdown(
        """
        <style>
        .chat-scroll {
            height: 540px;
            overflow-y: auto;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 14px;
            background: #f8fafc;
        }
        .msg-row {
            display: flex;
            margin-bottom: 10px;
            width: 100%;
        }
        .msg-row.user { justify-content: flex-end; }
        .msg-row.assistant { justify-content: flex-start; }
        .msg-bubble {
            max-width: 78%;
            padding: 10px 12px;
            border-radius: 12px;
            font-size: 14px;
            line-height: 1.4;
            white-space: normal;
            word-break: break-word;
        }
        .msg-bubble.user {
            background: #1f2937;
            color: #ffffff;
            border-bottom-right-radius: 4px;
        }
        .msg-bubble.assistant {
            background: #ffffff;
            color: #111827;
            border: 1px solid #e5e7eb;
            border-bottom-left-radius: 4px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    _init_state()

    st.title("DevOps AI System")
    st.caption(f"Supervisor: {SUPERVISOR_URL} | Session: {st.session_state.session_id}")

    with st.sidebar:
        st.header("Workflow Monitor")
        st.text_input("Supervisor URL", key="supervisor_url")
        st.text_input("X-API-Key (optional)", type="password", key="api_key")
        if "repo_input" not in st.session_state:
            st.session_state.repo_input = st.session_state.current_repo
        repo_input = st.text_input(
            "Pinned Repository (owner/repo)",
            key="repo_input",
            placeholder="e.g. OpenBB-finance/OpenBB",
        )
        if repo_input.strip():
            st.session_state.current_repo = repo_input.strip()
        if st.button("New Session"):
            st.session_state.session_id = str(uuid.uuid4())
            st.session_state.messages = []
            st.session_state.active_tools = []
            st.session_state.workflow_updates = []
            st.session_state.event_feed = []
            # Preserve API key / URL / pinned repo intentionally.
            st.rerun()

        st.markdown("---")
        active_tools_placeholder = st.empty()
        workflow_placeholder = st.empty()

    _render_sidebar(active_tools_placeholder, workflow_placeholder)

    left, right = st.columns([3, 2])

    with left:
        chat_placeholder = st.empty()
        _render_chat(chat_placeholder)

        with st.form("chat_form", clear_on_submit=True):
            query = st.text_input(
                "Your query",
                key="query_input",
                placeholder="Ask about repo status, workflows, PRs...",
            )
            send_clicked = st.form_submit_button("Send", type="primary")

    with right:
        st.subheader("Live Events")
        event_feed_placeholder = st.empty()
        _render_event_feed(event_feed_placeholder)

    if send_clicked:
        cleaned_query = (query or "").strip()
        if not cleaned_query:
            st.warning("Please enter a query.")
            return

        explicit_repo = _extract_repo_ref(cleaned_query)
        if explicit_repo:
            st.session_state.current_repo = explicit_repo
            st.session_state.repo_input = explicit_repo

        contextual_query = _build_contextual_query(
            current_query=cleaned_query,
            current_repo=st.session_state.current_repo,
        )

        st.session_state.messages.append({"role": "user", "content": cleaned_query})
        st.session_state.messages.append({"role": "assistant", "content": ""})
        assistant_index = len(st.session_state.messages) - 1
        _render_chat(chat_placeholder)

        with st.spinner("Streaming response..."):
            for evt in stream_chat(
                query=contextual_query,
                session_id=st.session_state.session_id,
                supervisor_url=st.session_state.supervisor_url,
                api_key=st.session_state.api_key or None,
            ):
                event_type = evt.get("event", "")
                data = evt.get("data", {}) or {}

                if event_type == "agent_started":
                    agent = data.get("agent") or data.get("message") or "agent"
                    _add_workflow_update(f"Agent started: {agent}")

                elif event_type == "tool_call_started":
                    tool_name = data.get("tool_name", "unknown_tool")
                    _add_workflow_update(f"Calling tool: {tool_name}")
                    if tool_name not in st.session_state.active_tools:
                        st.session_state.active_tools.append(tool_name)

                elif event_type == "tool_call_completed":
                    tool_name = data.get("tool_name") or "tool"
                    tool_output = data.get("tool_output", "")
                    summary = str(tool_output)
                    if len(summary) > 140:
                        summary = summary[:140] + "..."
                    _add_workflow_update(f"Tool completed: {tool_name} | {summary}")
                    if tool_name in st.session_state.active_tools:
                        st.session_state.active_tools.remove(tool_name)

                elif event_type == "llm_partial":
                    partial_text = data.get("text", "")
                    current = st.session_state.messages[assistant_index]["content"]
                    st.session_state.messages[assistant_index]["content"] = _merge_partial(current, partial_text)

                elif event_type == "llm_final":
                    final_text = data.get("output", "")
                    if final_text:
                        st.session_state.messages[assistant_index]["content"] = final_text
                    _add_workflow_update("Response complete.")

                elif event_type == "error":
                    error_message = data.get("message", "Unknown error")
                    _add_workflow_update(f"ERROR: {error_message}")
                    st.session_state.messages[assistant_index]["content"] += f"\n\nError: {error_message}"
                    with right:
                        st.error(error_message)

                _render_chat(chat_placeholder)
                _render_sidebar(active_tools_placeholder, workflow_placeholder)
                _render_event_feed(event_feed_placeholder)


if __name__ == "__main__":
    main()
