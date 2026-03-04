import streamlit as st
import json
import html
import requests
from datetime import datetime
from io import BytesIO


def upload_manifest_file(uploaded_file, api_base: str = "http://localhost:9000", session_id: str | None = None) -> dict | None:
    """Upload a dependency manifest file and scan it for vulnerabilities."""
    if not uploaded_file:
        return None

    try:
        # Determine file type from filename
        filename = uploaded_file.name.lower()
        file_type = None

        # Map common manifest file names/extensions
        type_mapping = {
            "requirements.txt": "requirements.txt",
            "package.json": "package.json",
            "pom.xml": "pom.xml",
            "build.gradle": "build.gradle",
            "pubspec.yaml": "pubspec.yaml",
            ".txt": "requirements.txt",
            ".json": "package.json",
            ".xml": "pom.xml",
            ".gradle": "build.gradle",
            ".yaml": "pubspec.yaml",
            ".yml": "pubspec.yaml",
        }

        # Try to match the filename directly
        if filename in type_mapping:
            file_type = type_mapping[filename]
        else:
            # Try to match by extension
            for ext, ftype in type_mapping.items():
                if ext.startswith(".") and filename.endswith(ext):
                    file_type = ftype
                    break

        if not file_type:
            supported = sorted(set(type_mapping.values()))
            st.error(f"❌ Unsupported manifest type: {uploaded_file.name}\n\nSupported files: {', '.join(supported)}")
            return None

        # Read file content
        try:
            file_content = uploaded_file.getvalue()
            if not file_content:
                st.error("❌ Uploaded file is empty")
                return None
        except Exception as e:
            st.error(f"❌ Error reading file: {str(e)}")
            return None

        # Create form data for multipart/form-data
        files = {"file": (uploaded_file.name, BytesIO(file_content), "application/octet-stream")}
        data = {"file_type": file_type}
        if session_id:
            data["session_id"] = session_id

        # Send to backend
        try:
            response = requests.post(
                f"{api_base}/dependency/manifest/upload",
                files=files,
                data=data,
                timeout=60
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 400:
                st.error(f"❌ Bad request: {response.json().get('detail', response.text)}")
                return None
            elif response.status_code == 503:
                st.error(f"❌ Service unavailable: Dependency scanning tools are not available")
                return None
            else:
                st.error(f"❌ Upload failed ({response.status_code}): {response.text}")
                return None

        except requests.Timeout:
            st.error("❌ Upload timed out. Please try again.")
            return None
        except requests.ConnectionError:
            st.error("❌ Cannot connect to API. Make sure the backend is running.")
            return None
        except Exception as e:
            st.error(f"❌ Error uploading file: {str(e)}")
            return None

    except Exception as e:
        st.error(f"❌ Unexpected error: {str(e)}")
        return None


def render_download_button_topright(session_id: str, chat_history: list[dict], api_base: str = "http://localhost:9000") -> None:
    has_conversation = len(chat_history) > 0

    # Floating container
    st.markdown(
        """
        <style>
        .floating-download {
            position: fixed;
            top: 0px;
            right: 0px;
            z-index: 9999;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.container():
        st.markdown('<div class="floating-download">', unsafe_allow_html=True)

        if has_conversation:
            try:
                if st.button("📥 Download", key="download_btn"):
                    with st.spinner("Generating report..."):
                        response = requests.get(
                            f"{api_base}/chat/report/{session_id}",
                            timeout=30
                        )

                        if response.status_code == 200:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"security_report_{session_id[:8]}_{timestamp}.pdf"

                            st.download_button(
                                label="📄 Download PDF",
                                data=response.content,
                                file_name=filename,
                                mime="application/pdf",
                                key=f"download_pdf_{session_id}"
                            )
                        else:
                            st.error(f"Failed: {response.status_code}")

            except Exception as e:
                st.error(str(e))
        else:
            st.button("📥 Download", disabled=True)

        st.markdown("</div>", unsafe_allow_html=True)


def render_header() -> None:
    st.markdown("<div class='main-title'>Cybersecurity Agent Chat</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='subtitle'>Investigate threats, vulnerabilities, and risks through coordinated agents.</div>",
        unsafe_allow_html=True,
    )


def _parse_tool_output(output):
    if isinstance(output, dict):
        return output
    if isinstance(output, list):
        return {"data": output}
    if isinstance(output, str):
        try:
            return json.loads(output)
        except Exception:
            return {"raw": output}
    return {"raw": str(output)}


def _render_trace(trace: dict) -> None:
    tool_calls = trace.get("tool_calls") or []
    agent_used = (trace.get("agent_used") or "").strip()

    route_steps = 1 if agent_used else 0
    total_steps = route_steps + (len(tool_calls) * 2)

    with st.expander(f"Show Supervisor Routing Trace ({total_steps} steps)", expanded=False):
        st.markdown(
            f"""
            <div class="trace-wrapper">
                <div class="trace-badges">
                    <span class="trace-badge">{route_steps} routed</span>
                    <span class="trace-badge">{len(tool_calls)} tool calls</span>
                    <span class="trace-badge">{len(tool_calls)} tool results</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        step = 1
        if agent_used:
            safe_agent = html.escape(agent_used)
            st.markdown(
                f"""
                <div class="trace-step route">
                    <div class="trace-step-head"><span class="trace-pill">Step {step}</span><span class="trace-kind">ROUTE</span></div>
                    <div class="trace-title">Supervisor routed to {safe_agent}</div>
                    <div class="trace-note">Agent selected by routing logic</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander(f"View raw details - Step {step}", expanded=False):
                st.json({"agent_used": agent_used})
            step += 1

        for call in tool_calls:
            tool_name = call.get("tool_name", "unknown_tool")
            safe_tool = html.escape(str(tool_name))

            st.markdown(
                f"""
                <div class="trace-step tool">
                    <div class="trace-step-head"><span class="trace-pill">Step {step}</span><span class="trace-kind">TOOL CALLED</span></div>
                    <div class="trace-title">{safe_agent if agent_used else "Agent"} called {safe_tool}</div>
                    <div class="trace-note">Waiting for MCP response</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander(f"View raw details - Step {step}", expanded=False):
                st.json({"tool_name": tool_name, "tool_input": call.get("tool_input", {})})
            step += 1

            parsed_output = _parse_tool_output(call.get("tool_output", ""))
            status = str(parsed_output.get("status", "")).lower()
            result_class = "trace-step result success" if status in {"success", "ok"} else "trace-step result"
            result_note = "Response returned to agent" if status in {"success", "ok"} else "Tool response captured"

            st.markdown(
                f"""
                <div class="{result_class}">
                    <div class="trace-step-head"><span class="trace-pill">Step {step}</span><span class="trace-kind">MCP RESULT</span></div>
                    <div class="trace-title">{safe_agent if agent_used else "Agent"} received result from {safe_tool}</div>
                    <div class="trace-note">{result_note}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander(f"View raw details - Step {step}", expanded=False):
                st.json(parsed_output)
            step += 1


def render_chat_history(chat_history: list[dict]) -> None:
    for msg in chat_history:
        if msg["role"] == "human":
            st.chat_message("user").write(msg["content"])
        elif msg["role"] == "ai":
            with st.chat_message("assistant"):
                st.write(msg["content"])
                trace = msg.get("trace") or {}
                tool_calls = trace.get("tool_calls") or []
                agent_used = trace.get("agent_used", "")
                if agent_used or tool_calls:
                    _render_trace(trace)
