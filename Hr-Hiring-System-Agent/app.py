"""
app.py
══════
HireSmart HR Hiring System — Streamlit UI

Architecture
────────────
  Login Screen  →  Role Validated  →  Role-filtered UI
      │
      ▼
  Chat Interface  ──HTTP──►  Supervisor MCP (port 9001)
                                  └──► 7 Specialist Agents (8001–8007)

Zero LangGraph imports. All agent logic runs in supervisor_server.py.

Usage
─────
    Terminal 1:  python start_servers.py
    Terminal 2:  streamlit run app.py

Login Accounts
──────────────
    admin@hrapp.com          / admin123   → Admin (all agents)
    hr.manager@hrapp.com     / hr123      → HR Manager
    recruiter@hrapp.com      / rec123     → Recruiter
    hiring.manager@hrapp.com / hm123      → Hiring Manager
"""

import json, sys, os, uuid, re, hashlib
import httpx
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db import init_db
from utils.auth import authenticate, ROLE_AGENTS, ROLE_LABELS, ROLE_COLORS

# ── Supervisor endpoint ───────────────────────────────────────────────────────
SUPERVISOR_URL = "http://127.0.0.1:9001/mcp"
HTTP_TIMEOUT   = int(os.getenv("SUPERVISOR_HTTP_TIMEOUT", "120"))
MAX_CONTEXT_MESSAGES = 10
MAX_CONTEXT_CHARS = 1200

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="HireSmart HR System",
    page_icon="📄",
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
  border-radius:8px!important;width:100%!important;margin-bottom:5px!important;
  padding:9px 14px!important;font-size:13px!important;text-align:left!important}
[data-testid="stSidebar"] .stButton>button:hover{background:#2563eb!important}
[data-testid="stChatMessage"]{background:#1e293b!important;border:1px solid #334155!important;
  border-radius:12px!important;padding:12px 16px!important;margin-bottom:10px!important}
[data-testid="stChatInput"] textarea{background:#1e293b!important;color:#e2e8f0!important;
  border:1px solid #334155!important;border-radius:10px!important}
[data-testid="stChatInput"]{background:#0f172a!important;border-top:1px solid #334155!important}

/* Login card */
.login-card{background:linear-gradient(135deg,#1e3a5f,#0f172a);padding:40px 44px;
  border-radius:16px;border:1px solid #334155;max-width:440px;margin:60px auto}
.login-title{font-size:26px;font-weight:800;color:#fff!important;margin-bottom:4px;text-align:center}
.login-sub{font-size:13px;color:#94a3b8!important;text-align:center;margin-bottom:28px}
.role-pill{display:inline-block;padding:3px 14px;border-radius:20px;font-size:11px;
  font-weight:700;margin:2px;border:1px solid}

/* Header */
.header-card{background:linear-gradient(135deg,#1e3a5f,#1d4ed8);
  padding:16px 24px;border-radius:12px;margin-bottom:16px;border:1px solid #334155}
.header-card h1{margin:0;font-size:19px;color:#fff!important}
.header-card p{margin:4px 0 0;font-size:12px;color:#93c5fd!important}

/* Trace panel */
.trace-title{font-size:11px;font-weight:700;color:#60a5fa!important;letter-spacing:1px;
  text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid #334155;margin-bottom:10px}
.route-card{background:#1e3a5f;border:1px solid #1d4ed8;border-left:5px solid #1d4ed8;
  border-radius:8px;padding:10px 14px;margin-bottom:8px}
.route-label{font-size:10px;font-weight:700;color:#60a5fa!important;margin-bottom:4px}
.route-to{font-size:14px;font-weight:700;color:#fbbf24!important}
.tool-call{background:#162032;border:1px solid #1d4ed8;border-left:4px solid #1d4ed8;
  border-radius:8px;padding:9px 13px;margin-bottom:7px}
.tool-result{background:#0f2e16;border:1px solid #15803d;border-left:4px solid #15803d;
  border-radius:8px;padding:9px 13px;margin-bottom:7px}
.badge{font-size:10px;font-weight:600;padding:2px 9px;border-radius:12px;margin-bottom:5px;display:inline-block}
.lbl{font-size:10px;font-weight:700;letter-spacing:0.5px;margin-bottom:3px}
.tool-call .lbl{color:#60a5fa!important}
.tool-result .lbl{color:#4ade80!important}
.tool-name{font-size:13px;font-weight:700;color:#fbbf24!important;margin-bottom:3px}
.tool-body{font-size:11px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#cbd5e1!important}
.agent-row{display:flex;align-items:center;gap:8px;margin-bottom:7px}
.user-info{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;margin-bottom:10px}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-thumb{background:#334155;border-radius:4px}
hr{border-color:#334155!important}

/* Interactive Cards */
.card-container .stButton > button {
  background: #1e293b !important;
  border: 1px solid #334155 !important;
  border-radius: 12px !important;
  padding: 20px !important;
  min-height: 140px !important;
  text-align: left !important;
  transition: all 0.2s ease !important;
  display: flex !important;
  flex-direction: column !important;
}
.card-container .stButton > button:hover {
  background: #2d3748 !important;
  border-color: #60a5fa !important;
  transform: translateY(-3px) !important;
  box-shadow: 0 8px 20px rgba(0,0,0,0.4) !important;
}
.card-icon { font-size: 28px; margin-bottom: 8px; }
.card-name { font-size: 16px; font-weight: 700; margin-bottom: 4px; }
.card-desc { font-size: 11px; color: #94a3b8 !important; line-height: 1.4; }
</style>
""", unsafe_allow_html=True)

# ── Agent metadata ─────────────────────────────────────────────────────────────
AGENT_META = {
    "Job Management":       {"icon": "🏷️",  "color": "#1d4ed8", "port": 8001, "desc": "Postings, vacancies, JDs"},
    "Resume Screening":     {"icon": "📋",  "color": "#15803d", "port": 8002, "desc": "Score, shortlist, rank"},
    "Interview Scheduling": {"icon": "📅",  "color": "#0e7490", "port": 8003, "desc": "Schedule, feedback, panels"},
    "Offer Management":     {"icon": "📝",  "color": "#b45309", "port": 8004, "desc": "Generate, approve, send"},
    "Onboarding":           {"icon": "🏠",  "color": "#15803d", "port": 8005, "desc": "Day 1, tasks, buddy"},
    "Candidate Comms":      {"icon": "✉️",  "color": "#5b21b6", "port": 8006, "desc": "All candidate emails"},
    "Analytics":            {"icon": "📊",  "color": "#c2410c", "port": 8007, "desc": "Reports & pipeline stats"},
}

# ── Role-specific quick actions ───────────────────────────────────────────────
QUICK_ACTIONS = {
    "admin": {
        "📊 Full Pipeline Report":         "Give me a full hiring pipeline summary report",
        "🏷️ List All Open Jobs":           "List all currently open job postings",
        "📋 Top Candidates – Backend":     "Show top 5 candidates for the Senior Backend Engineer role (job #1)",
        "📅 Upcoming Interviews":          "Show all interviews scheduled in the next 7 days",
        "📝 View All Offers":              "Show all offers and their current status",
        "✉️ Communication History":        "Get communication history for candidate #1",
        "📊 Time-to-Hire Report":          "Show me the time-to-hire analytics report",
        "🏠 Pending Onboardings":          "Show all pending onboarding records",
        "📊 Source Effectiveness":         "Which job boards are producing the best candidates?",
        "📊 Offer Acceptance Rate":        "What is our current offer acceptance rate?",
    },
    "hr_manager": {
        "🏷️ List All Open Jobs":           "List all currently open job postings",
        "📋 Top Candidates – Backend":     "Show top 5 candidates for the Senior Backend Engineer role (job #1)",
        "📝 Generate Offer for Riya":      "Get offer details for offer #1 (Riya Desai)",
        "📅 Upcoming Interviews":          "Show all interviews scheduled in the next 7 days",
        "📊 Pipeline Summary":             "Give me a hiring pipeline summary",
        "🏠 Setup Onboarding for Riya":    "Show onboarding status for candidate #6",
        "📊 Department Hiring Stats":      "Show hiring statistics by department",
        "📊 Interviewer Performance":      "Show interviewer statistics and performance",
    },
    "recruiter": {
        "🏷️ List All Open Jobs":           "List all currently open job postings",
        "📋 Score Backend Candidate":      "Score resume for candidate #3 (Rohit Jain)",
        "📋 Shortlist Arjun Mehta":        "Show candidate profile for candidate #1 (Arjun Mehta)",
        "📅 Schedule Interview":           "Show upcoming interviews for the next 7 days",
        "✉️ Send Status Update":           "Get communication history for candidate #2",
        "🏷️ Search Python Jobs":           "Search for open jobs requiring Python skills",
        "📋 List Candidates – Backend":    "List all candidates for the Senior Backend Engineer job (job #1)",
        "✉️ Bulk Email Candidates":        "Show active candidates for job #2 (Product Manager)",
    },
    "hiring_manager": {
        "📅 My Upcoming Interviews":       "Show all interviews scheduled in the next 14 days",
        "📅 Interview Feedback – Divya":   "Get interview feedback for candidate #2 (Divya Krishnan)",
        "📅 Interview Feedback – Arjun":   "Get all interview feedback for candidate #1 (Arjun Mehta)",
        "📊 Pipeline for Backend Role":    "Show pipeline analytics for the Senior Backend Engineer role",
        "📊 Department Analytics":         "Show hiring statistics for the Engineering department",
        "📅 Submit Feedback":              "Show interview details for interview #1",
    },
}

# ── HTTP call to supervisor ───────────────────────────────────────────────────
# Keep only compact human/assistant text for supervisor context.
def _compact_context(messages: list) -> list:
    compact = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "")
        if role not in ("human", "ai"):
            continue
        content = msg.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        content = content.strip()
        if not content:
            continue
        if len(content) > MAX_CONTEXT_CHARS:
            content = content[:MAX_CONTEXT_CHARS] + "... [truncated]"
        compact.append({"role": role, "content": content})
    return compact[-MAX_CONTEXT_MESSAGES:]


def _call_supervisor(
    messages: list,
    user_role: str = "",
    user_email: str = "",
    thread_id: str = "",
) -> dict:
    """Send conversation history to Supervisor MCP on port 9001."""
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {
            "name": "chat",
            "arguments": {
                "messages_json": json.dumps(messages),
                "thread_id": thread_id,
            }
        }
    }
    try:
        resp = httpx.post(
            SUPERVISOR_URL,
            json=payload,
            timeout=httpx.Timeout(
                connect=4.0,
                read=HTTP_TIMEOUT,
                write=10.0,
                pool=4.0,
            ),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        rpc = resp.json()

        if resp.status_code >= 400:
            err_msg = rpc.get("error", {}).get("message", resp.text)
            return {
                "error": f"HTTP {resp.status_code}: {err_msg}",
                "final_reply": f"Supervisor request failed ({resp.status_code}): {err_msg}",
                "trace": [],
                "messages": messages,
            }

        if "error" in rpc:
            err_msg = rpc.get("error", {}).get("message", str(rpc["error"]))
            return {
                "error": err_msg,
                "final_reply": f"Supervisor error: {err_msg}",
                "trace": [],
                "messages": messages,
            }

        content = rpc.get("result", {}).get("content", [])
        texts = []
        for item in content if isinstance(content, list) else []:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(item.get("text", ""))
        raw = "\n".join([t for t in texts if t]).strip()

        if not raw:
            return {
                "error": "Empty response",
                "final_reply": "Supervisor returned an empty response.",
                "trace": [],
                "messages": messages,
            }

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"final_reply": raw, "trace": [], "messages": messages}

        if isinstance(parsed, dict):
            return parsed
        return {"final_reply": str(parsed), "trace": [], "messages": messages}
    except httpx.ConnectError:
        return {
            "error": "ConnectError",
            "final_reply": "Cannot connect to Supervisor (port 9001). Run `python start_servers.py` first.",
            "trace": [],
            "messages": messages,
        }
    except httpx.TimeoutException:
        return {
            "error": "Timeout",
            "final_reply": (
                f"Supervisor did not respond within {HTTP_TIMEOUT}s. "
                "Check logs/supervisor (port 9001) and confirm all MCP agent servers (8001-8007) are running."
            ),
            "trace": [],
            "messages": messages,
        }
    except Exception as e:
        return {"error": str(e), "final_reply": f"Error: {e}", "trace": [], "messages": messages}


def _render_trace(trace: list) -> None:
    if not trace:
        st.caption("No routing trace available for this response.")
        return
    for step in trace:
        t = step.get("type", "")
        if t == "route":
            a = step["to"]
            meta = AGENT_META.get(a, {"icon": "Bot", "color": "#1d4ed8"})
            st.markdown(
                f'<div class="route-card"><div class="route-label">SUPERVISOR ROUTED TO</div>'
                f'<div class="route-to">{meta["icon"]} {a} Agent</div></div>',
                unsafe_allow_html=True,
            )
        elif t == "tool_call":
            a = step.get("agent", "")
            meta = AGENT_META.get(a, {"icon": "Bot", "color": "#1d4ed8"})
            args = json.dumps(step.get("args", {}), indent=2, ensure_ascii=False)
            st.markdown(
                f'<div class="tool-call">'
                f'<span class="badge" style="background:{meta["color"]}22;color:{meta["color"]}">'
                f'{meta["icon"]} {a} Agent</span>'
                f'<div class="lbl">TOOL CALLED</div>'
                f'<div class="tool-name">{step["tool"]}</div>'
                f'<div class="tool-body">{args}</div></div>',
                unsafe_allow_html=True,
            )
        elif t == "tool_result":
            a = step.get("agent", "")
            meta = AGENT_META.get(a, {"icon": "Bot", "color": "#15803d"})
            r = step.get("result", "")
            text = json.dumps(r, indent=2, ensure_ascii=False) if isinstance(r, (dict, list)) else str(r)
            if len(text) > 600:
                text = text[:600] + "\\n...(truncated)"
            st.markdown(
                f'<div class="tool-result">'
                f'<span class="badge" style="background:{meta["color"]}22;color:{meta["color"]}">'
                f'{meta["icon"]} {a} Agent</span>'
                f'<div class="lbl">[OK] MCP RESULT</div>'
                f'<div class="tool-name">{step["tool"]}</div>'
                f'<div class="tool-body">{text}</div></div>',
                unsafe_allow_html=True,
            )


def _extract_recommendations(content: str) -> tuple[str, list]:
    """
    Parse assistant content and extract trailing recommendation lines.
    Supported headers: Recommendations, Suggested Next Prompts, Suggestions.
    """
    if not isinstance(content, str):
        return str(content), []

    lines = content.splitlines()
    header_index = -1
    for i, raw in enumerate(lines):
        line = raw.strip().lower()
        if line in (
            "recommendations:",
            "suggestions:",
            "suggested next prompts:",
            "recommended next prompts:",
            "recommended prompts:",
            "next steps:",
        ):
            header_index = i
            break

    if header_index == -1:
        return content, []

    body_lines = lines[header_index + 1 :]
    recs = []
    blocked_patterns = (
        "provide id",
        "provide",
        "provide job id",
        "provide candidate id",
        "provide interview id",
        "provide offer id",
        "share id",
        "give id",
        "enter id",
    )
    for raw in body_lines:
        line = raw.strip()
        if not line:
            continue
        line = re.sub(r"^[-*]\s+", "", line)
        line = re.sub(r"^\d+\.\s+", "", line)
        line = re.sub(r"^\d+\)\s+", "", line)
        lowered = line.lower()
        if line and not any(p in lowered for p in blocked_patterns):
            recs.append(line)

    main = "\n".join(lines[:header_index]).strip()
    if not recs:
        return content, []
    return main, recs[:2]


def _render_ai_message(content: str, key_prefix: str) -> None:
    main_text, recs = _extract_recommendations(content)
    if main_text:
        st.write(main_text)

    if not recs:
        return

    st.markdown("**Recommendations**")
    for idx, rec in enumerate(recs):
        safe_key = hashlib.md5(f"{key_prefix}:{idx}:{rec}".encode("utf-8")).hexdigest()[:12]
        if st.button(f"→ {rec}", key=f"rec_{safe_key}", use_container_width=True):
            st.session_state.pending_msg = rec
            st.rerun()


def _run_turn(user_text: str) -> tuple[str, list]:
    st.session_state.messages.append({"role": "human", "content": user_text})
    context_messages = _compact_context(st.session_state.messages)
    result = _call_supervisor(
        context_messages,
        st.session_state.user["role"],
        st.session_state.user["email"],
        st.session_state.thread_id,
    )

    final_reply = (result.get("final_reply") or "").strip()
    trace = result.get("trace", [])
    if not final_reply:
        final_reply = "No response received from supervisor."

    st.session_state.messages.append({"role": "ai", "content": final_reply, "trace": trace})

    # Bound chat state so payload size and rerender cost stay predictable.
    if len(st.session_state.messages) > 40:
        st.session_state.messages = st.session_state.messages[-40:]

    return final_reply, trace


def _show_login() -> None:
    st.markdown("""
    <div style="text-align:center;padding:30px 0 10px">
      <div style="font-size:48px">📄</div>
      <div style="font-size:28px;font-weight:800;color:#fff">HireSmart</div>
      <div style="font-size:13px;color:#64748b;margin-top:4px">AI-Powered HR Hiring System</div>
    </div>
    """, unsafe_allow_html=True)

    col = st.columns([1,2,1])[1]
    with col:
        st.markdown('<div style="background:#1e293b;border:1px solid #334155;border-radius:16px;padding:32px 36px">', unsafe_allow_html=True)
        st.markdown('<p style="font-size:18px;font-weight:700;color:#60a5fa;margin-bottom:20px;text-align:center">🔐 Sign In</p>', unsafe_allow_html=True)

        email    = st.text_input("Email", placeholder="admin@hrapp.com", key="login_email")
        password = st.text_input("Password", type="password", placeholder="••••••••", key="login_password")

        if st.button("Sign In →", key="login_btn", use_container_width=True):
            if not email or not password:
                st.error("Please enter both email and password.")
            else:
                user = authenticate(email.strip(), password)
                if user:
                    st.session_state.user      = user
                    st.session_state.messages  = []
                    st.session_state.thread_id = uuid.uuid4().hex
                    st.rerun()
                else:
                    st.error("[ERROR] Invalid email or password.")

        st.markdown("---")
        st.markdown('<p style="font-size:11px;color:#475569;margin-bottom:6px">Test accounts:</p>', unsafe_allow_html=True)
        accounts = [
            ("admin@hrapp.com",          "admin123", "Admin",          "#f59e0b"),
            ("hr.manager@hrapp.com",     "hr123",    "HR Manager",     "#1d4ed8"),
            ("recruiter@hrapp.com",      "rec123",   "Recruiter",      "#15803d"),
            ("hiring.manager@hrapp.com", "hm123",    "Hiring Manager", "#5b21b6"),
        ]
        for em, pw, role, color in accounts:
            st.markdown(
                f'<div style="background:#0f172a;border:1px solid #334155;border-radius:6px;'
                f'padding:7px 10px;margin-bottom:5px;font-size:11px">'
                f'<span style="color:{color};font-weight:700">{role}</span>  '
                f'<span style="color:#94a3b8">{em}</span>  '
                f'<span style="color:#475569">/ {pw}</span>'
                f'</div>',
                unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────
def _sidebar(user: dict) -> None:
    role       = user["role"]
    role_color = ROLE_COLORS.get(role, "#334155")
    role_label = ROLE_LABELS.get(role, role)
    visible    = ROLE_AGENTS.get(role, [])

    with st.sidebar:
        # User info card
        st.markdown(
            f'<div class="user-info">'
            f'<div style="font-size:13px;font-weight:700;color:#e2e8f0">{user["name"]}</div>'
            f'<div style="font-size:11px;color:#94a3b8">{user["email"]}</div>'
            f'<div style="margin-top:6px">'
            f'<span style="background:{role_color}22;color:{role_color};border:1px solid {role_color}44;'
            f'font-size:11px;font-weight:700;padding:2px 10px;border-radius:12px">'
            f'{role_label}</span></div>'
            f'<div style="font-size:11px;color:#64748b;margin-top:3px">{user.get("department","")}</div>'
            f'</div>',
            unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### ⚡ Quick Actions")
        actions = QUICK_ACTIONS.get(role, {})
        for label, msg in actions.items():
            if st.button(label, key=f"qa_{label}"):
                st.session_state.pending_msg = msg

        st.markdown("---")
        st.markdown("### 🤖 Your Agents")
        # Supervisor row
        st.markdown(
            '<div class="agent-row">'
            '<span style="font-size:15px">🧠</span>'
            '<span style="font-size:12px;font-weight:500">Supervisor :9001</span>'
            '<span style="width:7px;height:7px;border-radius:50%;background:#f59e0b;'
            'display:inline-block;margin-left:auto"></span></div>',
            unsafe_allow_html=True)
        for a in visible:
            meta = AGENT_META.get(a, {"icon":"🤖","color":"#334155"})
            st.markdown(
                f'<div class="agent-row">'
                f'<span style="font-size:15px">{meta["icon"]}</span>'
                f'<span style="font-size:12px;font-weight:500">{a}</span>'
                f'<span style="width:7px;height:7px;border-radius:50%;background:{meta["color"]};'
                f'display:inline-block;margin-left:auto"></span></div>',
                unsafe_allow_html=True)

        # Show "locked" agents for non-admin
        if role != "admin":
            locked = [a for a in AGENT_META if a not in visible]
            if locked:
                st.markdown('<div style="margin-top:6px;padding-top:6px;border-top:1px solid #334155">', unsafe_allow_html=True)
                st.markdown('<span style="font-size:10px;color:#475569">🔒 Restricted (your role)</span>', unsafe_allow_html=True)
                for a in locked:
                    meta = AGENT_META.get(a, {"icon":"🤖","color":"#334155"})
                    st.markdown(
                        f'<div class="agent-row" style="opacity:0.4">'
                        f'<span style="font-size:15px">{meta["icon"]}</span>'
                        f'<span style="font-size:11px;color:#64748b">{a}</span>'
                        f'<span style="font-size:10px;color:#475569;margin-left:auto">🔒</span></div>',
                        unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---")
        if st.button("🗑️ Clear Chat", key="clear_chat"):
            st.session_state.messages  = []
            st.session_state.thread_id = uuid.uuid4().hex
            st.rerun()
        if st.button("🚪 Logout", key="logout"):
            for k in ["user","messages","pending_msg","selected_agent","thread_id"]:
                st.session_state.pop(k, None)
            st.rerun()
        st.caption(f"Supervisor :9001 → Agents :8001–8007")


# ── Welcome cards ─────────────────────────────────────────────────────────────
def _welcome_cards(role: str) -> None:
    if "selected_agent" not in st.session_state:
        st.session_state.selected_agent = None

    visible = ROLE_AGENTS.get(role, [])

    if st.session_state.selected_agent:
        agent_name = st.session_state.selected_agent
        meta = AGENT_META.get(agent_name, {"icon": "🤖", "color": "#334155", "desc": ""})
        
        col1, col2 = st.columns([0.8, 0.2])
        with col1:
            st.markdown(f"### {meta['icon']} {agent_name}")
        with col2:
            if st.button("← All Tools", use_container_width=True):
                st.session_state.selected_agent = None
                st.rerun()
        
        st.markdown(f'<p style="color:#94a3b8; font-size:13px; margin-top:-15px">{meta["desc"]}</p>', unsafe_allow_html=True)
        
        # Filter quick actions for this agent
        actions = QUICK_ACTIONS.get(role, {})
        agent_actions = {k: v for k, v in actions.items() if k.startswith(meta["icon"])}
        
        if not agent_actions:
            st.info(f"No specific quick actions for {agent_name} available for your role.")
        else:
            st.markdown("##### Select a quick action:")
            cols = st.columns(2)
            for i, (label, msg) in enumerate(agent_actions.items()):
                with cols[i % 2]:
                    if st.button(label, key=f"tool_qa_{label}", use_container_width=True):
                        st.session_state.pending_msg = msg
                        st.rerun()
    else:
        st.markdown("### 👋 What would you like to do?")
        st.markdown('<div class="card-container">', unsafe_allow_html=True)
        cols = st.columns(3)
        for i, name in enumerate(visible):
            meta = AGENT_META.get(name, {"icon": "🤖", "color": "#334155", "desc": ""})
            with cols[i % 3]:
                # Using a button that will be styled as a card via CSS
                button_label = (
                    f'{meta["icon"]}\n'
                    f'{name}\n'
                    f'{meta["desc"]}'
                )
                if st.button(button_label, key=f"agent_card_{name}", use_container_width=True):
                    st.session_state.selected_agent = name
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("---")


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    # DB init (once)
    if "db_ready" not in st.session_state:
        init_db()
        st.session_state.db_ready = True
    # Not logged in -> show login screen
    if "user" not in st.session_state or not st.session_state.user:
        _show_login()
        return
    user = st.session_state.user
    role = user["role"]
    # Session state
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "thread_id" not in st.session_state:
        st.session_state.thread_id = uuid.uuid4().hex
    # Sidebar
    _sidebar(user)
    # Header
    visible = ROLE_AGENTS.get(role, [])
    st.markdown(
        f'<div class="header-card">'
        f'<h1>HireSmart - HR Hiring Multi-Agent System</h1>'
        f'<p>Supervisor (port 9001) routes to: {" | ".join(visible)}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )
    if not st.session_state.messages:
        _welcome_cards(role)
    # Chat history with trace dropdown per assistant message
    for msg_idx, msg in enumerate(st.session_state.messages):
        role_msg = msg.get("role", "human") if isinstance(msg, dict) else "human"
        content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
        if role_msg == "human":
            with st.chat_message("user"):
                st.write(content)
        elif role_msg == "ai" and content and not msg.get("tool_calls"):
            with st.chat_message("assistant"):
                _render_ai_message(content, key_prefix=f"hist_{msg_idx}")
                with st.expander("Live Supervisor Routing Trace", expanded=False):
                    _render_trace(msg.get("trace", []))
    # Quick action handler
    if "pending_msg" in st.session_state:
        user_input = st.session_state.pop("pending_msg")
        with st.chat_message("user"):
            st.write(user_input)
        with st.chat_message("assistant"):
            with st.spinner("Supervisor routing to specialist agent..."):
                reply, trace = _run_turn(user_input)
            _render_ai_message(reply, key_prefix=f"live_qa_{uuid.uuid4().hex}")
            with st.expander("Live Supervisor Routing Trace", expanded=False):
                _render_trace(trace)
        st.rerun()
    # Chat input
    placeholder = "Ask anything... e.g. 'Show top candidates for Backend role', 'Schedule an interview'"
    user_input = st.chat_input(placeholder)
    if user_input:
        with st.chat_message("user"):
            st.write(user_input)
        with st.chat_message("assistant"):
            with st.spinner("Routing to best specialist agent..."):
                reply, trace = _run_turn(user_input)
            _render_ai_message(reply, key_prefix=f"live_chat_{uuid.uuid4().hex}")
            with st.expander("Live Supervisor Routing Trace", expanded=False):
                _render_trace(trace)
if __name__ == "__main__":
    main()
