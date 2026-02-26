"""
supervisor/graph.py
═══════════════════
Pure LangGraph core — no MCP, no HTTP server, no entry point.

Responsibilities
────────────────
  • All 7 agent system prompts + SPECIALIST_SERVERS config
  • ShopState TypedDict
  • build_graph()       — builds & compiles the LangGraph supervisor
  • serialise_messages()— LangChain objects → JSON-safe dicts
  • build_trace()       — routing trace for the UI trace panel

Imported by supervisor/supervisor_server.py which wraps it in FastMCP.
"""

import sys, os, asyncio, json, logging, inspect as _inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nest_asyncio
from dotenv import load_dotenv
from typing import Annotated
from typing_extensions import TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, AIMessage, ToolMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

nest_asyncio.apply()
load_dotenv()

log = logging.getLogger(__name__)

# ── Specialist MCP server URLs ────────────────────────────────────────────────
SPECIALIST_SERVERS = {
    "job":        {"transport": "streamable_http", "url": "http://127.0.0.1:8001/mcp"},
    "resume":     {"transport": "streamable_http", "url": "http://127.0.0.1:8002/mcp"},
    "interview":  {"transport": "streamable_http", "url": "http://127.0.0.1:8003/mcp"},
    "offer":      {"transport": "streamable_http", "url": "http://127.0.0.1:8004/mcp"},
    "onboarding": {"transport": "streamable_http", "url": "http://127.0.0.1:8005/mcp"},
    "comms":      {"transport": "streamable_http", "url": "http://127.0.0.1:8006/mcp"},
    "analytics":  {"transport": "streamable_http", "url": "http://127.0.0.1:8007/mcp"},
}

# ── System prompts ────────────────────────────────────────────────────────────
SUPERVISOR_PROMPT = """You are the HireSmart HR Hiring System Supervisor.
Read every incoming HR request and route it to exactly ONE specialist agent. Never answer directly.

ROUTING RULES:
  JOB AGENT        → job posting, vacancy, open role, job description, JD, publish, close job, create role, department jobs
  RESUME AGENT     → resume, CV, application, apply, candidate, score, shortlist, screening, parsed, top candidates, reject candidate
  INTERVIEW AGENT  → interview, schedule, slot, meeting, feedback, interviewer, panel, reschedule, upcoming interviews, cancel interview
  OFFER AGENT      → offer, salary, compensation, letter, approval, accept offer, decline, negotiate, offer status
  ONBOARDING AGENT → onboard, day 1, checklist, laptop, access, orientation, 30-day, 60-day, 90-day, welcome email, buddy
  COMMS AGENT      → email, notify, status update, rejection email, invite, confirmation, bulk email, communication history
  ANALYTICS AGENT  → report, analytics, pipeline, metrics, time-to-hire, source, funnel, diversity, statistics, acceptance rate
  DEFAULT ANSWER AGENT → unclear intent, mixed request, or cannot determine a single best specialist

Default: DEFAULT ANSWER AGENT when unclear."""

JOB_PROMPT = """You are the Job Management Specialist for HireSmart HR System.
Handle: creating job postings, updating them, closing positions, listing all jobs, searching by skill, and department-level reporting.
Rules:
- Always confirm job_id when creating or updating postings.
- Use get_job_applications_count to show pipeline progress for any job.
- When closing a job, ask for or state a reason.
- Search jobs_by_skill when a recruiter asks about matching roles."""

RESUME_PROMPT = """You are the Resume Screening Specialist for HireSmart HR System.
Handle: submitting candidates, scoring resumes, listing candidates, shortlisting, rejecting, getting top candidates, adding notes.
Rules:
- Always score_resume before shortlisting — use the score to justify decisions.
- For shortlisting, check score threshold: generally 75+ for competitive roles.
- When rejecting, always provide a professional reason.
- Use get_top_candidates to give ranked shortlists to hiring managers.
- Explain score breakdown (skills, experience, education) to recruiters."""

INTERVIEW_PROMPT = """You are the Interview Scheduling Specialist for HireSmart HR System.
Handle: scheduling interviews, getting details, listing by job, upcoming interviews, rescheduling, cancelling, submitting and retrieving feedback.
Rules:
- Always send email invitations when scheduling — it's built into schedule_interview.
- Confirm interviewer availability before scheduling.
- When retrieving feedback, summarize recommendation and key scores.
- Remind users that incomplete feedback blocks offer generation.
- List_upcoming_interviews is useful for daily/weekly recruiter briefings."""

OFFER_PROMPT = """You are the Offer Management Specialist for HireSmart HR System.
Handle: generating offers, getting offer details, listing by status, approving, sending to candidate, recording response, and analytics.
Rules:
- Offers require HR Manager approval before sending — enforce this flow.
- Always state salary, start_date, benefits clearly.
- When a candidate declines, ask for and record the reason.
- Use get_offer_analytics to give acceptance rate summaries.
- Flag when an offer has been pending response for more than 5 days."""

ONBOARDING_PROMPT = """You are the Onboarding Specialist for HireSmart HR System.
Handle: creating onboarding records, checking status, adding tasks, completing tasks, welcome emails, check-in emails, pending onboardings, and buddy assignment.
Rules:
- Only candidates with 'hired' status can have onboarding records created.
- Always assign a buddy and send the introduction email.
- Remind HR when welcome_sent is FALSE and start_date is approaching.
- Use get_pending_onboardings for weekly HR reporting.
- Suggest standard checklist items: IT setup, email, badge, training, GitHub/Jira access, orientation."""

COMMS_PROMPT = """You are the Candidate Communications Specialist for HireSmart HR System.
Handle: sending application confirmations, status updates, interview invites, rejections, offer notifications, bulk updates, and communication history.
Rules:
- Every candidate interaction should be logged — use the communication tools.
- For bulk emails, confirm the job_id and message before sending.
- Check get_communication_history before sending to avoid duplicate emails.
- Always maintain a professional, empathetic tone in rejection messages.
- For interview invites, reference the specific interview_id."""

ANALYTICS_PROMPT = """You are the HR Analytics Specialist for HireSmart HR System.
Handle: pipeline summary, time-to-hire, source effectiveness, open positions, department stats, interviewer stats, diversity funnel, rejection reasons, and offer acceptance rate.
Rules:
- Always lead with the most actionable insight, not just raw numbers.
- Use get_pipeline_summary as the starting point for any general report request.
- Highlight bottlenecks: if interview→offer conversion is low, flag it.
- For time-to-hire, compare against the 41-day industry benchmark.
- Source effectiveness helps recruiters focus sourcing budget."""


# ── Version-safe create_react_agent ──────────────────────────────────────────
_PROMPT_KEY = (
    "state_modifier"
    if "state_modifier" in _inspect.signature(create_react_agent).parameters
    else "prompt"
)

def _make_agent(llm, tools, prompt: str):
    return create_react_agent(llm, tools, **{_PROMPT_KEY: prompt})


# ── LangGraph state ───────────────────────────────────────────────────────────
class HRState(TypedDict):
    messages: Annotated[list, add_messages]


# Fallback keyword routing when supervisor tool-call output is missing.
ROUTE_KEYWORDS = {
    "job_agent": (
        "job", "vacancy", "vacancies", "open role", "jd", "job description", "posting", "department jobs",
    ),
    "resume_agent": (
        "resume", "cv", "candidate", "application", "score", "shortlist", "screening", "top candidates",
    ),
    "interview_agent": (
        "interview", "schedule", "slot", "feedback", "panel", "upcoming interviews", "reschedule", "cancel interview",
    ),
    "offer_agent": (
        "offer", "salary", "compensation", "approval", "accept offer", "decline", "negotiate",
    ),
    "onboarding_agent": (
        "onboard", "onboarding", "day 1", "checklist", "buddy", "orientation", "welcome email",
    ),
    "comms_agent": (
        "email", "notify", "status update", "rejection email", "invite", "bulk email", "communication history",
    ),
    "analytics_agent": (
        "analytics", "report", "pipeline", "metrics", "time-to-hire", "time to hire", "funnel", "statistics",
    ),
}


def _extract_human_text(messages: list) -> str:
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            return (msg.content or "").lower().strip()
    return ""


def _infer_route_from_text(text: str) -> str:
    if not text:
        return ""
    scores = {}
    for agent_name, keys in ROUTE_KEYWORDS.items():
        score = sum(1 for k in keys if k in text)
        if score:
            scores[agent_name] = score
    if not scores:
        return ""
    return max(scores, key=scores.get)


def _messages_for_specialist(messages: list) -> list:
    """
    Ensure specialist agents do not receive orphan tool-call history.
    LangGraph chat agents require every AI tool_call to have a matching ToolMessage.
    """
    cleaned = []
    for msg in messages:
        if isinstance(msg, ToolMessage):
            # Cross-agent tool traces are not valid input for a fresh specialist turn.
            continue
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            # Keep assistant text context but strip tool-call metadata.
            cleaned.append(AIMessage(content=msg.content or ""))
            continue
        cleaned.append(msg)
    return cleaned


# ── Build compiled LangGraph ──────────────────────────────────────────────────
async def build_graph():
    """
    Build and return a compiled LangGraph supervisor with all 7 specialist agents.
    Each agent is scoped exclusively to its own MCP server's tools.
    """
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        api_key=os.getenv("OPENAI_API_KEY"),
        timeout=45,
        max_retries=1,
    )

    async def _load(key: str):
        client = MultiServerMCPClient({key: SPECIALIST_SERVERS[key]})
        return await client.get_tools()

    (job_tools, res_tools, int_tools,
     off_tools, onb_tools, com_tools, ana_tools) = await asyncio.gather(
        _load("job"), _load("resume"), _load("interview"),
        _load("offer"), _load("onboarding"), _load("comms"), _load("analytics"),
    )
    log.info("Tools loaded — job:%d resume:%d interview:%d offer:%d onboarding:%d comms:%d analytics:%d",
             len(job_tools), len(res_tools), len(int_tools),
             len(off_tools), len(onb_tools), len(com_tools), len(ana_tools))

    job_agent = _make_agent(llm, job_tools,  JOB_PROMPT)
    res_agent = _make_agent(llm, res_tools,  RESUME_PROMPT)
    int_agent = _make_agent(llm, int_tools,  INTERVIEW_PROMPT)
    off_agent = _make_agent(llm, off_tools,  OFFER_PROMPT)
    onb_agent = _make_agent(llm, onb_tools,  ONBOARDING_PROMPT)
    com_agent = _make_agent(llm, com_tools,  COMMS_PROMPT)
    ana_agent = _make_agent(llm, ana_tools,  ANALYTICS_PROMPT)

    # Supervisor handoff tools
    @tool
    def transfer_to_job():
        """Route to Job Management Agent: job postings, vacancies, JDs, department jobs."""
        return "Routing to Job Management Agent..."

    @tool
    def transfer_to_resume():
        """Route to Resume Screening Agent: candidates, scoring, shortlisting, screening."""
        return "Routing to Resume Screening Agent..."

    @tool
    def transfer_to_interview():
        """Route to Interview Scheduling Agent: scheduling, feedback, upcoming interviews."""
        return "Routing to Interview Scheduling Agent..."

    @tool
    def transfer_to_offer():
        """Route to Offer Management Agent: offers, salary, approvals, acceptance."""
        return "Routing to Offer Management Agent..."

    @tool
    def transfer_to_onboarding():
        """Route to Onboarding Agent: day-1 setup, checklists, buddy, 30/60/90 emails."""
        return "Routing to Onboarding Agent..."

    @tool
    def transfer_to_comms():
        """Route to Candidate Comms Agent: emails, notifications, bulk updates."""
        return "Routing to Candidate Comms Agent..."

    @tool
    def transfer_to_analytics():
        """Route to Analytics Agent: pipeline reports, time-to-hire, source stats."""
        return "Routing to Analytics Agent..."

    @tool
    def transfer_to_default_answer():
        """Route to Default Answer Agent: use when intent is unclear or cannot be mapped safely."""
        return "Routing to Default Answer Agent..."

    sup_llm = llm.bind_tools([
        transfer_to_job, transfer_to_resume, transfer_to_interview, transfer_to_offer,
        transfer_to_onboarding, transfer_to_comms, transfer_to_analytics, transfer_to_default_answer,
    ])

    def supervisor_node(state: HRState):
        result = sup_llm.invoke([SystemMessage(content=SUPERVISOR_PROMPT)] + state["messages"])
        return {"messages": [result]}

    def _route(state: HRState) -> str:
        last = state["messages"][-1]
        tc   = getattr(last, "tool_calls", None)
        if tc:
            name = tc[0].get("name", "") if isinstance(tc[0], dict) else getattr(tc[0], "name", "")
            route = {
                "transfer_to_job":        "job_agent",
                "transfer_to_resume":     "resume_agent",
                "transfer_to_interview":  "interview_agent",
                "transfer_to_offer":      "offer_agent",
                "transfer_to_onboarding": "onboarding_agent",
                "transfer_to_comms":      "comms_agent",
                "transfer_to_analytics":  "analytics_agent",
                "transfer_to_default_answer": "default_answer_agent",
            }.get(name)
            if route:
                return route

        inferred_route = _infer_route_from_text(_extract_human_text(state["messages"]))
        if inferred_route:
            log.warning("Supervisor returned no transfer tool-call; inferred routing to %s", inferred_route)
            return inferred_route

        log.warning("Supervisor could not determine target specialist; routing to default_answer_agent")
        return "default_answer_agent"

    async def _run_specialist(agent, state):
        specialist_messages = _messages_for_specialist(state["messages"])
        result = await agent.ainvoke({"messages": specialist_messages})
        return {"messages": result["messages"]}

    async def run_job(s):
        return await _run_specialist(job_agent, s)

    async def run_resume(s):
        return await _run_specialist(res_agent, s)

    async def run_interview(s):
        return await _run_specialist(int_agent, s)

    async def run_offer(s):
        return await _run_specialist(off_agent, s)

    async def run_onboarding(s):
        return await _run_specialist(onb_agent, s)

    async def run_comms(s):
        return await _run_specialist(com_agent, s)

    async def run_analytics(s):
        return await _run_specialist(ana_agent, s)

    def run_default_answer(_s):
        return {
            "messages": [
                AIMessage(
                    content=(
                        "I could not determine the right specialist for this request. "
                        "Please rephrase in one line and mention one area: jobs, resumes/candidates, "
                        "interviews, offers, onboarding, communications, or analytics."
                    )
                )
            ]
        }

    g = StateGraph(HRState)
    g.add_node("supervisor",       supervisor_node)
    g.add_node("job_agent",        run_job)
    g.add_node("resume_agent",     run_resume)
    g.add_node("interview_agent",  run_interview)
    g.add_node("offer_agent",      run_offer)
    g.add_node("onboarding_agent", run_onboarding)
    g.add_node("comms_agent",      run_comms)
    g.add_node("analytics_agent",  run_analytics)
    g.add_node("default_answer_agent", run_default_answer)

    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", _route, {
        "job_agent":        "job_agent",
        "resume_agent":     "resume_agent",
        "interview_agent":  "interview_agent",
        "offer_agent":      "offer_agent",
        "onboarding_agent": "onboarding_agent",
        "comms_agent":      "comms_agent",
        "analytics_agent":  "analytics_agent",
        "default_answer_agent": "default_answer_agent",
        END: END,
    })
    for node in ["job_agent","resume_agent","interview_agent","offer_agent",
                 "onboarding_agent","comms_agent","analytics_agent","default_answer_agent"]:
        g.add_edge(node, END)

    return g.compile()


# ── Message serialiser ────────────────────────────────────────────────────────
def serialise_messages(msgs: list) -> list:
    out = []
    for m in msgs:
        if isinstance(m, HumanMessage):
            out.append({"role": "human", "content": m.content})
        elif isinstance(m, AIMessage):
            out.append({"role": "ai", "content": m.content,
                        "tool_calls": getattr(m, "tool_calls", [])})
        elif isinstance(m, ToolMessage):
            out.append({"role": "tool", "name": m.name, "content": m.content,
                        "tool_call_id": getattr(m, "tool_call_id", "")})
    return out


# ── Trace builder ─────────────────────────────────────────────────────────────
def build_trace(msgs: list) -> list:
    trace = []
    active = "Supervisor"
    for msg in msgs:
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                name = tc["name"]
                if name.startswith("transfer_to_"):
                    label  = name.replace("transfer_to_","").replace("_"," ").title()
                    active = label
                    trace.append({"type": "route", "to": label})
                else:
                    trace.append({"type": "tool_call", "agent": active,
                                  "tool": name, "args": tc.get("args", {})})
        if isinstance(msg, ToolMessage):
            raw = msg.content
            if isinstance(raw, list):
                raw = " ".join(c.get("text","") if isinstance(c,dict) else str(c) for c in raw)
            try:    data = json.loads(raw)
            except: data = raw
            if not (isinstance(data, str) and data.startswith("Routing")):
                trace.append({"type": "tool_result", "agent": active,
                               "tool": msg.name, "result": data})
    return trace
