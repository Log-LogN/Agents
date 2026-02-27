# HireSmart HR Hiring System

End-to-end HR hiring assistant built with Streamlit, LangGraph, and MCP (Model Context Protocol). It uses a Supervisor agent to route requests to specialist MCP servers that handle jobs, resumes, interviews, offers, onboarding, communications, and analytics.

This README provides:

- A step-by-step explanation of how the system works
- Details of the MCP servers and routing flow
- How to run the services and UI
- Dependency versions (from `requirements.txt`)

---

## HireSmart HR Hiring System Demo

![alt text](assets/demo.gif)

---

## 1. What This System Does

HireSmart is a multi-agent HR system that supports:

- Job posting management
- Candidate screening and scoring
- Interview scheduling and feedback
- Offer creation and status updates
- Onboarding workflows
- Candidate communications
- Hiring analytics

The system is split into two layers:

1. Supervisor (LangGraph + OpenAI model) decides which agent should handle the user request
2. Specialist MCP Servers execute domain-specific tools backed by a PostgreSQL database

The Streamlit UI is a thin client that sends user messages to the supervisor and displays results.

---

## 2. High-Level Architecture

```
User (Streamlit UI)
    |
    | HTTP (JSON-RPC over MCP)
    v
Supervisor MCP Server (port 9001)
    |
    | routes to ONE specialist
    v
Specialist MCP Servers (ports 8001-8007)
    |
    v
MCP TOOLS
    |
    v
PostgreSQL (data storage)
```

---

## Multi-Agent Architecture Flowchart
![alt text](<./assets/Chart1.png>)

---

## Multi-Agent Sequence Diagram
![alt text](<./assets/Chart2.png>)

---

Key files:

- `app.py` -> Streamlit UI
- `start_servers.py`-> launcher for all MCP servers
- `supervisor/` -> supervisor graph and server
- `supervisor/thread_memory.py` -> Redis memory management
- `mcp_servers/` -> specialist MCP servers
- `database/db.py` -> schema + seed data
- `.env` -> configuration

---

## 3. Detailed Flow (Step by Step)

### 3.1 UI to Supervisor

1. User types a message in the Streamlit UI (`app.py`).
2. The UI sends the message along with a `thread_id` to the Supervisor MCP endpoint:
   - `http://127.0.0.1:9001/mcp`
3. The Supervisor responds with:
   - `final_reply` (text to show the user)
   - `trace` (routing + tool calls)

### 3.2 Supervisor Routing & Persistence

1. The Supervisor loads the session history from **Redis** using the `thread_id`.
2. It uses a LangGraph state machine defined in `supervisor/graph.py`.
3. A system prompt defines routing rules for 7 specialist domains.
4. The supervisor LLM emits a tool call (e.g., `transfer_to_job`).
5. After getting the result, the Supervisor updates the history in Redis, potentially compacting old turns into a summary.

### 3.3 Specialist MCP Servers

Each specialist server is a FastMCP service exposing domain tools:

- Job server: `mcp_servers/job_server.py` (port 8001)
- Resume server: `mcp_servers/resume_server.py` (port 8002)
- Interview server: `mcp_servers/interview_server.py` (port 8003)
- Offer server: `mcp_servers/offer_server.py` (port 8004)
- Onboarding server: `mcp_servers/onboarding_server.py` (port 8005)
- Comms server: `mcp_servers/comms_server.py` (port 8006)
- Analytics server: `mcp_servers/analytics_server.py` (port 8007)

Each server:

1. Receives a call from the supervisor
2. Runs SQL queries via `database/db.py`
3. Returns results as JSON to the supervisor

### 3.4 Trace Logging

The supervisor generates a routing trace (tool calls + results). The Streamlit UI renders the trace under each response in a dropdown section.

---

## 4. How MCP Servers Work (Detailed)

### 4.1 MCP Protocol

- The Supervisor and specialists communicate over JSON-RPC
- Each MCP server exposes `@mcp.tool()` endpoints
- The Supervisor uses `langchain_mcp_adapters.MultiServerMCPClient` to call tools over HTTP

### 4.2 Supervisor MCP Server

File: `supervisor/supervisor_server.py`

- Hosts the `chat` tool on port 9001
- Validates connectivity to OpenAI before processing
- Builds a compiled LangGraph once and reuses it
- Returns JSON with `final_reply` and `trace`

### 4.3 Specialist MCP Servers

Each specialist server defines a set of tools for a domain. Example (Interview server):

- `schedule_interview`
- `get_interview_details`
- `submit_interview_feedback`
- `get_interview_feedback`

All tools use database connections from `database/db.py`.

---

## 5. Database and Data Model

File: `database/db.py`

- Creates schema and seed data on startup
- Key tables:
  - `users`
  - `jobs`
  - `candidates`
  - `interviews`
  - `interview_feedback`
  - `offers`
  - `onboarding`
  - `communications`

Constraints enforce valid ranges (e.g., interview feedback scores must be 1-10).

---

## 6. Running the System

### 6.1 Configure Environment

Update `.env` (use `.env.example` as template):

- `OPENAI_API_KEY`
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- Email settings if needed
- Redis memory settings (optional but recommended for multi-turn speed):
  - `REDIS_ENABLED`, `REDIS_URL`
  - `REDIS_THREAD_TEXT_LIMIT` (max chars before compaction)
  - `REDIS_THREAD_KEEP_MESSAGES` (recent messages kept verbatim)
  - `REDIS_THREAD_TTL_SEC` (thread expiration)
  - `REDIS_SUMMARY_MODEL` (model used to summarize old thread turns)

### Redis Thread Memory

- Each chat session now sends a `thread_id` to the supervisor.
- Supervisor stores per-thread request/response turns in Redis.
- When thread text size crosses `REDIS_THREAD_TEXT_LIMIT`, older turns are compressed into a running summary and only recent turns are kept in full.
- This reduces payload size and keeps multi-agent responses faster while preserving context.

### 6.2 Start All Servers

From the project root:

```
python start_servers.py
```

This starts:

- 7 specialist MCP servers (ports 8001-8007)
- Supervisor MCP server (port 9001)

Logs are written under `logs/`.

### 6.3 Run the UI

In a new terminal:

```
streamlit run app.py
```

Login accounts are shown on the login screen (admin, HR manager, recruiter, hiring manager).

---

## 7. Dependency Versions

From `requirements.txt`:

- langgraph>=0.2.0
- langchain>=0.2.0
- langchain-openai>=0.1.0
- langchain-core>=0.2.0
- langchain-mcp-adapters>=0.1.0
- mcp>=1.0.0
- python-dotenv>=1.0.0
- psycopg2-binary>=2.9.0
- streamlit>=1.35.0
- nest-asyncio>=1.6.0
- uvicorn>=0.30.0
- httpx>=0.27.0
- redis>=5.0.0

---

## 8. Common Troubleshooting

### 8.1 Supervisor Timeout

If you see `Supervisor did not respond within ...`:

- Verify all MCP servers are running
- Check `logs/9001_supervisor_agent.log` for errors

### 8.2 OpenAI Not Reachable

If the supervisor log shows OpenAI connectivity errors:

- Ensure outbound HTTPS to `api.openai.com:443` is allowed

### 8.3 DB Constraint Errors

Errors like `violates check constraint` indicate invalid input ranges. Example:

- `rating` must be 1-5
- `technical_score`, `culture_fit`, `communication` must be 1-10

---

## 9. Extending the System

To add a new specialist agent:

1. Create a new MCP server in `mcp_servers/`
2. Add it to `SPECIALIST_SERVERS` in `supervisor/graph.py`
3. Add a routing rule to `SUPERVISOR_PROMPT` and `ROUTE_KEYWORDS`
4. Add a transfer tool and graph node/edge

The `default_answer_agent` already acts as a safe fallback when routing is unclear.
