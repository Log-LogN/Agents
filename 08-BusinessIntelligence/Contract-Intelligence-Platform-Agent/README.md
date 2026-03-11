# Contract Intelligence Platform

AI-powered multi-agent contract lifecycle management system with a Supervisor API, seven MCP agent servers, and a Streamlit UI.

**What This Repo Contains**
- A Supervisor FastAPI service that classifies intent and routes requests to the right agent.
- Seven specialist agents, each running its own MCP server and tool set.
- A Streamlit UI with role-based access and both chat and workflow pages.
- A PostgreSQL-backed data layer with auto-initializing schema and demo seed data.

**Repository Layout**
- `app.py` Streamlit UI entrypoint.
- `start_servers.py` starts all seven MCP agent servers.
- `start_supervisor.py` starts the Supervisor API.
- `agents/` specialist agents, their graphs, MCP servers, and tools.
- `supervisor/` Supervisor API and LangGraph orchestration.
- `database/` PostgreSQL schema, connection helpers, seed data.
- `ui/` Streamlit pages, components, styles.
- `utils/` auth helpers (bcrypt, JWT, RBAC).
- `shared/` constants and prompt loader.

**Quick Start**
1. Install dependencies.
```bash
pip install -r requirements.txt
```
2. Configure environment.
```bash
copy .env.example .env
# Edit .env and set OPENAI_API_KEY, DATABASE_URL
```
3. Start MCP agent servers (Terminal 1).
```bash
python start_servers.py
```
4. Start Supervisor API (Terminal 2).
```bash
python start_supervisor.py
```
5. Start Streamlit UI (Terminal 3).
```bash
streamlit run app.py
```

**Environment Variables**
- `OPENAI_API_KEY` Required for LLM-backed analysis and summarization.
- `OPENAI_MODEL` Model name, default `gpt-4o-mini`.
- `DATABASE_URL` PostgreSQL connection string used by `database/db.py`.
- `SUPERVISOR_PORT` Defaults to `8000`.
- `DRAFT_PORT`, `REVIEW_PORT`, `APPROVAL_PORT`, `EXECUTION_PORT`, `OBLIGATION_PORT`, `COMPLIANCE_PORT`, `ANALYTICS_PORT` Defaults `8001-8007`.
- `UI_PORT` UI port, used by docs and conventions.
- `SECRET_KEY`, `JWT_ALGORITHM`, `JWT_EXPIRE_HOURS` Auth configuration for `utils/auth.py`.

**Dependencies (from requirements.txt)**
- `langgraph>=0.2.0`
- `langchain>=0.2.0`
- `langchain-openai>=0.1.0`
- `langchain-core>=0.2.0`
- `langchain-mcp-adapters>=0.1.0`
- `mcp>=1.0.0`
- `python-dotenv>=1.0.0`
- `psycopg2-binary>=2.9.0`
- `streamlit>=1.35.0`
- `nest-asyncio>=1.6.0`
- `uvicorn>=0.30.0`
- `httpx>=0.27.0`
- `redis>=5.0.0`
- `fastapi>=0.115.0`
- `PyJWT>=2.8.0`
- `bcrypt>=4.1.0`
- `pandas>=2.0.0`
- `numpy>=1.26.0`

**Ports**
| Service | Port |
| --- | --- |
| Supervisor API | 8000 |
| Draft Agent MCP | 8001 |
| Review Agent MCP | 8002 |
| Approval Agent MCP | 8003 |
| Execution Agent MCP | 8004 |
| Obligation Agent MCP | 8005 |
| Compliance Agent MCP | 8006 |
| Analytics Agent MCP | 8007 |
| Streamlit UI | 8501 |

---

**Architecture Diagram**

![alt text](<./assets/Chart1.png>)

---

**Sequence Diagram (Mermaid)**

![alt text](<./assets/Chart2.png>)

---

**Step-by-Step Execution Flow**

**A. Assistant Chat Flow (UI -> Supervisor -> MCP)**
1. The user opens the **Assistant** page in the UI (`ui/pages/assistant.py`).
2. The UI posts the chat message to the Supervisor API at `POST /chat` or `POST /debug/chat` (`supervisor/api.py`).
3. The Supervisor graph (`supervisor/graph.py`) classifies intent using an LLM prompt and the `ChatOpenAI` client.
4. RBAC is enforced using `utils/auth.can_access_intent()` and `shared/constants.INTENT_PERMISSION`.
5. The Supervisor calls the right agent reasoning function (for example `agents/review_agent/graph.py`).
6. The agent reasoning graph (`agents/common/graph_runtime.py`) builds a LangGraph with a reasoning step, tool step, and summarization step.
7. The graph loads MCP tools from the agent’s MCP server using `MultiServerMCPClient` with `streamable_http` and a URL like `http://localhost:8002/mcp`.
8. The LLM decides which tool(s) to call and the ToolNode executes them via MCP.
9. The tool implementations read/write PostgreSQL using `database/db.py` helpers.
10. The agent summarizes the results and returns output to the Supervisor.
11. The Supervisor formats the final response and writes an audit log row via `database.db.log_audit()`.
12. The UI renders the response; in debug mode it shows the full trace from `/debug/chat`.

**B. Direct UI Tool Flow (UI -> DB)**
1. Many Streamlit pages call tool functions directly (no MCP) for faster UI interactions.
2. Examples: `ui/pages/analytics.py` calls `agents/analytics_agent/mcp_server/tools/analytics_tools.py` directly.
3. Those tools access PostgreSQL through `database/db.py` and return results to the UI.

**Supervisor API Details**
- `POST /chat` Standard assistant endpoint returning `response`, `intent`, `duration_ms`.
- `POST /debug/chat` Same as `/chat` plus a full debug trace.
- `GET /health` Health check.
- `GET /agents/status` TCP port checks for all MCP agents.

**MCP Server Implementation Details**
Each agent MCP server follows the same pattern, for example `agents/review_agent/mcp_server/server.py`.
- Uses `FastMCP` to register tools via the `@mcp.tool()` decorator.
- Runs with `uvicorn` and exposes a `streamable_http_app()` on `http://localhost:<port>/mcp`.
- Wraps tool outputs in JSON strings so MCP clients can parse results.
- Exposes a `tool_agent_graph` helper that runs the agent’s LangGraph reasoning from within MCP.

**Agent Catalog and Tooling**
- DraftAgent (port 8001): `tool_create_contract`, `tool_get_templates`, `tool_get_clause_library`, `tool_update_contract`, `tool_save_draft`, `tool_agent_graph`.
- ReviewAgent (port 8002): `tool_analyze_contract`, `tool_get_risk_score`, `tool_suggest_redlines`, `tool_flag_clauses`, `tool_compare_to_playbook`, `tool_check_missing_clauses`, `tool_agent_graph`.
- ApprovalAgent (port 8003): `tool_create_approval_workflow`, `tool_get_approval_status`, `tool_approve_contract`, `tool_reject_contract`, `tool_escalate_approval`, `tool_get_pending_approvals`, `tool_agent_graph`.
- ExecutionAgent (port 8004): `tool_initiate_signing`, `tool_get_signing_status`, `tool_finalize_contract`, `tool_send_signing_reminder`, `tool_store_executed_contract`, `tool_generate_execution_summary`, `tool_agent_graph`.
- ObligationAgent (port 8005): `tool_extract_obligations`, `tool_get_obligations`, `tool_update_obligation_status`, `tool_get_upcoming_deadlines`, `tool_create_renewal_alert`, `tool_process_amendment`, `tool_agent_graph`.
- ComplianceAgent (port 8006): `tool_check_compliance`, `tool_get_compliance_issues`, `tool_run_gdpr_check`, `tool_run_jurisdiction_check`, `tool_generate_audit_trail`, `tool_check_data_residency`, `tool_agent_graph`.
- AnalyticsAgent (port 8007): `tool_get_portfolio_summary`, `tool_get_expiry_report`, `tool_get_risk_dashboard`, `tool_search_contracts`, `tool_get_spend_analytics`, `tool_get_cycle_time_report`, `tool_export_report`, `tool_agent_graph`.

**Agent Graph Runtime (LangGraph)**
- `agents/common/graph_runtime.py` builds a per-agent graph with three steps.
- `reasoning` step uses `ChatOpenAI` with tool bindings to decide on tool calls.
- `tools` step executes MCP tools via `ToolNode`.
- `summarize` step produces final user-facing output.
- Tool calls and outputs are captured in `tool_calls` for debugging and auditing.

**Database Layer**
- `database/db.py` manages schema, connection helpers, and seed data.
- Auto-creates the database (if the PostgreSQL user has permission).
- Initializes tables for users, contracts, clauses, templates, approvals, obligations, compliance, and audit logs.
- Seeds demo users, templates, clauses, and sample contracts on first run.

**Authentication and RBAC**
- `utils/auth.py` handles bcrypt password hashing and JWT token creation.
- `shared/constants.py` defines roles, permissions, and UI page access.
- The Supervisor enforces intent permissions before calling agents.

**Streamlit UI**
- `app.py` handles session state and page routing.
- `ui/pages/login.py` authenticates against the database using `utils/auth.authenticate_user()`.
- `ui/pages/assistant.py` calls the Supervisor API and renders the multi-agent chat experience.
- Other pages (Dashboard, Contracts, Draft, Review, Approvals, Obligations, Compliance, Analytics, Admin) load data via tool functions and database queries.

**Logs**
- MCP servers and the Supervisor API write logs to `logs/` (see `start_servers.py` and `start_supervisor.py`).
- The Supervisor also writes an audit trail to the `audit_log` table.

**Demo Login Accounts**
| Email | Password | Role |
| --- | --- | --- |
| admin@contract.ai | Admin@123 | Admin |
| legal@contract.ai | Legal@123 | Legal Counsel |
| manager@contract.ai | Manager@123 | Contract Manager |
| procure@contract.ai | Procure@123 | Procurement |
| finance@contract.ai | Finance@123 | Finance |
| viewer@contract.ai | Viewer@123 | Viewer |

**How To Run In 3 Terminals**
1. MCP Agents.
```bash
python start_servers.py
```
2. Supervisor API.
```bash
python start_supervisor.py
```
3. Streamlit UI.
```bash
streamlit run app.py
```

**Troubleshooting Notes**
- If PostgreSQL is not running or credentials are wrong, tools return error messages or fallback responses.
- If MCP agents are down, the Supervisor and Admin page will show them as DOWN.
