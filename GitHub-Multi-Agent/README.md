# 🤖 GitHub Multi-Agent System

> **Production-ready multi-agent architecture** — a GPT-4o-powered **Supervisor** intelligently routes natural-language requests to specialized **Agents**, each backed by its own **MCP Server** with dedicated tool implementations.

---

## 📸 Screenshots

| Streamlit Chat UI |              Supervisor CLI               |               MCP CLI               |
|:-:|:-----------------------------------------:|:-----------------------------------:|
| ![img.png](docs/images/img.png)| ![img_1.png](docs/images/img_1.png) | ![img_2.png](docs/images/img_2.png) |

---

## 🏗️ Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│              User / Streamlit Frontend                    │
└──────────────────────────┬───────────────────────────────┘
                           │  POST /chat  (SSE stream)
                           ▼
          ┌────────────────────────────────┐
          │       Supervisor API           │  :8000
          │   FastAPI + GPT-4o routing     │
          │   • API Key auth               │
          │   • Rate limiting (20 req/min) │
          │   • Prompt injection guard     │
          │   • Input validation           │
          └──────────────┬─────────────────┘
                         │  LLM decides agent
          ┌──────────────▼──────────────┐
          │       GitHub Agent          │  :8001
          │   FastAPI + LangGraph       │
          │   ReAct loop with MCP tools │
          └──────────────┬──────────────┘
                         │  stdio (MCP protocol)
          ┌──────────────▼──────────────┐
          │    GitHub MCP Server        │
          │    FastMCP (16 tools)       │
          └──────────────┬──────────────┘
                         │  REST (HTTPS)
          ┌──────────────▼──────────────┐
          │        GitHub API           │
          │    api.github.com           │
          └─────────────────────────────┘

```
---

## 📁 Project Structure

```
GitHub-Multi-Agent/
├── main.py                         ← Local dev launcher (asyncio, both services)
├── mcp_launcher.py                 ← Standalone MCP layer launcher (Rich UI)
├── supervisor_launcher.py          ← Standalone Supervisor launcher (Rich UI)
├── streamlit_app.py                ← Streamlit chat frontend (SSE streaming)
├── requirements.txt                ← All Python dependencies
├── .env.example                    ← Environment variables template
│
├── supervisor/
│   ├── api.py                      ← FastAPI app (port 8000) — secured entry point
│   └── graph.py                    ← LangGraph routing logic (GPT-4o JSON routing)
│
├── agents/
│   └── github/
│       ├── api.py                  ← FastAPI app (port 8001) — agent endpoint
│       ├── graph.py                ← LangGraph ReAct agent + MCP client
│       ├── resolver.py             ← Smart parameter resolver (branch, workflow_id, run_id)
│       └── mcp_server/
│           ├── server.py           ← FastMCP server (stdio transport)
│           └── tools/              ← 16 individual tool modules
│               ├── get_repo_info.py
│               ├── get_file_from_repo.py
│               ├── list_issues.py
│               ├── list_pull_requests.py
│               ├── get_pull_request.py
│               ├── search_code.py
│               ├── list_branches.py
│               ├── get_default_branch.py
│               ├── list_commits.py
│               ├── get_commit.py
│               ├── list_workflows.py
│               ├── list_workflow_runs.py
│               ├── get_workflow_run.py
│               ├── get_artifacts_for_run.py
│               ├── download_artifact.py
│               └── trigger_workflow_dispatch.py
│
└── shared/
    ├── config.py                   ← Centralized settings (all env vars)
    ├── models.py                   ← Pydantic request/response models
    ├── github_client.py            ← GitHub REST client (retry + rate-limit aware)
    ├── cache.py                    ← In-memory LRU cache + Redis adapter
    ├── cache_keys.py               ← Deterministic SHA-256 cache key builder
    ├── tooling.py                  ← cached_tool_call / uncached_tool_call helpers
    ├── approval.py                 ← HMAC approval token generation + validation
    ├── audit.py                    ← Audit log with automatic value masking
    └── telemetry.py                ← Thread-safe in-process metrics counters
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- OpenAI API key (`gpt-4o` access)
- GitHub Personal Access Token (PAT)

### 1 — Clone & install

```bash
git clone <your-repo-url>
cd GitHub-Multi-Agent
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys:

```dotenv
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
GITHUB_TOKEN=github_pat_...
SUPERVISOR_API_KEY=          # leave blank to disable auth in dev
```

> **GitHub Token scopes:**
> - Public repos only → `Public Repositories (read-only)`
> - Private repos → `repo`
> - Trigger workflows → `repo` + `actions:write`

### 3a — Run locally (development)

```bash
python main.py
```

Both services start with auto-reload:

| Service | URL |
|---|---|
| Supervisor API | http://localhost:8000 |
| GitHub Agent API | http://localhost:8001 |
| Supervisor Swagger | http://localhost:8000/docs |
| GitHub Agent Swagger | http://localhost:8001/docs |

### 3b — Run with Streamlit UI

```bash
# In a separate terminal (after main.py is running):
streamlit run streamlit_app.py
```

---

## 🖥️ Streamlit Chat Frontend

`streamlit_app.py` provides a **real-time streaming chat interface** that:

- Connects to the Supervisor's `/chat/stream` SSE endpoint
- Shows **live token-by-token output** as the agent reasons
- Renders tool call traces (tool name → input → output) in expandable sections
- Supports `X-API-Key` header injection for secured deployments
- Session ID tracking for multi-turn conversations

---

## 🔌 API Reference

### `POST /chat` — Supervisor

Send a natural-language message; the Supervisor routes it to the correct agent.

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '{"message": "List open issues in OpenBB-finance/OpenBB", "session_id": "user-1"}'
```

**Response:**

```json
{
  "output": "Here are the open issues in OpenBB-finance/OpenBB ...",
  "agent_used": "github",
  "session_id": "user-1",
  "tool_calls": [
    {
      "tool_name": "tool_list_issues",
      "tool_input": {"owner": "OpenBB-finance", "repo": "OpenBB", "state": "open"},
      "tool_output": "[{\"number\": 7001, \"title\": \"...\"}]"
    }
  ]
}
```

### `POST /chat/stream` — Supervisor (SSE)

Streaming variant — emits Server-Sent Events as the agent reasons.

```bash
curl -X POST http://localhost:8000/chat/stream \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -H "X-API-Key: <your-key>" \
  -d '{"message": "List open issues in OpenBB-finance/OpenBB"}'
```

SSE event types: `routing`, `tool_call`, `tool_result`, `llm_chunk`, `llm_final`, `error`

### `GET /agents` — Supervisor

List all registered agents and their live health status.

```bash
curl http://localhost:8000/agents -H "X-API-Key: <your-key>"
```

```json
{
  "agents": {
    "github": {"url": "http://localhost:8001", "status": "online"}
  }
}
```

### `GET /health` — (public, no auth)

```bash
curl http://localhost:8000/health
# {"status": "ok", "service": "supervisor"}
```

### `POST /invoke` — GitHub Agent (direct)

Bypass the supervisor and call the GitHub Agent directly.

```bash
curl -X POST http://localhost:8001/invoke \
  -H "Content-Type: application/json" \
  -d '{"message": "How many stars does microsoft/vscode have?"}'
```

---

## 🛠️ GitHub MCP Tool Inventory

All 16 tools are registered on the GitHub MCP Server and exposed to the LangGraph agent. Every read tool response is **cached** (in-memory LRU or Redis) and instrumented with telemetry counters.

| # | Tool | Description | Example Query |
|---|---|---|---|
| 1 | `get_repo_info` | Repo metadata: stars, forks, language, topics, license | `"Show repo info for OpenBB-finance/OpenBB"` |
| 2 | `get_file_from_repo` | Read any file from a branch | `"Get README.md from OpenBB-finance/OpenBB"` |
| 3 | `list_issues` | List open/closed issues with label filter | `"List open issues in OpenBB-finance/OpenBB"` |
| 4 | `list_pull_requests` | List PRs by state | `"List open PRs in OpenBB-finance/OpenBB"` |
| 5 | `get_pull_request` | Full details of a single PR | `"Explain PR #7376 in OpenBB-finance/OpenBB"` |
| 6 | `search_code` | Search code by keyword across the repo | `"Search 'form4' in OpenBB-finance/OpenBB"` |
| 7 | `list_branches` | List all branches | `"List branches in OpenBB-finance/OpenBB"` |
| 8 | `get_default_branch` | Resolve the default branch name | `"What is the default branch of OpenBB-finance/OpenBB?"` |
| 9 | `list_commits` | Recent commits on a branch | `"List latest commits in OpenBB-finance/OpenBB"` |
| 10 | `get_commit` | Inspect a single commit by SHA | `"Get commit <sha> in OpenBB-finance/OpenBB"` |
| 11 | `list_workflows` | List all GitHub Actions workflows | `"List workflows in OpenBB-finance/OpenBB"` |
| 12 | `list_workflow_runs` | List runs for a specific workflow | `"List workflow runs for workflow CI in OpenBB-finance/OpenBB"` |
| 13 | `get_workflow_run` | Details of a single workflow run | `"Get workflow run <run_id> in OpenBB-finance/OpenBB"` |
| 14 | `get_artifacts_for_run` | List artifacts attached to a run | `"List artifacts for run <run_id> in OpenBB-finance/OpenBB"` |
| 15 | `download_artifact` | Get artifact download URL/pointer | `"Get artifact download info for artifact <artifact_id> in OpenBB-finance/OpenBB"` |
| 16 | `trigger_workflow_dispatch` | Trigger a `workflow_dispatch` event **(approval required)** | See [Approval Flow](#-approval-flow-trigger_workflow_dispatch) below |

---

## 🔐 Approval Flow — `trigger_workflow_dispatch`

Triggering a workflow is a **write action** and requires a two-step approval process to prevent accidental or malicious execution:

**Step 1 — Request (no token)**

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <key>" \
  -d '{"message": "Trigger workflow CI on main in OpenBB-finance/OpenBB"}'
```

Response includes an `approval_token` with a 10-minute TTL.

**Step 2 — Confirm (with token)**

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <key>" \
  -d '{
    "message": "Trigger workflow CI on main in OpenBB-finance/OpenBB",
    "approval_token": "<token-from-step-1>"
  }'
```

The token is HMAC-signed (`SHA-256`), scoped to `tool_name + args + session_id`, and expires after `APPROVAL_TOKEN_TTL_SEC` seconds (default: 600).

---

## 🔑 Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | ✅ | — | OpenAI API key |
| `OPENAI_MODEL` | ✅ | `gpt-4o` | Model name |
| `GITHUB_TOKEN` | ✅ | — | GitHub PAT (needed for code search & write tools) |
| `SUPERVISOR_API_KEY` | — | *(empty = auth disabled)* | X-API-Key value for protected endpoints |
| `GITHUB_AGENT_URL` | ✅ | `http://localhost:8001` | URL the Supervisor uses to reach the GitHub Agent |
| `SUPERVISOR_PORT` | — | `8000` | Supervisor listen port |
| `GITHUB_AGENT_PORT` | — | `8001` | GitHub Agent listen port |
| `RATE_LIMIT_PER_MINUTE` | — | `20` | Max requests/minute per IP |
| `MAX_MESSAGE_LENGTH` | — | `2000` | Max characters in a chat message |
| `LOG_LEVEL` | — | `INFO` | Python logging level |
| `CACHE_BACKEND` | — | `memory` | `memory` (LRU) or `redis` |
| `REDIS_URL` | — | `redis://localhost:6379/0` | Redis connection URL |
| `CACHE_MAX_SIZE` | — | `256` | Max LRU cache entries |
| `CACHE_DEFAULT_TTL` | — | `120` | Default cache TTL in seconds |
| `TOOL_VERSION` | — | `v1` | Cache-busting version tag for all tools |
| `APPROVAL_SECRET` | — | *(derived from `SUPERVISOR_API_KEY`)* | HMAC secret for approval tokens |
| `APPROVAL_TOKEN_TTL_SEC` | — | `600` | Approval token expiry in seconds |
| `ALLOWED_ORIGINS` | — | `*` | Comma-separated CORS origins |

---

## 🔄 Full Request Flow

```
1.  User → POST /chat  (Supervisor :8000)

2.  Supervisor security pipeline:
      a. API Key verification (X-API-Key header)
      b. Rate limit check (sliding window, per IP)
      c. Input validation (length + empty check)
      d. Prompt injection guard (regex heuristics)

3.  Supervisor LangGraph (GPT-4o, JSON-mode):
      → decides: agent="github", refined_message="..."

4.  Supervisor → POST /invoke  (GitHub Agent :8001)

5.  GitHub Agent LangGraph ReAct loop:
      a. agent_node:  LLM sees system prompt + tools + message
                      → decides: call tool_list_issues
      b. Resolver:    auto-fills missing params (branch, workflow_id, run_id)
      c. tool_node:   MCP Client → stdio → MCP Server
      d. MCP Server:  cache lookup → GitHub REST API → cache write
      e. tool_node:   result injected back into message history
      f. agent_node:  LLM formulates final answer
      g. loop ends    (no more tool_calls)

6.  GitHub Agent → {output, tool_calls}

7.  Supervisor → {output, agent_used, session_id, tool_calls}

8.  User receives final response (or SSE stream)
```

---

## ⚙️ Cross-Cutting Features

### 🗄️ Caching

Every read tool is wrapped with `cached_tool_call()`:

- **Backend**: in-memory LRU (default) or Redis (`CACHE_BACKEND=redis`)
- **Key**: `mcp:{server}:{tool}:{tool_version}:sha256({sorted_args})`
- **TTL**: configurable per tool (e.g. `get_repo_info` = 300 s, `list_issues` = 120 s)
- **Invalidation**: bump `TOOL_VERSION` in `.env` to bust all cached entries

### 🔒 Security

| Layer | Implementation |
|---|---|
| API Key auth | `X-API-Key` header, constant-time HMAC compare |
| Rate limiting | In-memory sliding-window, 20 req/min/IP |
| Input validation | Length cap (2000 chars), empty-message reject |
| Prompt injection guard | Regex patterns: `ignore instructions`, `jailbreak`, `DAN mode`, etc. |
| CORS | Locked to `ALLOWED_ORIGINS` (default `*` for dev) |
| Approval tokens | HMAC-SHA-256 signed, TTL-bound, scoped to session + tool + args |

### 📊 Telemetry

Thread-safe in-process counters (no external dependency):

| Metric | Description |
|---|---|
| `tool_calls_total` | Total MCP tool invocations |
| `tool_call_<name>` | Per-tool invocation count |
| `cache_hit` | Cache hits across all tools |
| `cache_miss` | Cache misses |
| `github_rate_limited` | GitHub 429 responses received |
| `supervisor_chat_requests` | Successful `/chat` requests |
| `supervisor_chat_errors` | Failed `/chat` requests |
| `supervisor_rate_limit_exceeded` | Rate-limit rejections |

Read via: `GET /metrics` (if wired) or call `shared.telemetry.snapshot()`.

### 🔍 Smart Parameter Resolver (`resolver.py`)

The GitHub Agent includes an automatic parameter resolver that fills in missing context before a tool call:

- **Default branch** — if a tool needs a `branch` and none is provided, it calls `get_default_branch` automatically
- **Workflow ID** — if only a workflow name (e.g. `"CI"`) is given, it calls `list_workflows` to resolve the numeric ID
- **Run ID** — fuzzy resolution of the latest run for a given workflow

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `openai` | GPT-4o LLM calls |
| `langchain-openai` | OpenAI LangChain integration |
| `langchain-core` | Message types, base abstractions |
| `langgraph` | StateGraph for ReAct agent loops |
| `langchain-mcp-adapters` | Bridges MCP tools → LangChain tools |
| `mcp` | Model Context Protocol (FastMCP server) |
| `fastapi` | HTTP API layer |
| `uvicorn` | ASGI server |
| `httpx` | Async HTTP client (supervisor → agents) |
| `requests` | Sync HTTP client (GitHub API) |
| `pydantic` | Data validation & settings |
| `python-dotenv` | `.env` file loading |
| `redis` | Optional Redis cache backend |
| `streamlit` | Chat frontend UI |

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

