# MCP Fusion Agent

LangGraph-based multi-agent system that routes user requests to:
- a **Database Agent** (PostgreSQL query building and execution through MCP tools)
- a **Math Agent** (tool-driven calculations and percentage operations)

It uses an MCP server (`FastMCP`) and an OpenAI model for supervisor routing + tool selection.

## Request Flow
![img_1.png](img_1.png)

## Why this name
**MCP Fusion Agent** fits this repository because it fuses multiple specialized agents behind one chat interface through MCP.

## Repository Structure
- `agent/` - supervisor, routing logic, MCP client, and main agent service
- `mcp_server/` - MCP server and tool registrations (database + math tools)
- `core/` - config, constants, and logging setup
- `chat.py` - CLI entrypoint

## Features
- Supervisor-based routing between database and math workflows
- Database credential capture + schema-aware query execution
- Guardrails for SQL identifier validation and limited query shaping
- MCP tool discovery and OpenAI tool conversion
- Terminal chat and Streamlit chat UI

## Requirements
- Python 3.10+
- PostgreSQL client (`psql`) available in PATH (for DB execution tools)
- OpenAI API key

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create `.env`:
```env
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4o-mini
MCP_SERVER_URL=http://127.0.0.1:8000/mcp
```

## Run
Start MCP server:
```bash
uvicorn mcp_server.server:app --reload --port 8000
```

Run terminal chat:
```bash
python chat.py
```

## Notes
- `app_data/` is intentionally ignored for local/runtime data.
- If MCP server is down, the chat agent returns an unavailable message and retries on later requests.
