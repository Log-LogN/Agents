# Hospital Management System: Technical Documentation

This document provides a detailed, step-by-step explanation of the **Multi-Agent Hospital Management System**. It covers the architecture, technology stack, implementation details, and instructions on how to run both the servers and the UI.

---

## 1. System Overview

The Hospital Management System is a **Multi-Agent System (MAS)** built using the **Model Context Protocol (MCP)** and **LangGraph**. It consists of a central **Supervisor Agent** (running as a standalone FastAPI HTTP server on port 9001) that routes user requests to six specialized agents, each backed by its own MCP server.

### Core Features:

- **Supervisor Agent**: Standalone HTTP server (port 9001) with streaming support (SSE) for intelligent routing.
- **Specialized Agents**: 6 distinct departments (Appointment, Billing, Inventory, Pharmacy, Lab, Ward).
- **Intelligent Routing**: Automated task delegation based on user intent.
- **RBAC (Role-Based Access Control)**: Different levels of access for Patients, Front Desk, Billing, and Admin.
- **Persistent Storage**: PostgreSQL database for managing patients, doctors, inventory, and more.
- **Interactive UI**: Streamlit-based dashboard that communicates with the Supervisor over HTTP, with real-time execution tracing.

---

## 2. System Architecture & Workflow

To visualize how the system works, here is the high-level architecture and the step-by-step message flow.

### Architecture Overview

![alt text](<./assets/Patient-Centric Appointment-2026-02-25-051923.png>)

### Detailed Sequence Flow

![alt text](<./assets/Streamlit Application Risk-2026-02-25-051512.png>)

---

## 3. Technology Stack

- **Python**: Core programming language.
- **FastMCP**: A high-level framework for building MCP servers.
- **FastAPI + Uvicorn**: HTTP server for the Supervisor Agent (port 9001).
- **httpx**: HTTP client used by the Streamlit UI to call the Supervisor.
- **LangGraph & LangChain**: Orchestration of the multi-agent workflow.
- **PostgreSQL**: Relational database for structured data.
- **Streamlit**: Modern web framework for the frontend UI.
- **OpenAI (GPT-4o-mini)**: The "brain" behind the Supervisor and Specialist agents.

---

## 3. Project Structure

```text
Hospital Management/
├── App.py                # Streamlit UI (HTTP client to Supervisor)
├── start_servers.py      # Orchestrator to run all 7 servers
├── requirements.txt      # Project dependencies
├── .env                  # API keys and database credentials
├── database/
│   └── db.py             # Database schema & initialization logic
├── mcp_servers/          # Implementation of the 6 MCP servers
│   ├── appointment_server.py
│   ├── billing_server.py
│   ├── inventory_server.py
│   ├── pharmacy_server.py
│   ├── lab_server.py
│   └── ward_server.py
├── supervisor/
│   ├── graph.py              # Multi-agent LangGraph logic & routing
│   └── supervisor_server.py  # FastAPI HTTP server (port 9001)
└── utils/                # Shared utilities (Email, Printer, Auth)
```

---

## 4. MCP Servers Deep Dive

### What is MCP?

The **Model Context Protocol (MCP)** is an open standard that allows AI models to interact with external tools and data sources. In this project, each department is an "MCP Server" that exposes specific "Tools" (Python functions) to the agents.

### Implementation Pattern (FastMCP)

Every server in `mcp_servers/` follows a standard pattern:

1. **Initialize FastMCP**: Creates a server instance on a specific port.
2. **Define Tools**: Functions decorated with `@mcp.tool()` that perform database operations.
3. **Database Integration**: Tools use `database/db.py` to fetch or update data.
4. **Execution**: The server runs as a background process listening for HTTP requests.

### The 7 Servers:

| #   | Server          | Port | Type    | Key Tools                                          |
| --- | --------------- | ---- | ------- | -------------------------------------------------- |
| 1   | **Supervisor**  | 9001 | FastAPI | `/invoke`, `/stream`, `/health`                    |
| 2   | **Appointment** | 8001 | MCP     | `register_patient`, `book_appointment`, etc.       |
| 3   | **Billing**     | 8002 | MCP     | `generate_invoice`, `get_patient_bill`, etc.       |
| 4   | **Inventory**   | 8003 | MCP     | `update_stock`, `reorder_alerts`, etc.             |
| 5   | **Pharmacy**    | 8004 | MCP     | `create_prescription`, `dispense_medication`, etc. |
| 6   | **Lab**         | 8005 | MCP     | `order_lab_test`, `get_patient_lab_results`, etc.  |
| 7   | **Ward**        | 8006 | MCP     | `get_bed_availability`, `assign_bed`, etc.         |

---

## 5. Multi-Agent Supervisor Logic

The **Supervisor Agent** runs as a standalone FastAPI server (`supervisor/supervisor_server.py`) on **port 9001**. It uses **LangGraph** (`supervisor/graph.py`) to manage the state and transitions between agents.

### Supervisor Server Endpoints:

- **`POST /invoke`** — Accepts messages + actor context as JSON, runs the full agent pipeline, returns messages + trace + final reply.
- **`POST /stream`** — Same input, but streams trace steps and the final reply via Server-Sent Events (SSE).
- **`GET /health`** — Simple health check.

### Step-by-Step Agent Flow:

1. **State Definition**: A `SupervisorState` object holds the message history and current user context.
2. **Dynamic Tool Scoping**: Depending on the user's role (e.g., "Patient"), only specific tools are "exposed" to the agent.
3. **Routing**: The Supervisor reads the user's message and calls a `transfer_to_...` tool.
4. **Agent Handoff**: LangGraph transitions the state to the selected Specialist Agent.
5. **Tool Execution**: The Specialist Agent calls the relevant MCP tools to fulfill the request.
6. **Response**: The result is sent back to the Supervisor to formulate the final answer for the user.

---

## 6. How to Run the Project

### Step 1: Prerequisites

- **Python 3.10+** installed.
- **PostgreSQL** installed and running.
- **OpenAI API Key** ready.

### Step 2: Configuration

1. Create a `.env` file in the root directory.
2. Add your credentials:

```env
OPENAI_API_KEY=your_key_here
DB_HOST=localhost
DB_PORT=5432
DB_NAME=hospital_db
DB_USER=postgres
DB_PASSWORD=your_password
```

### Step 3: Install Dependencies

Run the following command in your terminal:

```bash
pip install -r requirements.txt
```

### Step 4: Start All Servers

Run the orchestrator script. This will initialize the database and start all 7 servers (1 Supervisor + 6 MCP) in parallel:

```bash
python start_servers.py
```

_Wait until you see `[READY] All 7 servers running (Supervisor + 6 MCP)!`_

### Step 5: Start the Streamlit UI

Open a **new terminal** and run:

```bash
streamlit run App.py
```

---

## 7. Understanding the UI

- **Quick Actions**: Sidebar buttons for common tasks (e.g., "Book Appointment").
- **Live Trace**: When you ask a question, an "Execution Trace" expander appears. It shows:
  - **Routing**: Which agent was chosen.
  - **Tool Calls**: Exactly what parameters were sent to the MCP server.
  - **MCP Results**: The raw data returned from the database.
- **Agents Online**: Shows the status and port of each specialized server.

---

_End of Documentation_
