# 📊 FinReport AI — Automated Financial Report Generator

A next-generation, multi-agent AI system for automated financial reporting. Built on the **Model Context Protocol (MCP)** and **LangGraph**, it enables natural language interaction with specialized financial data agents.

---

## 📊 FinReport AI - Demo

![alt text](<./assets/Demo.gif>)

---

## 🏗️ System Architecture

FinReport AI follows a **Hub-and-Spoke** multi-agent architecture where a Supervisor Agent routes inquiries to 7 specialized specialist agents.

![alt text](<./assets/Chart1.png>)

---

### 🏎️ Sequential Workflow

![alt text](<./assets/Chart2.png>)

---


### Core Components

1.  **Streamlit UI**: The user interface where users ask questions and view financial reports. It communicates with the Supervisor via JSON-RPC over HTTP.
2.  **Supervisor Agent**: The "brain" of the system. Built with **LangGraph**, it identifies user intent and routes requests to the appropriate specialist agent.
3.  **Specialist MCP Servers**: Seven dedicated agents (GL, P&L, Balance Sheet, etc.) that provide specific financial tools. Each runs as an independent MCP server using `FastMCP`.
4.  **PostgreSQL Database**: The source of truth for all financial data (transactions, accounts, budgets).

---

## ✨ Features & Specialist Agents

| Agent                   | Core Capabilities                                                            | Port   |
| :---------------------- | :--------------------------------------------------------------------------- | :----- |
| **📒 GL & Transaction** | Journal entries, Trial Balance, Account Reconciliation, Departmental Spend   | `8001` |
| **📈 Profit & Loss**    | Income Statement (Waterfall), EBITDA analysis, Revenue growth, Gross Margins | `8002` |
| **⚖️ Balance Sheet**    | Assets/Liabilities/Equity, Liquidity ratios, Debt-to-Equity, Working Capital | `8003` |
| **💸 Cash Flow**        | Cash Position (Live), Runway & Burn Rate, AR/AP Aging, Cash Alerts           | `8004` |
| **🎯 Budgeting**        | Actual vs Plan variance, Overspend ranking, Forecast updates, Budget alerts  | `8005` |
| **📊 KPI & Analytics**  | Dashboard generation, Industry Benchmarking, Trend analysis, Weekly digests  | `8006` |
| **📩 Report Delivery**  | Automated Board Packs, Email summaries, Multi-step Approval flows            | `8007` |

---

## � MCP Server Implementation

The system heavily utilizes the **Model Context Protocol (MCP)** for communication between the LLM and the tools.

### 1. Specialist Agents (`FastMCP`)

Each specialist agent (e.g., `mcp_servers/pl_server.py`) is implemented using the `FastMCP` library.

**Key Characteristics:**

- **Transport**: Uses `streamable-http`, which allows the server to act as a standard HTTP server responding to JSON-RPC 2.0 requests.
- **Port-based**: Each agent listens on a dedicated port (8001–8007).
- **Stateless**: Operations are stateless, making the system scalable.

**Example Code Structure (`pl_server.py`):**

```python
mcp = FastMCP("PLServer", host="127.0.0.1", port=8002, stateless_http=True)

@mcp.tool()
def get_income_statement(date_from: str, date_to: str) -> dict:
    # SQL logic to fetch data
    return {"revenue": 100000, "ebitda": 25000, ...}
```

### 2. Supervisor (`MultiServerMCPClient`)

The Supervisor (`supervisor/graph.py`) acts as a client to all these specialist agents. It uses `MultiServerMCPClient` from `langchain_mcp_adapters` to connect to multiple servers simultaneously.

**Workflow:**

- The Supervisor queries the specialist servers for their available tools.
- LangGraph uses these tool definitions to allow the LLM to choose which "specialist" to invoke.

---

## 🧠 Orchestration Logic (LangGraph)

The orchestration is handled in `supervisor/graph.py` using a state machine:

1.  **Supervisor Node**: Analyzes the latest human message and uses `_pick_route_node` (keyword-based logic) to decide which specialist agent should handle the request.
2.  **Specialist Nodes**: Once a specialist is selected, the graph transitions to that agent's node. Each specialist is equipped with its own set of MCP-defined tools.
3.  **Tool Execution**: If the LLM decides to use a tool, the MCP adapter handles the transformation and execution.
4.  **Final Reply**: The output is compiled and sent back to the UI.

---

## ⚡ Step-by-Step Execution Flow

1.  **User Inquiry**: User asks: _"Show the P&L for February 2026"_ in the Streamlit UI.
2.  **UI Request**: `ui/services.py` sends a JSON-RPC request to the Supervisor at port 9001.
3.  **Supervisor Routing**:
    - The Supervisor receives the message history.
    - `_pick_route_node` identifies "P&L" keywords.
    - The graph routes to `pl_agent`.
4.  **Specialist Action**:
    - `pl_agent` uses its `get_income_statement` tool.
    - The MCP adapter makes an HTTP POST request to `127.0.0.1:8002/mcp`.
5.  **Data Retrieval**: The P&L server executes SQL against PostgreSQL and returns the financial dict.
6.  **Response Synthesis**: The LLM formats the raw data into a human-readable table/summary.
7.  **Display**: The UI receives the final reply and the `trace` (showing which agents were involved) and renders them.

---

## 🛠️ Tech Stack & Dependencies

| Category          | Dependency               | Version    | Purpose                               |
| :---------------- | :----------------------- | :--------- | :------------------------------------ |
| **UI**            | `streamlit`              | `>=1.32.0` | Frontend dashboard                    |
| **Orchestration** | `langgraph`              | `>=0.1.0`  | Multi-agent state machine             |
| **MCP**           | `mcp[cli]`               | `>=1.0.0`  | Model Context Protocol implementation |
| **AI Adapter**    | `langchain-mcp-adapters` | `>=0.1.0`  | Client-side MCP connectivity          |
| **LLM**           | `langchain-openai`       | `>=0.1.0`  | GPT-4o integration                    |
| **Database**      | `psycopg2-binary`        | `>=2.9.9`  | PostgreSQL connectivity               |
| **Utility**       | `redis`                  | `>=5.0.0`  | Multi-turn conversation memory        |

---

## 🚀 Quick Start

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with your OpenAI Key, DB URL, and Email settings
```

### 2. Launch All Servers

FinReport AI uses a cluster of 8 servers. Launch them all with one command:

```bash
python start_servers.py
```

### 3. Start the UI

In a new terminal:

```bash
streamlit run app.py
```

---

## 🔐 Role-Based Access

| Role             | Email                   | Password     | Access Level                          |
| :--------------- | :---------------------- | :----------- | :------------------------------------ |
| **Admin**        | `admin@finapp.com`      | `admin123`   | Full System Access                    |
| **CFO**          | `cfo@finapp.com`        | `cfo123`     | Strategic (P&L, BS, CF, KPI, Reports) |
| **FP&A Analyst** | `analyst@finapp.com`    | `analyst123` | Operational (GL, P&L, Budget, KPI)    |
| **Controller**   | `controller@finapp.com` | `ctrl123`    | Compliance (GL, BS, CF, Reports)      |

---

## 💬 Example Inquiries

- _"Show the P&L for February 2026 with EBITDA breakdown"_
- _"What is our cash position and how many months of runway remain?"_
- _"Which departments are significantly over budget this month?"_
- _"Compare our current gross margin vs industry benchmarks."_
- _"Generate and send the monthly board pack to the board distribution list."_
