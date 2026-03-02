# Cybersecurity Agent System

A comprehensive AI-powered cybersecurity analysis platform built with LangGraph, FastAPI, and MCP (Model Context Protocol). The system provides intelligent agent routing, vulnerability analysis, reconnaissance, and conversation persistence.

## 🚀 Features

### Core Capabilities
- **Intelligent Agent Routing**: Automatically routes queries to appropriate specialized agents
- **Vulnerability Analysis**: Comprehensive CVE and package vulnerability scanning
- **Reconnaissance**: DNS lookup, port scanning, and WHOIS analysis
- **Conversation Memory**: Redis-backed session persistence for multi-turn conversations
- **Streaming Responses**: Real-time updates via Server-Sent Events
- **ChatGPT-like UI**: Modern web interface for testing and interaction

### Agents
- **Supervisor Agent**: Routes requests and manages conversation flow
- **Vulnerability Agent**: Analyzes software packages and CVEs
- **Recon Agent**: Performs network reconnaissance
- **Direct Answer Agent**: Handles general cybersecurity questions

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Streamlit UI  │    │  FastAPI Server │    │   MCP Servers   │
│                 │    │                 │    │                 │
│ - Session Mgmt  │◄──►│ - /chat         │◄──►│ - Recon (8001)  │
│ - Chat Interface│    │ - /chat/stream  │    │ - Vuln (8003)   │
│ - History       │    │ - /chat/history │    │ - Reporting (8002)
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │     Redis       │
                       │                 │
                       │ - Session Store │
                       │ - Conversation  │
                       │     History     │
                       └─────────────────┘
```

### Components
- **Supervisor API** (`agent/supervisor/`): Main orchestration layer
- **Agent Graphs** (`agent/recon_graph.py`, `agent/vulnerability_graph.py`): Specialized agent logic
- **MCP Tools** (`mcp_tools/`): External tool integrations
- **Shared** (`shared/`): Common models, config, and utilities
- **UI** (`streamlit_app.py`): Testing interface

## 📋 Prerequisites

- Python 3.11+
- Redis Server
- OpenAI API Key

## 🛠️ Installation

1. **Clone and Setup**:
   ```bash
   cd /path/to/project
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Environment Variables**:
   Create `.env` file:
   ```env
   OPENAI_API_KEY=your_openai_api_key
   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_DB=0
   LOG_LEVEL=INFO
   ```

3. **Start Redis**:
   ```bash
   redis-server
   ```

## 🚀 Usage

### 1. Start MCP Servers
```bash
python mcp_launcher.py
```
This starts the tool servers on ports 8001-8003.

### 2. Start Supervisor API
```bash
python supervisor_launcher.py
```
API available at `http://localhost:9000`.

### 3. Start UI (Optional)
```bash
streamlit run streamlit_app.py
```
UI available at `http://localhost:8501`.

## 📡 API Endpoints

### Chat Endpoints
- `POST /chat` - Standard JSON response
- `POST /chat/stream` - Server-Sent Events streaming
- `GET /chat/history/{session_id}` - Retrieve conversation history

### Request Format
```json
{
  "message": "Check vulnerabilities for next@15.0.8",
  "session_id": "optional-session-id"
}
```

### Response Format
```json
{
  "output": "Analysis results...",
  "agent_used": "vulnerability",
  "session_id": "generated-or-provided-id",
  "tool_calls": [...]
}
```

## 🔧 Configuration

### Environment Variables
- `OPENAI_API_KEY`: Required for LLM functionality
- `REDIS_HOST/PORT/DB`: Redis connection settings
- `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)
- `MAX_MESSAGE_LENGTH`: Input validation limit

### Customization
- **Agent Prompts**: Modify prompts in `agent/*/graph.py`
- **Tool Integration**: Add new tools in `mcp_tools/`
- **UI Styling**: Customize `streamlit_app.py`

## 🧪 Testing

### Manual Testing
1. Start all services (MCP + Supervisor + Redis)
2. Use Streamlit UI or direct API calls
3. Test session persistence by refreshing the page

### Example Queries
- `"Check vulnerabilities for next@15.0.8"`
- `"Scan ports on example.com"`
- `"What is DNS?"`
- `"Analyze CVE-2023-12345"`

### Session Continuity
```bash
# First request
curl -X POST http://localhost:9000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Check next package", "session_id": "test-session"}'

# Follow-up with same session
curl -X POST http://localhost:9000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Use version 15.0.8", "session_id": "test-session"}'
```

## 🏗️ Development

### Project Structure
```
27022026/
├── agent/
│   ├── supervisor/          # Main API and routing
│   ├── recon_graph.py       # Reconnaissance agent
│   └── vulnerability_graph.py # Vulnerability agent
├── mcp_tools/               # MCP server implementations
│   ├── recon/
│   ├── vulnerability/
│   └── reporting/
├── shared/                  # Common utilities
│   ├── config.py
│   ├── models.py
│   └── telemetry.py
├── test/                    # Test files
├── streamlit_app.py         # UI for testing
├── supervisor_launcher.py   # API server launcher
├── mcp_launcher.py          # MCP servers launcher
├── requirements.txt
└── README.md
```

### Adding New Agents
1. Create agent graph in `agent/`
2. Update supervisor routing in `agent/supervisor/graph.py`
3. Add MCP tools if needed
4. Update UI if required

### Extending Tools
1. Add tool implementation in appropriate `mcp_tools/*/tools/`
2. Register in server `__init__.py`
3. Update agent prompts to use new tools

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-agent`
3. Make changes and test thoroughly
4. Submit pull request with description

### Guidelines
- Follow existing code patterns
- Add tests for new functionality
- Update documentation
- Ensure Redis/session compatibility

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for defensive cybersecurity research and authorized testing only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse.

## 🆘 Support

For issues and questions:
1. Check the logs in `supervisor.log`
2. Verify Redis connection
3. Ensure all services are running
4. Review API documentation above

---

**Built with**: LangGraph, FastAPI, Streamlit, Redis, OpenAI API
**Date**: March 2, 2026</content>
<parameter name="filePath">/Users/loglogn/parth/Agents/27022026/README.md
