"""Project-wide constants."""

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_MCP_SERVER_URL = "http://127.0.0.1:8000/mcp"

DB_AGENT_SYSTEM_PROMPT = (
    "You are a PostgreSQL database assistant. "
    "Convert user requests to SQL tool calls. "
    "Use one of build_select_query/build_count_query/build_join_query first, "
    "then execute_query. "
    "The active schema is '{schema}'. "
    "Known table metadata:\n{table_context}\n"
    "Assume credentials are already collected. "
    "For requests like 'latest N <table>', use order_by='id desc' and limit=N. "
    "For requests like 'how many rows match between table A and table B by key', "
    "prefer build_join_query with columns=['COUNT(*) AS total']. "
    "When parameters are missing, use sensible defaults."
)

MATH_AGENT_SYSTEM_PROMPT = (
    "You are a mathematical operations assistant. "
    "Choose the correct math tool based on the user request and call it directly. "
    "If user asks for arithmetic expression, use math_evaluate_expression. "
    "For 'x out of y' or score percentage, call math_percentage_from_total with obtained=x and total=y. "
    "For 'N percent of value', call math_percentage. "
    "For power/exponent requests, call math_power."
)

SUPERVISOR_ROUTER_SYSTEM_PROMPT = (
    "You are a strict supervisor router for two agents: database_agent and math_agent. "
    "Pick exactly one route based on the user request intent. "
    "Return only one token: database_agent or math_agent. "
    "Use database_agent for SQL, tables, schema, records, users/orders/news in DB context, joins, counts from DB. "
    "Use math_agent for arithmetic, percentages, remaining/left word problems, equations, and numeric reasoning."
)

# TOOL_SELECTION_SYSTEM_PROMPT = (
#     "You are a tool-calling assistant. "
#     "For every user request, you must respond only by calling a relevant tool. "
#     "Do not provide any direct text responses outside of tool calls. "
#     "Use the full user message as input when required. "
#     "If no suitable tool exists, do not generate a normal reply."
# )

MCP_UNAVAILABLE_MESSAGE = (
    "MCP server is unavailable right now. Start/restart it with "
    "'uvicorn mcp_server.server:app --reload --port 8000' and retry."
)

DATABASE_ROUTE_KEYWORDS = (
    "database",
    "postgres",
    "postgresql",
    "sql",
    "schema",
    "table",
    "query",
    "credential",
    "credentials",
    "host=",
    "port=",
    "user=",
    "password=",
    "database=",
    "dbname=",
)

MATH_ROUTE_KEYWORDS = (
    "math",
    "mathematics",
    "calculate",
    "calculation",
    "add",
    "sum",
    "plus",
    "subtract",
    "minus",
    "multiply",
    "product",
    "divide",
    "percentage",
    "percent",
    "power",
    "square",
    "cube",
)
