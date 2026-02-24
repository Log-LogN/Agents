"""Main LangGraph MCP tool-calling agent service."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, Optional

from langgraph.graph import END, StateGraph
from openai import OpenAI

from core.config import load_settings
from core.constants import (
    DB_AGENT_SYSTEM_PROMPT,
    MATH_AGENT_SYSTEM_PROMPT,
    MCP_UNAVAILABLE_MESSAGE,
    SUPERVISOR_ROUTER_SYSTEM_PROMPT,
)
from .mcp_client import MCPClient
from .router import infer_route
from .tool_converter import mcp_tools_to_openai_tools
from .types import AgentState

logger = logging.getLogger("agent")


QUERY_BUILDER_TOOLS = {"build_select_query", "build_count_query", "build_join_query"}
EXECUTE_QUERY_TOOL = "execute_query"


class MCPToolCallingAgent:
    def __init__(self, model: Optional[str] = None, mcp_server_url: Optional[str] = None) -> None:
        settings = load_settings(model=model, mcp_server_url=mcp_server_url)

        self.openai = OpenAI(api_key=settings.openai_api_key)
        self.model = settings.model
        self.mcp_client = MCPClient(settings.mcp_server_url)

        self.mcp_tools: list[Any] = []
        self.openai_tools: list[Dict[str, Any]] = []
        self.database_openai_tools: list[Dict[str, Any]] = []
        self.math_openai_tools: list[Dict[str, Any]] = []
        self.available_tool_names: set[str] = set()
        self._tools_loaded = False
        self.db_credentials: Dict[str, str] = {}
        self.active_schema: str = ""
        self.table_metadata: Dict[str, list[Dict[str, str]]] = {}
        self.metadata_path: str = ""
        self.graph = self._build_graph()

    async def start(self) -> None:
        await self._refresh_tools()

    async def close(self) -> None:
        await self.mcp_client.close()
        self._tools_loaded = False

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        workflow.add_node("user_input", self._user_input_node)
        workflow.add_node("supervisor", self._supervisor_node)
        workflow.add_node("database_agent", self._database_agent_node)
        workflow.add_node("math_agent", self._math_agent_node)
        workflow.add_node("response", self._response_node)

        workflow.set_entry_point("user_input")
        workflow.add_edge("user_input", "supervisor")
        workflow.add_conditional_edges(
            "supervisor",
            self._route_after_supervisor,
            {
                "database_agent": "database_agent",
                "math_agent": "math_agent",
                "response": "response",
            },
        )
        workflow.add_edge("database_agent", "response")
        workflow.add_edge("math_agent", "response")
        workflow.add_edge("response", END)

        return workflow.compile()

    async def _user_input_node(self, state: AgentState) -> AgentState:
        return state

    async def _supervisor_node(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        route = await self._infer_supervisor_route(user_input)
        state["route"] = route
        return state

    def _route_after_supervisor(self, state: AgentState) -> str:
        return state.get("route", "response")

    async def _database_agent_node(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]

        if self._is_reset_request(user_input):
            self.db_credentials = {}
            self.active_schema = ""
            self.table_metadata = {}
            self.metadata_path = ""
            state["final_response"] = "Database context cleared. Please provide PostgreSQL credentials."
            return state

        credential_updates = self._extract_postgres_credentials(user_input)
        if credential_updates:
            self.db_credentials.update(credential_updates)

        missing_fields = self._missing_credential_fields()
        if missing_fields:
            state["final_response"] = (
                "Database agent needs PostgreSQL credentials before running tools. "
                f"Missing: {', '.join(missing_fields)}. "
                "Provide in one message like: "
                "`host=localhost port=5432 database=mydb user=postgres password=secret`."
            )
            return state

        schema = self._extract_schema(user_input)
        if schema and schema != self.active_schema:
            self.active_schema = schema
            self.table_metadata = {}
            self.metadata_path = ""

        if not self.active_schema:
            state["final_response"] = (
                "Credentials saved. Please choose a schema, for example: `use schema public`."
            )
            return state

        metadata_status = await self._ensure_metadata_loaded()
        if metadata_status:
            logger.info(metadata_status)
        if metadata_status.startswith("Metadata load failed") and not self.table_metadata:
            state["final_response"] = (
                f"{metadata_status}. Please verify credentials/schema and ensure DB is reachable."
            )
            return state

        if self._is_schema_selection_only(user_input):
            if self.table_metadata:
                preview_tables = ", ".join(sorted(self.table_metadata.keys())[:10])
                state["final_response"] = (
                    f"Active schema set to '{self.active_schema}'. "
                    f"Loaded metadata for {len(self.table_metadata)} table(s). "
                    f"Tables: {preview_tables}"
                )
            else:
                state["final_response"] = (
                    f"Active schema set to '{self.active_schema}', but no table metadata was found."
                )
            return state

        try:
            if not self.database_openai_tools:
                state["final_response"] = "No database tools are currently available from MCP."
                return state

            table_context = self._build_table_context(user_input)

            response = self.openai.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": DB_AGENT_SYSTEM_PROMPT.format(
                            schema=self.active_schema,
                            table_context=table_context,
                        ),
                    },
                    {"role": "user", "content": user_input},
                ],
                tools=self.database_openai_tools,
                tool_choice="auto",
                temperature=0,
            )

            message = response.choices[0].message
            state["llm_text"] = (message.content or "").strip()

            if message.tool_calls:
                tool_call = message.tool_calls[0]
                state["tool_name"] = tool_call.function.name
                try:
                    parsed_args = json.loads(tool_call.function.arguments or "{}")
                    if not isinstance(parsed_args, dict):
                        parsed_args = {}
                except json.JSONDecodeError:
                    parsed_args = {}

                if state["tool_name"] in QUERY_BUILDER_TOOLS:
                    parsed_args = self._inject_active_schema_into_builder_args(parsed_args)
                elif state["tool_name"] == EXECUTE_QUERY_TOOL:
                    parsed_args["connection"] = self._connection_payload()

                state["tool_args"] = parsed_args
                result = await self.mcp_client.call_tool(state["tool_name"], state["tool_args"])
                # Enforce your required execution flow:
                # build_* -> execute_query in the same turn.
                if state["tool_name"] in QUERY_BUILDER_TOOLS:
                    execution_response = await self._run_execute_query_from_builder_result(result)
                    state["tool_result"] = execution_response
                    state["final_response"] = execution_response
                else:
                    state["tool_result"] = result
                    state["final_response"] = result
            elif state["llm_text"]:
                state["final_response"] = state["llm_text"]
            else:
                state["final_response"] = "Database request received, but no tool action was selected."
        except Exception as exc:
            logger.exception("Database agent execution failed")
            state["final_response"] = f"Database agent failed: {exc}"

        return state

    async def _response_node(self, state: AgentState) -> AgentState:
        if state.get("final_response"):
            return state

        tool_result = state.get("tool_result", "").strip()
        llm_text = state.get("llm_text", "").strip()

        if tool_result:
            state["final_response"] = tool_result
        elif llm_text:
            state["final_response"] = llm_text
        else:
            state["final_response"] = "I could not determine an action for that request."

        return state

    async def _math_agent_node(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        try:
            if not self.math_openai_tools:
                state["final_response"] = "No mathematical tools are currently available from MCP."
                return state

            score_payload = self._extract_score_percentage_inputs(user_input)
            if score_payload:
                state["tool_name"] = "math_percentage_from_total"
                state["tool_args"] = score_payload
                result = await self.mcp_client.call_tool(state["tool_name"], state["tool_args"])
                state["tool_result"] = result
                state["final_response"] = result
                return state

            response = self.openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": MATH_AGENT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_input},
                ],
                tools=self.math_openai_tools,
                tool_choice="auto",
                temperature=0,
            )

            message = response.choices[0].message
            state["llm_text"] = (message.content or "").strip()

            if message.tool_calls:
                tool_call = message.tool_calls[0]
                state["tool_name"] = tool_call.function.name
                try:
                    parsed_args = json.loads(tool_call.function.arguments or "{}")
                    if not isinstance(parsed_args, dict):
                        parsed_args = {}
                except json.JSONDecodeError:
                    parsed_args = {}

                state["tool_args"] = parsed_args
                result = await self.mcp_client.call_tool(state["tool_name"], state["tool_args"])
                state["tool_result"] = result
                state["final_response"] = result
            elif state["llm_text"]:
                state["final_response"] = state["llm_text"]
            else:
                state["final_response"] = "Math request received, but no tool action was selected."
        except Exception as exc:
            logger.exception("Math agent execution failed")
            state["final_response"] = f"Math agent failed: {exc}"

        return state

    @staticmethod
    def _extract_score_percentage_inputs(user_input: str) -> Optional[Dict[str, float]]:
        text = user_input.lower()

        # Pattern: "638 out of 700"
        out_of = re.search(r"(\d+(?:\.\d+)?)\s*out\s*of\s*(\d+(?:\.\d+)?)", text)
        if out_of:
            return {"obtained": float(out_of.group(1)), "total": float(out_of.group(2))}

        # Pattern: "total marks is 700 and i get 638" / "got 638 from 700"
        nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", text)]
        if len(nums) >= 2 and any(k in text for k in ("total", "marks", "score", "out of", "from")):
            total = nums[0]
            obtained = nums[1]
            if "total" in text or "marks" in text:
                return {"obtained": obtained, "total": total}
            return {"obtained": nums[0], "total": nums[1]}

        return None

    async def _infer_supervisor_route(self, user_input: str) -> str:
        db_state_hint = (
            "Database context is pending credentials/schema completion."
            if self._database_context_pending()
            else "Database context is not pending."
        )
        try:
            response = self.openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SUPERVISOR_ROUTER_SYSTEM_PROMPT},
                    {"role": "system", "content": db_state_hint},
                    {"role": "user", "content": user_input},
                ],
                temperature=0,
                max_tokens=8,
            )
            content = (response.choices[0].message.content or "").strip().lower()
            if "math_agent" in content:
                return "math_agent"
            if "database_agent" in content:
                return "database_agent"
        except Exception:
            logger.warning("Supervisor LLM routing failed; falling back to keyword router.", exc_info=True)

        return infer_route(user_input)

    def _database_context_pending(self) -> bool:
        return bool(self.db_credentials) and (bool(self._missing_credential_fields()) or not self.active_schema)

    def _missing_credential_fields(self) -> list[str]:
        required = ("host", "port", "database", "user", "password")
        return [name for name in required if not self.db_credentials.get(name)]

    @staticmethod
    def _is_reset_request(user_input: str) -> bool:
        text = user_input.lower()
        return "reset db" in text or "clear db" in text or "clear database" in text

    @staticmethod
    def _extract_schema(user_input: str) -> str:
        patterns = (
            r"\buse\s+schema\s+([a-zA-Z_][a-zA-Z0-9_]*)",
            r"\bschema\s*(?:=|:|is)?\s*([a-zA-Z_][a-zA-Z0-9_]*)",
        )
        for pattern in patterns:
            match = re.search(pattern, user_input, flags=re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _is_schema_selection_only(user_input: str) -> bool:
        return bool(
            re.match(r"^\s*use\s+schema\s+[a-zA-Z_][a-zA-Z0-9_]*\s*$", user_input, flags=re.IGNORECASE)
            or re.match(r"^\s*schema\s*(?:=|:)\s*[a-zA-Z_][a-zA-Z0-9_]*\s*$", user_input, flags=re.IGNORECASE)
        )

    @staticmethod
    def _extract_postgres_credentials(user_input: str) -> Dict[str, str]:
        # Accept formats such as: host=... port=... database=... user=... password=...
        pair_pattern = re.compile(r"\b([a-zA-Z_]+)\s*(?:=|:)\s*([^\s,;]+)")
        raw_pairs = {k.lower(): v for k, v in pair_pattern.findall(user_input)}
        alias_map = {
            "host": "host",
            "port": "port",
            "database": "database",
            "dbname": "database",
            "db": "database",
            "user": "user",
            "username": "user",
            "password": "password",
            "pass": "password",
        }
        normalized: Dict[str, str] = {}
        for key, value in raw_pairs.items():
            target = alias_map.get(key)
            if target:
                normalized[target] = value
        return normalized

    async def _run_execute_query_from_builder_result(self, builder_result: str) -> str:
        payload = self._parse_json_dict(builder_result)
        query = str(payload.get("query", "")).strip()
        if not query:
            return builder_result

        execute_args: Dict[str, Any] = {
            "query": query,
            "connection": self._connection_payload(),
        }
        parameters = payload.get("parameters", [])
        if isinstance(parameters, list) and parameters:
            execute_args["parameters"] = parameters

        return await self.mcp_client.call_tool(EXECUTE_QUERY_TOOL, execute_args)

    @staticmethod
    def _parse_json_dict(raw_text: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}

    def _connection_payload(self) -> Dict[str, str]:
        return {
            "host": self.db_credentials.get("host", ""),
            "port": self.db_credentials.get("port", ""),
            "database": self.db_credentials.get("database", ""),
            "user": self.db_credentials.get("user", ""),
            "password": self.db_credentials.get("password", ""),
        }

    async def _ensure_metadata_loaded(self) -> str:
        if self.table_metadata:
            return "Metadata already loaded."

        schema = self.active_schema.strip()
        if not schema:
            return "Metadata not loaded: schema is empty."

        metadata_query = (
            "SELECT table_name, column_name, data_type "
            "FROM information_schema.columns "
            f"WHERE table_schema = '{schema}' "
            "ORDER BY table_name, ordinal_position"
        )
        raw_result = await self.mcp_client.call_tool(
            EXECUTE_QUERY_TOOL,
            {"query": metadata_query, "connection": self._connection_payload()},
        )
        parsed = self._parse_json_dict(raw_result)
        if parsed.get("status") != "ok":
            return f"Metadata load failed: {parsed.get('error', 'unknown error')}"

        rows = parsed.get("rows", [])
        table_map: Dict[str, list[Dict[str, str]]] = {}
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                table_name = str(row.get("table_name", "")).strip()
                column_name = str(row.get("column_name", "")).strip()
                data_type = str(row.get("data_type", "")).strip()
                if not table_name or not column_name:
                    continue
                table_map.setdefault(table_name, []).append(
                    {"column_name": column_name, "data_type": data_type}
                )

        self.table_metadata = table_map
        self._persist_metadata_json()
        return f"Loaded metadata for {len(self.table_metadata)} table(s)."

    def _persist_metadata_json(self) -> None:
        if not self.table_metadata:
            return
        os.makedirs("app_data", exist_ok=True)
        db_name = re.sub(r"[^a-zA-Z0-9_]+", "_", self.db_credentials.get("database", "db"))
        schema = re.sub(r"[^a-zA-Z0-9_]+", "_", self.active_schema or "schema")
        path = os.path.join("app_data", f"table_metadata_{db_name}_{schema}.json")
        payload = {
            "database": self.db_credentials.get("database", ""),
            "schema": self.active_schema,
            "tables": self.table_metadata,
        }
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, ensure_ascii=True)
        self.metadata_path = path
        logger.info("Stored table metadata JSON at %s", self.metadata_path)

    def _build_table_context(self, user_input: str) -> str:
        if not self.table_metadata:
            return "No table metadata available."

        text = user_input.lower()
        tokens = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text))
        matched_tables: list[str] = []
        for table_name in sorted(self.table_metadata.keys()):
            singular = table_name[:-1] if table_name.endswith("s") else table_name
            if table_name.lower() in text or singular.lower() in tokens:
                matched_tables.append(table_name)

        selected_tables = matched_tables[:5] if matched_tables else sorted(self.table_metadata.keys())[:8]
        lines: list[str] = []
        for table_name in selected_tables:
            columns = self.table_metadata.get(table_name, [])
            col_preview = ", ".join(col["column_name"] for col in columns[:20])
            lines.append(f"- {table_name}: {col_preview}")
        return "\n".join(lines) if lines else "No table metadata available."

    def _inject_active_schema_into_builder_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.active_schema:
            return args

        def with_schema(table_name: Any) -> Any:
            if not isinstance(table_name, str):
                return table_name
            if "." in table_name:
                return table_name
            return f"{self.active_schema}.{table_name}"

        updated = dict(args)
        if "table_name" in updated:
            updated["table_name"] = with_schema(updated.get("table_name"))
        if "primary_table" in updated:
            updated["primary_table"] = with_schema(updated.get("primary_table"))
        if "related_table" in updated:
            updated["related_table"] = with_schema(updated.get("related_table"))
        return updated

    async def _refresh_tools(self) -> None:
        self.mcp_tools = await self.mcp_client.list_tools()
        self.openai_tools = mcp_tools_to_openai_tools(self.mcp_tools)
        self.database_openai_tools = [
            tool
            for tool in self.openai_tools
            if str(tool.get("function", {}).get("name", "")).strip() in QUERY_BUILDER_TOOLS
            or str(tool.get("function", {}).get("name", "")).strip() == EXECUTE_QUERY_TOOL
        ]
        self.math_openai_tools = [
            tool
            for tool in self.openai_tools
            if str(tool.get("function", {}).get("name", "")).strip().startswith("math_")
        ]
        self.available_tool_names = {
            str(getattr(tool, "name", "")).strip() for tool in self.mcp_tools if getattr(tool, "name", None)
        }
        self._tools_loaded = True
        logger.info(
            "Discovered %d MCP tools (%d database tools, %d math tools)",
            len(self.mcp_tools),
            len(self.database_openai_tools),
            len(self.math_openai_tools),
        )

    async def _ensure_ready(self) -> None:
        if not self._tools_loaded or not self.openai_tools:
            await self._refresh_tools()

    async def run(self, user_input: str) -> str:
        try:
            await self._ensure_ready()
        except Exception:
            logger.warning("MCP server unavailable. Will retry on next message.", exc_info=True)
            return MCP_UNAVAILABLE_MESSAGE

        initial_state: AgentState = {
            "user_input": user_input,
            "route": "",
            "llm_text": "",
            "tool_name": "",
            "tool_args": {},
            "tool_result": "",
            "final_response": "",
        }

        final_state = await self.graph.ainvoke(initial_state)
        return final_state.get("final_response", "No response generated.")
