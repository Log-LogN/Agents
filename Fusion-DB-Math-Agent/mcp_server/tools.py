"""Tool registrations for the MCP server."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("mcp_server.tools")


def _validate_identifier(name: str) -> str:
    pattern = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?$")
    if not pattern.match(name):
        raise ValueError(f"Invalid SQL identifier: {name}")
    return name


def _validate_column(name: str) -> str:
    value = name.strip()
    if value == "*":
        return value

    if re.fullmatch(
        r"(?i)count\(\*\)\s+(?:as\s+)?[a-zA-Z_][a-zA-Z0-9_]*",
        value,
    ):
        return value

    return _validate_identifier(value)


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value).replace("'", "''")
    return f"'{text}'"


def _build_where_clause(filters: Optional[Dict[str, Any]]) -> str:
    if not filters:
        return ""

    clauses: List[str] = []
    for field, value in filters.items():
        field_name = _validate_identifier(str(field))
        clauses.append(f"{field_name} = {_sql_literal(value)}")

    return f" WHERE {' AND '.join(clauses)}"


def _normalize_order_by(order_by: Optional[str]) -> str:
    if not order_by:
        return ""

    parts: List[str] = []
    for raw_part in order_by.split(","):
        token = raw_part.strip()
        if not token:
            continue
        tokens = token.split()
        column = _validate_identifier(tokens[0])
        direction = "ASC"
        if len(tokens) > 1:
            candidate = tokens[1].upper()
            if candidate not in ("ASC", "DESC"):
                raise ValueError(f"Invalid sort direction: {tokens[1]}")
            direction = candidate
        parts.append(f"{column} {direction}")

    if not parts:
        return ""
    return f" ORDER BY {', '.join(parts)}"


def _normalize_limit(limit: Optional[int]) -> str:
    if limit is None:
        return ""
    safe_limit = max(1, min(int(limit), 1000))
    return f" LIMIT {safe_limit}"


def _payload(query: str, parameters: Optional[List[Any]] = None) -> str:
    return json.dumps({"query": query, "parameters": parameters or []})


def _extract_connection(connection: Optional[Dict[str, Any]]) -> Dict[str, str]:
    conn = connection or {}
    required_fields = ("host", "port", "database", "user", "password")
    missing = [field for field in required_fields if not str(conn.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Missing DB connection fields: {', '.join(missing)}")
    return {field: str(conn[field]) for field in required_fields}


def _is_read_query(query: str) -> bool:
    return bool(re.match(r"^\s*(select|with)\b", query, flags=re.IGNORECASE))


def _run_psql_select_as_json_rows(query: str, connection: Dict[str, str]) -> List[Dict[str, Any]]:
    # Wrap query to emit one JSON object per row for reliable parsing.
    wrapped_query = f"SELECT row_to_json(q)::text FROM ({query.rstrip(';')}) AS q;"
    cmd = [
        "psql",
        "-h",
        connection["host"],
        "-p",
        connection["port"],
        "-U",
        connection["user"],
        "-d",
        connection["database"],
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-t",
        "-A",
        "-c",
        wrapped_query,
    ]
    env = {**os.environ, "PGPASSWORD": connection["password"]}
    logger.info("execute_query SELECT via psql host=%s db=%s", connection["host"], connection["database"])
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "psql select execution failed")

    rows: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        row_text = line.strip()
        if not row_text:
            continue
        parsed = json.loads(row_text)
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _run_psql_write_query(query: str, connection: Dict[str, str]) -> str:
    cmd = [
        "psql",
        "-h",
        connection["host"],
        "-p",
        connection["port"],
        "-U",
        connection["user"],
        "-d",
        connection["database"],
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        query,
    ]
    env = {**os.environ, "PGPASSWORD": connection["password"]}
    logger.info("execute_query WRITE via psql host=%s db=%s", connection["host"], connection["database"])
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "psql write execution failed")
    return (result.stdout or "").strip()


def register_tools(mcp: FastMCP) -> None:
    @mcp.tool(description="Prepare SELECT query parameters and return final SQL payload as JSON.")
    def build_select_query(
        table_name: str,
        columns: Optional[List[str]] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
        order_by: Optional[str] = None,
    ) -> str:
        logger.info("Tool build_select_query called table=%s limit=%s order_by=%s", table_name, limit, order_by)
        table = _validate_identifier(table_name)
        selected_columns = ", ".join(_validate_column(col) for col in (columns or ["*"]))
        where_clause = _build_where_clause(filters)
        query = (
            f"SELECT {selected_columns} FROM {table}"
            f"{where_clause}"
            f"{_normalize_order_by(order_by)}"
            f"{_normalize_limit(limit)}"
        )
        return _payload(query, [])

    @mcp.tool(description="Prepare COUNT query parameters and return final SQL payload as JSON.")
    def build_count_query(
        table_name: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> str:
        logger.info("Tool build_count_query called table=%s", table_name)
        table = _validate_identifier(table_name)
        where_clause = _build_where_clause(filters)
        query = f"SELECT COUNT(*) AS total FROM {table}{where_clause}"
        return _payload(query, [])

    @mcp.tool(description="Prepare JOIN query parameters and return final SQL payload as JSON.")
    def build_join_query(
        primary_table: str,
        related_table: str,
        join_condition: str,
        columns: Optional[List[str]] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> str:
        logger.info(
            "Tool build_join_query called primary_table=%s related_table=%s limit=%s",
            primary_table,
            related_table,
            limit,
        )
        left = _validate_identifier(primary_table)
        right = _validate_identifier(related_table)

        condition_pattern = re.compile(
            r"^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*"
            r"[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$"
        )
        if not condition_pattern.match(join_condition.strip()):
            raise ValueError("Invalid join_condition. Use format like: orders.user_id = users.id")

        selected_columns = ", ".join(_validate_column(col) for col in (columns or ["*"]))
        where_clause = _build_where_clause(filters)
        query = (
            f"SELECT {selected_columns} FROM {left} "
            f"JOIN {right} ON {join_condition.strip()}"
            f"{where_clause}"
            f"{_normalize_limit(limit)}"
        )
        return _payload(query, [])

    @mcp.tool(description="Execute the prepared query on PostgreSQL.")
    def execute_query(
        query: str,
        parameters: Optional[List[Any]] = None,
        connection: Optional[Dict[str, Any]] = None,
    ) -> str:
        _ = parameters
        normalized_query = query.strip()
        logger.info("Tool execute_query called query=%s", normalized_query)
        try:
            conn = _extract_connection(connection)

            if _is_read_query(normalized_query):
                rows = _run_psql_select_as_json_rows(normalized_query, conn)
                return json.dumps(
                    {
                        "status": "ok",
                        "mode": "postgres",
                        "query": normalized_query,
                        "row_count": len(rows),
                        "rows": rows,
                    }
                )

            message = _run_psql_write_query(normalized_query, conn)
            return json.dumps(
                {
                    "status": "ok",
                    "mode": "postgres",
                    "query": normalized_query,
                    "message": message,
                }
            )
        except Exception as exc:
            logger.exception("Tool execute_query failed")
            return json.dumps(
                {
                    "status": "error",
                    "mode": "postgres",
                    "query": normalized_query,
                    "error": str(exc),
                }
            )

    @mcp.tool(description="Add two numbers.")
    def math_add(a: float, b: float) -> str:
        result = a + b
        logger.info("Tool math_add called a=%s b=%s result=%s", a, b, result)
        return json.dumps({"operation": "add", "a": a, "b": b, "result": result})

    @mcp.tool(description="Subtract second number from first number.")
    def math_subtract(a: float, b: float) -> str:
        result = a - b
        logger.info("Tool math_subtract called a=%s b=%s result=%s", a, b, result)
        return json.dumps({"operation": "subtract", "a": a, "b": b, "result": result})

    @mcp.tool(description="Multiply two numbers.")
    def math_multiply(a: float, b: float) -> str:
        result = a * b
        logger.info("Tool math_multiply called a=%s b=%s result=%s", a, b, result)
        return json.dumps({"operation": "multiply", "a": a, "b": b, "result": result})

    @mcp.tool(description="Divide first number by second number.")
    def math_divide(a: float, b: float) -> str:
        if b == 0:
            return json.dumps({"status": "error", "error": "Division by zero is not allowed."})
        result = a / b
        logger.info("Tool math_divide called a=%s b=%s result=%s", a, b, result)
        return json.dumps({"operation": "divide", "a": a, "b": b, "result": result})

    @mcp.tool(description="Raise a number to a power.")
    def math_power(base: float, exponent: float) -> str:
        result = base**exponent
        logger.info("Tool math_power called base=%s exponent=%s result=%s", base, exponent, result)
        return json.dumps(
            {
                "operation": "power",
                "base": base,
                "exponent": exponent,
                "result": result,
            }
        )

    @mcp.tool(description="Calculate percentage value: (value * percent) / 100.")
    def math_percentage(value: float, percent: float) -> str:
        result = (value * percent) / 100.0
        logger.info("Tool math_percentage called value=%s percent=%s result=%s", value, percent, result)
        return json.dumps(
            {
                "operation": "percentage",
                "value": value,
                "percent": percent,
                "result": result,
            }
        )

    @mcp.tool(description="Calculate score percentage: (obtained / total) * 100.")
    def math_percentage_from_total(obtained: float, total: float) -> str:
        if total == 0:
            return json.dumps({"status": "error", "error": "Total cannot be zero."})
        result = (obtained / total) * 100.0
        logger.info(
            "Tool math_percentage_from_total called obtained=%s total=%s result=%s",
            obtained,
            total,
            result,
        )
        return json.dumps(
            {
                "operation": "percentage_from_total",
                "obtained": obtained,
                "total": total,
                "result": result,
            }
        )

    @mcp.tool(description="Evaluate arithmetic expression using safe parser.")
    def math_evaluate_expression(expression: str) -> str:
        if not re.fullmatch(r"[0-9\.\+\-\*/\(\)\s]+", expression):
            return json.dumps({"status": "error", "error": "Expression contains unsupported characters."})
        try:
            # Restricted eval for basic arithmetic only.
            result = eval(expression, {"__builtins__": {}}, {})
            logger.info("Tool math_evaluate_expression called expression=%s result=%s", expression, result)
            return json.dumps(
                {
                    "operation": "evaluate_expression",
                    "expression": expression,
                    "result": result,
                }
            )
        except Exception as exc:
            return json.dumps({"status": "error", "error": str(exc)})
