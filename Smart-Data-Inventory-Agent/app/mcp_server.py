"""Strict MCP server with decorator-registered tools."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, TypeVar

import pandas as pd
from mcp.server.fastmcp import FastMCP

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_FILE = BASE_DIR / "sales_data.csv"
LOG_FILE = BASE_DIR / "outputs" / "tool_calls.log"

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
LOGGER = logging.getLogger("sales_mcp_tools")
if not LOGGER.handlers:
    LOGGER.setLevel(logging.INFO)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(file_handler)
    LOGGER.propagate = False

mcp = FastMCP("smart-sales-data-agent")
T = TypeVar("T")


def _safe_arg_preview(args: dict[str, Any]) -> dict[str, Any]:
    preview: dict[str, Any] = {}
    for key, value in args.items():
        if key == "data" and isinstance(value, dict):
            preview[key] = {
                "row_count": value.get("row_count"),
                "columns_count": len(value.get("columns", [])),
            }
        elif key in {"top_products_data", "top_products"} and isinstance(value, dict):
            preview[key] = {
                "items": len(value),
                "sample_keys": list(value.keys())[:3],
            }
        elif key == "report" and isinstance(value, str):
            preview[key] = {"chars": len(value)}
        else:
            preview[key] = value
    return preview


def _run_tool(tool_name: str, args: dict[str, Any], op: Callable[[], T]) -> T:
    started = time.perf_counter()
    payload = {
        "tool": tool_name,
        "args": _safe_arg_preview(args),
    }
    try:
        result = op()
        payload["status"] = "success"
        return result
    except Exception as exc:
        payload["status"] = "error"
        payload["error"] = str(exc)
        raise
    finally:
        payload["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        LOGGER.info(json.dumps(payload, ensure_ascii=True))


def _load_sales_df() -> pd.DataFrame:
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Sales data file not found: {DATA_FILE}")
    try:
        df = pd.read_csv(DATA_FILE, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(DATA_FILE, encoding="latin1")

    required = {"SALES", "PRODUCTLINE"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"CSV missing columns: {sorted(missing)}")
    return df


@mcp.tool()
def get_sales_data(limit: int | None = None) -> dict[str, Any]:
    """Return sales rows from sales_data.csv as records with schema metadata."""
    return _run_tool(
        "get_sales_data",
        {"limit": limit},
        lambda: _get_sales_data_impl(limit),
    )


def _get_sales_data_impl(limit: int | None = None) -> dict[str, Any]:
    df = _load_sales_df()
    if limit is not None and limit > 0:
        df = df.head(limit)
    return {
        "row_count": int(len(df)),
        "columns": list(df.columns),
        "records": df.to_dict(orient="records"),
    }


@mcp.tool()
def top_products(
    data: dict[str, Any] | None = None,
    n: int = 5,
    group_by: str = "PRODUCTLINE",
) -> dict[str, float]:
    """Compute top N groups by total SALES. Accepts optional data from get_sales_data."""
    return _run_tool(
        "top_products",
        {"data": data, "n": n, "group_by": group_by},
        lambda: _top_products_impl(data=data, n=n, group_by=group_by),
    )


def _top_products_impl(
    data: dict[str, Any] | None = None,
    n: int = 5,
    group_by: str = "PRODUCTLINE",
) -> dict[str, float]:
    if data is None:
        df = _load_sales_df()
    else:
        records = data.get("records", [])
        df = pd.DataFrame(records)
    if df.empty:
        return {}
    if group_by not in df.columns:
        raise ValueError(f"group_by column not found: {group_by}")

    totals = (
        df.groupby(group_by, as_index=True)["SALES"]
        .sum()
        .sort_values(ascending=False)
        .head(n)
    )
    return {product: float(value) for product, value in totals.items()}


@mcp.tool()
def revenue_after_exclusion(
    exclude_name: str,
    n: int = 5,
    group_by: str = "PRODUCTLINE",
) -> dict[str, Any]:
    """Calculate revenue impact after excluding one item from top N."""
    return _run_tool(
        "revenue_after_exclusion",
        {"exclude_name": exclude_name, "n": n, "group_by": group_by},
        lambda: _revenue_after_exclusion_impl(exclude_name, n, group_by),
    )


def _revenue_after_exclusion_impl(
    exclude_name: str,
    n: int = 5,
    group_by: str = "PRODUCTLINE",
) -> dict[str, Any]:
    top = _top_products_impl(n=n, group_by=group_by)
    matched_name = next(
        (name for name in top.keys() if name.lower() == exclude_name.lower()),
        None,
    )
    excluded_value = float(top.get(matched_name, 0.0)) if matched_name else 0.0
    total_before = float(sum(top.values()))
    total_after = float(total_before - excluded_value)
    return {
        "group_by": group_by,
        "n": n,
        "excluded_name": exclude_name,
        "matched_name": matched_name,
        "found_in_top_n": matched_name is not None,
        "excluded_value": excluded_value,
        "total_before": total_before,
        "total_after": total_after,
        "top_products": top,
    }


@mcp.tool()
def list_groupable_fields() -> list[str]:
    """Return common dimensions that can be used for top-N grouping."""
    return _run_tool(
        "list_groupable_fields",
        {},
        _list_groupable_fields_impl,
    )


def _list_groupable_fields_impl() -> list[str]:
    df = _load_sales_df()
    preferred = [
        "PRODUCTLINE",
        "PRODUCTCODE",
        "COUNTRY",
        "CITY",
        "YEAR_ID",
        "DEALSIZE",
    ]
    return [col for col in preferred if col in df.columns]


@mcp.tool()
def product_details(limit: int = 5, sort_by: str = "SALES") -> list[dict[str, Any]]:
    """Return row-level details for top records, useful for 'show me 5 products' style queries."""
    return _run_tool(
        "product_details",
        {"limit": limit, "sort_by": sort_by},
        lambda: _product_details_impl(limit=limit, sort_by=sort_by),
    )


def _product_details_impl(limit: int = 5, sort_by: str = "SALES") -> list[dict[str, Any]]:
    df = _load_sales_df()
    if sort_by not in df.columns:
        raise ValueError(f"sort_by column not found: {sort_by}")
    rows = df.sort_values(by=sort_by, ascending=False).head(limit)
    return rows.to_dict(orient="records")


@mcp.tool()
def generate_report(
    top_products_data: dict[str, float] | None = None,
    query: str = "",
    n: int = 5,
    group_by: str = "PRODUCTLINE",
) -> str:
    """Build a text report from top-product totals. Auto-computes if not provided."""
    return _run_tool(
        "generate_report",
        {
            "top_products_data": top_products_data,
            "query": query,
            "n": n,
            "group_by": group_by,
        },
        lambda: _generate_report_impl(top_products_data, query, n, group_by),
    )


def _generate_report_impl(
    top_products_data: dict[str, float] | None = None,
    query: str = "",
    n: int = 5,
    group_by: str = "PRODUCTLINE",
) -> str:
    if top_products_data is None:
        top_products_data = _top_products_impl(n=n, group_by=group_by)

    title = "Smart Sales Report"
    lines = [title, "=" * len(title)]
    if query:
        lines.append(f"User request: {query}")

    if not top_products_data:
        lines.append("No product sales data available.")
        return "\n".join(lines)

    lines.append("Top products by revenue:")
    total = sum(top_products_data.values())
    for index, (product, revenue) in enumerate(top_products_data.items(), start=1):
        lines.append(f"{index}. {product}: ${revenue:,.2f}")

    lines.append(f"Total revenue across top set: ${total:,.2f}")
    return "\n".join(lines)


@mcp.tool()
def save_report(report: str, output_path: str = "outputs/report.txt") -> str:
    """Persist a report to disk and return absolute path."""
    return _run_tool(
        "save_report",
        {"report": report, "output_path": output_path},
        lambda: _save_report_impl(report, output_path),
    )


def _save_report_impl(report: str, output_path: str = "outputs/report.txt") -> str:
    target = Path(output_path)
    if not target.is_absolute():
        target = BASE_DIR / target

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report, encoding="utf-8")
    return str(target.resolve())


# ASGI app for uvicorn. Exposed at /mcp endpoint by script.
app = mcp.streamable_http_app()
