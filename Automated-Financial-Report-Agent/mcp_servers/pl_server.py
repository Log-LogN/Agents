"""mcp_servers/pl_server.py — Profit & Loss Agent (port 8002 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db

mcp = FastMCP("PLServer", host="127.0.0.1", port=8002, stateless_http=True, json_response=True)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def _sum_type(cur, acct_type: str, date_from: str, date_to: str, category: str = "") -> float:
    """Sum transaction amounts for a given account type in a period."""
    q = """SELECT COALESCE(SUM(t.amount),0) AS total
           FROM transactions t JOIN accounts a ON t.account_id=a.id
           WHERE a.type=%s AND t.txn_date BETWEEN %s AND %s"""
    params = [acct_type, date_from, date_to]
    if category:
        q += " AND t.category=%s"; params.append(category)
    cur.execute(q, params)
    return float(cur.fetchone()["total"])


@mcp.tool()
def get_income_statement(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """Generate a full P&L: revenue → COGS → gross profit → opex → EBITDA → net income."""
    conn = get_connection(); cur = _cur(conn)
    revenue  = _sum_type(cur, "revenue", date_from, date_to)
    cogs     = _sum_type(cur, "expense", date_from, date_to, "cogs")
    gross    = revenue - cogs
    # Operating expenses (salary + overhead + marketing + travel + software)
    opex_cats = ["salary", "overhead", "marketing", "travel", "software"]
    opex = sum(_sum_type(cur, "expense", date_from, date_to, c) for c in opex_cats)
    depreciation  = _sum_type(cur, "expense", date_from, date_to, "depreciation")
    ebitda        = gross - opex
    interest      = _sum_type(cur, "expense", date_from, date_to, "interest")
    ebit          = ebitda - depreciation
    net_income    = ebit - interest
    conn.close()
    gm_pct = round(gross / revenue * 100, 2) if revenue else 0
    ebitda_pct = round(ebitda / revenue * 100, 2) if revenue else 0
    ni_pct = round(net_income / revenue * 100, 2) if revenue else 0
    return {
        "period":            f"{date_from} to {date_to}",
        "revenue":           round(revenue, 2),
        "cogs":              round(cogs, 2),
        "gross_profit":      round(gross, 2),
        "gross_margin_pct":  gm_pct,
        "operating_expenses": round(opex, 2),
        "ebitda":            round(ebitda, 2),
        "ebitda_margin_pct": ebitda_pct,
        "depreciation":      round(depreciation, 2),
        "ebit":              round(ebit, 2),
        "interest_expense":  round(interest, 2),
        "net_income":        round(net_income, 2),
        "net_margin_pct":    ni_pct,
    }


@mcp.tool()
def get_revenue_summary(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """Revenue breakdown by category (product / saas / services / other)."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT t.category, SUM(t.amount) AS total
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type='revenue' AND t.txn_date BETWEEN %s AND %s
        GROUP BY t.category ORDER BY total DESC
    """, (date_from, date_to))
    rows = cur.fetchall(); conn.close()
    categories = {}
    grand = 0.0
    for r in rows:
        categories[r["category"]] = float(r["total"])
        grand += float(r["total"])
    breakdown = {k: {"amount": v, "pct_of_revenue": round(v/grand*100, 1) if grand else 0}
                 for k, v in categories.items()}
    return {"period": f"{date_from} to {date_to}", "total_revenue": round(grand, 2),
            "breakdown": breakdown}


@mcp.tool()
def get_cogs_breakdown(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """COGS detail by category for a period."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT t.category, t.department, SUM(t.amount) AS total, COUNT(*) AS txns
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type='expense' AND t.category='cogs' AND t.txn_date BETWEEN %s AND %s
        GROUP BY t.category, t.department ORDER BY total DESC
    """, (date_from, date_to))
    rows = cur.fetchall(); conn.close()
    items = [{"category": r["category"], "department": r["department"],
              "total": float(r["total"]), "transactions": r["txns"]} for r in rows]
    total = sum(i["total"] for i in items)
    return {"period": f"{date_from} to {date_to}", "total_cogs": round(total, 2), "breakdown": items}


@mcp.tool()
def get_operating_expenses(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """Itemised operating expense report by category."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT t.category, t.department, SUM(t.amount) AS total
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type='expense' AND t.category != 'cogs'
          AND t.txn_date BETWEEN %s AND %s
        GROUP BY t.category, t.department ORDER BY total DESC
    """, (date_from, date_to))
    rows = cur.fetchall(); conn.close()
    items = [{"category": r["category"], "department": r["department"], "total": float(r["total"])} for r in rows]
    total = sum(i["total"] for i in items)
    return {"period": f"{date_from} to {date_to}", "total_opex": round(total, 2), "breakdown": items}


@mcp.tool()
def get_gross_margin(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """Gross margin % with period-over-period trend."""
    conn = get_connection(); cur = _cur(conn)
    revenue = _sum_type(cur, "revenue", date_from, date_to)
    cogs    = _sum_type(cur, "expense", date_from, date_to, "cogs")
    gross   = revenue - cogs
    gm_pct  = round(gross / revenue * 100, 2) if revenue else 0
    # Previous period (shift 1 month back roughly)
    from datetime import date, timedelta
    d1 = date.fromisoformat(date_from); d2 = date.fromisoformat(date_to)
    gap = (d2 - d1).days + 1
    prev_to   = (d1 - timedelta(days=1)).isoformat()
    prev_from = (d1 - timedelta(days=gap)).isoformat()
    prev_rev  = _sum_type(cur, "revenue", prev_from, prev_to)
    prev_cogs = _sum_type(cur, "expense", prev_from, prev_to, "cogs")
    prev_gm   = round((prev_rev - prev_cogs) / prev_rev * 100, 2) if prev_rev else 0
    conn.close()
    return {
        "period": f"{date_from} to {date_to}",
        "revenue": round(revenue, 2), "cogs": round(cogs, 2),
        "gross_profit": round(gross, 2), "gross_margin_pct": gm_pct,
        "prior_period_gm_pct": prev_gm,
        "change_pp": round(gm_pct - prev_gm, 2),
    }


@mcp.tool()
def get_ebitda(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """EBITDA calculation with addback schedule."""
    conn = get_connection(); cur = _cur(conn)
    revenue      = _sum_type(cur, "revenue", date_from, date_to)
    cogs         = _sum_type(cur, "expense", date_from, date_to, "cogs")
    opex_cats    = ["salary", "overhead", "marketing", "travel", "software"]
    opex         = sum(_sum_type(cur, "expense", date_from, date_to, c) for c in opex_cats)
    depreciation = _sum_type(cur, "expense", date_from, date_to, "depreciation")
    interest     = _sum_type(cur, "expense", date_from, date_to, "interest")
    taxes        = _sum_type(cur, "expense", date_from, date_to, "tax")
    ebit         = revenue - cogs - opex - depreciation
    ebitda       = ebit + depreciation
    conn.close()
    return {
        "period": f"{date_from} to {date_to}",
        "revenue": round(revenue, 2), "cogs": round(cogs, 2),
        "operating_expenses": round(opex, 2),
        "ebit":  round(ebit, 2),
        "addback_depreciation": round(depreciation, 2),
        "addback_interest":     round(interest, 2),
        "addback_taxes":        round(taxes, 2),
        "ebitda":               round(ebitda, 2),
        "ebitda_margin_pct":    round(ebitda / revenue * 100, 2) if revenue else 0,
    }


@mcp.tool()
def get_period_comparison(
    current_from: str = "2026-02-01", current_to: str = "2026-02-28",
    prior_from: str = "2026-01-01", prior_to: str = "2026-01-31"
) -> dict:
    """Side-by-side P&L comparison: current period vs prior period."""
    def _pl(df, dt):
        conn = get_connection(); cur = _cur(conn)
        rev  = _sum_type(cur, "revenue", df, dt)
        cogs = _sum_type(cur, "expense", df, dt, "cogs")
        opex = sum(_sum_type(cur, "expense", df, dt, c) for c in ["salary","overhead","marketing","travel","software"])
        conn.close()
        gross = rev - cogs
        ebitda = gross - opex
        return {"revenue": round(rev,2), "cogs": round(cogs,2), "gross_profit": round(gross,2),
                "gross_margin_pct": round(gross/rev*100,2) if rev else 0,
                "opex": round(opex,2), "ebitda": round(ebitda,2),
                "ebitda_margin_pct": round(ebitda/rev*100,2) if rev else 0}
    curr  = _pl(current_from, current_to)
    prior = _pl(prior_from, prior_to)
    def _chg(a, b):
        return round(((a-b)/b)*100, 1) if b else 0
    return {
        "current_period": f"{current_from} to {current_to}", "current": curr,
        "prior_period":   f"{prior_from} to {prior_to}",   "prior":   prior,
        "changes": {k: _chg(curr[k], prior[k]) for k in curr if isinstance(curr[k], (int,float))},
    }


@mcp.tool()
def get_revenue_growth_rate(periods: int = 3) -> list:
    """Revenue growth rate month-over-month for the last N months."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT DATE_TRUNC('month', txn_date) AS month, SUM(amount) AS revenue
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type='revenue'
        GROUP BY 1 ORDER BY 1 DESC LIMIT %s
    """, (periods,))
    rows = list(reversed(cur.fetchall())); conn.close()
    result = []
    for i, r in enumerate(rows):
        rev   = float(r["revenue"])
        prev  = float(rows[i-1]["revenue"]) if i > 0 else None
        mom   = round((rev-prev)/prev*100, 1) if prev else None
        result.append({"month": str(r["month"])[:7], "revenue": rev, "growth_mom_pct": mom})
    return result if result else [{"message": "Insufficient data for growth rate calculation."}]


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
