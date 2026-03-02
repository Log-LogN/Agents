"""mcp_servers/budget_server.py — Budget & Variance Agent (port 8005 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_variance_alert

mcp = FastMCP("BudgetServer", host="127.0.0.1", port=8005, stateless_http=True, json_response=True)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def set_department_budget(
    department: str, fiscal_year: int, period: int,
    amount: float, category: str = "total", created_by: str = ""
) -> dict:
    """Create or update the budget for a department in a fiscal period."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT id FROM budgets WHERE department=%s AND fiscal_year=%s AND period=%s AND category=%s
    """, (department, fiscal_year, period, category))
    existing = cur.fetchone()
    if existing:
        cur.execute("""
            UPDATE budgets SET amount=%s, created_by=%s WHERE id=%s
        """, (amount, created_by, existing["id"]))
        action = "updated"
    else:
        cur.execute("""
            INSERT INTO budgets (department,fiscal_year,period,amount,category,created_by)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (department, fiscal_year, period, amount, category, created_by))
        action = "created"
    conn.commit(); conn.close()
    return {"success": True, "action": action, "department": department,
            "fiscal_year": fiscal_year, "period": period, "amount": amount,
            "message": f"Budget {action} for {department} {fiscal_year}-P{period}: ₹{amount:,.2f}"}


@mcp.tool()
def get_department_budget(department: str, fiscal_year: int = 2026, period: int = 2) -> dict:
    """Retrieve the approved budget for any department and period."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT id, department, fiscal_year, period, amount, category, created_by, created_at
        FROM budgets WHERE department ILIKE %s AND fiscal_year=%s AND period=%s
        ORDER BY category
    """, (f"%{department}%", fiscal_year, period))
    rows = cur.fetchall(); conn.close()
    if not rows:
        return {"found": False, "message": f"No budget found for {department} {fiscal_year}-P{period}."}
    items = [{"category": r["category"], "amount": float(r["amount"]),
              "created_by": r["created_by"]} for r in rows]
    total = sum(i["amount"] for i in items)
    return {"found": True, "department": rows[0]["department"], "fiscal_year": fiscal_year,
            "period": period, "total_budget": round(total,2), "categories": items}


@mcp.tool()
def get_variance_report(fiscal_year: int = 2026, period: int = 2) -> list:
    """Full actual vs budget variance for all departments."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT b.department, b.category,
               SUM(b.amount)               AS budget,
               COALESCE(SUM(ba.actual_amount), 0) AS actual
        FROM budgets b
        LEFT JOIN budget_actuals ba ON ba.budget_id=b.id
        WHERE b.fiscal_year=%s AND b.period=%s
        GROUP BY b.department, b.category
        ORDER BY b.department
    """, (fiscal_year, period))
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        budget = float(r["budget"])
        actual = float(r["actual"])
        variance = actual - budget
        pct = round(variance/budget*100, 1) if budget else 0
        result.append({
            "department": r["department"], "category": r["category"],
            "budget": budget, "actual": actual,
            "variance": round(variance,2), "variance_pct": pct,
            "status": "🔴 OVER" if variance > 0 else "🟢 UNDER" if variance < 0 else "🟡 ON PLAN",
        })
    return result if result else [{"message": "No budget data found for this period."}]


@mcp.tool()
def get_top_overspend_depts(fiscal_year: int = 2026, period: int = 2, top_n: int = 5) -> list:
    """Ranked list of departments most over budget."""
    report = get_variance_report(fiscal_year, period)
    over = [r for r in report if isinstance(r, dict) and r.get("variance", 0) > 0]
    over.sort(key=lambda x: x["variance"], reverse=True)
    return over[:top_n] if over else [{"message": "No departments over budget — great work! 🎉"}]


@mcp.tool()
def get_budget_utilisation(fiscal_year: int = 2026, period: int = 2) -> list:
    """Budget utilisation % per department."""
    report = get_variance_report(fiscal_year, period)
    result = []
    for r in report:
        if not isinstance(r, dict) or "budget" not in r:
            continue
        util = round(r["actual"]/r["budget"]*100, 1) if r["budget"] else 0
        result.append({
            "department": r["department"], "category": r["category"],
            "budget": r["budget"], "actual": r["actual"],
            "utilisation_pct": util,
            "status": ("🔴 Over" if util > 100 else
                       "🟡 High (>90%)" if util > 90 else
                       "🟢 Normal" if util > 50 else
                       "🔵 Low (<50%)"),
        })
    result.sort(key=lambda x: x["utilisation_pct"], reverse=True)
    return result if result else [{"message": "No budget data found."}]


@mcp.tool()
def get_forecast_vs_actual(fiscal_year: int = 2026) -> dict:
    """Full-year rolling forecast vs actual spend summary."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT b.department,
               SUM(b.amount)                      AS annual_budget,
               COALESCE(SUM(ba.actual_amount), 0) AS ytd_actual
        FROM budgets b
        LEFT JOIN budget_actuals ba ON ba.budget_id=b.id
        WHERE b.fiscal_year=%s
        GROUP BY b.department ORDER BY ytd_actual DESC
    """, (fiscal_year,))
    rows = cur.fetchall(); conn.close()
    items = []
    for r in rows:
        bud = float(r["annual_budget"])
        act = float(r["ytd_actual"])
        run_rate = act * 12  # annualise 1-month
        items.append({
            "department": r["department"], "annual_budget": bud,
            "ytd_actual": act, "annualised_run_rate": round(run_rate,2),
            "full_year_variance": round(run_rate-bud,2),
        })
    return {"fiscal_year": fiscal_year, "note": "Annualised run rate based on 1-month actuals",
            "departments": items}


@mcp.tool()
def update_budget_forecast(
    department: str, fiscal_year: int, period: int,
    new_forecast: float, updated_by: str = ""
) -> dict:
    """Update the budget forecast for a department and period."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        UPDATE budgets SET amount=%s, created_by=%s
        WHERE department ILIKE %s AND fiscal_year=%s AND period=%s
        RETURNING id, department
    """, (new_forecast, updated_by, f"%{department}%", fiscal_year, period))
    row = cur.fetchone(); conn.commit(); conn.close()
    if row:
        return {"success": True, "department": row["department"],
                "updated_forecast": new_forecast,
                "message": f"Forecast updated for {row['department']} {fiscal_year}-P{period}: ₹{new_forecast:,.2f}"}
    return {"success": False, "message": f"No budget found for {department} {fiscal_year}-P{period}."}


@mcp.tool()
def send_variance_alert_email(recipients: str, threshold_pct: float = 10.0) -> dict:
    """Send variance alert email for all departments exceeding threshold %."""
    report = get_variance_report()
    over = [r for r in report if isinstance(r, dict) and r.get("variance_pct", 0) > threshold_pct]
    sent = []
    for dept in over:
        result = send_variance_alert(
            recipients, dept["department"],
            dept["budget"], dept["actual"], dept["variance_pct"]
        )
        sent.append({"department": dept["department"], "variance_pct": dept["variance_pct"],
                     "email_sent": result["success"]})
    return {"alerts_sent": len(sent), "departments": sent,
            "message": f"Variance alerts sent for {len(sent)} department(s) over {threshold_pct}%"}


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
