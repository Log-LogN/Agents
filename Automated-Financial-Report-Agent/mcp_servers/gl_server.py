"""mcp_servers/gl_server.py — GL / Transaction Agent (port 8001 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db

mcp = FastMCP("GLServer", host="127.0.0.1", port=8001, stateless_http=True, json_response=True)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def post_transaction(
    txn_date: str, account_code: str, description: str,
    amount: float, txn_type: str, category: str,
    department: str, reference: str, posted_by: str
) -> dict:
    """Post a new journal entry. txn_type: debit or credit. txn_date: YYYY-MM-DD."""
    if txn_type not in ("debit", "credit"):
        return {"success": False, "message": "txn_type must be 'debit' or 'credit'"}
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT id, name FROM accounts WHERE code=%s AND is_active=TRUE", (account_code,))
    acc = cur.fetchone()
    if not acc:
        conn.close()
        return {"success": False, "message": f"Account code '{account_code}' not found."}
    cur.execute("""
        INSERT INTO transactions
          (txn_date,account_id,description,amount,txn_type,category,department,reference,posted_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
    """, (txn_date, acc["id"], description, amount, txn_type, category, department, reference, posted_by))
    txn_id = cur.fetchone()["id"]
    conn.commit(); conn.close()
    return {"success": True, "transaction_id": txn_id, "account": acc["name"],
            "amount": amount, "type": txn_type,
            "message": f"Transaction #{txn_id} posted to '{acc['name']}' successfully."}


@mcp.tool()
def get_account_balance(account_code: str) -> dict:
    """Return the current balance for any account by its code."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT id,code,name,type,category FROM accounts WHERE code=%s", (account_code,))
    acc = cur.fetchone()
    if not acc:
        conn.close()
        return {"found": False, "message": f"Account '{account_code}' not found."}
    cur.execute("""
        SELECT
          COALESCE(SUM(amount) FILTER (WHERE txn_type='debit'), 0)  AS total_debits,
          COALESCE(SUM(amount) FILTER (WHERE txn_type='credit'), 0) AS total_credits,
          COUNT(*) AS txn_count
        FROM transactions WHERE account_id=%s
    """, (acc["id"],))
    row = dict(cur.fetchone()); conn.close()
    debits  = float(row["total_debits"])
    credits = float(row["total_credits"])
    balance = debits - credits if acc["type"] in ("asset", "expense") else credits - debits
    return {
        "found": True, "code": acc["code"], "name": acc["name"],
        "type": acc["type"], "category": acc["category"],
        "total_debits": debits, "total_credits": credits,
        "balance": balance, "transaction_count": row["txn_count"],
    }


@mcp.tool()
def list_transactions(
    date_from: str = "2026-01-01", date_to: str = "2026-12-31",
    account_code: str = "", category: str = "", department: str = "",
    limit: int = 50
) -> list:
    """List transactions with optional filters. Dates: YYYY-MM-DD."""
    conn = get_connection(); cur = _cur(conn)
    q = """SELECT t.id,t.txn_date,t.description,t.amount,t.txn_type,
                  t.category,t.department,t.reference,a.code,a.name as account_name
           FROM transactions t JOIN accounts a ON t.account_id=a.id
           WHERE t.txn_date BETWEEN %s AND %s"""
    params = [date_from, date_to]
    if account_code:
        q += " AND a.code=%s"; params.append(account_code)
    if category:
        q += " AND t.category=%s"; params.append(category)
    if department:
        q += " AND t.department ILIKE %s"; params.append(f"%{department}%")
    q += f" ORDER BY t.txn_date DESC LIMIT {limit}"
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["amount"] = float(d["amount"])
        d["txn_date"] = str(d["txn_date"])[:10]
        result.append(d)
    return result if result else [{"message": "No transactions found matching filters."}]


@mcp.tool()
def get_chart_of_accounts(account_type: str = "all") -> list:
    """Return chart of accounts. account_type: asset/liability/equity/revenue/expense/all."""
    conn = get_connection(); cur = _cur(conn)
    q = "SELECT id,code,name,type,category,department FROM accounts WHERE is_active=TRUE"
    params = []
    if account_type != "all":
        q += " AND type=%s"; params.append(account_type)
    q += " ORDER BY code"
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    return [dict(r) for r in rows] if rows else [{"message": "No accounts found."}]


@mcp.tool()
def get_trial_balance(as_of_date: str = "2026-02-28") -> dict:
    """Generate a trial balance as of a given date. Date: YYYY-MM-DD."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT a.code, a.name, a.type,
               COALESCE(SUM(t.amount) FILTER (WHERE t.txn_type='debit'), 0)  AS debits,
               COALESCE(SUM(t.amount) FILTER (WHERE t.txn_type='credit'), 0) AS credits
        FROM accounts a
        LEFT JOIN transactions t ON a.id=t.account_id AND t.txn_date<=%s
        WHERE a.is_active=TRUE
        GROUP BY a.id, a.code, a.name, a.type
        ORDER BY a.code
    """, (as_of_date,))
    rows = cur.fetchall(); conn.close()
    accounts = []
    total_debits = total_credits = 0.0
    for r in rows:
        d = dict(r)
        d["debits"]  = float(d["debits"])
        d["credits"] = float(d["credits"])
        total_debits  += d["debits"]
        total_credits += d["credits"]
        accounts.append(d)
    return {
        "as_of_date": as_of_date,
        "accounts": accounts,
        "total_debits": round(total_debits, 2),
        "total_credits": round(total_credits, 2),
        "balanced": abs(total_debits - total_credits) < 1.0,
    }


@mcp.tool()
def reconcile_account(account_code: str, expected_balance: float) -> dict:
    """Compare GL balance vs expected subledger balance — flag discrepancy."""
    result = get_account_balance(account_code)
    if not result.get("found"):
        return result
    gl_balance   = result["balance"]
    discrepancy  = round(gl_balance - expected_balance, 2)
    return {
        "account_code":    account_code,
        "account_name":    result["name"],
        "gl_balance":      gl_balance,
        "expected_balance": expected_balance,
        "discrepancy":     discrepancy,
        "status":          "RECONCILED" if abs(discrepancy) < 1.0 else "DISCREPANCY FOUND",
        "message": ("✅ Account reconciled — no discrepancy." if abs(discrepancy) < 1.0
                    else f"⚠️ Discrepancy of ₹{abs(discrepancy):,.2f} found. Please investigate."),
    }


@mcp.tool()
def get_department_expenses(department: str, date_from: str = "2026-01-01", date_to: str = "2026-12-31") -> dict:
    """Sum all expense-type transactions for a department in a date range."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT t.category,
               SUM(t.amount) AS total,
               COUNT(*)      AS count
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type='expense'
          AND t.department ILIKE %s
          AND t.txn_date BETWEEN %s AND %s
        GROUP BY t.category ORDER BY total DESC
    """, (f"%{department}%", date_from, date_to))
    rows = cur.fetchall(); conn.close()
    categories = [{"category": r["category"], "total": float(r["total"]), "count": r["count"]} for r in rows]
    total = sum(c["total"] for c in categories)
    return {
        "department": department, "date_from": date_from, "date_to": date_to,
        "total_expenses": round(total, 2), "breakdown": categories,
        "message": f"Total expenses for {department}: ₹{total:,.2f}",
    }


@mcp.tool()
def get_revenue_by_category(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> list:
    """Break down revenue transactions by category for a period."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT t.category, SUM(t.amount) AS total, COUNT(*) AS count
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type='revenue' AND t.txn_date BETWEEN %s AND %s
        GROUP BY t.category ORDER BY total DESC
    """, (date_from, date_to))
    rows = cur.fetchall(); conn.close()
    result = []
    grand_total = 0.0
    for r in rows:
        total = float(r["total"])
        grand_total += total
        result.append({"category": r["category"], "total": total, "count": r["count"]})
    # Add grand total row
    result.append({"category": "TOTAL", "total": round(grand_total, 2), "count": None})
    return result if result else [{"message": "No revenue transactions found."}]


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
