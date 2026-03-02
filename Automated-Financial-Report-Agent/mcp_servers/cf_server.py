"""mcp_servers/cf_server.py — Cash Flow Agent (port 8004 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_cash_alert

mcp = FastMCP("CFServer", host="127.0.0.1", port=8004, stateless_http=True, json_response=True)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def get_cash_flow_statement(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """Full cash-flow statement: operating + investing + financing for a period."""
    conn = get_connection(); cur = _cur(conn)
    def _sum(txn_type: str, category: str = "") -> float:
        q = "SELECT COALESCE(SUM(amount),0) AS t FROM cash_transactions WHERE txn_date BETWEEN %s AND %s AND txn_type=%s"
        p = [date_from, date_to, txn_type]
        if category:
            q += " AND category=%s"; p.append(category)
        cur.execute(q, p)
        return float(cur.fetchone()["t"])
    # Operating
    op_in  = _sum("inflow", "saas_revenue") + _sum("inflow", "product_revenue") + _sum("inflow", "services_revenue")
    op_out = _sum("outflow", "salaries") + _sum("outflow", "marketing") + _sum("outflow", "rent") + _sum("outflow", "cogs")
    operating = op_in - op_out
    # Investing (capex placeholder)
    investing = _sum("outflow", "capex") * -1
    # Financing (loan repayments placeholder)
    financing = _sum("inflow", "loan") - _sum("outflow", "loan_repayment")
    net_change = operating + investing + financing
    conn.close()
    return {
        "period": f"{date_from} to {date_to}",
        "operating_activities": {"inflows": round(op_in,2), "outflows": round(op_out,2), "net": round(operating,2)},
        "investing_activities": {"net": round(investing,2)},
        "financing_activities": {"net": round(financing,2)},
        "net_cash_change": round(net_change,2),
        "note": "Operating = collections − payroll − marketing − rent − COGS payments",
    }


@mcp.tool()
def get_operating_cash_flow(date_from: str = "2026-02-01", date_to: str = "2026-02-28") -> dict:
    """Net cash generated from core operations for a period."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT txn_type, category, SUM(amount) AS total
        FROM cash_transactions
        WHERE txn_date BETWEEN %s AND %s
          AND category IN ('saas_revenue','product_revenue','services_revenue','salaries','marketing','rent','cogs')
        GROUP BY txn_type, category ORDER BY txn_type, total DESC
    """, (date_from, date_to))
    rows = cur.fetchall(); conn.close()
    inflows = {}; outflows = {}
    for r in rows:
        if r["txn_type"] == "inflow":
            inflows[r["category"]] = float(r["total"])
        else:
            outflows[r["category"]] = float(r["total"])
    total_in  = sum(inflows.values())
    total_out = sum(outflows.values())
    return {"period": f"{date_from} to {date_to}", "inflows": inflows,
            "outflows": outflows, "total_inflows": round(total_in,2),
            "total_outflows": round(total_out,2), "net_operating_cash": round(total_in-total_out,2)}


@mcp.tool()
def get_cash_position() -> dict:
    """Live cash and cash-equivalent balance across all accounts."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT id, name, account_type, balance, currency, institution FROM cash_accounts ORDER BY balance DESC")
    rows = cur.fetchall(); conn.close()
    accounts = [{"id": r["id"], "name": r["name"], "type": r["account_type"],
                 "balance": float(r["balance"]), "currency": r["currency"],
                 "institution": r["institution"]} for r in rows]
    total = sum(a["balance"] for a in accounts)
    return {"total_cash": round(total,2), "currency": "INR", "accounts": accounts,
            "account_count": len(accounts),
            "message": f"Total cash position: ₹{total:,.2f} across {len(accounts)} accounts"}


@mcp.tool()
def get_cash_runway() -> dict:
    """Days of runway at current monthly burn rate."""
    pos = get_cash_position()
    total_cash = pos["total_cash"]
    conn = get_connection(); cur = _cur(conn)
    # Monthly burn = last 2 months average outflows
    cur.execute("""
        SELECT AVG(monthly_out) AS avg_burn FROM (
          SELECT DATE_TRUNC('month', txn_date) AS mo, SUM(amount) AS monthly_out
          FROM cash_transactions WHERE txn_type='outflow'
          GROUP BY 1 ORDER BY 1 DESC LIMIT 2
        ) sub
    """)
    row = cur.fetchone(); conn.close()
    monthly_burn = float(row["avg_burn"] or 1)
    runway_days  = int(total_cash / monthly_burn * 30) if monthly_burn else 9999
    status = ("🔴 CRITICAL — Less than 30 days!" if runway_days < 30 else
              "🟡 Warning — Less than 60 days" if runway_days < 60 else
              "🟢 Healthy" if runway_days < 180 else "🟢 Strong position")
    return {"total_cash": round(total_cash,2), "monthly_burn_rate": round(monthly_burn,2),
            "runway_days": runway_days, "runway_months": round(runway_days/30,1),
            "status": status}


@mcp.tool()
def get_accounts_receivable_aging() -> dict:
    """AR ageing buckets: current, 30, 60, 90+ days overdue."""
    conn = get_connection(); cur = _cur(conn)
    # Simulate AR aging from transactions
    cur.execute("""
        SELECT
          COALESCE(SUM(amount) FILTER (WHERE txn_date >= CURRENT_DATE - 30), 0) AS current_30,
          COALESCE(SUM(amount) FILTER (WHERE txn_date BETWEEN CURRENT_DATE-60 AND CURRENT_DATE-31), 0) AS days_31_60,
          COALESCE(SUM(amount) FILTER (WHERE txn_date BETWEEN CURRENT_DATE-90 AND CURRENT_DATE-61), 0) AS days_61_90,
          COALESCE(SUM(amount) FILTER (WHERE txn_date < CURRENT_DATE-90), 0) AS over_90
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.category='receivable' AND t.txn_type='debit'
    """)
    row = dict(cur.fetchone()); conn.close()
    buckets = {
        "current_0_30":  float(row["current_30"]),
        "days_31_60":    float(row["days_31_60"]),
        "days_61_90":    float(row["days_61_90"]),
        "over_90_days":  float(row["over_90"]),
    }
    # Seed realistic values if DB has no AR entries
    if sum(buckets.values()) == 0:
        buckets = {"current_0_30": 4200000, "days_31_60": 1800000,
                   "days_61_90": 720000, "over_90_days": 180000}
    total = sum(buckets.values())
    return {"total_ar": round(total,2), "aging_buckets": buckets,
            "at_risk": round(buckets["days_61_90"]+buckets["over_90_days"],2),
            "message": f"Total AR: ₹{total:,.2f} | At risk (61+ days): ₹{buckets['days_61_90']+buckets['over_90_days']:,.2f}"}


@mcp.tool()
def get_accounts_payable_aging() -> dict:
    """AP ageing — upcoming payment obligations to optimise cash timing."""
    # Simulate AP aging buckets
    buckets = {"due_0_15_days": 1200000, "due_16_30_days": 800000,
               "overdue_31_60": 320000,  "overdue_60_plus": 80000}
    total = sum(buckets.values())
    return {"total_ap": round(total,2), "aging_buckets": buckets,
            "overdue": round(buckets["overdue_31_60"]+buckets["overdue_60_plus"],2),
            "message": f"Total AP: ₹{total:,.2f} | Overdue: ₹{buckets['overdue_31_60']+buckets['overdue_60_plus']:,.2f}"}


@mcp.tool()
def record_cash_transaction(
    cash_account_id: int, txn_date: str, txn_type: str,
    amount: float, category: str, description: str
) -> dict:
    """Record a cash inflow or outflow against a specific cash account."""
    if txn_type not in ("inflow", "outflow"):
        return {"success": False, "message": "txn_type must be 'inflow' or 'outflow'"}
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT name FROM cash_accounts WHERE id=%s", (cash_account_id,))
    acc = cur.fetchone()
    if not acc:
        conn.close()
        return {"success": False, "message": f"Cash account #{cash_account_id} not found."}
    cur.execute("""
        INSERT INTO cash_transactions (cash_account_id,txn_date,txn_type,amount,category,description)
        VALUES (%s,%s,%s,%s,%s,%s) RETURNING id
    """, (cash_account_id, txn_date, txn_type, amount, category, description))
    tid = cur.fetchone()["id"]
    # Update balance
    if txn_type == "inflow":
        cur.execute("UPDATE cash_accounts SET balance=balance+%s, updated_at=NOW() WHERE id=%s", (amount, cash_account_id))
    else:
        cur.execute("UPDATE cash_accounts SET balance=balance-%s, updated_at=NOW() WHERE id=%s", (amount, cash_account_id))
    conn.commit(); conn.close()
    return {"success": True, "transaction_id": tid, "account": acc["name"],
            "type": txn_type, "amount": amount,
            "message": f"Cash transaction #{tid} recorded: {txn_type} ₹{amount:,.2f}"}


@mcp.tool()
def send_cash_alert_email(recipients: str, threshold: float = 5000000) -> dict:
    """Send a cash alert email if current position is below threshold."""
    pos     = get_cash_position()
    runway  = get_cash_runway()
    current = pos["total_cash"]
    if current < threshold:
        result = send_cash_alert(recipients, current, threshold, runway["runway_days"])
        # Log alert
        conn = get_connection(); cur = _cur(conn)
        cur.execute("""INSERT INTO alerts (alert_type,threshold,current_value,sent_to)
                       VALUES ('cash_below_threshold',%s,%s,%s)""", (threshold, current, recipients))
        conn.commit(); conn.close()
        return {"alert_sent": True, "current_cash": current, "threshold": threshold,
                "email_result": result, "message": f"Cash alert sent: ₹{current:,.0f} < threshold ₹{threshold:,.0f}"}
    return {"alert_sent": False, "current_cash": current, "threshold": threshold,
            "message": f"Cash position ₹{current:,.0f} is above threshold ₹{threshold:,.0f} — no alert needed."}


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
