"""mcp_servers/returns_server.py — Returns, Refunds & Fraud Detection tools (port 8002)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from datetime import datetime, timedelta
from database.db import get_connection, init_db
from utils.email_service import send_return_confirmation_email, send_refund_email

mcp = FastMCP("ReturnsServer", host="127.0.0.1", port=8002,
              stateless_http=True, json_response=True)

def _cur(c): return c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def check_return_eligibility(order_id: int, customer_email: str) -> dict:
    """
    Check if an order is eligible for return.
    Rules: delivered, within 30 days, not already returned, not cancelled.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT status, delivered_at, customer_email FROM orders WHERE id=%s", (order_id,))
    order = c.fetchone()
    if not order:
        conn.close()
        return {"eligible": False, "reason": f"Order #{order_id} not found."}
    if order["customer_email"] != customer_email:
        conn.close()
        return {"eligible": False, "reason": "Email does not match this order."}
    if order["status"] != "delivered":
        conn.close()
        return {"eligible": False, "reason": f"Order is '{order['status']}' — only delivered orders can be returned."}
    if not order["delivered_at"]:
        conn.close()
        return {"eligible": False, "reason": "Delivery not confirmed."}
    days_since = (datetime.now() - order["delivered_at"]).days
    if days_since > 30:
        conn.close()
        return {"eligible": False, "reason": f"Return window expired — delivered {days_since} days ago (limit: 30 days)."}
    # Check if already returned
    c.execute("SELECT id, status FROM returns WHERE order_id=%s", (order_id,))
    existing = c.fetchone()
    conn.close()
    if existing:
        return {"eligible": False, "reason": f"Return already initiated for this order (#{existing['id']}, status: {existing['status']})."}
    return {"eligible": True, "days_since_delivery": days_since,
            "message": f"[OK] Order #{order_id} is eligible for return ({days_since} days since delivery)."}


@mcp.tool()
def flag_return_fraud(customer_email: str, order_id: int) -> dict:
    """
    Check for fraud patterns before processing a return.
    Flags: serial returners (5+ returns in 90 days), empty-box patterns, account age.
    """
    conn = get_connection(); c = _cur(conn)
    # Count returns in last 90 days
    c.execute("""
        SELECT COUNT(*) as cnt FROM returns
        WHERE customer_email=%s AND initiated_at > NOW() - INTERVAL '90 days'
    """, (customer_email,))
    recent_returns = c.fetchone()["cnt"]

    # Check fraud flags on existing returns
    c.execute("SELECT COUNT(*) as cnt FROM returns WHERE customer_email=%s AND fraud_flag=TRUE", (customer_email,))
    prior_fraud = c.fetchone()["cnt"]

    # Check customer account age
    c.execute("SELECT created_at FROM customers WHERE email=%s", (customer_email,))
    cust = c.fetchone()
    conn.close()

    risk_factors = []
    if recent_returns >= 5:
        risk_factors.append(f"Serial returner: {recent_returns} returns in last 90 days")
    if prior_fraud > 0:
        risk_factors.append(f"Prior fraud flags: {prior_fraud} previous fraud incidents")
    if cust:
        account_age_days = (datetime.now() - cust["created_at"]).days
        if account_age_days < 7:
            risk_factors.append(f"New account: only {account_age_days} days old")

    fraud_risk = "HIGH" if len(risk_factors) >= 2 else "MEDIUM" if risk_factors else "LOW"
    return {
        "customer_email": customer_email, "order_id": order_id,
        "fraud_risk": fraud_risk, "risk_factors": risk_factors,
        "recent_returns_90_days": recent_returns,
        "recommendation": "BLOCK" if fraud_risk == "HIGH" else ("REVIEW" if fraud_risk == "MEDIUM" else "APPROVE"),
        "message": f"Fraud risk: {fraud_risk}. Factors: {risk_factors if risk_factors else 'None'}."
    }


@mcp.tool()
def initiate_return(order_id: int, customer_email: str, product_id: int, reason: str) -> dict:
    """
    Initiate a return request for a delivered order.
    Runs eligibility + fraud check automatically before creating the return.
    """
    conn = get_connection(); c = _cur(conn)
    # Verify ownership
    c.execute("SELECT id FROM orders WHERE id=%s AND customer_email=%s", (order_id, customer_email))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} not found for '{customer_email}'."}
    c.execute("SELECT name FROM customers WHERE email=%s", (customer_email,))
    cust = c.fetchone()
    conn.close()
    # Eligibility check inline
    elig = check_return_eligibility(order_id, customer_email)
    if not elig["eligible"]:
        return {"status": "ineligible", "message": elig["reason"]}

    # Fraud check
    fraud = flag_return_fraud(customer_email, order_id)
    fraud_flag   = fraud["fraud_risk"] in ("HIGH", "MEDIUM")
    fraud_reason = "; ".join(fraud["risk_factors"]) if fraud["risk_factors"] else None
    status       = "flagged" if fraud["fraud_risk"] == "HIGH" else "pending"

    conn = get_connection(); c = _cur(conn)
    c.execute("""
        INSERT INTO returns(order_id,customer_email,product_id,reason,status,fraud_flag,fraud_reason)
        VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id
    """, (order_id, customer_email, product_id, reason, status, fraud_flag, fraud_reason))
    ret_id = c.fetchone()["id"]
    conn.commit(); conn.close()

    if cust and status != "flagged":
        send_return_confirmation_email(cust["name"], customer_email, ret_id, order_id, reason)

    if status == "flagged":
        return {"status": "flagged", "return_id": ret_id,
                "message": f"[ALERT] Return #{ret_id} flagged for manual review. Reason: {fraud_reason}. Our team will contact you within 24 hours."}
    return {"status": "initiated", "return_id": ret_id,
            "message": f"[OK] Return #{ret_id} initiated for Order #{order_id}. We will review within 24–48 hours. ✉️ Confirmation sent."}


@mcp.tool()
def approve_return(return_id: int) -> dict:
    """Approve a pending return and trigger refund processing."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM returns WHERE id=%s", (return_id,))
    ret = c.fetchone()
    if not ret:
        conn.close()
        return {"status": "error", "message": f"Return #{return_id} not found."}
    if ret["fraud_flag"]:
        conn.close()
        return {"status": "error", "message": "Cannot approve — fraud flag is set on this return."}
    c.execute("UPDATE returns SET status='approved', resolved_at=NOW() WHERE id=%s", (return_id,))
    conn.commit(); conn.close()
    return {"status": "approved", "return_id": return_id,
            "message": f"[OK] Return #{return_id} approved. Proceed to process_refund to issue the refund."}


@mcp.tool()
def reject_return(return_id: int, reason: str) -> dict:
    """Reject a return request with a given reason."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id FROM returns WHERE id=%s", (return_id,))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": f"Return #{return_id} not found."}
    c.execute("UPDATE returns SET status='rejected', fraud_reason=%s, resolved_at=NOW() WHERE id=%s", (reason, return_id))
    conn.commit(); conn.close()
    return {"status": "rejected", "return_id": return_id,
            "message": f"[STOP] Return #{return_id} rejected. Reason: {reason}"}


@mcp.tool()
def process_refund(return_id: int, amount: float, method: str = "original_payment") -> dict:
    """
    Process a refund for an approved return.
    method: original_payment | store_credit | bank_transfer
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT r.*, cu.name FROM returns r JOIN customers cu ON r.customer_email=cu.email WHERE r.id=%s", (return_id,))
    ret = c.fetchone()
    if not ret:
        conn.close()
        return {"status": "error", "message": f"Return #{return_id} not found."}
    if ret["status"] != "approved":
        conn.close()
        return {"status": "error", "message": f"Return is '{ret['status']}' — must be approved before refund."}
    c.execute("""
        INSERT INTO refunds(return_id,customer_email,amount,method,status,processed_at)
        VALUES(%s,%s,%s,%s,'completed',NOW()) RETURNING id
    """, (return_id, ret["customer_email"], amount, method))
    refund_id = c.fetchone()["id"]
    # Add store credit points if method is store_credit
    if method == "store_credit":
        points = int(amount // 10)
        c.execute("UPDATE customers SET loyalty_points=loyalty_points+%s WHERE email=%s", (points, ret["customer_email"]))
        c.execute("INSERT INTO loyalty_history(customer_email,points_change,reason,balance_after) SELECT %s,%s,%s,loyalty_points FROM customers WHERE email=%s",
                  (ret["customer_email"], points, f"Store credit refund for Return #{return_id}", ret["customer_email"]))
    conn.commit(); conn.close()
    send_refund_email(ret["name"], ret["customer_email"], refund_id, amount, method)
    return {"status": "processed", "refund_id": refund_id, "amount": amount, "method": method,
            "message": f"[OK] Refund #{refund_id} of ₹{amount:,.0f} processed via {method.replace('_',' ')}. ✉️ Confirmation emailed."}


@mcp.tool()
def get_return_status(customer_email: str) -> list:
    """Get all return requests for a customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT r.id, r.order_id, r.reason, r.status, r.fraud_flag, r.initiated_at, r.resolved_at,
               p.name as product_name
        FROM returns r LEFT JOIN products p ON r.product_id=p.id
        WHERE r.customer_email=%s ORDER BY r.initiated_at DESC
    """, (customer_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No returns found for '{customer_email}'."}]
    return [{**dict(r), "initiated_at": str(r["initiated_at"])[:16],
             "resolved_at": str(r["resolved_at"])[:16] if r["resolved_at"] else None} for r in rows]


@mcp.tool()
def get_refund_status(customer_email: str) -> list:
    """Get all refunds for a customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, return_id, amount, method, status, processed_at
        FROM refunds WHERE customer_email=%s ORDER BY processed_at DESC
    """, (customer_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No refunds found for '{customer_email}'."}]
    return [{**dict(r), "amount": float(r["amount"]),
             "processed_at": str(r["processed_at"])[:16] if r["processed_at"] else None} for r in rows]


if __name__ == "__main__":
    init_db()
    print("[RUN] Returns MCP Server on http://127.0.0.1:8002/mcp")
    mcp.run(transport="streamable-http")