"""mcp_servers/payment_server.py — Payment & Billing tools (port 8004)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("PaymentServer", host="127.0.0.1", port=8004,
              stateless_http=True, json_response=True)

def _cur(c): return c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# Valid promo codes (in production these would be in DB)
PROMO_CODES = {
    "SAVE10":   {"discount_pct": 10, "min_order": 500,   "description": "10% off on orders above ₹500"},
    "WELCOME20":{"discount_pct": 20, "min_order": 1000,  "description": "20% off for new customers"},
    "FLASH50":  {"discount_pct": 50, "min_order": 5000,  "description": "50% off flash sale — orders above ₹5000"},
    "GOLD15":   {"discount_pct": 15, "min_order": 2000,  "description": "15% off for Gold members"},
    "EXPIRED":  {"discount_pct": 5,  "min_order": 100,   "description": "Expired promo code", "expired": True},
}


@mcp.tool()
def get_payment_details(order_id: int, customer_email: str) -> list:
    """Get all payment transactions for a specific order."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, amount, method, status, transaction_id, payment_date
        FROM payments WHERE order_id=%s AND customer_email=%s ORDER BY payment_date
    """, (order_id, customer_email))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No payments found for Order #{order_id}."}]
    result = [{**dict(r), "amount": float(r["amount"]),
               "payment_date": str(r["payment_date"])[:16]} for r in rows]
    # Flag if duplicates found
    if len(result) > 1:
        amounts = [r["amount"] for r in result]
        if len(amounts) != len(set(amounts)):
            for r in result:
                r["[WARNING]_warning"] = "Possible duplicate charge detected!"
    return result


@mcp.tool()
def verify_charge(order_id: int, customer_email: str) -> dict:
    """
    Verify if a charge is correct for an order.
    Detects duplicate charges and mismatches between order total and payment.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT total_amount FROM orders WHERE id=%s AND customer_email=%s", (order_id, customer_email))
    order = c.fetchone()
    if not order:
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} not found for '{customer_email}'."}
    c.execute("""
        SELECT COUNT(*) as count, SUM(amount) as total FROM payments
        WHERE order_id=%s AND customer_email=%s AND status='completed'
    """, (order_id, customer_email))
    pay = c.fetchone()
    conn.close()
    order_total  = float(order["total_amount"])
    payment_total= float(pay["total"] or 0)
    count        = pay["count"]
    duplicate    = count > 1
    overcharge   = round(payment_total - order_total, 2) > 0
    issues = []
    if duplicate:  issues.append(f"Duplicate charge: {count} transactions found for same order")
    if overcharge: issues.append(f"Overcharged by ₹{payment_total - order_total:,.2f}")
    return {
        "order_id": order_id, "order_total": order_total,
        "total_charged": payment_total, "transaction_count": count,
        "duplicate_detected": duplicate, "overcharge_detected": overcharge,
        "issues": issues,
        "status": "[WARNING] Issues found" if issues else "✅ Charge is correct",
        "message": f"{'[WARNING] ISSUE: ' + '; '.join(issues) if issues else '✅ Charge verified — amount matches order total.'}"
    }


@mcp.tool()
def flag_duplicate_charge(order_id: int, customer_email: str) -> dict:
    """Flag a duplicate charge for an order and initiate refund process."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, amount, transaction_id FROM payments
        WHERE order_id=%s AND customer_email=%s AND status='completed'
        ORDER BY payment_date
    """, (order_id, customer_email))
    payments = c.fetchall()
    conn.close()
    if len(payments) < 2:
        return {"status": "error", "message": f"No duplicate charges found for Order #{order_id}."}
    amounts = [float(p["amount"]) for p in payments]
    if len(set(amounts)) == len(amounts):
        return {"status": "no_duplicate", "message": "Charges are for different amounts — not a duplicate."}
    # Mark the duplicate as refund_pending
    duplicate_payment = payments[-1]  # the later one is the duplicate
    conn = get_connection(); c = _cur(conn)
    c.execute("UPDATE payments SET status='refund_pending' WHERE id=%s", (duplicate_payment["id"],))
    conn.commit(); conn.close()
    return {
        "status": "flagged", "duplicate_payment_id": duplicate_payment["id"],
        "duplicate_amount": float(duplicate_payment["amount"]),
        "transaction_id": duplicate_payment["transaction_id"],
        "message": f"[ALERT] Duplicate charge of ₹{float(duplicate_payment['amount']):,.0f} flagged. Refund will be processed within 3–5 business days."
    }


@mcp.tool()
def check_coupon(code: str, order_total: float) -> dict:
    """
    Validate a promo/coupon code and calculate the discount.
    Returns discount amount and final price.
    """
    code = code.upper().strip()
    promo = PROMO_CODES.get(code)
    if not promo:
        return {"valid": False, "message": f"Promo code '{code}' does not exist."}
    if promo.get("expired"):
        return {"valid": False, "message": f"Promo code '{code}' has expired."}
    if order_total < promo["min_order"]:
        return {"valid": False,
                "message": f"Order total ₹{order_total:,.0f} is below minimum ₹{promo['min_order']:,.0f} for code '{code}'."}
    discount = round(order_total * promo["discount_pct"] / 100, 2)
    final    = round(order_total - discount, 2)
    return {
        "valid": True, "code": code,
        "discount_pct": promo["discount_pct"],
        "discount_amount": discount, "original_total": order_total, "final_total": final,
        "description": promo["description"],
        "message": f"[OK] Code '{code}' valid! {promo['discount_pct']}% off → Save ₹{discount:,.0f}. Final total: ₹{final:,.0f}."
    }


@mcp.tool()
def get_invoice(order_id: int, customer_email: str) -> dict:
    """Generate an invoice summary for an order."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT o.id, o.created_at, o.total_amount, o.status, cu.name, cu.email, cu.address, cu.city
        FROM orders o JOIN customers cu ON o.customer_email=cu.email
        WHERE o.id=%s AND o.customer_email=%s
    """, (order_id, customer_email))
    order = c.fetchone()
    if not order:
        conn.close()
        return {"found": False, "message": f"Order #{order_id} not found for '{customer_email}'."}
    c.execute("""
        SELECT p.name, p.sku, oi.quantity, oi.unit_price, oi.subtotal
        FROM order_items oi JOIN products p ON oi.product_id=p.id WHERE oi.order_id=%s
    """, (order_id,))
    items = c.fetchall()
    c.execute("SELECT method, transaction_id FROM payments WHERE order_id=%s AND status='completed' LIMIT 1", (order_id,))
    pay = c.fetchone()
    conn.close()
    return {
        "found": True,
        "invoice_no": f"INV-{order_id:05d}",
        "order_id": order_id, "customer": order["name"],
        "email": order["email"], "address": f"{order['address']}, {order['city']}",
        "date": str(order["created_at"])[:10],
        "items": [{**dict(i), "unit_price": float(i["unit_price"]), "subtotal": float(i["subtotal"])} for i in items],
        "total": float(order["total_amount"]),
        "payment_method": pay["method"].replace("_", " ").title() if pay else "Unknown",
        "transaction_id": pay["transaction_id"] if pay else None,
    }


@mcp.tool()
def get_transaction_history(customer_email: str) -> list:
    """Get full payment transaction history for a customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT p.id, p.order_id, p.amount, p.method, p.status, p.transaction_id, p.payment_date
        FROM payments p WHERE p.customer_email=%s ORDER BY p.payment_date DESC
    """, (customer_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No transactions found for '{customer_email}'."}]
    return [{**dict(r), "amount": float(r["amount"]),
             "payment_date": str(r["payment_date"])[:16]} for r in rows]


@mcp.tool()
def apply_store_credit(customer_email: str, order_id: int, credit_amount: float) -> dict:
    """Apply store credit (from loyalty points or refund) to an order."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, loyalty_points FROM customers WHERE email=%s", (customer_email,))
    cust = c.fetchone()
    if not cust:
        conn.close()
        return {"status": "error", "message": f"Customer '{customer_email}' not found."}
    # 1 point = ₹1 store credit
    if cust["loyalty_points"] < credit_amount:
        conn.close()
        return {"status": "error",
                "message": f"Insufficient points. You have {cust['loyalty_points']} points (₹{cust['loyalty_points']} credit), need ₹{credit_amount:,.0f}."}
    new_points = cust["loyalty_points"] - int(credit_amount)
    c.execute("UPDATE customers SET loyalty_points=%s WHERE email=%s", (new_points, customer_email))
    c.execute("INSERT INTO loyalty_history(customer_email,points_change,reason,balance_after) VALUES(%s,%s,%s,%s)",
              (customer_email, -int(credit_amount), f"Store credit applied to Order #{order_id}", new_points))
    conn.commit(); conn.close()
    return {"status": "applied", "credit_applied": credit_amount, "points_deducted": int(credit_amount),
            "remaining_points": new_points,
            "message": f"[OK] ₹{credit_amount:,.0f} store credit applied to Order #{order_id}. Remaining points: {new_points}."}


if __name__ == "__main__":
    init_db()
    print("[RUN] Payment MCP Server on http://127.0.0.1:8004/mcp")
    mcp.run(transport="streamable-http")